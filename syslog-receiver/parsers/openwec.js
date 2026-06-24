// OpenWEC parser. OpenWEC is the WEF collector running as a sidecar on the
// syslog box (Stage 2 Phase 4). It receives Windows events from customer GPO
// over WS-Management mTLS (port 5986) and forwards them to localhost syslog
// in this format:
//
//   <PRI>1 <TIMESTAMP> <HOSTNAME> openwec - [openwec@33580 client="<id>" computer="<host>"] <JSON-of-event>
//
// MDRv2 Stage 2 (T10/T13). Lights up the data path for AD audit detection
// rules in Stage 3 (Kerberoasting, DCSync, EID 4624/4625, Pass-the-Hash, etc).

'use strict'

const OPENWEC_RE = /\[openwec@\d+\s+([^\]]+)\]\s*(\{[\s\S]*\})\s*$/
const UNSAFE_PATH_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

function detect(msg) {
  return /\[openwec@\d+/.test(msg) || /\bopenwec\b.*?\{[\s\S]*"Event(ID|Data|Channel)"/.test(msg)
}

function extractSdParams(sdParamsStr) {
  // Parse `client="X" computer="Y"` style key=value pairs from syslog SD-PARAMS
  const out = {}
  const re = /(\w+)="([^"]*)"/g
  let m
  while ((m = re.exec(sdParamsStr)) !== null) {
    out[m[1]] = m[2]
  }
  return out
}

function parse(msg) {
  const m = OPENWEC_RE.exec(msg)
  if (!m) return null

  const sd = extractSdParams(m[1])
  let eventJson
  try {
    eventJson = JSON.parse(m[2])
  } catch {
    return null
  }

  // Extract canonical Windows event fields. Field names follow Microsoft's
  // EventLog XML convention (Computer / Channel / EventID / EventData).
  // Some are direct on the JSON; others are nested under Event.System or
  // Event.EventData depending on the OpenWEC output mode.
  const eventId = pick(eventJson, 'EventID', 'Event.System.EventID', 'event_id')
  const computer = pick(eventJson, 'Computer', 'Event.System.Computer', 'computer') ?? sd.computer
  const channel = pick(eventJson, 'Channel', 'Event.System.Channel', 'channel')
  const provider = pick(eventJson, 'Provider', 'Event.System.Provider.Name', 'provider')
  const level = pick(eventJson, 'Level', 'Event.System.Level', 'level')
  const eventData = pick(eventJson, 'EventData', 'Event.EventData', 'event_data') ?? {}

  // Common Windows-event fields surfaced from EventData when present.
  // Event 4624 (logon) / 4625 (failed logon) shape:
  const subjectUser = pickField(eventData, 'SubjectUserName', 'TargetUserName')
  const subjectDomain = pickField(eventData, 'SubjectDomainName', 'TargetDomainName')
  const targetUser = pickField(eventData, 'TargetUserName')
  const logonType = pickField(eventData, 'LogonType')
  const ipAddress = pickField(eventData, 'IpAddress', 'SourceNetworkAddress')
  const workstation = pickField(eventData, 'WorkstationName')
  const processName = pickField(eventData, 'ProcessName', 'NewProcessName')
  const commandLine = pickField(eventData, 'CommandLine')

  // MDRv2 Stage 3 — extracted EventData fields used by new detection rules.
  // EID 4688 process create:  ParentProcessName, ParentImage, ParentCommandLine
  const parentProcessName = pickField(eventData, 'ParentProcessName', 'ParentImage')
  const parentCommandLine = pickField(eventData, 'ParentCommandLine')
  // EID 4663 file access:    GrantedAccess
  const grantedAccess = pickField(eventData, 'GrantedAccess', 'AccessList')
  // Sysmon (when present):    Hashes (file hash), Image (loaded image)
  const hashes = pickField(eventData, 'Hashes', 'FileHash')
  const imageLoaded = pickField(eventData, 'ImageLoaded', 'TargetImage')
  // EID 4769 Kerberos TGS:    ServiceName, TicketEncryptionType
  const serviceName = pickField(eventData, 'ServiceName')
  const ticketEncryptionType = pickField(eventData, 'TicketEncryptionType')
  // EID 7045 service install: ServiceName (alt), ImagePath, ServiceType, StartType
  const imagePath = pickField(eventData, 'ImagePath')
  const serviceType = pickField(eventData, 'ServiceType')
  const startType = pickField(eventData, 'StartType')
  // EID 4698 scheduled task:  TaskName, RunLevel, Author
  const taskName = pickField(eventData, 'TaskName')
  const runLevel = pickField(eventData, 'RunLevel')
  const taskAuthor = pickField(eventData, 'Author')
  // EID 4662 directory access: ObjectName, ObjectAccess, AccessMask, Properties
  const objectName = pickField(eventData, 'ObjectName')
  const objectAccess = pickField(eventData, 'OperationType')
  const accessMask = pickField(eventData, 'AccessMask')
  const properties = pickField(eventData, 'Properties')
  // EID 4625 failed logon:    Status, SubStatus, FailureReason
  const failureReason = pickField(eventData, 'FailureReason', 'Status', 'SubStatus')
  // EID 4624 logon details:   LogonProcessName, AuthenticationPackageName
  // Used by Pass-the-Hash rule (logon_process_name='seclogo' + auth_pkg='Negotiate' + workstation mismatch).
  const logonProcessName = pickField(eventData, 'LogonProcessName')
  const authPackageName = pickField(eventData, 'AuthenticationPackageName')
  // R6 SMB Admin-share write — EIDs 5140 / 5145.
  const shareName = pickField(eventData, 'ShareName')
  const relativeTargetName = pickField(eventData, 'RelativeTargetName')
  // R5 UAC Bypass — Sysmon EID 13 (registry value set).
  const targetObject = pickField(eventData, 'TargetObject')
  // R9 Priv Esc Token Theft — EID 4673 privileged service called.
  const privilegeList = pickField(eventData, 'PrivilegeList', 'Privileges')
  const serviceServer = pickField(eventData, 'Service', 'Server')
  // Pass-the-Hash signature — workstation_name in the auth event differs
  // from the host that submitted it. Only meaningful on EID 4624 with both
  // values populated.
  const workstationMismatch =
    workstation && computer
      ? String(workstation).toLowerCase() !== String(computer).toLowerCase().split('.')[0]
      : null

  return {
    win_event_id:
      typeof eventId === 'string' || typeof eventId === 'number' ? Number(eventId) : null,
    win_channel: channel,
    win_provider: provider,
    win_level: level,
    win_subject_user: subjectUser,
    win_subject_domain: subjectDomain,
    win_target_user: targetUser,
    win_logon_type: logonType !== undefined && logonType !== null ? Number(logonType) : null,
    win_workstation: workstation,
    win_process_name: processName,
    win_parent_process_name: parentProcessName,
    win_command_line: commandLine,
    win_service_name: serviceName,
    win_ticket_encryption_type: ticketEncryptionType,
    win_image_path: imagePath,
    win_service_type: serviceType,
    win_start_type: startType,
    win_task_name: taskName,
    win_run_level: runLevel,
    win_task_author: taskAuthor,
    win_object_name: objectName,
    win_object_access: objectAccess,
    win_access_mask: accessMask,
    win_properties: properties,
    win_failure_reason: failureReason,
    win_logon_process_name: logonProcessName,
    win_authentication_package_name: authPackageName,
    win_logon_workstation_mismatch: workstationMismatch,
    // R6 — network share access (5140/5145)
    win_share_name: shareName,
    win_relative_target_name: relativeTargetName,
    // R5 — Sysmon EID 13 registry value set
    win_target_object: targetObject,
    // R9 — privilege grants (4673) + service server
    win_privilege_list: privilegeList,
    win_service_server: serviceServer,
    win_event_data: eventData, // raw EventData preserved for future rule queries
    // Stage 2 Deliverable (Monday 2877685372) — unprefixed field aliases:
    // spec listed process_name, command_line, parent_process_name,
    // parent_command_line, account_name, account_domain, hashes,
    // granted_access, image_loaded. Old win_* names retained above for
    // back-compat with rule queries that reference them.
    process_name: processName,
    command_line: commandLine,
    parent_process_name: parentProcessName,
    parent_command_line: parentCommandLine,
    account_name: subjectUser ?? targetUser,
    account_domain: subjectDomain,
    hashes,
    granted_access: grantedAccess,
    image_loaded: imageLoaded,
    src_ip: ipAddress,
    src_user: subjectUser ?? targetUser,
    hostname: computer,
    client_id_hint: sd.client, // forwarded from the openwec mTLS subject for cross-check at allowlist time
    event_category: classifyByEid(eventId),
    event_action: actionByEid(eventId),
    parser_name: 'openwec',
    // IngestSource bucket — drives the IngestSource registry bootstrap.
    // Sysmon channel events override to 'sysmon'; everything else is 'wef'.
    ingest_source: channel === 'Microsoft-Windows-Sysmon/Operational' ? 'sysmon' : 'wef',
  }
}

function pick(obj, ...paths) {
  for (const p of paths) {
    const parts = p.split('.')
    let cur = obj
    let ok = true
    for (const part of parts) {
      if (
        !UNSAFE_PATH_KEYS.has(part) &&
        cur &&
        typeof cur === 'object' &&
        Object.hasOwn(cur, part)
      ) {
        cur = cur[part] // nosemgrep: javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop
      } else {
        ok = false
        break
      }
    }
    if (ok && cur !== undefined && cur !== null) return cur
  }
  return undefined
}

function pickField(eventData, ...names) {
  if (!eventData || typeof eventData !== 'object') return undefined
  for (const n of names) {
    if (
      !UNSAFE_PATH_KEYS.has(n) &&
      Object.hasOwn(eventData, n) &&
      eventData[n] !== undefined &&
      eventData[n] !== null &&
      eventData[n] !== '-'
    ) {
      return eventData[n]
    }
  }
  return undefined
}

function classifyByEid(eid) {
  const id = Number(eid)
  if (!Number.isFinite(id)) return 'windows'
  if ([4624, 4625, 4634, 4647, 4648, 4768, 4769, 4771, 4776].includes(id)) return 'auth'
  if ([4663, 4660, 4670].includes(id)) return 'file'
  if ([4688, 4689].includes(id)) return 'process'
  if ([4720, 4722, 4724, 4725, 4726, 4738, 4732, 4756].includes(id)) return 'identity'
  if ([4698, 4699, 4700, 4701, 4702].includes(id)) return 'persistence'
  if ([1102].includes(id)) return 'tampering'
  if ([4662, 4928, 4929, 4932, 4933].includes(id)) return 'directory'
  if ([7045, 7036, 7034].includes(id)) return 'service'
  if ([5140, 5145].includes(id)) return 'share' // R6 SMB share access
  if ([4672, 4673, 4674].includes(id)) return 'privilege' // R9 priv use
  if ([5001, 5007, 5012, 5025].includes(id)) return 'tampering' // R8 Defender tamper
  if ([13, 19, 20, 21].includes(id)) return 'sysmon' // R5 reg-write / R7 WMI subscriptions
  return 'windows'
}

function actionByEid(eid) {
  const id = Number(eid)
  if (id === 4624) return 'login_success'
  if (id === 4625) return 'login_failure'
  if (id === 4634 || id === 4647) return 'logoff'
  if (id === 4688) return 'process_create'
  if (id === 4689) return 'process_terminate'
  if (id === 4698) return 'scheduled_task_created'
  if (id === 4720) return 'user_created'
  if (id === 4724) return 'password_reset'
  if (id === 4732) return 'group_member_added'
  if (id === 4769) return 'kerberos_tgs_request'
  if (id === 4768) return 'kerberos_tgt_request'
  if (id === 4776) return 'ntlm_authentication'
  if (id === 1102) return 'audit_log_cleared'
  if (id === 7045) return 'service_installed'
  if (id === 4662) return 'directory_object_access'
  if (id === 5140) return 'share_accessed'
  if (id === 5145) return 'share_check'
  if (id === 4672) return 'special_privileges_assigned'
  if (id === 4673) return 'privileged_service_called'
  if (id === 5001) return 'defender_realtime_disabled'
  if (id === 5007) return 'defender_config_changed'
  if (id === 5012) return 'defender_scanning_disabled'
  if (id === 13) return 'sysmon_registry_value_set'
  if (id === 19) return 'sysmon_wmi_filter_create'
  if (id === 20) return 'sysmon_wmi_consumer_create'
  if (id === 21) return 'sysmon_wmi_binding_create'
  return 'windows_event'
}

module.exports = { detect, parse }
