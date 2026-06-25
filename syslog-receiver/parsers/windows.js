// Windows file-access parser — NXLog (im_msvistalog) shipping Security-channel
// events as NEWLINE-DELIMITED JSON over TCP 1514.
//
// NXLog's to_json() FLATTENS the event: System fields and EventData fields are
// promoted to TOP-LEVEL keys on one JSON object, e.g.:
//   {"EventID":4663,"Hostname":"FS01","Computer":"FS01.corp.local",
//    "Channel":"Security","ProviderName":"Microsoft-Windows-Security-Auditing",
//    "EventTime":"2026-06-24 11:22:33","SubjectUserName":"jdoe",
//    "SubjectDomainName":"CORP","ObjectName":"C:\\Share\\file.docx",
//    "ObjectType":"File","AccessList":"%%4416\n\t\t\t\t","AccessMask":"0x1", ... }
//
// Only EIDs 4663 / 4660 / 4670 / 5140 / 5145 are forwarded (filtered at source
// in the NXLog config), but parse() is defensive for any other EID too.
//
// DISPATCH ORDER: this module is registered in parsers/index.js BEFORE json.js so
// that a flat Windows event gets Windows normalization. Its detect() is strict —
// it only claims a payload that JSON-parses AND carries a NUMERIC EventID AND a
// Windows marker (Channel / Hostname / Computer / ProviderName). Non-Windows JSON
// has no numeric EventID + Windows marker, so it falls through to json.js.
//
// PURE function, no OpenSearch import — unit-testable with node:test, zero deps.

'use strict'

const UNSAFE_PATH_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

// Windows access-right %%-codes (seen in AccessList / Accesses) and the matching
// hex AccessMask bits used as a fallback when the textual list is absent.
// Reference: Microsoft "Access Control" constants + 4663/5145 event docs.
const ACCESS_CODES = {
  '%%1537': 'DELETE',       // SACL DELETE
  '%%1538': 'READ_CONTROL',
  '%%1539': 'WRITE_DAC',    // change permissions  -> permission_change
  '%%1540': 'WRITE_OWNER',  // take ownership      -> permission_change
  '%%1541': 'SYNCHRONIZE',
  '%%4416': 'ReadData',     // / ListDirectory     -> file_read
  '%%4417': 'WriteData',    // / AddFile           -> file_write
  '%%4418': 'AppendData',   // / AddSubdirectory   -> file_write
  '%%4419': 'ReadEA',
  '%%4420': 'WriteEA',
  '%%4423': 'ReadAttributes',
  '%%4424': 'WriteAttributes',
}

// Hex AccessMask bit -> right name (standard Windows file/dir access mask).
const MASK_BITS = [
  [0x10000, 'DELETE'],
  [0x40000, 'WRITE_DAC'],
  [0x80000, 'WRITE_OWNER'],
  [0x1, 'ReadData'],
  [0x2, 'WriteData'],
  [0x4, 'AppendData'],
]

// LogonType -> human label (Microsoft 4624/4625 LogonType values).
const LOGON_TYPE_LABELS = {
  2: 'interactive',
  3: 'network',
  4: 'batch',
  5: 'service',
  7: 'unlock',
  8: 'network_cleartext',
  9: 'new_credentials',
  10: 'remote_interactive',
  11: 'cached_interactive',
}

// Account-lifecycle EIDs -> normalized event_action. TargetUserName is the
// account being acted on; SubjectUserName is the admin/actor doing it.
const ACCOUNT_ACTIONS = {
  4720: 'account_created',
  4722: 'account_enabled',
  4723: 'password_change',
  4724: 'password_reset',
  4725: 'account_disabled',
  4726: 'account_deleted',
}

function detect(raw) {
  if (raw == null) return false
  const t = String(raw).trim()
  // Cheap pre-check: must be a single JSON object.
  if (!t.startsWith('{') || !t.endsWith('}')) return false
  let obj
  try {
    obj = JSON.parse(t)
  } catch {
    return false
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false
  // Require a NUMERIC EventID. NXLog emits EventID as a JSON number, but accept
  // an all-digits string too (defensive). A non-numeric / absent EventID means
  // this is not the flattened Windows event we own.
  const eid = obj.EventID
  const eidNum =
    typeof eid === 'number'
      ? eid
      : typeof eid === 'string' && /^\d+$/.test(eid.trim())
        ? Number(eid)
        : NaN
  if (!Number.isFinite(eidNum)) return false
  // Require at least one Windows marker so a generic {"EventID":1,...} app log
  // from some non-Windows source is NOT claimed (falls through to json.js).
  return (
    has(obj, 'Channel') ||
    has(obj, 'Hostname') ||
    has(obj, 'Computer') ||
    has(obj, 'ProviderName')
  )
}

function parse(raw) {
  const t = String(raw).trim()
  let obj
  try {
    obj = JSON.parse(t)
  } catch {
    return null
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null

  const eid = toEid(obj.EventID)
  if (eid == null) return null

  const channel = pick(obj, 'Channel')
  const provider = pick(obj, 'ProviderName', 'SourceName', 'Provider')
  const host = pick(obj, 'Computer', 'Hostname')
  const subjectUser = pick(obj, 'SubjectUserName')
  const subjectDomain = pick(obj, 'SubjectDomainName')

  const out = {
    device_vendor: 'microsoft',
    device_product: 'windows-security',
    event_category: classifyByEid(eid),
    parser_name: 'windows-nxlog',
    ingest_source: 'nxlog',
    win_event_id: eid,
    win_channel: channel ?? null,
    win_provider: provider ?? null,
    host: host ?? null,
    hostname: host ?? null,
    // Dashboard "Sources" aggregates on `source` (api/sources/route.ts terms:source).
    // Use the machine name so every Windows host shows up as its own source.
    source: host ?? 'Windows',
    src_user: composeUser(subjectUser, subjectDomain),
    src_domain: subjectDomain ?? null,
    message: pick(obj, 'Message') ?? null,
  }

  // @timestamp from EventTime when present. NXLog EventTime is typically
  // "YYYY-MM-DD HH:MM:SS" (local) — keep the raw string if it doesn't parse to
  // a Date so we never emit Invalid Date.
  const eventTime = pick(obj, 'EventTime', 'EventTimeWritten')
  if (eventTime != null) {
    const d = new Date(String(eventTime).replace(' ', 'T'))
    out['@timestamp'] = Number.isFinite(d.getTime()) ? d.toISOString() : String(eventTime)
    out.win_event_time = String(eventTime)
  }

  switch (eid) {
    case 4663: {
      // Object access — the core file-access event.
      out.file_path = pick(obj, 'ObjectName') ?? null
      out.win_object_type = pick(obj, 'ObjectType') ?? null
      const accessRaw = pick(obj, 'AccessList', 'Accesses')
      const accessMask = pick(obj, 'AccessMask')
      out.access = accessRaw != null ? cleanAccess(accessRaw) : null
      out.win_access_mask = accessMask != null ? String(accessMask) : null
      out.event_action = deriveFileAction(accessRaw, accessMask) || 'file_access'
      break
    }
    case 4660: {
      // Object deleted — frequently carries only HandleId (no ObjectName); the
      // matching 4663 (with DELETE) carries the path. Mark the delete regardless.
      out.event_action = 'file_delete'
      const objName = pick(obj, 'ObjectName')
      if (objName != null) out.file_path = objName
      const handle = pick(obj, 'HandleId', 'ObjectHandle')
      if (handle != null) out.win_handle_id = String(handle)
      break
    }
    case 4670: {
      // Permissions on an object were changed.
      out.event_action = 'permission_change'
      out.file_path = pick(obj, 'ObjectName') ?? null
      out.win_object_type = pick(obj, 'ObjectType') ?? null
      const oldSd = pick(obj, 'OldSd')
      const newSd = pick(obj, 'NewSd')
      if (oldSd != null) out.win_old_sd = String(oldSd)
      if (newSd != null) out.win_new_sd = String(newSd)
      break
    }
    case 5145: {
      // Detailed file-share access — IpAddress is THE WORKSTATION IP (the client
      // reaching the share), IpPort its source port. ShareName + RelativeTargetName
      // join into the accessed UNC-style path.
      const shareName = pick(obj, 'ShareName')
      const relTarget = pick(obj, 'RelativeTargetName')
      out.share_name = shareName ?? null
      out.relative_target_name = relTarget ?? null
      out.file_path = joinSharePath(shareName, relTarget)
      out.src_ip = normIp(pick(obj, 'IpAddress')) // workstation IP — important
      out.src_port = toInt(pick(obj, 'IpPort'))
      const accessRaw = pick(obj, 'AccessList', 'Accesses')
      const accessMask = pick(obj, 'AccessMask')
      out.access = accessRaw != null ? cleanAccess(accessRaw) : null
      out.win_access_mask = accessMask != null ? String(accessMask) : null
      // Prefer a derived read/write action; otherwise the generic share_access.
      out.event_action = deriveFileAction(accessRaw, accessMask) || 'share_access'
      break
    }
    case 5140: {
      // A network share object was accessed (connect).
      out.event_action = 'share_connect'
      out.share_name = pick(obj, 'ShareName') ?? null
      const shareLocal = pick(obj, 'ShareLocalPath')
      if (shareLocal != null) out.win_share_local_path = String(shareLocal)
      out.src_ip = normIp(pick(obj, 'IpAddress'))
      out.src_port = toInt(pick(obj, 'IpPort'))
      const accessMask = pick(obj, 'AccessMask')
      out.win_access_mask = accessMask != null ? String(accessMask) : null
      break
    }
    // ── ENDPOINT / DESKTOP enrichment (ported from openwec.js field logic) ──
    case 4624: {
      // Successful logon. TargetUserName is WHO logged on; SubjectUserName is the
      // (often SYSTEM) account that requested it — so override src_user with the
      // target. IpAddress is the source workstation IP (null when '-').
      out.event_action = 'login'
      const targetUser = pick(obj, 'TargetUserName')
      const targetDomain = pick(obj, 'TargetDomainName')
      if (targetUser != null) {
        out.src_user = composeUser(targetUser, targetDomain)
        if (targetDomain != null) out.src_domain = targetDomain
      }
      applyLogonType(out, pick(obj, 'LogonType'))
      const ip = normIp(pick(obj, 'IpAddress'))
      if (ip != null) out.src_ip = ip
      const port = toInt(pick(obj, 'IpPort'))
      if (port != null) out.src_port = port
      const logonProcess = pick(obj, 'LogonProcessName', 'LogonProcess')
      if (logonProcess != null) out.logon_process = String(logonProcess)
      const authPackage = pick(obj, 'AuthenticationPackageName', 'AuthenticationPackage')
      if (authPackage != null) out.auth_package = String(authPackage)
      const workstation = pick(obj, 'WorkstationName')
      if (workstation != null) out.win_workstation = String(workstation)
      break
    }
    case 4625: {
      // Failed logon. TargetUserName is the attempted account.
      out.event_action = 'login_failed'
      const targetUser = pick(obj, 'TargetUserName')
      const targetDomain = pick(obj, 'TargetDomainName')
      if (targetUser != null) {
        out.src_user = composeUser(targetUser, targetDomain)
        if (targetDomain != null) out.src_domain = targetDomain
      }
      applyLogonType(out, pick(obj, 'LogonType'))
      const ip = normIp(pick(obj, 'IpAddress'))
      if (ip != null) out.src_ip = ip
      const port = toInt(pick(obj, 'IpPort'))
      if (port != null) out.src_port = port
      const fr = pick(obj, 'FailureReason', 'Status', 'SubStatus')
      if (fr != null) out.failure_reason = String(fr)
      const logonProcess = pick(obj, 'LogonProcessName', 'LogonProcess')
      if (logonProcess != null) out.logon_process = String(logonProcess)
      const authPackage = pick(obj, 'AuthenticationPackageName', 'AuthenticationPackage')
      if (authPackage != null) out.auth_package = String(authPackage)
      const workstation = pick(obj, 'WorkstationName')
      if (workstation != null) out.win_workstation = String(workstation)
      break
    }
    case 4634:
    case 4647: {
      // Logoff. src_user from Subject (already composed in `out`); fall back to
      // TargetUserName when the Subject fields were absent.
      out.event_action = 'logoff'
      if (out.src_user == null) {
        const targetUser = pick(obj, 'TargetUserName')
        const targetDomain = pick(obj, 'TargetDomainName')
        if (targetUser != null) out.src_user = composeUser(targetUser, targetDomain)
      }
      break
    }
    case 4648: {
      // Logon using explicit credentials.
      out.event_action = 'login_explicit'
      const targetUser = pick(obj, 'TargetUserName')
      const targetDomain = pick(obj, 'TargetDomainName')
      if (targetUser != null) out.src_user = composeUser(targetUser, targetDomain)
      const targetServer = pick(obj, 'TargetServerName')
      if (targetServer != null) out.target_server = String(targetServer)
      const ip = normIp(pick(obj, 'IpAddress'))
      if (ip != null) out.src_ip = ip
      break
    }
    case 4672: {
      // Special privileges assigned to a new logon (admin-equivalent session).
      out.event_action = 'special_privileges'
      // src_user already = composed SubjectUserName; keep it.
      const privs = pick(obj, 'PrivilegeList', 'Privileges')
      if (privs != null) out.win_privilege_list = String(privs).replace(/\s+/g, ' ').trim()
      break
    }
    case 4688: {
      // A new process was created.
      out.event_action = 'process_create'
      out.process_name = pick(obj, 'NewProcessName') ?? null
      const cmd = pick(obj, 'CommandLine')
      if (cmd != null) out.command_line = String(cmd)
      const parent = pick(obj, 'ParentProcessName')
      if (parent != null) out.parent_process_name = String(parent)
      // src_user already = composed SubjectUserName; keep it.
      const procId = pick(obj, 'NewProcessId', 'ProcessId')
      if (procId != null) out.win_process_id = String(procId)
      break
    }
    case 4720:
    case 4722:
    case 4723:
    case 4724:
    case 4725:
    case 4726: {
      // Account lifecycle: created/enabled/pwdchange/pwdreset/disabled/deleted.
      // TargetUserName = account acted on; SubjectUserName = actor (src_user).
      out.event_action = ACCOUNT_ACTIONS[eid]
      const targetUser = pick(obj, 'TargetUserName')
      const targetDomain = pick(obj, 'TargetDomainName')
      if (targetUser != null) out.target_user = composeUser(targetUser, targetDomain)
      break
    }
    case 4728:
    case 4732:
    case 4756: {
      // Member added to a (global / local / universal) security group.
      // MemberName/MemberSid = who was added; TargetUserName = the group.
      out.event_action = 'group_member_added'
      const member = pick(obj, 'MemberName', 'MemberSid')
      if (member != null) out.target_user = String(member)
      const group = pick(obj, 'TargetUserName')
      if (group != null) out.group_name = composeUser(group, pick(obj, 'TargetDomainName'))
      break
    }
    case 4740: {
      // A user account was locked out. TargetUserName = locked account;
      // TargetDomainName here is typically the source computer name.
      out.event_action = 'account_lockout'
      const targetUser = pick(obj, 'TargetUserName')
      if (targetUser != null) out.target_user = String(targetUser)
      const callerComputer = pick(obj, 'TargetDomainName')
      if (callerComputer != null) out.win_workstation = String(callerComputer)
      break
    }
    case 1102: {
      // The security audit log was cleared. Actor lives under SubjectUserName but
      // on 1102 it is carried in the UserData block which NXLog flattens to keys
      // prefixed differently — accept several spellings.
      out.event_action = 'audit_log_cleared'
      if (out.src_user == null) {
        const actor = pick(obj, 'SubjectUserName', 'UserName', 'AccountName')
        const actorDomain = pick(obj, 'SubjectDomainName', 'DomainName')
        if (actor != null) out.src_user = composeUser(actor, actorDomain)
      }
      break
    }
    case 7045: {
      // A service was installed in the system (System log).
      out.event_action = 'service_installed'
      out.service_name = pick(obj, 'ServiceName') ?? null
      const imagePath = pick(obj, 'ImagePath')
      if (imagePath != null) out.service_path = String(imagePath)
      const serviceType = pick(obj, 'ServiceType')
      if (serviceType != null) out.win_service_type = String(serviceType)
      const startType = pick(obj, 'StartType')
      if (startType != null) out.win_start_type = String(startType)
      break
    }
    default: {
      // Defensive: any other forwarded EID still gets a stable action + the
      // common fields, and any path-ish / share-ish fields we recognize.
      out.event_action = `win_${eid}`
      const objName = pick(obj, 'ObjectName')
      if (objName != null) out.file_path = objName
      const shareName = pick(obj, 'ShareName')
      if (shareName != null) out.share_name = shareName
      const relTarget = pick(obj, 'RelativeTargetName')
      if (relTarget != null) out.relative_target_name = relTarget
      const ip = normIp(pick(obj, 'IpAddress'))
      if (ip != null) out.src_ip = ip
      const port = toInt(pick(obj, 'IpPort'))
      if (port != null) out.src_port = port
      const accessMask = pick(obj, 'AccessMask')
      if (accessMask != null) out.win_access_mask = String(accessMask)
      break
    }
  }

  return out
}

// ── helpers ─────────────────────────────────────────────

function has(obj, key) {
  return (
    !UNSAFE_PATH_KEYS.has(key) &&
    Object.hasOwn(obj, key) &&
    obj[key] !== undefined &&
    obj[key] !== null &&
    obj[key] !== '' &&
    obj[key] !== '-'
  )
}

// First present, non-empty top-level key wins.
function pick(obj, ...keys) {
  for (const k of keys) {
    if (has(obj, k)) return obj[k]
  }
  return undefined
}

function toEid(v) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (typeof v === 'string' && /^\d+$/.test(v.trim())) return Number(v.trim())
  return null
}

function toInt(v) {
  if (v == null || v === '' || v === '-') return null
  const n = typeof v === 'number' ? v : parseInt(v, 10)
  return Number.isFinite(n) ? n : null
}

// Drop NXLog's leading "::ffff:" v4-mapped prefix and the "-" placeholder.
function normIp(v) {
  if (v == null) return null
  const s = String(v).trim().replace(/^::ffff:/i, '')
  if (s === '' || s === '-' || s === '::') return null
  return s
}

function composeUser(user, domain) {
  if (user == null || user === '' || user === '-') return null
  if (domain != null && domain !== '' && domain !== '-') return `${domain}\\${user}`
  return String(user)
}

// Set logon_type (integer) + logon_type_label from a raw LogonType value.
// No-op when the value is absent or non-numeric.
function applyLogonType(out, raw) {
  const n = toInt(raw)
  if (n == null) return
  out.logon_type = n
  if (Object.prototype.hasOwnProperty.call(LOGON_TYPE_LABELS, n)) {
    out.logon_type_label = LOGON_TYPE_LABELS[n]
  }
}

// EID -> event_category (mirrors openwec.js classifyByEid for the EIDs this
// NXLog source forwards). The file-access EIDs stay 'file' as before.
function classifyByEid(eid) {
  if ([4663, 4660, 4670, 5140, 5145].includes(eid)) return 'file'
  if ([4624, 4625, 4634, 4647, 4648].includes(eid)) return 'auth'
  if (eid === 4688) return 'process'
  if (
    [4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4740, 4756].includes(eid)
  ) {
    return 'identity'
  }
  if (eid === 4672) return 'privilege'
  if (eid === 1102) return 'tampering'
  if (eid === 7045) return 'service'
  return 'windows'
}

// Collapse NXLog's whitespace-decorated access list (e.g. "%%4416\n\t\t\t\t")
// into a clean single-line, space-separated token string for the 'access' field.
function cleanAccess(v) {
  if (v == null) return null
  const s = String(v).replace(/\s+/g, ' ').trim()
  return s === '' ? null : s
}

// Build the accessed path from ShareName + RelativeTargetName. ShareName is
// typically like "\\\\*\\SHARE$"; RelativeTargetName is the file under it.
function joinSharePath(share, rel) {
  const s = share != null && share !== '' && share !== '-' ? String(share) : ''
  const r = rel != null && rel !== '' && rel !== '-' ? String(rel) : ''
  if (s && r) return `${s.replace(/\\+$/, '')}\\${r.replace(/^\\+/, '')}`
  return s || r || null
}

// Decode AccessList / AccessMask to a normalized event_action with precedence:
//   delete > permission_change > write > read.
// Returns null if nothing recognizable was found (caller supplies a default).
function deriveFileAction(accessRaw, accessMask) {
  let canDelete = false
  let canPerm = false
  let canWrite = false
  let canRead = false

  // 1) Textual %%-codes (and a few plain names) in the access list.
  if (accessRaw != null) {
    const text = String(accessRaw)
    for (const [code, name] of Object.entries(ACCESS_CODES)) {
      if (text.includes(code)) tag(name)
    }
    // Plain English names sometimes appear (e.g. 5145 "Accesses" list).
    if (/\bDELETE\b/i.test(text)) canDelete = true
    if (/Write\s*DAC|WRITE_DAC|Write\s*Owner|WRITE_OWNER/i.test(text)) canPerm = true
    if (/WriteData|AppendData|AddFile|AddSubdirectory/i.test(text)) canWrite = true
    if (/ReadData|ListDirectory/i.test(text)) canRead = true
  }

  // 2) Hex AccessMask bits as a fallback.
  const mask = parseMask(accessMask)
  if (mask != null) {
    for (const [bit, name] of MASK_BITS) {
      if ((mask & bit) === bit) tag(name)
    }
  }

  function tag(name) {
    switch (name) {
      case 'DELETE':
        canDelete = true
        break
      case 'WRITE_DAC':
      case 'WRITE_OWNER':
        canPerm = true
        break
      case 'WriteData':
      case 'AppendData':
        canWrite = true
        break
      case 'ReadData':
        canRead = true
        break
      default:
        break
    }
  }

  if (canDelete) return 'file_delete'
  if (canPerm) return 'permission_change'
  if (canWrite) return 'file_write'
  if (canRead) return 'file_read'
  return null
}

function parseMask(v) {
  if (v == null) return null
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  const s = String(v).trim()
  if (s === '' || s === '-') return null
  // Accept "0x..." hex or plain decimal.
  const n = /^0x/i.test(s) ? parseInt(s, 16) : parseInt(s, 10)
  return Number.isFinite(n) ? n : null
}

module.exports = { detect, parse }
