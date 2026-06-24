// Palo Alto PAN-OS parser — CSV format.
// Spec: https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions
//
// Log line format (after optional syslog header):
//   FUTURE_USE,RECEIVE_TIME,SERIAL,TYPE,SUBTYPE,CONFIG_VERSION,GENERATE_TIME,...
//
// Type is in field 4 (0-indexed 3). Subtype in field 5. Field positions beyond
// that vary per type. We handle: TRAFFIC, THREAT, URL (subtype of THREAT),
// SYSTEM, AUTHENTICATION, USERID. Field positions below are PAN-OS 10.x
// canonical indices — zero-based into the parsed CSV array.

'use strict'

const { normProto } = require('./util')

const KNOWN_TYPES = new Set(['TRAFFIC', 'THREAT', 'URL', 'SYSTEM', 'AUTHENTICATION', 'USERID', 'CONFIG', 'HIP-MATCH', 'GLOBALPROTECT', 'CORRELATION'])

// Fix #3 — Known PAN-OS session-end actions (TRAFFIC/THREAT/URL "action"
// field). PAN-OS 10.1+/11.x insert extra Device-Group-hierarchy and UUID fields
// that SHIFT positional indices; when that happens, fields[30] is no longer the
// action and fields[24]/[25] are no longer the ports. We GUARD against emitting
// garbage by validating the positionally-extracted action against this set and
// the ports as numeric — if the guard fails we return null so the dispatcher
// quarantines (server stores raw) instead of indexing bogus '0x0'/'0' values.
const PAN_ACTIONS = new Set([
  'allow', 'deny', 'drop', 'reset-both', 'reset-client', 'reset-server',
  'drop-icmp', 'reset-icmp', 'drop-all', 'block-url', 'block-ip',
  'block-continue', 'block-override', 'continue', 'override', 'alert',
  'sinkhole', 'block', 'random-drop',
])

// A field is "port-like" if it is empty (absent) or a numeric string 0-65535.
function isPortLike(v) {
  if (v == null || v === '') return true
  return /^\d{1,5}$/.test(String(v).trim()) && parseInt(v, 10) <= 65535
}

// Validate a positionally-extracted session record before we trust its
// src_port/dst_port/proto/action. Returns true only when the action token is a
// real PAN action AND the port fields are numeric (or absent). This is the
// minimum guard required by Fix #3 to prevent garbage from a shifted schema.
function sessionFieldsValid(action, srcPort, dstPort) {
  if (!action || !PAN_ACTIONS.has(String(action).trim().toLowerCase())) return false
  if (!isPortLike(srcPort) || !isPortLike(dstPort)) return false
  return true
}

function toPort(v) {
  if (v == null || v === '') return null
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : null
}

// Resolve the session-record fields (src_port, dst_port, proto, action) for
// TRAFFIC/THREAT/URL, tolerating the PAN-OS 10.1+/11.x index shift.
//
// PAN-OS keeps these consecutive in EVERY schema version:
//   ... src_port, dst_port, nat_src_port, nat_dst_port, flags, proto, action ...
// In the canonical 10.0 map that is fields 24,25,26,27,28,29,30. When 10.1+
// inserts DG-hierarchy + UUID columns earlier in the line, the whole block
// shifts right by a constant. So: find the ACTION token (a known PAN action) at
// or after the canonical position, then derive the rest RELATIVE to it
// (proto = action-1, dst_port = action-5, src_port = action-6).
//
// Returns { srcPort, dstPort, proto, action, actionIdx } with validated values,
// or null if no plausible, guarded layout is found (Fix #3 — never emit garbage).
function resolveSessionFields(fields) {
  // 1) Canonical 10.0 positions.
  const canon = {
    srcPort: fields[24], dstPort: fields[25], proto: fields[29], action: fields[30], actionIdx: 30,
  }
  if (sessionFieldsValid(canon.action, canon.srcPort, canon.dstPort)) return canon

  // 2) Shifted schema — locate the action token, derive the block from it.
  // Search a sane window (>= 30, the canonical action index) for a field whose
  // value is a known PAN action AND whose derived port fields are numeric.
  for (let idx = 30; idx < fields.length; idx++) {
    const a = fields[idx]
    if (!a || !PAN_ACTIONS.has(String(a).trim().toLowerCase())) continue
    const srcPort = fields[idx - 6]
    const dstPort = fields[idx - 5]
    const proto = fields[idx - 1]
    if (sessionFieldsValid(a, srcPort, dstPort)) {
      return { srcPort, dstPort, proto, action: a, actionIdx: idx }
    }
  }
  return null
}

// CSV splitter respecting double-quote strings and escaped quotes.
function splitCSV(line) {
  const out = []
  let cur = ''
  let inQ = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++; continue }
      inQ = !inQ
      continue
    }
    if (c === ',' && !inQ) {
      out.push(cur)
      cur = ''
      continue
    }
    cur += c
  }
  out.push(cur)
  return out
}

function detect(msg) {
  // Strip optional leading syslog header <PRI>... until the real CSV starts.
  // PAN-OS CSV has RECEIVE_TIME as field 2 in YYYY/MM/DD HH:MM:SS format.
  // A positive detection: we find ",YYYY/MM/DD HH:MM:SS," followed later by ",<TYPE>,"
  const panRe = /,\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2},[A-Z0-9]+,(TRAFFIC|THREAT|URL|SYSTEM|AUTHENTICATION|USERID|CONFIG|HIP-MATCH|GLOBALPROTECT|CORRELATION),/
  return panRe.test(msg)
}

function parse(msg) {
  // Find the CSV starting point — skip syslog <PRI> header + timestamp if present
  // The reliable anchor is the receive_time field (YYYY/MM/DD HH:MM:SS) at position 1.
  // Find the first digit-year sequence and back up one field.
  const panRe = /(?:^|[\s,])(\d{4}\/\d{2}\/\d{2}\s\d{2}:\d{2}:\d{2})/
  const m = panRe.exec(msg)
  if (!m) return null
  // The field BEFORE the timestamp is FUTURE_USE. Find the preceding comma to
  // start the CSV from the field-0 position.
  // Simpler approach: anchor on the timestamp, walk back to find the character
  // that is either start-of-line or a comma preceded by nothing but syslog
  // header fragments.
  const tsIdx = m.index + (m[0].length - m[1].length)
  // Walk back to find "SOMETHING," where SOMETHING is the future_use field.
  // We grab from the nearest comma-or-start up to end-of-line.
  let start = msg.lastIndexOf(',', tsIdx - 2)
  if (start < 0) start = msg.lastIndexOf(' ', tsIdx - 2) // after syslog header space
  if (start < 0) start = -1
  // back one more to include the future_use field (if possible — up to another comma or <PRI>
  // close or line start)
  let futStart = msg.lastIndexOf(',', start - 1)
  if (futStart < 0) {
    const priEnd = msg.indexOf('>')
    futStart = priEnd >= 0 ? priEnd : -1
  }
  const csvStart = futStart + 1
  const csv = msg.substring(csvStart)

  const fields = splitCSV(csv)
  if (fields.length < 8) return null
  const logType = (fields[3] || '').trim().toUpperCase()
  if (!KNOWN_TYPES.has(logType)) return null

  const receiveTime = fields[1] || null
  const serial = fields[2] || null
  const subtype = fields[4] || null

  const common = {
    device_vendor: 'paloalto',
    device_product: 'pan-os',
    pan_log_type: logType,
    pan_subtype: subtype || null,
    pan_serial: serial,
    syslog_timestamp: receiveTime,
    source: serial || 'paloalto',
    application: null,
    severity: null,
    src_ip: null, dst_ip: null, src_port: null, dst_port: null,
    src_user: null, event_action: null, event_category: null,
    network_protocol: null, network_service: null, src_country: null, dst_country: null,
    bytes_sent: null, bytes_received: null, session_id: null,
    fw_policy_id: null,
    _pan_raw: null,
  }

  // Field positions per PAN-OS 10.x (0-indexed into the CSV array, pre-UUID schema)
  // Position map (common 0-22): 0 future_use | 1 receive_time | 2 serial |
  //   3 type | 4 subtype | 5 config_version | 6 generate_time | 7 src_ip |
  //   8 dst_ip | 9 nat_src | 10 nat_dst | 11 rule | 12 src_user | 13 dst_user |
  //   14 application | 15 vsys | 16 from_zone | 17 to_zone | 18 inbound_if |
  //   19 outbound_if | 20 log_action | 21 time_logged | 22 session_id
  if (logType === 'TRAFFIC') {
    // Fix #3 — guard the positional session fields against schema shift.
    const sf = resolveSessionFields(fields)
    if (!sf) return null // shifted/garbled schema → quarantine (store raw), no bogus values
    const srcPort = toPort(sf.srcPort)
    const dstPort = toPort(sf.dstPort)
    // bytes/country are derived RELATIVE to the action index so they survive a
    // shift too (canonical: bytes_sent=32, bytes_received=33, src_country=42,
    // dst_country=43 → action+2, action+3, action+12, action+13).
    const ai = sf.actionIdx
    return {
      ...common,
      src_ip: fields[7] || null,
      dst_ip: fields[8] || null,
      fw_policy_id: fields[11] || null,
      src_user: fields[12] || null,
      application: fields[14] || null,
      session_id: fields[22] || null,
      src_port: srcPort,
      dst_port: dstPort,
      network_protocol: normProto(sf.proto),
      event_action: sf.action || null, // allow|deny|drop|reset-* (RAW vendor verb, Fix #8)
      bytes_sent: fields[ai + 2] ? parseInt(fields[ai + 2], 10) : null,
      bytes_received: fields[ai + 3] ? parseInt(fields[ai + 3], 10) : null,
      event_category: 'network',
      src_country: fields[ai + 12] || null,
      dst_country: fields[ai + 13] || null,
      message: `PAN TRAFFIC ${sf.action} ${fields[7]}:${srcPort ?? ''} → ${fields[8]}:${dstPort ?? ''} app=${fields[14]}`,
    }
  }

  if (logType === 'THREAT') {
    // Fix #3 — guard the positional session fields against schema shift.
    const sf = resolveSessionFields(fields)
    if (!sf) return null // shifted/garbled schema → quarantine, no bogus values
    const ai = sf.actionIdx
    // Threat-specific columns are RELATIVE to the action index (canonical:
    // misc=31, id=32, category=33, severity=34, direction=35 → action+1..+5).
    const severityMap = { critical: 2, high: 3, medium: 4, low: 5, informational: 6 }
    const sev = severityMap[(fields[ai + 4] || '').toLowerCase()] ?? null
    const threatMisc = fields[ai + 1] || null
    const threatId = fields[ai + 2] || null
    return {
      ...common,
      src_ip: fields[7] || null,
      dst_ip: fields[8] || null,
      fw_policy_id: fields[11] || null,
      src_user: fields[12] || null,
      application: fields[14] || null,
      session_id: fields[22] || null,
      src_port: toPort(sf.srcPort),
      dst_port: toPort(sf.dstPort),
      network_protocol: normProto(sf.proto),
      event_action: sf.action || null, // RAW vendor verb (Fix #8)
      pan_threat_misc: threatMisc, // URL, filename, or hash depending on subtype
      pan_threat_id: threatId,
      pan_threat_category: fields[ai + 3] || null,
      severity: sev,
      pan_direction: fields[ai + 5] || null, // client-to-server | server-to-client
      event_category: 'intrusion',
      message: `PAN THREAT ${subtype} ${threatId} ${fields[7]} → ${fields[8]}${threatMisc ? ' (' + threatMisc + ')' : ''}`,
    }
  }

  if (logType === 'SYSTEM') {
    const severityMap = { critical: 2, high: 3, medium: 4, low: 5, informational: 6 }
    return {
      ...common,
      pan_event_id: fields[7] || null,
      pan_object: fields[8] || null,
      pan_module: fields[10] || null,
      severity: severityMap[(fields[11] || '').toLowerCase()] ?? null,
      event_category: 'system',
      event_action: fields[7] || null,
      message: fields[12] || `PAN SYSTEM ${fields[7]}`,
    }
  }

  if (logType === 'AUTHENTICATION') {
    return {
      ...common,
      src_ip: fields[7] || null,
      src_user: fields[8] || null,
      pan_auth_type: fields[11] || null,
      pan_auth_event_type: fields[12] || null,
      event_action: 'authenticate',
      event_category: 'auth',
      event_subtype: (fields[12] || '').toLowerCase().includes('fail') ? 'failure' : 'success',
      message: `PAN AUTH ${fields[12]} user=${fields[8]} ip=${fields[7]}`,
    }
  }

  if (logType === 'USERID') {
    return {
      ...common,
      src_ip: fields[7] || null,
      src_user: fields[8] || null,
      pan_userid_factor: fields[9] || null,
      pan_userid_event: fields[11] || null,
      event_action: 'user_map',
      event_category: 'identity',
      event_subtype: subtype || null,
      message: `PAN USER-ID ${subtype} user=${fields[8]} ip=${fields[7]}`,
    }
  }

  if (logType === 'URL') {
    // Fix #3 — guard the positional session fields against schema shift.
    const sf = resolveSessionFields(fields)
    if (!sf) return null // shifted/garbled schema → quarantine, no bogus values
    const ai = sf.actionIdx
    const url = fields[ai + 1] || null      // canonical 31 (misc) holds the URL
    return {
      ...common,
      src_ip: fields[7] || null,
      dst_ip: fields[8] || null,
      src_user: fields[12] || null,
      application: fields[14] || null,
      src_port: toPort(sf.srcPort),
      dst_port: toPort(sf.dstPort),
      network_protocol: normProto(sf.proto),
      event_action: sf.action || null, // RAW vendor verb (Fix #8)
      pan_url: url,
      pan_url_category: fields[ai + 3] || null, // canonical 33
      event_category: 'url',
      message: `PAN URL ${sf.action} ${url || ''}`,
    }
  }

  // Fallback for known-but-unhandled types: keep raw for debugging
  return {
    ...common,
    _pan_raw: csv.substring(0, 2000),
    event_category: 'unknown',
    message: `PAN ${logType} (raw fields: ${fields.length})`,
  }
}

module.exports = { detect, parse }
