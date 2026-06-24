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

const KNOWN_TYPES = new Set(['TRAFFIC', 'THREAT', 'URL', 'SYSTEM', 'AUTHENTICATION', 'USERID', 'CONFIG', 'HIP-MATCH', 'GLOBALPROTECT', 'CORRELATION'])

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
    return {
      ...common,
      src_ip: fields[7] || null,
      dst_ip: fields[8] || null,
      fw_policy_id: fields[11] || null,
      src_user: fields[12] || null,
      application: fields[14] || null,
      session_id: fields[22] || null,
      src_port: fields[24] ? parseInt(fields[24], 10) : null,
      dst_port: fields[25] ? parseInt(fields[25], 10) : null,
      network_protocol: fields[29] || null,
      event_action: fields[30] || null, // allow|deny|drop|reset-*
      bytes_sent: fields[32] ? parseInt(fields[32], 10) : null,
      bytes_received: fields[33] ? parseInt(fields[33], 10) : null,
      event_category: 'network',
      src_country: fields[42] || null,
      dst_country: fields[43] || null,
      message: `PAN TRAFFIC ${fields[30]} ${fields[7]}:${fields[24]} → ${fields[8]}:${fields[25]} app=${fields[14]}`,
    }
  }

  if (logType === 'THREAT') {
    const severityMap = { critical: 2, high: 3, medium: 4, low: 5, informational: 6 }
    const sev = severityMap[(fields[34] || '').toLowerCase()] ?? null
    return {
      ...common,
      src_ip: fields[7] || null,
      dst_ip: fields[8] || null,
      fw_policy_id: fields[11] || null,
      src_user: fields[12] || null,
      application: fields[14] || null,
      session_id: fields[22] || null,
      src_port: fields[24] ? parseInt(fields[24], 10) : null,
      dst_port: fields[25] ? parseInt(fields[25], 10) : null,
      network_protocol: fields[29] || null,
      event_action: fields[30] || null,
      pan_threat_misc: fields[31] || null, // URL, filename, or hash depending on subtype
      pan_threat_id: fields[32] || null,
      pan_threat_category: fields[33] || null,
      severity: sev,
      pan_direction: fields[35] || null, // client-to-server | server-to-client
      event_category: 'intrusion',
      message: `PAN THREAT ${subtype} ${fields[32]} ${fields[7]} → ${fields[8]}${fields[31] ? ' (' + fields[31] + ')' : ''}`,
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
    return {
      ...common,
      src_ip: fields[7] || null,
      dst_ip: fields[8] || null,
      src_user: fields[12] || null,
      application: fields[14] || null,
      src_port: fields[24] ? parseInt(fields[24], 10) : null,
      dst_port: fields[25] ? parseInt(fields[25], 10) : null,
      event_action: fields[30] || null,
      pan_url: fields[31] || null,
      pan_url_category: fields[33] || null,
      event_category: 'url',
      message: `PAN URL ${fields[30]} ${fields[31]}`,
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
