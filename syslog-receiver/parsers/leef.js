// LEEF parser — IBM QRadar Log Enhanced Event Format.
// Spec: https://www.ibm.com/docs/en/dsm?topic=leef-overview
//
// Frame (LEEF 1.0):
//   LEEF:1.0|Vendor|Product|Version|EventID|Key=Value<tab>Key=Value...
// Frame (LEEF 2.0 — delimiter-configurable):
//   LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|Key=Value<delim>Key=Value...
//
// LEEF 2.0 adds a 6th pipe field that is the custom delimiter char (often \t,
// ^, or |). If the 6th field is a single char / hex escape, LEEF 2.0. Otherwise
// LEEF 1.0 and the 6th field is already the extension.
//
// Common ECS-ish keys: src, dst, srcPort, dstPort, usrName, action, cat, proto.

'use strict'

function detect(msg) {
  return /(?:^|\s)LEEF:\d+\.\d+\|/.test(msg)
}

function parseDelimiter(raw) {
  // "\t" literal → tab char; "x09" → hex; single char → as-is
  if (raw === '\\t' || raw === '^I') return '\t'
  if (/^x[0-9a-fA-F]{2}$/.test(raw)) return String.fromCharCode(parseInt(raw.slice(1), 16))
  if (raw.length === 1) return raw
  return '\t' // default
}

function parse(msg) {
  const leefStart = msg.indexOf('LEEF:')
  if (leefStart < 0) return null
  const leefMsg = msg.substring(leefStart)

  const parts = leefMsg.split('|')
  if (parts.length < 6) return null

  const header = parts[0] // e.g. "LEEF:1.0" or "LEEF:2.0"
  const versionMatch = header.match(/^LEEF:(\d+)\.(\d+)$/)
  if (!versionMatch) return null
  const majorVer = parseInt(versionMatch[1], 10)

  const vendor = parts[1]
  const product = parts[2]
  const productVersion = parts[3]
  const eventId = parts[4]

  let extension
  let delimiter = '\t'

  if (majorVer >= 2 && parts.length >= 7) {
    // LEEF 2.0 has explicit delimiter field
    delimiter = parseDelimiter(parts[5])
    extension = parts.slice(6).join('|') // pipes legal inside extension in 2.0
  } else {
    extension = parts.slice(5).join('|')
    // LEEF 1.0 defaults to tab but many implementations use space or ^
    if (!extension.includes('\t') && extension.includes('^')) delimiter = '^'
    else if (!extension.includes('\t') && /\s\w+=/.test(extension)) delimiter = ' '
  }

  // Split extension on delimiter, then split each piece on the first '='
  const ext = {}
  const pieces = delimiter === ' '
    ? extension.match(/\w+=(?:"[^"]*"|\S+)/g) || []
    : extension.split(delimiter)
  for (const piece of pieces) {
    const eq = piece.indexOf('=')
    if (eq > 0) {
      const k = piece.substring(0, eq).trim()
      let v = piece.substring(eq + 1).trim()
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1)
      ext[k] = v
    }
  }

  // LEEF severity is typically in `sev` (0-10). Map to syslog 0-7.
  const leefSev = ext.sev ? parseInt(ext.sev, 10) : null
  const syslogSev = Number.isFinite(leefSev)
    ? Math.max(0, Math.min(7, 7 - Math.round((leefSev / 10) * 7)))
    : null

  return {
    device_vendor: (vendor || '').toLowerCase() || null,
    device_product: product || null,
    device_version: productVersion || null,
    leef_version: majorVer,
    leef_event_id: eventId || null,
    leef_severity: leefSev,
    severity: syslogSev,

    src_ip: ext.src || ext.srcIP || null,
    dst_ip: ext.dst || ext.dstIP || null,
    src_port: ext.srcPort ? parseInt(ext.srcPort, 10) : null,
    dst_port: ext.dstPort ? parseInt(ext.dstPort, 10) : null,
    src_user: ext.usrName || ext.srcUserName || null,
    event_action: ext.action || null,
    event_category: ext.cat || ext.category || null,
    network_protocol: ext.proto || null,
    bytes_sent: ext.dstBytes ? parseInt(ext.dstBytes, 10) : null,
    bytes_received: ext.srcBytes ? parseInt(ext.srcBytes, 10) : null,

    source: vendor || 'leef',
    application: product || null,
    message: `${eventId}${ext.msg ? ' — ' + ext.msg : ''}`,
    _leef_ext: ext,
  }
}

module.exports = { detect, parse }
