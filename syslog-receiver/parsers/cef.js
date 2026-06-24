// CEF parser — ArcSight Common Event Format (industry standard for SIEM interop).
// Spec: https://docs.trendmicro.com/all/ent/tda/v9.5/en-us/tda_9.5_olh/Appendices/CEF.htm
//
// Frame:
//   CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
//
// Example (Imperva WAF):
//   CEF:0|Imperva|SecureSphere|12.3|1|Brute Force|5|src=10.0.0.5 dst=10.0.0.10 spt=54321 dpt=80 suser=admin
//
// Extension is a space-separated list of key=value pairs. PER THE CEF SPEC, a
// value MAY CONTAIN SPACES (e.g. act=Brute Force Detected, msg=Connection
// permitted by rule 7). The only reliable boundary between one pair and the
// next is the start of the NEXT key — ` key=`. So we locate every key start,
// then take each value from just after its '=' up to the start of the next key
// (or end of line). Values are then CEF-unescaped (\= \\ \n \r \|).
//
// Common ECS-ish keys: src, dst, spt, dpt, suser, duser, act, cat, request,
// outcome, deviceExternalId, proto, msg.
//
// EVENT_ACTION POLICY (Fix #8): event_action carries the RAW vendor verb
// (ext.act / ext.deviceAction), exactly like the cloud receiver. No
// canonicalization here — MDR rules see the same verb the device emitted.
//
// Severity: 0 (Unknown) - 10 (Highest). We map to the 0-7 syslog severity scale
// by scaling /10 * 7.

'use strict'

const { normProto } = require('./util')

// Locate each key start in the extension. A CEF key is [A-Za-z][A-Za-z0-9]*
// immediately followed by '='. It begins either at the very start of the
// extension or after whitespace. We use this to slice values that may
// themselves contain spaces.
const KEY_START_RE = /(?:^|\s)([A-Za-z][A-Za-z0-9]*)=/g

function detect(msg) {
  // CEF may be preceded by a syslog header — match anywhere near the start.
  return /(?:^|\s)CEF:\d+\|/.test(msg)
}

// Unescape CEF escapes inside an extension value: \= \\ \n \r \| (and any
// other \x → x). Done AFTER value slicing so an escaped char never confuses
// key-boundary detection.
function unescape(v) {
  return v
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\(.)/g, '$1')
}

// Parse the CEF extension into a flat key→value object, allowing spaces inside
// values. We walk the list of key starts and take each value up to the next
// key start (exclusive of that key's leading whitespace).
function parseExtension(extension) {
  const ext = {}
  const keys = []
  KEY_START_RE.lastIndex = 0
  let m
  while ((m = KEY_START_RE.exec(extension)) !== null) {
    // m[1] = key name. The value starts right after the '=' (lastIndex). The
    // match itself begins at m.index (the leading whitespace, or string start)
    // — we use m.index as the upper boundary for the PREVIOUS value, then trim
    // the separating whitespace off the tail.
    keys.push({ name: m[1], valueStart: KEY_START_RE.lastIndex, matchStart: m.index })
  }
  for (let i = 0; i < keys.length; i++) {
    const cur = keys[i]
    const next = keys[i + 1]
    // Value runs from just-after-'=' to the start of the NEXT key's match
    // (or end of line), with the separating whitespace trimmed off the tail.
    const end = next ? next.matchStart : extension.length
    const raw = extension.substring(cur.valueStart, end).replace(/\s+$/, '')
    if (ext[cur.name] === undefined) ext[cur.name] = unescape(raw)
  }
  return ext
}

function parse(msg) {
  // Strip syslog header if present — find CEF: prefix
  const cefStart = msg.indexOf('CEF:')
  if (cefStart < 0) return null
  const cefMsg = msg.substring(cefStart)

  // Split on unescaped pipes (|). After 7 pipes consumed, everything
  // remaining is the Extension (which may contain '=' but not unescaped '|').
  const parts = []
  let current = ''
  let i = 4 // skip "CEF:"
  while (i < cefMsg.length && parts.length < 7) {
    const c = cefMsg[i]
    if (c === '\\' && i + 1 < cefMsg.length) {
      current += cefMsg[i + 1]
      i += 2
      continue
    }
    if (c === '|') {
      parts.push(current)
      current = ''
      i++
      continue
    }
    current += c
    i++
  }
  if (parts.length < 7) return null
  // Everything from i to end is the extension
  const extension = cefMsg.substring(i)

  const [version, vendor, product, productVersion, sigId, name, severityStr] = parts

  // Parse extension key=value pairs (values may contain spaces).
  const ext = parseExtension(extension)

  // CEF severity 0-10 → syslog 0-7 (inverted: CEF high = urgent = syslog low)
  const cefSev = parseInt(severityStr, 10)
  const syslogSev = Number.isFinite(cefSev)
    ? Math.max(0, Math.min(7, 7 - Math.round((cefSev / 10) * 7)))
    : null

  // Source user vs destination user — NEVER fold the dest user into src_user.
  // suser/sourceUserName → src_user; duser/destinationUserName → dst_user.
  const srcUser = ext.suser || ext.sourceUserName || null
  const dstUser = ext.duser || ext.destinationUserName || null

  return {
    device_vendor: (vendor || '').toLowerCase() || null,
    device_product: product || null,
    device_version: productVersion || null,
    cef_version: version ? parseInt(version, 10) : null,
    cef_signature_id: sigId || null,
    cef_name: name || null,
    cef_severity: Number.isFinite(cefSev) ? cefSev : null,
    severity: syslogSev,

    src_ip: ext.src || ext.sourceAddress || null,
    dst_ip: ext.dst || ext.destinationAddress || null,
    src_port: ext.spt ? parseInt(ext.spt, 10) : ext.sourcePort ? parseInt(ext.sourcePort, 10) : null,
    dst_port: ext.dpt ? parseInt(ext.dpt, 10) : ext.destinationPort ? parseInt(ext.destinationPort, 10) : null,
    src_user: srcUser,
    dst_user: dstUser,
    src_domain: ext.sntdom || ext.sourceNtDomain || null,
    event_action: ext.act || ext.deviceAction || null, // RAW vendor verb (Fix #8)
    event_category: ext.cat || ext.deviceEventCategory || null,
    network_protocol: normProto(ext.proto),
    bytes_sent: ext.out ? parseInt(ext.out, 10) : null,
    bytes_received: ext.in ? parseInt(ext.in, 10) : null,

    application: name || null,
    source: vendor || 'cef',
    message: `${name}${ext.msg ? ' — ' + ext.msg : ''}`,
    _cef_ext: ext, // preserve full extension for debugging / custom rules
  }
}

module.exports = { detect, parse }
