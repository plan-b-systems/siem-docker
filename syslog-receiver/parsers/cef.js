// CEF parser — ArcSight Common Event Format (industry standard for SIEM interop).
// Spec: https://docs.trendmicro.com/all/ent/tda/v9.5/en-us/tda_9.5_olh/Appendices/CEF.htm
//
// Frame:
//   CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
//
// Example (Imperva WAF):
//   CEF:0|Imperva|SecureSphere|12.3|1|Brute Force|5|src=10.0.0.5 dst=10.0.0.10 spt=54321 dpt=80 suser=admin
//
// Extension is a space-separated list of key=value pairs. Values may contain
// escaped pipes (\|) and equals (\=). Common ECS-ish keys: src, dst, spt, dpt,
// suser, duser, act, cat, request, outcome, deviceExternalId.
//
// Severity: 0 (Unknown) - 10 (Highest). We map to the 0-7 syslog severity scale
// by scaling /10 * 7.

'use strict'

const KV_REGEX = /(\w+)=((?:[^\s\\]|\\.)+?)(?=\s+\w+=|\s*$)/g

function detect(msg) {
  // CEF may be preceded by a syslog header — match anywhere near the start.
  return /(?:^|\s)CEF:\d+\|/.test(msg)
}

function unescape(v) {
  return v.replace(/\\(.)/g, '$1')
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

  // Parse extension key=value pairs
  const ext = {}
  KV_REGEX.lastIndex = 0
  let m
  while ((m = KV_REGEX.exec(extension)) !== null) {
    ext[m[1]] = unescape(m[2]).trim()
  }

  // CEF severity 0-10 → syslog 0-7 (inverted: CEF high = urgent = syslog low)
  const cefSev = parseInt(severityStr, 10)
  const syslogSev = Number.isFinite(cefSev)
    ? Math.max(0, Math.min(7, 7 - Math.round((cefSev / 10) * 7)))
    : null

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
    src_user: ext.suser || ext.sourceUserName || ext.duser || null,
    src_domain: ext.sntdom || ext.sourceNtDomain || null,
    event_action: ext.act || ext.deviceAction || null,
    event_category: ext.cat || ext.deviceEventCategory || null,
    network_protocol: ext.proto || null,
    bytes_sent: ext.out ? parseInt(ext.out, 10) : null,
    bytes_received: ext.in ? parseInt(ext.in, 10) : null,

    application: name || null,
    source: vendor || 'cef',
    message: `${name}${ext.msg ? ' — ' + ext.msg : ''}`,
    _cef_ext: ext, // preserve full extension for debugging / custom rules
  }
}

module.exports = { detect, parse }
