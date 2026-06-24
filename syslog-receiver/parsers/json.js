// JSON parser — structured logs emitted as JSON (filebeat, fluentd, custom apps).
//
// Detection: trimmed message starts with `{` and parses as valid JSON.
// We DON'T touch messages that start with `<PRI>` even if they contain JSON
// later — that's a syslog-framed message and belongs in another parser.
//
// Supported shapes (all merged into normalized fields):
//   - Flat:       {"src_ip":"1.2.3.4","dst_ip":"5.6.7.8","action":"allow"}
//   - ECS:        {"source":{"ip":"1.2.3.4"},"destination":{"ip":"5.6.7.8"},"event":{"action":"allow"}}
//   - Nested:     {"network":{"transport":"tcp"},"user":{"name":"jdoe"}}
//   - syslog-json wrapper: {"ts":"...","host":"...","facility":...,"severity":...,"msg":"..."}

'use strict'

const UNSAFE_PATH_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

function detect(msg) {
  const trimmed = msg.trim()
  if (!trimmed.startsWith('{')) return false
  // Cheap tail check to avoid JSON.parse on partial data
  if (!trimmed.endsWith('}')) return false
  return true
}

function pick(obj, ...paths) {
  for (const path of paths) {
    const parts = path.split('.')
    let v = obj
    for (const p of parts) {
      if (UNSAFE_PATH_KEYS.has(p) || v == null || typeof v !== 'object' || !Object.hasOwn(v, p)) {
        v = undefined
        break
      }
      v = v[p] // nosemgrep: javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop
    }
    if (v != null && v !== '') return v
  }
  return null
}

function toInt(v) {
  if (v == null) return null
  const n = typeof v === 'number' ? v : parseInt(v, 10)
  return Number.isFinite(n) ? n : null
}

function parse(msg) {
  const trimmed = msg.trim()
  let obj
  try {
    obj = JSON.parse(trimmed)
  } catch {
    return null
  }
  if (!obj || typeof obj !== 'object') return null

  // Pull ECS + flat keys. First non-null wins.
  const srcIp = pick(obj, 'source.ip', 'src_ip', 'src', 'srcip', 'sourceIp', 'client.ip')
  const dstIp = pick(obj, 'destination.ip', 'dst_ip', 'dst', 'dstip', 'destinationIp', 'server.ip')
  const srcPort = toInt(pick(obj, 'source.port', 'src_port', 'srcPort', 'srcport'))
  const dstPort = toInt(pick(obj, 'destination.port', 'dst_port', 'dstPort', 'dstport'))
  const user = pick(obj, 'user.name', 'src_user', 'username', 'user', 'userid')
  const action = pick(obj, 'event.action', 'action', 'event_action')
  const category = pick(obj, 'event.category', 'category', 'event_category', 'cat')
  const proto = pick(obj, 'network.transport', 'network.protocol', 'protocol', 'proto')
  const service = pick(obj, 'network.service', 'service', 'app')
  const host = pick(obj, 'host.name', 'host', 'hostname', 'source.host')
  const vendor = pick(obj, 'observer.vendor', 'device.vendor', 'vendor')
  const product = pick(obj, 'observer.product', 'device.product', 'product')

  // Message text
  const messageText = pick(obj, 'message', 'msg', '@message', 'event.original')

  // Severity: syslog-like 0-7 or named ("info", "error")
  const sevRaw = pick(obj, 'severity', 'log.level', 'level', 'severity_code')
  let severity = null
  if (typeof sevRaw === 'number' && sevRaw >= 0 && sevRaw <= 7) {
    severity = sevRaw
  } else if (typeof sevRaw === 'string') {
    const map = {
      emergency: 0,
      alert: 1,
      critical: 2,
      error: 3,
      err: 3,
      warning: 4,
      warn: 4,
      notice: 5,
      info: 6,
      informational: 6,
      debug: 7,
    }
    severity = map[sevRaw.toLowerCase()] ?? null
  }

  return {
    device_vendor: vendor ? String(vendor).toLowerCase() : null,
    device_product: product || null,
    source: host || vendor || 'json',
    application: pick(obj, 'application', 'app', 'service') || null,
    severity,

    src_ip: srcIp || null,
    dst_ip: dstIp || null,
    src_port: srcPort,
    dst_port: dstPort,
    src_user: user || null,
    src_domain: pick(obj, 'user.domain', 'src_domain', 'domain'),
    event_action: action || null,
    event_category: category || null,
    network_protocol: proto || null,
    network_service: service || null,
    bytes_sent: toInt(pick(obj, 'source.bytes', 'network.bytes', 'bytes_sent')),
    bytes_received: toInt(pick(obj, 'destination.bytes', 'bytes_received')),

    message: typeof messageText === 'string' ? messageText : JSON.stringify(obj),
    _json: obj,
  }
}

module.exports = { detect, parse }
