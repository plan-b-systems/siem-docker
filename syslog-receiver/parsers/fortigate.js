// FortiGate key=value parser — Fortinet FortiOS syslog (the dominant on-prem
// firewall in the Israeli SMB market alongside Check Point).
//
// FortiGate emits flat key=value records, e.g.:
//   date=2024-06-20 time=11:22:33 devname="FGT-60F" devid="FGT..." logid="..."
//     type="traffic" subtype="forward" level="notice" srcip=192.0.2.10
//     srcport=51514 dstip=198.51.100.5 dstport=443 proto=6 action="deny"
//     service="HTTPS" policyid=12 srcintf="lan" dstintf="wan1" user="alice"
//     srccountry="Israel" dstcountry="United States" sentbyte=840 rcvdbyte=0
//     crscore=30 crlevel="high" sessionid=123456
//
// This module is a PURE function (no OpenSearch import) so it is unit-testable
// with node:test and zero npm install. server.js calls it as the post-dispatch
// FortiGate step (mirroring the cloud receiver's inline layering), keeping the
// FortiGate logic in one tested place instead of duplicated in server.js.

'use strict'

const LEVEL_MAP = {
  emergency: 0, alert: 1, critical: 2, error: 3,
  warning: 4, notice: 5, information: 6, debug: 7,
}

// Detect: FortiOS records always carry at least one of these anchor keys.
// Conservative enough to avoid stealing Check Point (which has its own parser
// running earlier) or generic key=value traffic.
function detect(msg) {
  return /(?:date=|devname=|logid=|type=)/.test(msg) && /\b(?:srcip=|dstip=|action=|logid=)/.test(msg)
}

function kvParse(msg) {
  const kv = {}
  const kvRegex = /(\w+)=("(?:[^"\\]|\\.)*"|[^\s"]+)/g
  let m
  while ((m = kvRegex.exec(msg)) !== null) {
    kv[m[1]] = m[2].replace(/^"|"$/g, '')
  }
  return kv
}

function normProto(p) {
  if (p === '6') return 'tcp'
  if (p === '17') return 'udp'
  if (p === '1') return 'icmp'
  return p || null
}

function toInt(v) {
  if (v == null || v === '') return null
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : null
}

function parse(msg) {
  const kv = kvParse(msg)

  const out = {
    device_vendor: 'fortinet',
    device_product: 'fortigate',
    source: kv.devname || kv.srcname || 'fortigate',
    application: kv.type || kv.subtype || null,
    message: msg,
    ingest_source: 'syslog',

    // ── Normalized fields (ECS-inspired) ──
    event_action: kv.action || null,       // deny, allow, close, timeout
    event_category: kv.type || null,        // traffic, utm, event
    event_subtype: kv.subtype || null,      // forward, local, webfilter
    src_ip: kv.srcip || null,
    dst_ip: kv.dstip || null,
    src_port: toInt(kv.srcport),
    dst_port: toInt(kv.dstport),
    src_user: kv.user || kv.unauthuser || null,
    src_country: kv.srccountry || null,
    dst_country: kv.dstcountry || null,
    network_protocol: normProto(kv.proto),
    network_service: kv.service || null,
    fw_policy_id: kv.policyid || null,
    fw_risk_score: toInt(kv.crscore),
    fw_risk_level: kv.crlevel || null,
    bytes_sent: toInt(kv.sentbyte),
    bytes_received: toInt(kv.rcvdbyte),
    src_interface: kv.srcintf || null,
    dst_interface: kv.dstintf || null,
    session_id: kv.sessionid || null,
  }

  // Map FortiGate level to syslog severity (server still owns the leading
  // <PRI> fallback for severity/facility).
  if (kv.level && LEVEL_MAP[kv.level] !== undefined) {
    out.severity = LEVEL_MAP[kv.level]
  }

  // FortiGate's own timestamp when present.
  if (kv.date && kv.time) {
    out.syslog_timestamp = `${kv.date} ${kv.time}`
  }

  return out
}

module.exports = { detect, parse, kvParse, LEVEL_MAP }
