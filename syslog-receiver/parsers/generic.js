// Generic heuristic firewall/network parser — the LAST-RESORT extractor.
//
// GOAL (Mike): even for a firewall vendor we have NOT written a dedicated
// parser for, the product must still yield the common fields. This module
// regex-extracts source/destination IPs, ports, protocol, and an action
// keyword from arbitrary free-text (and from arbitrary key=value blobs).
//
// It is intentionally permissive in parse() but its detect() is conservative:
// it only claims a line that contains at least one IPv4 address AND some
// firewall-ish signal (a second IP, an action keyword, a known kv key, or a
// proto token). This keeps it from hijacking ordinary application syslog
// (sshd, cron, etc.) which the server's RFC3164/5424 path handles better.
//
// In the server dispatch this parser is invoked AFTER FortiGate kv and the
// RFC parsers have had their turn — it is the firewall-aware fallback that
// sits in front of the raw "source=unknown" store.

'use strict'

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g

// Action keywords seen across firewall vendors. First match wins; we normalize
// synonyms to a small canonical set so downstream rules can match one value.
// NOTE: reset variants are matched BEFORE the broad deny pattern so a
// "reset-both" line resolves to 'deny' via the explicit reset rule (and is not
// missed). reset / reset-both / reset-client / reset-server are connection
// terminations (deny-family outcome) emitted by PAN-OS and others (Fix #7).
const ACTION_PATTERNS = [
  { re: /\b(accept(?:ed)?|allow(?:ed)?|permit(?:ted)?|pass(?:ed)?)\b/i, action: 'allow' },
  { re: /\breset(?:-(?:both|client|server))?\b/i, action: 'deny' },
  { re: /\b(den(?:y|ied)|block(?:ed)?|drop(?:ped)?|reject(?:ed)?|discard(?:ed)?)\b/i, action: 'deny' },
  { re: /\b(close[d]?|teardown|disconnect(?:ed)?)\b/i, action: 'close' },
  { re: /\b(timeout|timed[-\s]?out)\b/i, action: 'timeout' },
]

const PROTO_RE = /\b(tcp|udp|icmp|icmpv6|gre|esp|ah|sctp)\b/i

// Common key=value port keys across vendors (Forti, Check Point, pfSense, etc.)
const SRC_PORT_KEYS = /\b(?:s_?port|src_?port|sourceport|spt)=("?)(\d{1,5})\1/i
const DST_PORT_KEYS = /\b(?:d_?port|dst_?port|destport|dpt|dstport)=("?)(\d{1,5})\1/i
const SRC_IP_KEYS = /\b(?:src(?:_?ip)?|source(?:address)?|saddr|sa)=("?)((?:\d{1,3}\.){3}\d{1,3})\1/i
const DST_IP_KEYS = /\b(?:dst(?:_?ip)?|dest(?:ination)?(?:address)?|daddr|da)=("?)((?:\d{1,3}\.){3}\d{1,3})\1/i

// "ip:port" or "ip/port" or "ip port" pairs — used when IPs are positional.
function findPortNear(msg, ip) {
  if (!ip) return null
  const esc = ip.replace(/\./g, '\\.')
  const m = msg.match(new RegExp(esc + '[:/](\\d{1,5})\\b'))
  return m ? parseInt(m[1], 10) : null
}

function detect(msg) {
  IPV4.lastIndex = 0
  const ips = msg.match(IPV4)
  if (!ips || ips.length === 0) return false
  // Firewall-ish signal required beyond a lone IP.
  if (ips.length >= 2) return true
  if (ACTION_PATTERNS.some((p) => p.re.test(msg))) return true
  if (SRC_IP_KEYS.test(msg) || DST_IP_KEYS.test(msg)) return true
  if (SRC_PORT_KEYS.test(msg) || DST_PORT_KEYS.test(msg)) return true
  if (PROTO_RE.test(msg)) return true
  return false
}

function detectAction(msg) {
  for (const p of ACTION_PATTERNS) {
    if (p.re.test(msg)) return p.action
  }
  return null
}

function parse(msg) {
  const result = {
    device_vendor: 'unknown',
    source: 'firewall',
    message: msg,
    src_ip: null,
    dst_ip: null,
    src_port: null,
    dst_port: null,
    network_protocol: null,
    event_action: null,
    event_category: 'network',
  }

  // 1) Prefer explicit key=value IPs (most reliable).
  const sip = msg.match(SRC_IP_KEYS)
  const dip = msg.match(DST_IP_KEYS)
  if (sip) result.src_ip = sip[2]
  if (dip) result.dst_ip = dip[2]

  // 2) Fall back to positional IPv4s (first = src, second = dst).
  if (!result.src_ip || !result.dst_ip) {
    IPV4.lastIndex = 0
    const ips = msg.match(IPV4) || []
    if (!result.src_ip && ips[0]) result.src_ip = ips[0]
    if (!result.dst_ip && ips[1]) result.dst_ip = ips[1]
  }

  // 3) Ports — key=value first, then "ip:port"/"ip/port" adjacency.
  const sp = msg.match(SRC_PORT_KEYS)
  const dp = msg.match(DST_PORT_KEYS)
  if (sp) result.src_port = parseInt(sp[2], 10)
  if (dp) result.dst_port = parseInt(dp[2], 10)
  if (result.src_port == null) result.src_port = findPortNear(msg, result.src_ip)
  if (result.dst_port == null) result.dst_port = findPortNear(msg, result.dst_ip)

  // 4) Protocol + action keywords.
  const proto = msg.match(PROTO_RE)
  if (proto) result.network_protocol = proto[1].toLowerCase()
  result.event_action = detectAction(msg)

  // If we extracted literally nothing useful, signal a non-parse so the
  // caller can store as raw rather than a misleading half-empty network doc.
  if (!result.src_ip && !result.dst_ip && !result.event_action) return null

  return result
}

module.exports = { detect, parse }
