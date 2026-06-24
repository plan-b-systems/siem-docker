// Cisco IOS / ASA / FTD parser.
// Frame: [optional <PRI>][optional timestamp] %FACILITY-SEVERITY-MNEMONIC: message
//
// Severity is the digit 0-7 in the frame (Cisco severity equals syslog severity).
//
// Common mnemonics we special-case below. Everything else is extracted
// generically — facility/severity/mnemonic — and the message body is preserved.
//
// Reference: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/basic_sm.html

'use strict'

const { normProto } = require('./util')

const FRAME_RE = /%([A-Z][A-Z0-9_]*)-(\d)-([A-Z0-9_]+):\s*(.*)$/

// Protocol token as it appears in an ASA body, e.g. "Deny tcp src ...",
// "Built outbound TCP connection", "for udp". We pull the proto word and run it
// through normProto so network_protocol is consistent with every other parser.
const ASA_PROTO_RE = /\b(tcp|udp|icmp|icmpv6|gre|esp|ah|sctp|ip)\b/i

function detect(msg) {
  return FRAME_RE.test(msg)
}

function pickField(text, ...names) {
  // Many Cisco log bodies have "key = value" or "key=value" pairs.
  for (const n of names) {
    const re = new RegExp('\\b' + n + '\\s*=\\s*([^\\s,;]+)')
    const m = text.match(re)
    if (m) return m[1]
  }
  return null
}

function parse(msg) {
  const m = msg.match(FRAME_RE)
  if (!m) return null
  const [, facility, sevChar, mnemonic, body] = m
  const severity = parseInt(sevChar, 10)

  const base = {
    device_vendor: 'cisco',
    cisco_facility: facility,
    cisco_mnemonic: mnemonic,
    severity,
    source: 'cisco',
    application: `${facility}-${mnemonic}`,
    message: body.trim(),
    event_action: null,
    event_category: null,
    event_subtype: null,
    src_ip: null, dst_ip: null, src_port: null, dst_port: null,
    src_user: null, network_protocol: null,
  }

  // Try to extract IPs: look for "iface:ip/port ... iface:ip/port" — common
  // ASA shape is "outside:a.b.c.d/port to inside:e.f.g.h/port". Allow anything
  // (including "to", "->", punctuation) between the two iface:ip/port blocks.
  const ifaceIpPort = /([A-Za-z][\w\-]*?):(\d+\.\d+\.\d+\.\d+)\/(\d+)/g
  const matches = []
  let ifm
  while ((ifm = ifaceIpPort.exec(body)) !== null) {
    matches.push({ iface: ifm[1], ip: ifm[2], port: parseInt(ifm[3], 10) })
    if (matches.length >= 2) break
  }
  if (matches.length >= 2) {
    base.src_interface = matches[0].iface
    base.src_ip = matches[0].ip
    base.src_port = matches[0].port
    base.dst_interface = matches[1].iface
    base.dst_ip = matches[1].ip
    base.dst_port = matches[1].port
  } else if (matches.length === 1) {
    base.src_interface = matches[0].iface
    base.src_ip = matches[0].ip
    base.src_port = matches[0].port
  } else {
    // Fallback: first two IPv4 addresses in body
    const ips = body.match(/\d+\.\d+\.\d+\.\d+/g)
    if (ips && ips.length >= 1) base.src_ip = ips[0]
    if (ips && ips.length >= 2) base.dst_ip = ips[1]
  }

  // ASA flow events — well-documented mnemonics
  // 302013 = TCP connection built, 302014 = TCP teardown
  // 302015 = UDP connection built, 302016 = UDP teardown
  if (facility === 'ASA' && ['302013', '302014', '302015', '302016'].includes(mnemonic)) {
    base.event_category = 'network'
    base.event_action = mnemonic.endsWith('13') || mnemonic.endsWith('15') ? 'connection_open' : 'connection_close'
    base.network_protocol = mnemonic.startsWith('3020') && mnemonic.slice(-2).startsWith('1') ? 'tcp' : 'udp'
  }

  // 106023 = Packet denied by ACL (ASA)
  if (facility === 'ASA' && mnemonic === '106023') {
    base.event_category = 'network'
    base.event_action = 'deny'
  }

  // 106100 = ACL hit (permit/deny based on body)
  if (facility === 'ASA' && mnemonic === '106100') {
    base.event_category = 'network'
    base.event_action = /\bdenied\b/i.test(body) ? 'deny' : 'allow'
  }

  // 113004 / 113005 / 113012 — AAA auth success/failure
  if (facility === 'ASA' && ['113004', '113005', '113012', '113015'].includes(mnemonic)) {
    base.event_category = 'auth'
    base.event_action = 'login'
    base.event_subtype = /\bfail(ed|ure)\b/i.test(body) ? 'failure' : 'success'
    base.src_user = pickField(body, 'user', 'username') || null
  }

  // IOS ACL log: %SEC-6-IPACCESSLOGP — generic ACL hit
  if (facility === 'SEC' && mnemonic === 'IPACCESSLOGP') {
    base.event_category = 'network'
    base.event_action = /\bdenied\b/i.test(body) ? 'deny' : 'allow'
  }

  // %SEC_LOGIN-4-LOGIN_FAILED / %SEC_LOGIN-5-LOGIN_SUCCESS
  if (facility === 'SEC_LOGIN' || facility === 'LOGIN') {
    base.event_category = 'auth'
    base.event_action = 'login'
    base.event_subtype = mnemonic.includes('FAIL') ? 'failure' : 'success'
    base.src_user = pickField(body, 'user', 'username') || null
  }

  // %SYS-5-CONFIG_I — config change
  if (facility === 'SYS' && mnemonic.startsWith('CONFIG')) {
    base.event_category = 'config'
    base.event_action = 'modify'
    base.src_user = pickField(body, 'user') || null
  }

  // %LINK / %LINEPROTO — interface state
  if (facility === 'LINK' || facility === 'LINEPROTO') {
    base.event_category = 'network'
    base.event_action = /\bDOWN\b/.test(body) ? 'interface_down' : /\bUP\b/.test(body) ? 'interface_up' : null
  }

  // %AUTH-* / %AAA-* — generic auth facility bucket
  if ((facility === 'AUTH' || facility === 'AAA') && !base.event_category) {
    base.event_category = 'auth'
    base.event_action = /\bfail/i.test(body) ? 'failure' : 'success'
  }

  // Fix #2 / #7 — extract protocol from the ASA/IOS body when not already set
  // by a flow-event mnemonic. e.g. "Deny tcp src ..." → network_protocol=tcp.
  if (!base.network_protocol) {
    const pm = body.match(ASA_PROTO_RE)
    if (pm) base.network_protocol = normProto(pm[1])
  }

  return base
}

module.exports = { detect, parse }
