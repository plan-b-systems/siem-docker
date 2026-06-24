// Check Point parser — Log Exporter "syslog" / "Splunk" key=value output.
//
// GOAL (Mike): parse Check Point firewall logs NATIVELY so the customer does
// NOT have to reconfigure Log Exporter to CEF. Check Point's Log Exporter can
// emit CEF, LEEF, JSON, or its own key=value "syslog"/"Splunk" format. CEF and
// LEEF are handled by their own parsers (which run BEFORE this one in the
// dispatch). JSON is handled by json.js. This module covers the remaining,
// most-common native shape: the key=value text format.
//
// Real Log-Exporter key=value sample (single line, after optional <PRI> header):
//   <134>1 2024-06-20T11:22:33Z gw-fw CheckPoint 1234 - [action:"Drop"; ... ]
// but the far more common "Splunk"/"syslog" formats are flat key=value, e.g.:
//   loc=12345 product=VPN-1 & FireWall-1 action=drop orig=10.0.0.1 ...
//      src=192.0.2.10 dst=198.51.100.5 proto=tcp service=443 s_port=51514
//      rule=12 rule_name="Block Inbound" originsicname=CN=gw-fw,O=mgmt
//      ifname=eth0 ifdir=inbound
//
// Field names follow Check Point's exported-fields convention:
//   src / dst        — source / destination IP
//   s_port           — source port      (sport also seen)
//   service          — destination port OR named service ("https")
//   proto            — protocol ("tcp"/"udp"/"icmp" or 6/17/1)
//   action           — Accept / Drop / Reject / Block / Encrypt / Decrypt ...
//   product          — Check Point blade ("VPN-1 & FireWall-1", "Threat Emulation"…)
//   originsicname    — origin gateway SIC name (CN=...,O=...)
//   rule / rule_name — policy rule number / name
//   user             — authenticated user when present
//   ifname / ifdir   — interface + direction
//
// Detection MUST be conservative so it does not steal FortiGate / generic
// key=value traffic. We require a Check Point product marker:
//   * product= naming a Check Point blade, OR
//   * originsicname= (SIC name is unique to Check Point), OR
//   * the literal "CheckPoint" / "Check Point" token in the syslog header, OR
//   * Check Point's classic "loc=<n> ... action=" combined with src=/dst=.

'use strict'

// key=value where the value is either a quoted string or a run of
// non-space characters. Quoted values may contain spaces (e.g. rule_name).
// We intentionally allow values with spaces only when quoted; bare values
// stop at the next whitespace. A trailing ';' (Check Point sometimes
// separates pairs with "; ") is stripped from bare values.
const KV_REGEX = /([\w.\-]+)=("[^"]*"|[^\s;]+)/g

const CP_PRODUCT_MARKERS = /\b(?:VPN-1|FireWall-1|Threat\s*Emulation|Threat\s*Extraction|Anti[-\s]?Bot|Anti[-\s]?Virus|Application\s*Control|URL\s*Filtering|IPS|Identity\s*Awareness|SmartDefense|Mobile\s*Access|DLP|Endpoint|Quantum|Harmony|SandBlast)\b/i

function detect(msg) {
  // Cheap reject: must look like key=value at all.
  if (!/=/.test(msg)) return false

  // Strong, Check-Point-unique markers.
  if (/\boriginsicname=/i.test(msg)) return true
  if (/\bCheck\s?Point\b/i.test(msg)) return true
  // product= naming a known Check Point blade.
  const prod = msg.match(/\bproduct=("[^"]*"|[^\s;]+)/i)
  if (prod) {
    const val = prod[1].replace(/^"|"$/g, '')
    if (CP_PRODUCT_MARKERS.test(val)) return true
  }
  // Classic Check Point shape: loc=<digits> together with action= and src=/dst=.
  // FortiGate never emits loc=; this disambiguates from Forti key=value.
  if (/\bloc=\d+/.test(msg) && /\baction=/i.test(msg) && (/\bsrc=/i.test(msg) || /\bdst=/i.test(msg))) {
    return true
  }
  return false
}

function kvParse(msg) {
  const kv = {}
  KV_REGEX.lastIndex = 0
  let m
  while ((m = KV_REGEX.exec(msg)) !== null) {
    const key = m[1].toLowerCase()
    let val = m[2]
    if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1)
    // First occurrence wins (Check Point can repeat keys; the first is canonical).
    if (kv[key] === undefined) kv[key] = val
  }
  return kv
}

// Check Point action → normalized event_action (lowercased, canonical).
// Keeps the original casing semantics but normalizes to lower for consistency
// with the other parsers (FortiGate emits "deny"/"accept" lowercase).
function normAction(a) {
  if (!a) return null
  return String(a).toLowerCase()
}

// Protocol can arrive as a name ("tcp") or an IANA number ("6"). Normalize
// numbers to names so downstream rules can match a single value.
function normProto(p) {
  if (!p) return null
  const s = String(p).toLowerCase()
  if (s === '6') return 'tcp'
  if (s === '17') return 'udp'
  if (s === '1') return 'icmp'
  return s
}

function toInt(v) {
  if (v == null) return null
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : null
}

function parse(msg) {
  const kv = kvParse(msg)
  // Must have extracted at least the firewall-meaningful keys, else this is
  // not a Check Point traffic/audit log and we bail (lets dispatch quarantine).
  const hasAny = kv.src || kv.dst || kv.action || kv.product || kv.originsicname
  if (!hasAny) return null

  // service holds either a numeric dest port or a named service. If numeric,
  // treat as dst_port; always preserve the textual value as network_service.
  const serviceRaw = kv.service || kv.dport || kv.dst_port || null
  const serviceIsPort = serviceRaw != null && /^\d+$/.test(String(serviceRaw))
  const dstPort = serviceIsPort ? toInt(serviceRaw) : toInt(kv.dport || kv.dst_port)

  // origin gateway name — prefer the SIC CN, else orig/origin host.
  let source = 'checkpoint'
  if (kv.originsicname) {
    const cn = kv.originsicname.match(/CN=([^,]+)/i)
    source = cn ? cn[1] : kv.originsicname
  } else if (kv.orig || kv.origin) {
    source = kv.orig || kv.origin
  }

  const action = normAction(kv.action)

  return {
    device_vendor: 'checkpoint',
    device_product: kv.product || 'check-point',
    source,
    application: kv.product || null,
    message: msg,

    event_action: action,                      // accept / drop / reject / block ...
    event_category: kv.product ? null : 'network',
    src_ip: kv.src || kv.orig_src || null,
    dst_ip: kv.dst || kv.orig_dst || null,
    src_port: toInt(kv.s_port || kv.sport || kv.src_port),
    dst_port: dstPort,
    src_user: kv.user || kv.src_user || null,
    network_protocol: normProto(kv.proto),
    network_service: serviceIsPort ? null : (serviceRaw || null),
    fw_policy_id: kv.rule || kv.rule_uid || null,
    fw_rule_name: kv.rule_name || null,
    src_interface: (kv.ifdir && /in/i.test(kv.ifdir)) ? (kv.ifname || null) : (kv.in_ifname || null),
    dst_interface: (kv.ifdir && /out/i.test(kv.ifdir)) ? (kv.ifname || null) : (kv.out_ifname || null),
    bytes_sent: toInt(kv.bytes || kv.client_outbound_bytes || kv.sent_bytes),
    bytes_received: toInt(kv.received_bytes || kv.client_inbound_bytes),
    // Check-Point-specific extras (kept for forensic/rule use).
    cp_sic_name: kv.originsicname || null,
    cp_blade: kv.product || null,
    cp_inzone: kv.inzone || null,
    cp_outzone: kv.outzone || null,
  }
}

module.exports = { detect, parse }
