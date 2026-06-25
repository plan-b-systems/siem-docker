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
//   * Check Point's classic "loc=<n> ... action=" combined with src=/dst=, OR
//   * (Fix #6) a marker-stripped CP key=value line: a Check-Point action verb
//     (Accept/Drop/Reject/Block/Encrypt/...) together with a CP-specific field
//     (rule=/s_port=/service=) AND src=/dst=. FortiGate uses srcport=/dstport=/
//     policyid= and ALWAYS carries devname=/logid=, so we explicitly reject any
//     line bearing those FortiGate markers to keep the disambiguation test green.
//   * (Fix #6) Check Point Log-Exporter BRACKET/COLON format:
//        [action:"Drop"; src:"1.2.3.4"; dst:"5.6.7.8"; ... ]
//     — semicolon-separated key:"value"; pairs inside square brackets.
//
// SMB / QUANTUM SPARK "Log Exporter" (Fix: on-prem Check Point SMB appliances):
//   Check Point Small/Medium-Business gateways (Quantum Spark / 1500-series /
//   "SMB" appliances) emit a DIFFERENT native shape than the enterprise gateway:
//   space-separated key="value" pairs (capitalised "Action", quoted values that
//   may contain spaces), optionally prefixed by an RFC3164 syslog header
//   (<PRI>Mon DD HH:MM:SS HOSTNAME). Real production sample (one line):
//     <85>Jun 25 15:24:41 037161661 Action="accept" Uuid="{0x6a3d1165,...}"
//       src="192.168.252.95" dst="149.154.167.91" proto="6" service_id="HTTPS"
//       inzone="Internal" outzone="External" rule_name="Outgoing Default Policy"
//       name="Telegram" category="Instant Messaging" gateway_id="gw...|...|MAC"
//       ProductName="Application Control" svc="443" ProductFamily=""
//   These were previously mis-claimed by aruba.js (the bare MAC / token tripped
//   its heuristic markers) or fell through unparsed. They are CP-unique: a
//   double-quoted Action plus CP-only fields (rule_name=/inzone=/ProductName=/
//   Uuid="{0x ...). We detect + parse them here as device_product=quantum-spark.

'use strict'

const { normProto } = require('./util')

// key=value where the value is either a quoted string or a run of
// non-space characters. Quoted values may contain spaces (e.g. rule_name).
// We intentionally allow values with spaces only when quoted; bare values
// stop at the next whitespace. A trailing ';' (Check Point sometimes
// separates pairs with "; ") is stripped from bare values.
const KV_REGEX = /([\w.\-]+)=("[^"]*"|[^\s;]+)/g

const CP_PRODUCT_MARKERS = /\b(?:VPN-1|FireWall-1|Threat\s*Emulation|Threat\s*Extraction|Anti[-\s]?Bot|Anti[-\s]?Virus|Application\s*Control|URL\s*Filtering|IPS|Identity\s*Awareness|SmartDefense|Mobile\s*Access|DLP|Endpoint|Quantum|Harmony|SandBlast)\b/i

// Check Point action verbs (the canonical Log-Exporter "action" values). Used
// by the marker-stripped fallback detection so a CP line with no product token
// is still claimed when it clearly carries a CP action + CP-shaped fields.
const CP_ACTION_VERBS = /\b(?:Accept|Drop|Reject|Block|Prevent|Detect|Encrypt|Decrypt|Bypass|Inspect|Monitor|Ask|Inline|Redirect|Quarantine)\b/i

// FortiGate-only markers — if present, this is FortiGate (which has its own
// parser running AFTER us via server.js) and we MUST NOT claim it. Keeps the
// "Check Point detect() does NOT claim a FortiGate line" disambiguation green.
const FORTI_MARKERS = /\b(?:devname=|logid=|srcport=|dstport=|policyid=|devid=)/i

// Bracket/colon Log-Exporter pair: key:"value" (semicolon-separated, inside []).
const BRACKET_KV_REGEX = /([\w.\-]+):"([^"]*)"/g

// ── Check Point SMB / Quantum Spark "Log Exporter" key="value" format ──
// Space-separated key="value" pairs; values are ALWAYS double-quoted and may
// contain spaces ("Outgoing Default Policy") and special chars (the gateway_id
// MAC, the Uuid "{0x...}" blob). A simple key="value" tokenizer captures them.
const SMB_KV_REGEX = /(\w+)="([^"]*)"/g

// RFC3164 header that may prefix the SMB line:  <PRI>Mon DD HH:MM:SS HOSTNAME
// (HOSTNAME is the appliance id, e.g. "037161661"). The receiver may or may not
// have stripped it already, so detection/parsing must tolerate BOTH.
const RFC3164_PREFIX =
  /^<\d{1,3}>(?:\d\s+)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+/

// SMB-distinctive secondary fields: at least one of these alongside a quoted
// Action makes a line unambiguously Check Point SMB (no other vendor in our
// stack emits this exact key="value" vocabulary).
const SMB_SECONDARY =
  /\b(?:rule_name|rule_uid|layer_uuid|layer_name|inzone|outzone|ProductName|match_id|UP_match_table)="/

// True iff the line is the SMB / Quantum Spark key="value" format: a quoted
// Action plus EITHER a CP-distinctive secondary field OR a Uuid="{0x ..." blob.
function isSmbFormat(msg) {
  if (!/\bAction="/.test(msg)) return false
  if (SMB_SECONDARY.test(msg)) return true
  if (/\bUuid="\{0x/i.test(msg)) return true
  return false
}

// Strip a leading RFC3164 <PRI>timestamp HOSTNAME header if present, returning
// { hostname, body }. If there is no header, hostname is null and body is msg.
function stripRfc3164(msg) {
  const m = msg.match(RFC3164_PREFIX)
  if (m) return { hostname: m[1], body: msg.slice(m[0].length) }
  return { hostname: null, body: msg }
}

// Parse SMB key="value" pairs into the SAME lowercased kv shape kvParse()
// produces (first NON-EMPTY value wins, so empty user=""/ProductName="" never
// shadows a later populated key). Returns { kv, hostname }.
function smbParse(msg) {
  const { hostname, body } = stripRfc3164(msg)
  const kv = {}
  SMB_KV_REGEX.lastIndex = 0
  let m
  while ((m = SMB_KV_REGEX.exec(body)) !== null) {
    const key = m[1].toLowerCase()
    const val = m[2]
    // First NON-EMPTY occurrence wins; treat "" as absent so a later populated
    // duplicate (or a populated field after an empty one) is what we keep.
    if (kv[key] === undefined || kv[key] === '') kv[key] = val
  }
  return { kv, hostname }
}

// True iff the line looks like the bracketed key:"value"; Log-Exporter format
// AND carries an action plus a src/dst — distinctive enough to be CP-only.
function isBracketFormat(msg) {
  if (!/\[[^\]]*:"/.test(msg)) return false // must have [ ... key:"... ]
  const hasAction = /\baction:"[^"]*"/i.test(msg)
  const hasEndpoint = /\bsrc:"[^"]*"/i.test(msg) || /\bdst:"[^"]*"/i.test(msg)
  return hasAction && hasEndpoint
}

// Parse the bracket/colon format into the SAME lowercased kv shape kvParse()
// produces, so the rest of parse() is format-agnostic.
function bracketParse(msg) {
  const kv = {}
  BRACKET_KV_REGEX.lastIndex = 0
  let m
  while ((m = BRACKET_KV_REGEX.exec(msg)) !== null) {
    const key = m[1].toLowerCase()
    if (kv[key] === undefined) kv[key] = m[2]
  }
  return kv
}

function detect(msg) {
  // Cheap reject: must look like key=value OR key:"value" at all.
  if (!/[=:]/.test(msg)) return false

  // Check Point SMB / Quantum Spark key="value": a double-quoted Action plus a
  // CP-distinctive secondary field (rule_name=/inzone=/ProductName=/...) OR a
  // Uuid="{0x ..." blob. Distinctive enough to be CP-only and MUST be checked
  // before the generic markers so SMB lines (which carry no originsicname/loc/
  // CheckPoint token) are still claimed. Does NOT match generic syslog: it
  // requires the quoted Action AND a CP-only key.
  if (isSmbFormat(msg)) return true

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

  // Fix #6 — Check Point Log-Exporter BRACKET/COLON format:
  //   [action:"Drop"; src:"1.2.3.4"; dst:"5.6.7.8"; proto:"6"; ... ]
  // Distinctive enough (square-bracketed key:"value"; pairs with an action +
  // src/dst) that no other vendor in our stack uses it.
  if (isBracketFormat(msg) && !FORTI_MARKERS.test(msg)) return true

  // Fix #6 — marker-stripped CP key=value: a Check Point action verb + a
  // CP-shaped field (rule= / s_port= / service=) + src=/dst=. Reject anything
  // bearing FortiGate-only markers so we never steal FortiGate.
  if (CP_ACTION_VERBS.test(msg) &&
      (/\brule=/i.test(msg) || /\bs_port=/i.test(msg) || /\bservice=/i.test(msg)) &&
      (/\bsrc=/i.test(msg) || /\bdst=/i.test(msg)) &&
      !FORTI_MARKERS.test(msg)) {
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

// EVENT_ACTION POLICY (Fix #8): keep the RAW vendor verb, matching cef.js /
// leef.js / fortigate.js and the cloud receiver. Check Point's Log-Exporter
// emits its own casing ("Drop"/"Accept"); we pass it through unchanged so MDR
// rules see the same verb the device emitted (FortiGate happens to emit lower
// already, so the cross-vendor verb space is the vendor's native spelling).
function rawAction(a) {
  if (a == null || a === '') return null
  return String(a)
}

function toInt(v) {
  if (v == null) return null
  const n = parseInt(v, 10)
  return Number.isFinite(n) ? n : null
}

// Treat empty-string vendor values ("") as absent so user=""/ProductName=""
// never become bogus populated fields.
function nz(v) {
  if (v == null || v === '') return null
  return v
}

// Parse the Check Point SMB / Quantum Spark key="value" format into the
// normalized shape. Field names follow the SMB Log-Exporter vocabulary:
//   src/dst, proto (numeric), svc (numeric dest port), service_id (named
//   service), Action, rule_name, inzone/outzone, name (application),
//   category (app classification), ProductName (CP blade), user, bytes,
//   gateway_id (raw, with a trailing MAC), Uuid (session id).
function parseSmb(msg) {
  const { kv, hostname } = smbParse(msg)

  // Must carry firewall-meaningful keys; else bail (lets dispatch quarantine).
  const hasAny = nz(kv.action) || nz(kv.src) || nz(kv.dst) || nz(kv.productname) || nz(kv.uuid)
  if (!hasAny) return null

  // svc is the numeric destination port; service_id is the named service.
  const svcRaw = nz(kv.svc)
  const dstPort = svcRaw != null && /^\d+$/.test(svcRaw) ? toInt(svcRaw) : null

  // Action lowercased → canonical event_action (accept/drop/reject/block).
  const action = nz(kv.action) ? String(kv.action).toLowerCase() : null

  // gateway_id keeps its raw form; extract the trailing MAC into a CP/device
  // field (NOT src_mac — this is the GATEWAY's MAC, not a station's).
  const gatewayId = nz(kv.gateway_id)
  let gatewayMac = null
  let gatewayName = null
  if (gatewayId) {
    const macM = gatewayId.match(/([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*$/)
    if (macM) gatewayMac = macM[1].toLowerCase()
    // Leading token before the first '|' is the gateway name (e.g. "gw7F9C8BA3").
    gatewayName = gatewayId.split('|')[0] || null
  }

  // source/host: prefer the syslog-header HOSTNAME so the firewall shows up in
  // the dashboard Sources list (which aggregates on 'source'). When the header
  // was already stripped (sample 3), fall back to the gateway name, else a
  // constant so the field is never empty.
  const source = hostname || gatewayName || 'checkpoint'

  // bytes: a generic bytes field plus directional bytes when present.
  const bytesSent = toInt(nz(kv.client_outbound_bytes) || nz(kv.server_outbound_bytes))
  const bytesReceived = toInt(nz(kv.client_inbound_bytes) || nz(kv.server_inbound_bytes))

  return {
    device_vendor: 'checkpoint',
    device_product: 'quantum-spark',
    source,
    host: source,
    application: nz(kv.name) || nz(kv.productname) || null,
    message: msg.trim(),

    event_action: action,
    event_category: 'network',
    event_subtype: nz(kv.category) || null,   // app classification ("Instant Messaging")

    src_ip: nz(kv.src) || null,
    dst_ip: nz(kv.dst) || null,
    src_port: null,
    dst_port: dstPort,
    src_user: nz(kv.user) || nz(kv.src_user_name) || null,
    network_protocol: normProto(nz(kv.proto)),
    // Keep the app-layer protocol value too (e.g. "HTTPS"/"Unknown Protocol").
    app_protocol: nz(kv.protocol) || null,
    network_service: nz(kv.service_id) || null,

    fw_rule_name: nz(kv.rule_name) || null,
    fw_policy_id: nz(kv.rule_uid) || null,
    bytes: toInt(nz(kv.bytes)),
    bytes_sent: bytesSent,
    bytes_received: bytesReceived,

    // Check-Point-specific extras (kept for forensic/rule use).
    cp_blade: nz(kv.productname) || null,
    cp_inzone: nz(kv.inzone) || null,
    cp_outzone: nz(kv.outzone) || null,
    cp_gateway_id: gatewayId,
    cp_gateway_mac: gatewayMac,
    cp_uuid: nz(kv.uuid) || null,
    cp_session_id: nz(kv.uuid) || null,
  }
}

function parse(msg) {
  // Check Point SMB / Quantum Spark key="value" format takes priority — it is
  // detected by a quoted Action + a CP-distinctive key (see isSmbFormat).
  if (isSmbFormat(msg)) return parseSmb(msg)

  // Bracket/colon Log-Exporter format vs flat key=value. Pick whichever yields
  // the CP fields. Bracket format is detected by its [ ... key:"value" ] shape.
  const kv = isBracketFormat(msg) ? bracketParse(msg) : kvParse(msg)
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

  const action = rawAction(kv.action)

  return {
    device_vendor: 'checkpoint',
    device_product: kv.product || 'check-point',
    source,
    application: kv.product || null,
    message: msg,

    event_action: action,                      // RAW vendor verb (Fix #8)
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
