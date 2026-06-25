// Aruba parser — HP Aruba wireless controllers (ArubaOS 8.x), ArubaOS-CX
// switches, Instant APs, and ClearPass. Added for Israeli market coverage
// 2026-04-24.
//
// ArubaOS wireless log shapes (after optional <PRI> header):
//   authmgr[pid]: <SYMBOL>|log-level|MODULE|..|msg
//     "authmgr[1234]: <522008> |auth|  Sta aa:bb:cc:dd:ee:ff: 802.1X auth success"
//   stm[pid]: <SYMBOL>|... (station management)
//   wms[pid]: <SYMBOL>|... (wireless management / rogue AP detection)
//   mobility[pid]: roaming + client connection events
//
// ArubaOS-CX (CLI, config, system):
//   Event|Severity|Component|Text (pipe-separated)
//
// Instant AP:
//   AP NAME: text with "user: <mac>" / "SSID: <ssid>" / "channel change" etc.
//
// Detection is heuristic — look for signature tokens unique to Aruba products.

'use strict'

const ARUBA_MARKERS = /\b(?:authmgr|stm|wms|mobility|cli-hdlr|ArubaOS|AP-[A-Z0-9\-]+:|Instant|ClearPass|ArubaOSCX|aruba)\b/

// Check Point SMB / Quantum Spark signatures. These key="value" lines were
// being mis-claimed by the heuristic Aruba markers (a bare MAC / a vendor token
// in gateway_id tripped the markers). Aruba MUST NOT claim a line carrying any
// CP signature — checkpoint.js owns it (and runs BEFORE aruba in the dispatch).
const CHECKPOINT_SIGNATURES =
  /\bAction="|\brule_name="|\bProductName="|\bUuid="\{0x|\blayer_uuid="|\blayer_name="|\binzone="|\boutzone="/i

// SYMBOL_FRAME matches Aruba structured events. Pipes can appear in two
// arrangements:
//   <ID> |level| module| text        (3 pipes — controller/wireless mgmt)
//   <ID> |level| text                (2 pipes — shorter auth/stm format)
// For the 2-pipe case, the middle field is stored as BOTH severity hint and
// aruba_module (real Aruba logs use the slot ambiguously — sometimes a syslog
// level, sometimes a classification token like "auth").
const SYMBOL_FRAME_3 = /<(\d+)>\s*\|([a-z]+)\|\s*([A-Za-z][\w .-]*?)\|\s*(.*)$/i
const SYMBOL_FRAME_2 = /<(\d+)>\s*\|([a-z]+)\|\s*(.*)$/i

function detect(msg) {
  // Never claim a Check Point SMB / Quantum Spark line (key="value" with a
  // quoted Action / rule_name / ProductName / Uuid="{0x...). checkpoint.js owns
  // those and is dispatched before aruba; this guard keeps aruba from stealing
  // them if it were ever called first or in isolation.
  if (CHECKPOINT_SIGNATURES.test(msg)) return false
  return ARUBA_MARKERS.test(msg)
}

const LEVEL_TO_SEV = {
  emerg: 0, emergency: 0,
  alert: 1,
  crit: 2, critical: 2,
  err: 3, error: 3,
  warn: 4, warning: 4,
  notice: 5,
  info: 6, informational: 6,
  debug: 7,
}

function pick(body, ...names) {
  for (const n of names) {
    const re = new RegExp('\\b' + n + '\\s*[:=]\\s*([^\\s,;]+)', 'i')
    const m = body.match(re)
    if (m) return m[1]
  }
  return null
}

function parse(msg) {
  const base = {
    device_vendor: 'aruba',
    source: 'aruba',
    application: null,
    severity: null,
    src_ip: null, dst_ip: null, src_port: null, dst_port: null,
    src_user: null, src_mac: null, aruba_symbol_id: null,
    aruba_module: null, event_action: null, event_category: null,
    event_subtype: null, message: msg.trim(),
  }

  // Identify sub-product by marker
  if (/\bArubaOSCX\b/i.test(msg) || /\bHPE Aruba Networking\b/i.test(msg)) {
    base.device_product = 'arubaos-cx'
  } else if (/\bClearPass\b/i.test(msg)) {
    base.device_product = 'clearpass'
  } else if (/\bInstant\b/i.test(msg) || /\bIAP\b/.test(msg)) {
    base.device_product = 'instant'
  } else {
    base.device_product = 'arubaos'
  }

  // Extract process name (e.g., "authmgr[1234]:")
  const procMatch = msg.match(/\b(authmgr|stm|wms|mobility|cli-hdlr|sapd|fpapps|ArubaOSCX)(?:\[(\d+)\])?:\s*(.*)/)
  let body = msg
  if (procMatch) {
    base.application = procMatch[1]
    if (procMatch[2]) base.pid = procMatch[2]
    body = procMatch[3]
  }

  // Extract <symbol>|level|[module|]text frame. Try 3-pipe shape first;
  // fall back to 2-pipe where the same field serves as level AND module.
  const sym3 = body.match(SYMBOL_FRAME_3)
  if (sym3) {
    base.aruba_symbol_id = sym3[1]
    const lvl = (sym3[2] || '').toLowerCase()
    base.severity = LEVEL_TO_SEV[lvl] ?? null
    base.aruba_module = sym3[3].trim() || null
    body = sym3[4].trim()
    base.message = body
  } else {
    const sym2 = body.match(SYMBOL_FRAME_2)
    if (sym2) {
      base.aruba_symbol_id = sym2[1]
      const lvl = (sym2[2] || '').toLowerCase()
      base.severity = LEVEL_TO_SEV[lvl] ?? null
      base.aruba_module = lvl || null
      body = sym2[3].trim()
      base.message = body
    }
  }

  // MAC address (station)
  const macMatch = body.match(/\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b/)
  if (macMatch) base.src_mac = macMatch[1].toLowerCase()

  // IPv4 — first one is usually the station IP
  const ipMatch = body.match(/\b(\d+\.\d+\.\d+\.\d+)\b/g)
  if (ipMatch && ipMatch.length >= 1) base.src_ip = ipMatch[0]
  if (ipMatch && ipMatch.length >= 2) base.dst_ip = ipMatch[1]

  // Username for 802.1X / admin login
  base.src_user = pick(body, 'username', 'user', 'usr', 'login') || null

  // SSID / BSSID
  base.aruba_ssid = pick(body, 'ssid') || null
  base.aruba_bssid = pick(body, 'bssid') || null

  // Event classification by process + keywords
  const app = base.application || ''
  if (app === 'authmgr' || /\b802\.1[xX]\b/.test(body)) {
    base.event_category = 'auth'
    base.event_action = 'login'
    if (/\b(fail|denied|reject|error)\b/i.test(body)) base.event_subtype = 'failure'
    else if (/\b(success|authenticated|accepted|passed)\b/i.test(body)) base.event_subtype = 'success'
  } else if (app === 'stm') {
    // Station management: association, disassoc, deauth
    if (/\bassoc/i.test(body)) { base.event_category = 'network'; base.event_action = 'associate' }
    else if (/\bdisassoc|deauth/i.test(body)) { base.event_category = 'network'; base.event_action = 'disassociate' }
  } else if (app === 'wms') {
    // Wireless management — rogue AP detection etc.
    base.event_category = 'intrusion'
    if (/\brogue\b/i.test(body)) base.event_action = 'rogue_ap'
    else if (/\binterference\b/i.test(body)) base.event_action = 'interference'
  } else if (app === 'mobility') {
    base.event_category = 'network'
    if (/\broam/i.test(body)) base.event_action = 'roam'
  } else if (app === 'cli-hdlr' || /\b(config|configure)\b/i.test(body)) {
    base.event_category = 'config'
    base.event_action = 'modify'
    base.src_user = base.src_user || pick(body, 'user', 'by') || null
  } else if (/\blogin\b|\blogout\b/i.test(body)) {
    base.event_category = 'auth'
    base.event_action = /\blogout\b/i.test(body) ? 'logout' : 'login'
  }

  return base
}

module.exports = { detect, parse }
