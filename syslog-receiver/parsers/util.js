// Shared parser helpers (ON-PREM).
//
// Centralizes cross-vendor normalization so EVERY parser emits the same value
// for the same concept. Two concerns live here:
//
//   1) normProto(v)   — network_protocol normalization (numeric IANA proto OR
//                        vendor name → one canonical lowercase token).
//   2) normVendor(v)  — device_vendor canonicalization (so 'Check Point',
//                        'checkpoint', 'CheckPoint' all collapse to one value).
//                        Applied centrally in index.js dispatch() so a parser
//                        only has to set device_vendor to whatever the wire
//                        gave us; the dispatcher folds it to canonical.
//
// EVENT_ACTION POLICY (Fix #8 — matches the CLOUD receiver):
//   The cloud keeps the RAW vendor verb in event_action (cef.js → ext.act,
//   leef.js → ext.action, fortigate → kv.action). It does NOT canonicalize the
//   firewall verb. We do the SAME on-prem: event_action carries the vendor's
//   own verb (e.g. 'Drop', 'blocked', 'deny', 'reset-both'). Parsers that
//   synthesize an action from a non-verb source (cisco mnemonics, generic
//   keyword heuristic) map to the small canonical set ('allow'/'deny'/...)
//   because there is no raw vendor verb to preserve. This file does NOT
//   transform event_action — callers own it — so the policy stays explicit and
//   consistent. normProto/normVendor are the only value rewrites done centrally.

'use strict'

// IANA protocol number → canonical name. Extend as needed; unknown numbers pass
// through as their string form, unknown names pass through lowercased.
const PROTO_NUM = {
  '1': 'icmp',
  '6': 'tcp',
  '17': 'udp',
  '47': 'gre',
  '50': 'esp',
  '51': 'ah',
  '58': 'icmpv6',
  '132': 'sctp',
}

// Known protocol names we recognize (so we can keep them lowercased verbatim).
const PROTO_NAMES = new Set([
  'tcp', 'udp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah', 'sctp', 'ipv6', 'ip',
])

/**
 * Normalize a network protocol value to a single canonical lowercase token.
 * - Numeric IANA proto (6/17/1/47/50/...) → name (tcp/udp/icmp/gre/esp/...).
 * - Known names → lowercased verbatim.
 * - Anything else → lowercased and trimmed (best effort; never throws).
 * - null/undefined/'' → null.
 */
function normProto(v) {
  if (v == null) return null
  const s = String(v).trim().toLowerCase()
  if (s === '') return null
  if (Object.prototype.hasOwnProperty.call(PROTO_NUM, s)) return PROTO_NUM[s]
  if (PROTO_NAMES.has(s)) return s
  return s
}

// Canonical device_vendor map. Keys are lowercased/space-collapsed inputs; the
// value is the ONE canonical token used everywhere downstream (MDR rules,
// dashboard facets). Add aliases as new vendor spellings show up on the wire.
const VENDOR_CANON = {
  'check point': 'checkpoint',
  'checkpoint': 'checkpoint',
  'check point software technologies': 'checkpoint',
  'palo alto networks': 'paloalto',
  'palo alto': 'paloalto',
  'paloalto': 'paloalto',
  'paloaltonetworks': 'paloalto',
  'fortinet': 'fortinet',
  'fortigate': 'fortinet',
  'cisco': 'cisco',
  'cisco systems': 'cisco',
  'aruba': 'aruba',
  'aruba networks': 'aruba',
  'hpe aruba': 'aruba',
}

/**
 * Canonicalize a device_vendor string so the SAME vendor is always one value.
 * Lowercases, collapses internal whitespace, then maps known aliases. Unknown
 * vendors pass through lowercased+collapsed (still consistent run-to-run).
 * null/undefined/'' → null.
 */
function normVendor(v) {
  if (v == null) return null
  const s = String(v).trim().toLowerCase().replace(/\s+/g, ' ')
  if (s === '') return null
  if (Object.prototype.hasOwnProperty.call(VENDOR_CANON, s)) return VENDOR_CANON[s]
  return s
}

module.exports = { normProto, normVendor, PROTO_NUM, VENDOR_CANON }
