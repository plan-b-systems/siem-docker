// Parser dispatcher (ON-PREM). Tries registered parsers in priority order;
// returns the first successful parse, or null if none matched. server.js falls
// back to its built-in FortiGate kv, RFC 5424 / RFC 3164, then the GENERIC
// heuristic firewall parser when this returns null.
//
// Ported from cloud-siem-receiver/parsers/index.js for the on-prem
// multivendor firewall parsing feature (feat/onprem-multivendor-firewall-parser).
// On-prem is SINGLE-TENANT: no allowlist / shared-NAT / quarantine-API. We keep
// the same strict-parse return contract as the cloud so the modules stay
// drop-in identical and unit-testable, but the on-prem server treats the
// 'quarantine' kind as "store raw + log" rather than calling a portal API.
//
// Parsers are PURE functions with NO OpenSearch import — unit-testable with
// node:test and zero npm install.

'use strict'

const cef = require('./cef')
const leef = require('./leef')
const windows = require('./windows')
const json = require('./json')
const checkpoint = require('./checkpoint')
const palo = require('./palo')
const cisco = require('./cisco')
const aruba = require('./aruba')
const dns = require('./dns')
const openwec = require('./openwec')
const { normVendor } = require('./util')

// Priority matters: highly-specific signatures first.
//   * CEF / LEEF leading tokens (CEF:n| / LEEF:n.n|) can't be confused with
//     anything else — and Check Point Log Exporter CEF/LEEF output lands here.
//   * Windows (NXLog) flattened-JSON events — a single JSON object with a
//     NUMERIC EventID + a Windows marker (Channel/Hostname/Computer/
//     ProviderName). MUST run BEFORE generic json.js so Windows file-access
//     events get Windows normalization; non-Windows JSON has no numeric
//     EventID+marker so it falls through to json.js unchanged.
//   * JSON (leading `{`) next.
//   * Check Point key=value ("syslog"/"Splunk" Log-Exporter) BEFORE the
//     server's FortiGate kv step — its detect() requires Check-Point-unique
//     markers (originsicname / CheckPoint / blade product / loc=) so it will
//     not steal FortiGate or generic key=value traffic.
//   * PAN-OS CSV, then Cisco %FACILITY-SEVERITY-MNEMONIC, then Aruba markers,
//     then OpenWEC + DNS (resolver/wec-specific markers).
// NOTE: FortiGate kv and the generic heuristic fallback are intentionally NOT
// in this list — server.js runs them after this dispatch returns null, exactly
// mirroring the cloud's layering.
// checkpoint MUST precede aruba: Check Point SMB / Quantum Spark key="value"
// lines (Action="..." rule_name="..." ProductName="..." gateway_id="...|MAC")
// were being mis-claimed by aruba's heuristic markers. checkpoint.detect() now
// claims them and runs first here, so CP always wins (aruba.detect() also has a
// belt-and-braces CP guard).
const PARSERS = [
  { name: 'cef', ...cef },
  { name: 'leef', ...leef },
  { name: 'windows-nxlog', ...windows },
  { name: 'json', ...json },
  { name: 'checkpoint', ...checkpoint },
  { name: 'palo', ...palo },
  { name: 'cisco', ...cisco },
  { name: 'aruba', ...aruba },
  { name: 'openwec', ...openwec },
  { name: 'dns', ...dns },
]

/**
 * Run the dispatcher over a raw syslog message string.
 *
 * Return shape (kept identical to the cloud for module portability):
 *   { kind: 'parsed', parsed, family }
 *     — a parser claimed AND successfully extracted fields.
 *   { kind: 'quarantine', family, reason }
 *     — a parser CLAIMED (detect=true) but parse() returned null or threw.
 *       On-prem: caller stores the raw payload (source='unknown') + logs.
 *   null
 *     — no parser claimed. Caller falls through to FortiGate kv → RFC →
 *       generic heuristic.
 *
 * @param {string} msg — the already-stringified, trimmed inbound payload
 * @returns {{kind:'parsed', parsed: object, family: string} | {kind:'quarantine', family: string, reason: string} | null}
 */
function dispatch(msg) {
  for (const p of PARSERS) {
    if (!p.detect(msg)) continue
    try {
      const result = p.parse(msg)
      if (result) {
        result.parser_name = p.name
        // Fix #4 — canonicalize device_vendor centrally so the SAME vendor is
        // always ONE value regardless of how it arrived on the wire (CEF
        // "Check Point" / LEEF "Check Point" / kv "checkpoint" → 'checkpoint';
        // "Palo Alto Networks" → 'paloalto'; etc.). Applied to EVERY module's
        // output here so individual parsers don't each have to know the map.
        if (result.device_vendor != null) {
          result.device_vendor = normVendor(result.device_vendor)
        }
        // Strip internal debug blobs before returning — OpenSearch would choke
        // on unbounded free-form keys from _cef_ext / _leef_ext / _json etc.
        delete result._cef_ext
        delete result._leef_ext
        delete result._json
        delete result._pan_raw
        return { kind: 'parsed', parsed: result, family: p.name }
      }
      // Parser claimed but returned null = strict-parse failure.
      return { kind: 'quarantine', family: p.name, reason: 'parse_returned_null' }
    } catch (err) {
      console.error(`[parser:${p.name}] error: ${err.message}`)
      return { kind: 'quarantine', family: p.name, reason: `parse_threw:${err.message.slice(0, 80)}` }
    }
  }
  return null
}

module.exports = { dispatch, PARSERS }
