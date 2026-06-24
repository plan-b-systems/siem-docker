// Unit tests for the on-prem multivendor firewall parser stack.
//
// Uses Node's BUILT-IN test runner (node:test) + node:assert — NO new npm deps.
// Tests the PURE parser modules directly (parsers/index.js dispatch, plus the
// fortigate + generic modules that server.js runs after the dispatch), so no
// OpenSearch / npm install is required to run them.
//
// Run:  node --test
//
// Each vendor/format is exercised with a REAL-shaped sample log line and the
// normalized fields are asserted. The same normalized field NAMES the cloud
// receiver uses (src_ip, dst_ip, src_port, dst_port, event_action, ...) are
// checked so the dashboard + MDR engine stay drop-in compatible.

'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { dispatch } = require('../parsers')
const fortigate = require('../parsers/fortigate')
const generic = require('../parsers/generic')
const checkpoint = require('../parsers/checkpoint')
const { normProto, normVendor } = require('../parsers/util')

// Convenience: run the extended dispatch and assert it produced a parse.
function parsed(line) {
  const r = dispatch(line)
  assert.ok(r, `dispatch returned null for: ${line.slice(0, 60)}`)
  assert.equal(r.kind, 'parsed', `expected parsed, got ${r && r.kind}`)
  return r
}

// ───────────────────────── Check Point: CEF ─────────────────────────
test('Check Point CEF (Log Exporter CEF mode) → normalized fields', () => {
  // Real-shaped Check Point Log-Exporter CEF line.
  const line =
    '<134>1 2024-06-20T11:22:33Z gw-fw CheckPoint - - ' +
    'CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Firewall|7|' +
    'src=192.0.2.10 dst=198.51.100.5 spt=51514 dpt=443 proto=tcp act=Drop suser=alice'
  const r = parsed(line)
  assert.equal(r.family, 'cef')
  const p = r.parsed
  // Fix #4 — device_vendor is canonicalized centrally in dispatch(): the CEF
  // header "Check Point" collapses to the canonical 'checkpoint' token (same
  // value the kv / LEEF Check Point logs produce).
  assert.equal(p.device_vendor, 'checkpoint')
  assert.equal(p.src_ip, '192.0.2.10')
  assert.equal(p.dst_ip, '198.51.100.5')
  assert.equal(p.src_port, 51514)
  assert.equal(p.dst_port, 443)
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.event_action, 'Drop')
  assert.equal(p.src_user, 'alice')
  assert.equal(p.parser_name, 'cef')
})

// ──────────────── Check Point: key=value Log Exporter ────────────────
test('Check Point key=value Log-Exporter (syslog/Splunk format) → normalized fields', () => {
  const line =
    '<134>Jun 20 11:22:33 mgmt CheckPoint: ' +
    'loc=98765 product="VPN-1 & FireWall-1" action=drop src=10.1.2.3 dst=8.8.8.8 ' +
    'proto=tcp service=443 s_port=51200 rule=12 rule_name="Block Outbound DNS" ' +
    'originsicname="CN=gw-fw,O=mgmt.example.com.abcdef" user=bob ifname=eth0 ifdir=inbound'
  const r = parsed(line)
  assert.equal(r.family, 'checkpoint')
  const p = r.parsed
  assert.equal(p.device_vendor, 'checkpoint')
  assert.equal(p.event_action, 'drop')
  assert.equal(p.src_ip, '10.1.2.3')
  assert.equal(p.dst_ip, '8.8.8.8')
  assert.equal(p.src_port, 51200)
  assert.equal(p.dst_port, 443) // service= numeric → dst_port
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.src_user, 'bob')
  assert.equal(p.fw_policy_id, '12')
  assert.equal(p.fw_rule_name, 'Block Outbound DNS')
  assert.equal(p.source, 'gw-fw') // CN extracted from SIC name
  assert.equal(p.src_interface, 'eth0')
  assert.equal(p.parser_name, 'checkpoint')
})

test('Check Point key=value with named service keeps network_service textual', () => {
  const line =
    'product="Application Control" action=accept src=10.0.0.5 dst=10.0.0.9 ' +
    'proto=6 service=https s_port=40000 originsicname="CN=fw2,O=foo"'
  const p = parsed(line).parsed
  assert.equal(p.network_service, 'https')
  assert.equal(p.dst_port, null) // non-numeric service → no dst_port
  assert.equal(p.network_protocol, 'tcp') // proto=6 normalized
})

test('Check Point detect() does NOT claim a FortiGate line', () => {
  const forti = 'date=2024-06-20 time=11:22:33 devname="FGT" type="traffic" srcip=1.2.3.4 action=deny'
  assert.equal(checkpoint.detect(forti), false)
})

// ───────────────────────── FortiGate traffic ─────────────────────────
test('FortiGate traffic key=value → full normalized fields', () => {
  const line =
    '<189>date=2024-06-20 time=11:22:33 devname="FGT-60F" devid="FG60FT1234567890" ' +
    'logid="0000000013" type="traffic" subtype="forward" level="notice" ' +
    'srcip=192.168.1.50 srcport=51514 srcintf="lan" dstip=140.82.121.4 dstport=443 ' +
    'dstintf="wan1" proto=6 action="deny" policyid=7 service="HTTPS" user="alice" ' +
    'srccountry="Israel" dstcountry="United States" sentbyte=840 rcvdbyte=0 ' +
    'crscore=30 crlevel="high" sessionid=987654'
  // FortiGate is NOT in the dispatch (server runs it after) — call module directly.
  assert.equal(fortigate.detect(line), true)
  const p = fortigate.parse(line)
  assert.equal(p.device_vendor, 'fortinet')
  assert.equal(p.device_product, 'fortigate')
  assert.equal(p.event_action, 'deny')
  assert.equal(p.event_category, 'traffic')
  assert.equal(p.event_subtype, 'forward')
  assert.equal(p.src_ip, '192.168.1.50')
  assert.equal(p.dst_ip, '140.82.121.4')
  assert.equal(p.src_port, 51514)
  assert.equal(p.dst_port, 443)
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.network_service, 'HTTPS')
  assert.equal(p.src_user, 'alice')
  assert.equal(p.src_country, 'Israel')
  assert.equal(p.dst_country, 'United States')
  assert.equal(p.fw_policy_id, '7')
  assert.equal(p.fw_risk_score, 30)
  assert.equal(p.fw_risk_level, 'high')
  assert.equal(p.bytes_sent, 840)
  assert.equal(p.bytes_received, 0)
  assert.equal(p.src_interface, 'lan')
  assert.equal(p.dst_interface, 'wan1')
  assert.equal(p.session_id, '987654')
  assert.equal(p.severity, 5) // level=notice
})

// ───────────────────────── Palo Alto CSV TRAFFIC ─────────────────────
test('Palo Alto PAN-OS CSV TRAFFIC → normalized fields by position', () => {
  // Canonical PAN-OS 10.x TRAFFIC line (comma-separated). Field indices per
  // palo.js: 7 src_ip, 8 dst_ip, 11 rule, 14 application, 24 src_port,
  // 25 dst_port, 29 proto, 30 action, 42 src_country, 43 dst_country.
  const f = new Array(47).fill('')
  f[0] = '1'; f[1] = '2024/06/20 11:22:33'; f[2] = '001801000000'; f[3] = 'TRAFFIC'; f[4] = 'end'
  f[5] = '2049'; f[6] = '2024/06/20 11:22:30'
  f[7] = '192.168.10.20'; f[8] = '203.0.113.5'
  f[11] = 'Allow-Web'; f[14] = 'ssl'
  f[24] = '52000'; f[25] = '443'; f[29] = 'tcp'; f[30] = 'allow'
  f[32] = '4096'; f[33] = '8192'
  f[42] = 'Israel'; f[43] = 'United States'
  const line = '<14>' + f.join(',')
  const r = parsed(line)
  assert.equal(r.family, 'palo')
  const p = r.parsed
  assert.equal(p.device_vendor, 'paloalto')
  assert.equal(p.pan_log_type, 'TRAFFIC')
  assert.equal(p.src_ip, '192.168.10.20')
  assert.equal(p.dst_ip, '203.0.113.5')
  assert.equal(p.src_port, 52000)
  assert.equal(p.dst_port, 443)
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.event_action, 'allow')
  assert.equal(p.fw_policy_id, 'Allow-Web')
  assert.equal(p.application, 'ssl')
  assert.equal(p.src_country, 'Israel')
  assert.equal(p.dst_country, 'United States')
  assert.equal(p.event_category, 'network')
})

// ───────────────────────── Palo Alto CSV THREAT ──────────────────────
test('Palo Alto PAN-OS CSV THREAT → normalized + threat fields', () => {
  // THREAT line. palo.js indices: 31 threat_misc(url/file), 32 threat_id,
  // 33 threat_category, 34 severity, 35 direction.
  const f = new Array(45).fill('')
  f[0] = '1'; f[1] = '2024/06/20 11:25:00'; f[2] = '001801000000'; f[3] = 'THREAT'; f[4] = 'vulnerability'
  f[6] = '2024/06/20 11:24:58'
  f[7] = '203.0.113.99'; f[8] = '192.168.10.20'
  f[11] = 'Inbound-Block'; f[14] = 'web-browsing'
  f[24] = '40000'; f[25] = '80'; f[29] = 'tcp'; f[30] = 'reset-both'
  f[31] = 'evil.example.com/exploit'; f[32] = '30001'; f[33] = 'code-execution'
  f[34] = 'critical'; f[35] = 'client-to-server'
  const line = '<14>' + f.join(',')
  const r = parsed(line)
  assert.equal(r.family, 'palo')
  const p = r.parsed
  assert.equal(p.pan_log_type, 'THREAT')
  assert.equal(p.src_ip, '203.0.113.99')
  assert.equal(p.dst_ip, '192.168.10.20')
  assert.equal(p.src_port, 40000)
  assert.equal(p.dst_port, 80)
  assert.equal(p.event_action, 'reset-both')
  assert.equal(p.pan_threat_id, '30001')
  assert.equal(p.pan_threat_category, 'code-execution')
  assert.equal(p.pan_threat_misc, 'evil.example.com/exploit')
  assert.equal(p.pan_direction, 'client-to-server')
  assert.equal(p.severity, 2) // critical → 2
  assert.equal(p.event_category, 'intrusion')
})

// ───────────────────────── Cisco ASA ─────────────────────────────────
test('Cisco ASA deny line → normalized fields', () => {
  const line =
    '<166>%ASA-4-106023: Deny tcp src outside:203.0.113.7/44321 ' +
    'dst inside:192.168.1.10/3389 by access-group "outside_access_in"'
  const r = parsed(line)
  assert.equal(r.family, 'cisco')
  const p = r.parsed
  assert.equal(p.device_vendor, 'cisco')
  assert.equal(p.cisco_facility, 'ASA')
  assert.equal(p.cisco_mnemonic, '106023')
  assert.equal(p.src_ip, '203.0.113.7')
  assert.equal(p.dst_ip, '192.168.1.10')
  assert.equal(p.src_port, 44321)
  assert.equal(p.dst_port, 3389)
  assert.equal(p.event_action, 'deny')
  assert.equal(p.event_category, 'network')
  assert.equal(p.severity, 4)
})

// ───────────────────────── CEF (generic vendor) ──────────────────────
test('Generic CEF (non-Check Point vendor) still parses', () => {
  const line =
    'CEF:0|Imperva|SecureSphere|12.3|1|Brute Force|5|' +
    'src=10.0.0.5 dst=10.0.0.10 spt=54321 dpt=80 suser=admin act=blocked'
  const r = parsed(line)
  assert.equal(r.family, 'cef')
  assert.equal(r.parsed.device_vendor, 'imperva')
  assert.equal(r.parsed.event_action, 'blocked')
})

// ───────────────────────── LEEF ──────────────────────────────────────
test('LEEF 1.0 (e.g. Check Point/QRadar) → normalized fields', () => {
  const line =
    'LEEF:1.0|Check Point|VPN-1|R81|Drop|src=172.16.0.5\tdst=172.16.0.9\t' +
    'srcPort=33333\tdstPort=22\tproto=tcp\taction=Drop\tusrName=carol'
  const r = parsed(line)
  assert.equal(r.family, 'leef')
  const p = r.parsed
  assert.equal(p.src_ip, '172.16.0.5')
  assert.equal(p.dst_ip, '172.16.0.9')
  assert.equal(p.src_port, 33333)
  assert.equal(p.dst_port, 22)
  assert.equal(p.event_action, 'Drop')
  assert.equal(p.src_user, 'carol')
})

// ───────────────────────── JSON ──────────────────────────────────────
test('JSON firewall log (ECS-ish) → normalized fields', () => {
  const line = JSON.stringify({
    source: { ip: '10.5.5.5', port: 5555 },
    destination: { ip: '93.184.216.34', port: 443 },
    event: { action: 'allow', category: 'network' },
    network: { transport: 'tcp' },
    user: { name: 'dave' },
    observer: { vendor: 'sophos' },
    message: 'allowed flow',
  })
  const r = parsed(line)
  assert.equal(r.family, 'json')
  const p = r.parsed
  assert.equal(p.src_ip, '10.5.5.5')
  assert.equal(p.dst_ip, '93.184.216.34')
  assert.equal(p.src_port, 5555)
  assert.equal(p.dst_port, 443)
  assert.equal(p.event_action, 'allow')
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.src_user, 'dave')
  assert.equal(p.device_vendor, 'sophos')
})

// ───────────────────────── Generic / unknown vendor ──────────────────
test('Generic heuristic fallback extracts IPs/ports/action from unknown vendor', () => {
  // A vendor we have no dedicated parser for (e.g. a no-name SMB router).
  const line = 'kernel: IN=eth0 OUT=eth1 SRC=10.9.8.7 DST=1.1.1.1 PROTO=TCP SPT=12345 DPT=53 DROP'
  // Not claimed by the extended dispatch.
  assert.equal(dispatch(line), null)
  // But the generic firewall fallback claims + extracts it.
  assert.equal(generic.detect(line), true)
  const p = generic.parse(line)
  assert.equal(p.src_ip, '10.9.8.7')
  assert.equal(p.dst_ip, '1.1.1.1')
  assert.equal(p.src_port, 12345)
  assert.equal(p.dst_port, 53)
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.event_action, 'deny') // DROP → deny
  assert.equal(p.device_vendor, 'unknown')
})

test('Generic fallback maps allow/accept keywords', () => {
  const line = 'fw1 ACCEPT connection from 192.0.2.1 to 192.0.2.2 udp dport=123'
  const p = generic.parse(line)
  assert.equal(p.event_action, 'allow')
  assert.equal(p.src_ip, '192.0.2.1')
  assert.equal(p.dst_ip, '192.0.2.2')
  assert.equal(p.dst_port, 123)
})

test('Generic detect() does NOT claim a plain non-firewall syslog line', () => {
  const line = 'sshd[1234]: Accepted password for root from logged session'
  // No IP present → must not be claimed (the RFC path handles plain syslog).
  // Note: "Accepted" is an action keyword but with no IP, detect requires a
  // firewall signal beyond a lone keyword — and there is no IP at all here.
  assert.equal(generic.detect(line), false)
})

// ───────────────────────── Malformed line ────────────────────────────
test('Malformed line is not falsely parsed by any extended parser', () => {
  const line = '<<<garbage|not|a|real|log&&&==='
  const r = dispatch(line)
  // Either no parser claims it (null), or one claims-but-fails (quarantine).
  // It must NOT come back as a confident "parsed" with bogus network fields.
  if (r) {
    assert.notEqual(r.kind, 'parsed', `malformed line should not parse cleanly: ${JSON.stringify(r)}`)
  } else {
    assert.equal(r, null)
  }
})

test('Malformed key=value (Check-Point-marked but empty) does not yield bogus fields', () => {
  // Has the CheckPoint token (so checkpoint.detect=true) but no usable kv.
  const line = 'CheckPoint: ='
  const r = dispatch(line)
  // checkpoint.parse returns null (no src/dst/action/product) → quarantine kind.
  assert.ok(r === null || r.kind === 'quarantine', `got ${JSON.stringify(r)}`)
})

// ───────────────────────── parser_name plumbing ──────────────────────
test('dispatch stamps parser_name and strips debug blobs', () => {
  const line = 'CEF:0|Imperva|SecureSphere|12.3|1|Test|5|src=1.2.3.4'
  const p = parsed(line).parsed
  assert.equal(p.parser_name, 'cef')
  assert.equal(p._cef_ext, undefined)
  assert.equal(p._json, undefined)
})

// ════════════════════════ REGRESSION TESTS (adversarial validation) ════════
// Added with the firewall-parser bug fixes. Each guards a specific defect found
// by adversarial validation.

// Fix #1 — CEF extension values that contain SPACES must survive (act + msg),
// and src_user must come from suser (not be empty / not be the dest user).
test('CEF: act/msg values with spaces survive into event_action + message + src_user', () => {
  const line =
    'CEF:0|Imperva|SecureSphere|12.3|100|Threat|7|' +
    "src=10.0.0.5 dst=10.0.0.10 spt=54321 dpt=80 act=Brute Force Detected " +
    "suser=admin msg=Connection permitted by rule 7"
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'Brute Force Detected') // full multi-word verb
  assert.equal(p.src_user, 'admin')
  // trailing msg= (with spaces) survives into the composed message
  assert.match(p.message, /Connection permitted by rule 7$/)
  // earlier fields are still parsed correctly (value-with-spaces didn't swallow them)
  assert.equal(p.src_ip, '10.0.0.5')
  assert.equal(p.dst_ip, '10.0.0.10')
  assert.equal(p.src_port, 54321)
  assert.equal(p.dst_port, 80)
})

// Fix #2 — CEF proto given as a numeric IANA value AND uppercase name → 'tcp'.
test('CEF: numeric proto (6) normalizes to tcp', () => {
  const line = 'CEF:0|Imperva|SecureSphere|12.3|1|Test|5|src=1.2.3.4 dst=5.6.7.8 proto=6 act=allow'
  assert.equal(parsed(line).parsed.network_protocol, 'tcp')
})
test('CEF: uppercase proto name (TCP) normalizes to tcp', () => {
  const line = 'CEF:0|Imperva|SecureSphere|12.3|1|Test|5|src=1.2.3.4 dst=5.6.7.8 proto=TCP act=allow'
  assert.equal(parsed(line).parsed.network_protocol, 'tcp')
})

// Fix #5 — duser maps to dst_user, NOT src_user.
test('CEF: duser-only maps to dst_user and leaves src_user null', () => {
  const line = 'CEF:0|Imperva|SecureSphere|12.3|1|Test|5|src=1.2.3.4 dst=5.6.7.8 duser=victim act=blocked'
  const p = parsed(line).parsed
  assert.equal(p.dst_user, 'victim')
  assert.equal(p.src_user, null) // dest user must NEVER be folded into src_user
})

// Fix #4 — device_vendor is identical across Check Point CEF / LEEF / kv.
test('device_vendor is canonical and identical across Check Point CEF/LEEF/kv', () => {
  const cefLine =
    'CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Firewall|7|src=1.1.1.1 dst=2.2.2.2 act=Drop'
  const leefLine =
    'LEEF:1.0|Check Point|VPN-1|R81|Drop|src=1.1.1.1\tdst=2.2.2.2\taction=Drop'
  const kvLine =
    'CheckPoint: loc=1 product="VPN-1 & FireWall-1" action=drop src=1.1.1.1 dst=2.2.2.2 ' +
    'originsicname="CN=gw,O=mgmt"'
  const a = parsed(cefLine).parsed.device_vendor
  const b = parsed(leefLine).parsed.device_vendor
  const c = parsed(kvLine).parsed.device_vendor
  assert.equal(a, 'checkpoint')
  assert.equal(b, 'checkpoint')
  assert.equal(c, 'checkpoint')
  assert.equal(a, b)
  assert.equal(b, c)
})

// Fix #3 — a PAN-OS 10.1+/11.x line whose session block is SHIFTED right by
// extra DG-hierarchy/UUID columns must still extract the right ports/proto/
// action via the schema guard — NOT garbage.
test('Palo Alto shifted (longer) schema → guard re-aligns, no garbage', () => {
  // Build a canonical TRAFFIC record, then INSERT 5 extra columns just before
  // the session block (simulating DG-hierarchy + UUID inserts in 10.1+/11.x).
  const f = new Array(47).fill('')
  f[0] = '1'; f[1] = '2024/06/20 11:22:33'; f[2] = '001801000000'; f[3] = 'TRAFFIC'; f[4] = 'end'
  f[6] = '2024/06/20 11:22:30'
  f[7] = '192.168.10.20'; f[8] = '203.0.113.5'
  f[11] = 'Allow-Web'; f[14] = 'ssl'
  f[24] = '52000'; f[25] = '443'; f[29] = 'tcp'; f[30] = 'allow'
  f[32] = '4096'; f[33] = '8192'; f[42] = 'Israel'; f[43] = 'United States'
  // Shift the session block right by 5 columns (everything from idx 24 onward).
  const SHIFT = 5
  const shifted = f.slice(0, 24).concat(new Array(SHIFT).fill('SHIM'), f.slice(24))
  const line = '<14>' + shifted.join(',')
  const r = parsed(line)
  assert.equal(r.family, 'palo')
  const p = r.parsed
  assert.equal(p.event_action, 'allow')
  assert.equal(p.src_port, 52000)
  assert.equal(p.dst_port, 443)
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.src_ip, '192.168.10.20') // header fields unaffected by the shift
  assert.equal(p.dst_ip, '203.0.113.5')
})

// Fix #3 — a genuinely garbled session block (bogus action, non-numeric ports)
// must NOT emit bogus src_port/dst_port/proto/action — the guard fires and the
// dispatcher quarantines (stores raw) instead.
test('Palo Alto garbled session fields → guard fires, no bogus parse', () => {
  const f = new Array(47).fill('')
  f[0] = '1'; f[1] = '2024/06/20 11:22:33'; f[2] = '001801000000'; f[3] = 'TRAFFIC'; f[4] = 'end'
  f[6] = '2024/06/20 11:22:30'
  f[7] = '192.168.10.20'; f[8] = '203.0.113.5'
  // No valid action token anywhere, ports are non-numeric junk.
  f[24] = '0x0'; f[25] = 'NaN'; f[29] = 'junk'; f[30] = 'frobnicate'
  const line = '<14>' + f.join(',')
  const r = dispatch(line)
  // palo.detect() claims it (TRAFFIC anchor) but parse() returns null → quarantine.
  assert.ok(r === null || r.kind === 'quarantine', `got ${JSON.stringify(r)}`)
  if (r && r.kind === 'parsed') {
    // Defensive: if it ever parses, it must not carry the garbage values.
    assert.notEqual(r.parsed.src_port, 0)
    assert.notEqual(r.parsed.event_action, 'frobnicate')
  }
})

// Fix #2 / #7 — Cisco ASA 106023 "Deny tcp ..." → network_protocol=tcp.
test('Cisco ASA 106023 extracts protocol from body → network_protocol=tcp', () => {
  const line =
    '<166>%ASA-4-106023: Deny tcp src outside:203.0.113.7/44321 ' +
    'dst inside:192.168.1.10/3389 by access-group "outside_access_in"'
  const p = parsed(line).parsed
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.event_action, 'deny')
})

// Fix #7 — generic fallback maps reset-both to an action (deny-family).
test('Generic fallback: reset-both maps to an action', () => {
  const line = 'fw1 reset-both connection 10.0.0.1 to 10.0.0.2 tcp dport=443'
  const p = generic.parse(line)
  assert.ok(p, 'generic should parse the reset-both line')
  assert.equal(p.event_action, 'deny') // reset* is a connection-termination (deny) outcome
})

// Fix #6 — Check Point Log-Exporter BRACKET/COLON format is parsed.
test('Check Point bracket/colon Log-Exporter format → normalized fields', () => {
  const line =
    '<134>1 2024-06-20T11:22:33Z gw-fw - - - ' +
    '[action:"Drop"; src:"1.2.3.4"; dst:"5.6.7.8"; proto:"6"; s_port:"40000"; ' +
    'service:"443"; rule:"7"; rule_name:"Block Inbound"]'
  const r = parsed(line)
  assert.equal(r.family, 'checkpoint')
  const p = r.parsed
  assert.equal(p.device_vendor, 'checkpoint')
  assert.equal(p.event_action, 'Drop')
  assert.equal(p.src_ip, '1.2.3.4')
  assert.equal(p.dst_ip, '5.6.7.8')
  assert.equal(p.src_port, 40000)
  assert.equal(p.dst_port, 443) // numeric service → dst_port
  assert.equal(p.network_protocol, 'tcp') // proto "6" normalized
  assert.equal(p.fw_policy_id, '7')
  assert.equal(p.fw_rule_name, 'Block Inbound')
})

// Fix #6 — broadened detect() claims a marker-stripped CP key=value line but
// STILL refuses a FortiGate line (disambiguation must stay intact).
test('Check Point detect() claims marker-stripped CP kv, rejects FortiGate', () => {
  const cpStripped =
    'action=Drop src=10.0.0.1 dst=10.0.0.2 proto=tcp service=443 s_port=40000 rule=7'
  assert.equal(checkpoint.detect(cpStripped), true)
  // FortiGate markers (devname=/logid=/srcport=/policyid=) must still be rejected.
  const forti =
    'date=2024-06-20 time=11:22:33 devname="FGT" logid="0001" type="traffic" ' +
    'srcip=1.2.3.4 srcport=5000 dstip=5.6.7.8 action=deny policyid=7'
  assert.equal(checkpoint.detect(forti), false)
})

// Fix #2 — direct unit coverage of the shared normProto helper.
test('util.normProto: numbers + names normalize consistently', () => {
  assert.equal(normProto('6'), 'tcp')
  assert.equal(normProto('17'), 'udp')
  assert.equal(normProto('1'), 'icmp')
  assert.equal(normProto('47'), 'gre')
  assert.equal(normProto('50'), 'esp')
  assert.equal(normProto('TCP'), 'tcp')
  assert.equal(normProto('Udp'), 'udp')
  assert.equal(normProto(''), null)
  assert.equal(normProto(null), null)
})

// Fix #4 — direct unit coverage of the shared normVendor helper.
test('util.normVendor: aliases collapse to one canonical token', () => {
  assert.equal(normVendor('Check Point'), 'checkpoint')
  assert.equal(normVendor('checkpoint'), 'checkpoint')
  assert.equal(normVendor('CheckPoint'), 'checkpoint')
  assert.equal(normVendor('Palo Alto Networks'), 'paloalto')
  assert.equal(normVendor('Fortinet'), 'fortinet')
  assert.equal(normVendor('Cisco'), 'cisco')
})
