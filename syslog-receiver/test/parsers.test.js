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
const aruba = require('../parsers/aruba')
const windows = require('../parsers/windows')
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

// ════════════════ CHECK POINT SMB / QUANTUM SPARK (key="value") ═════════════
// Check Point Small/Medium-Business gateways (Quantum Spark / 1500-series) emit
// a NATIVE space-separated key="value" Log-Exporter shape, optionally prefixed
// by an RFC3164 <PRI>Mon DD HH:MM:SS HOSTNAME header. These REAL production
// lines were previously mis-claimed by aruba.js (device_vendor=aruba) or fell
// through unparsed (device_vendor=null). They must parse as device_vendor=
// checkpoint / device_product=quantum-spark. Samples are verbatim from a live
// Bezeq SMB gateway.

// Sample 1 — App-control accept WITH src/dst, header present, named application.
test('Check Point SMB/Quantum Spark: app-control accept with src/dst → checkpoint', () => {
  const line =
    '<85>Jun 25 15:24:41 037161661 Action="accept" ' +
    'Uuid="{0x6a3d1165,0x0,0xb1e37c00,0x14a5}" duration="0:53:56" ' +
    'src="192.168.252.95" dst="149.154.167.91" proto="6" user="" ' +
    'protocol="Unknown Protocol" sig_id="11" service_id="HTTPS" ' +
    'inzone="Internal" outzone="External" rule_name="Outgoing Default Policy" ' +
    'layer_name="Outgoing" name="Telegram" category="Instant Messaging" ' +
    'risk="3" gateway_id="gw7F9C8BA3|Bezeq6|00:1C:7F:9C:8B:A3" ' +
    'ProductName="Application Control" svc="443" ProductFamily=""'
  const r = parsed(line)
  assert.equal(r.family, 'checkpoint')
  const p = r.parsed
  assert.equal(p.device_vendor, 'checkpoint')
  assert.equal(p.device_product, 'quantum-spark')
  assert.equal(p.parser_name, 'checkpoint')
  assert.equal(p.event_action, 'accept') // lowercased
  assert.equal(p.event_category, 'network')
  assert.equal(p.src_ip, '192.168.252.95')
  assert.equal(p.dst_ip, '149.154.167.91')
  assert.equal(p.network_protocol, 'tcp') // proto="6"
  assert.equal(p.dst_port, 443) // svc="443"
  assert.equal(p.network_service, 'HTTPS') // service_id
  assert.equal(p.fw_rule_name, 'Outgoing Default Policy')
  assert.equal(p.cp_inzone, 'Internal')
  assert.equal(p.cp_outzone, 'External')
  assert.equal(p.application, 'Telegram') // name
  assert.equal(p.event_subtype, 'Instant Messaging') // category
  assert.equal(p.src_user, null) // user="" → null (empty treated as absent)
  // HOSTNAME from the syslog header drives source (dashboard Sources facet).
  assert.equal(p.source, '037161661')
  assert.equal(p.host, '037161661')
  // gateway_id kept raw; trailing MAC extracted into a CP/device field (not src_mac).
  assert.equal(p.cp_gateway_id, 'gw7F9C8BA3|Bezeq6|00:1C:7F:9C:8B:A3')
  assert.equal(p.cp_gateway_mac, '00:1c:7f:9c:8b:a3')
  assert.equal(p.src_mac, undefined) // gateway MAC must NOT be misfiled as src_mac
  assert.equal(p.cp_blade, 'Application Control')
})

// Sample 2 — accept with NAMED app-layer protocol + svc, header present.
test('Check Point SMB/Quantum Spark: accept with named protocol + svc → checkpoint', () => {
  const line =
    '<85>Jun 25 14:55:16 037161661 Action="accept" src="10.0.0.53" ' +
    'dst="170.114.78.80" proto="6" protocol="HTTPS" service_id="HTTPS" ' +
    'inzone="Internal" outzone="External" rule_name="Outgoing Default Policy" ' +
    'name="Zoom" category="Web Conferencing" ' +
    'gateway_id="gw7F9C8BA3|Bezeq6|00:1C:7F:9C:8B:A3" ' +
    'ProductName="Application Control" svc="443" ProductFamily=""'
  const r = parsed(line)
  assert.equal(r.family, 'checkpoint')
  const p = r.parsed
  assert.equal(p.device_vendor, 'checkpoint')
  assert.equal(p.device_product, 'quantum-spark')
  assert.equal(p.event_action, 'accept')
  assert.equal(p.src_ip, '10.0.0.53')
  assert.equal(p.dst_ip, '170.114.78.80')
  assert.equal(p.network_protocol, 'tcp')
  assert.equal(p.dst_port, 443)
  assert.equal(p.network_service, 'HTTPS')
  assert.equal(p.app_protocol, 'HTTPS') // app-layer 'protocol' value kept too
  assert.equal(p.fw_rule_name, 'Outgoing Default Policy')
  assert.equal(p.cp_inzone, 'Internal')
  assert.equal(p.cp_outzone, 'External')
  assert.equal(p.application, 'Zoom')
  assert.equal(p.event_subtype, 'Web Conferencing')
  assert.equal(p.source, '037161661')
})

// Sample 3 — URL-filtering session-close variant: HEADER ALREADY STRIPPED, NO
// src/dst, carries bytes/packets. Must still parse as checkpoint WITHOUT throwing.
test('Check Point SMB/Quantum Spark: stripped-header session close (no src/dst) → checkpoint', () => {
  const line =
    'Action="accept" Uuid="{0x6a3d1e50,0x0,0x5fad5855,0xeae88559}" ' +
    'start_time="25Jun2026 15:25:52" elapsed="0:00:13" packets="4" bytes="404" ' +
    'client_inbound_interface="wlan0" ' +
    'gateway_id="gw7F9C8BA3|Bezeq6|00:1C:7F:9C:8B:A3" ProductName="" ProductFamily=""'
  let r
  assert.doesNotThrow(() => { r = parsed(line) }, 'sample 3 must parse without throwing')
  assert.equal(r.family, 'checkpoint')
  const p = r.parsed
  assert.equal(p.device_vendor, 'checkpoint')
  assert.equal(p.device_product, 'quantum-spark')
  assert.equal(p.event_action, 'accept')
  assert.equal(p.src_ip, null) // no src on a session-close record
  assert.equal(p.dst_ip, null)
  assert.equal(p.bytes, 404)
  // No header → source falls back to the gateway_id name (never empty).
  assert.equal(p.source, 'gw7F9C8BA3')
  assert.equal(p.host, 'gw7F9C8BA3')
  assert.equal(p.cp_gateway_mac, '00:1c:7f:9c:8b:a3')
})

// detect(): SMB lines are claimed; aruba does NOT steal them.
test('Check Point SMB detect() claims the SMB key="value" shape; aruba does not', () => {
  const s1 =
    '<85>Jun 25 15:24:41 037161661 Action="accept" src="192.168.252.95" ' +
    'dst="149.154.167.91" rule_name="Outgoing Default Policy" ' +
    'gateway_id="gw7F9C8BA3|Bezeq6|00:1C:7F:9C:8B:A3" ProductName="Application Control"'
  const s3 =
    'Action="accept" Uuid="{0x6a3d1e50,0x0,0x5fad5855,0xeae88559}" ' +
    'gateway_id="gw7F9C8BA3|Bezeq6|00:1C:7F:9C:8B:A3" ProductName=""'
  assert.equal(checkpoint.detect(s1), true)
  assert.equal(checkpoint.detect(s3), true)
  // ARUBA FIX: aruba.detect() must refuse a line carrying CP signatures.
  assert.equal(aruba.detect(s1), false)
  assert.equal(aruba.detect(s3), false)
})

// SMB detect() must NOT match a generic syslog line (no quoted Action + CP key).
test('Check Point SMB detect() does NOT claim generic syslog', () => {
  assert.equal(checkpoint.detect('sshd[123]: Accepted password for root from 10.0.0.1'), false)
  // A quoted action alone (no CP-distinctive key) is not enough.
  assert.equal(checkpoint.detect('Action="accept" foo="bar" baz="qux"'), false)
})

// ARUBA REGRESSION — a REAL ArubaOS authmgr 802.1X line must STILL parse as
// aruba (the CP guard must not over-reach and break legitimate Aruba logs).
test('Aruba authmgr 802.1X line still parses as aruba (no CP-guard regression)', () => {
  const line =
    '<189>authmgr[1234]: <522008> |auth|  Sta aa:bb:cc:dd:ee:ff: ' +
    '802.1X auth success for user=alice'
  assert.equal(checkpoint.detect(line), false) // CP must not claim it
  assert.equal(aruba.detect(line), true)
  const r = parsed(line)
  assert.equal(r.family, 'aruba')
  const p = r.parsed
  assert.equal(p.device_vendor, 'aruba')
  assert.equal(p.event_category, 'auth')
  assert.equal(p.event_action, 'login')
  assert.equal(p.event_subtype, 'success')
  assert.equal(p.src_mac, 'aa:bb:cc:dd:ee:ff')
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

// ════════════════════════ WINDOWS (NXLog file-access) ══════════════════════
// NXLog im_msvistalog ships Security-channel events as NEWLINE-DELIMITED JSON
// over TCP 1514. to_json() FLATTENS EventData to top-level keys, so each event
// is one flat JSON object. windows.js claims it (numeric EventID + Windows
// marker) BEFORE json.js. EIDs 4663/4660/4670/5140/5145 map to file/share
// normalized fields. Non-Windows JSON must fall through to json.js.

// Convenience: build a flat NXLog-style event object → JSON string.
function nx(obj) {
  return JSON.stringify(obj)
}

// ── 4663 READ ──
test('Windows 4663 (object access, READ) → file_read', () => {
  const line = nx({
    EventID: 4663,
    Hostname: 'FS01',
    Computer: 'FS01.corp.local',
    Channel: 'Security',
    ProviderName: 'Microsoft-Windows-Security-Auditing',
    EventTime: '2026-06-24 11:22:33',
    SubjectUserName: 'jdoe',
    SubjectDomainName: 'CORP',
    ObjectName: 'C:\\Share\\report.docx',
    ObjectType: 'File',
    // NXLog decorates the access list with newlines/tabs.
    AccessList: '%%4416\n\t\t\t\t',
    AccessMask: '0x1',
  })
  const r = parsed(line)
  assert.equal(r.family, 'windows-nxlog')
  const p = r.parsed
  assert.equal(p.win_event_id, 4663)
  assert.equal(p.file_path, 'C:\\Share\\report.docx')
  assert.equal(p.src_user, 'CORP\\jdoe')
  assert.equal(p.event_action, 'file_read')
  assert.equal(p.device_vendor, 'microsoft')
  assert.equal(p.device_product, 'windows-security')
  assert.equal(p.event_category, 'file')
  assert.equal(p.parser_name, 'windows-nxlog')
  assert.equal(p.ingest_source, 'nxlog')
  assert.equal(p.win_channel, 'Security')
  assert.equal(p.host, 'FS01.corp.local')
  // access list cleaned to a single-line token (no raw newlines/tabs).
  assert.equal(p.access, '%%4416')
})

// ── 4663 WRITE ──
test('Windows 4663 (object access, WRITE) → file_write', () => {
  const line = nx({
    EventID: 4663,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'alice',
    SubjectDomainName: 'CORP',
    ObjectName: 'C:\\Share\\budget.xlsx',
    AccessList: '%%4417',
    AccessMask: '0x2',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4663)
  assert.equal(p.event_action, 'file_write')
  assert.equal(p.file_path, 'C:\\Share\\budget.xlsx')
  assert.equal(p.src_user, 'CORP\\alice')
})

// ── 4663 DELETE — DELETE wins over a co-present read/write bit ──
test('Windows 4663 (object access, DELETE) → file_delete (precedence)', () => {
  const line = nx({
    EventID: 4663,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'bob',
    SubjectDomainName: 'CORP',
    ObjectName: 'C:\\Share\\old.tmp',
    // Both DELETE and ReadData present — delete must take precedence.
    AccessList: '%%1537\n\t\t\t\t%%4416',
    AccessMask: '0x10001',
  })
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'file_delete')
  assert.equal(p.file_path, 'C:\\Share\\old.tmp')
})

// ── 4663 hex-mask fallback when AccessList is absent ──
test('Windows 4663 with only hex AccessMask (0x10000=DELETE) → file_delete', () => {
  const line = nx({
    EventID: 4663,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'svc',
    ObjectName: 'D:\\data\\x',
    AccessMask: '0x10000',
  })
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'file_delete')
  assert.equal(p.src_user, 'svc') // no domain → bare username
})

// ── 4660 DELETE (HandleId only, no ObjectName) ──
test('Windows 4660 (handle-only delete) → file_delete + win_handle_id', () => {
  const line = nx({
    EventID: 4660,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'bob',
    SubjectDomainName: 'CORP',
    HandleId: '0x4f8',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4660)
  assert.equal(p.event_action, 'file_delete')
  assert.equal(p.win_handle_id, '0x4f8')
  assert.equal(p.src_user, 'CORP\\bob')
  assert.equal(p.file_path, undefined) // no ObjectName on this 4660
})

// ── 4670 permission change ──
test('Windows 4670 (permissions changed) → permission_change', () => {
  const line = nx({
    EventID: 4670,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'admin',
    SubjectDomainName: 'CORP',
    ObjectName: 'C:\\Share\\Finance',
    ObjectType: 'File',
    OldSd: 'D:(A;;FA;;;BA)',
    NewSd: 'D:(A;;FA;;;BA)(A;;FR;;;DU)',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4670)
  assert.equal(p.event_action, 'permission_change')
  assert.equal(p.file_path, 'C:\\Share\\Finance')
  assert.equal(p.src_user, 'CORP\\admin')
})

// ── 5145 detailed file share — workstation IP + UNC path ──
test('Windows 5145 (detailed file share) → workstation IP + UNC file_path', () => {
  const line = nx({
    EventID: 5145,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'carol',
    SubjectDomainName: 'CORP',
    ShareName: '\\\\*\\Finance$',
    ShareLocalPath: '\\??\\D:\\Finance',
    RelativeTargetName: 'reports\\q2.xlsx',
    IpAddress: '10.20.30.40', // THE WORKSTATION IP
    IpPort: '54231',
    AccessMask: '0x2', // WriteData
    AccessList: '%%4417',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 5145)
  assert.equal(p.src_ip, '10.20.30.40') // workstation IP, not the server
  assert.equal(p.src_port, 54231)
  assert.equal(p.share_name, '\\\\*\\Finance$')
  assert.equal(p.relative_target_name, 'reports\\q2.xlsx')
  assert.equal(p.file_path, '\\\\*\\Finance$\\reports\\q2.xlsx')
  assert.equal(p.src_user, 'CORP\\carol')
  assert.equal(p.event_action, 'file_write') // derived from WriteData
})

// ── 5145 with v4-mapped IP + no derivable access → share_access ──
test('Windows 5145 strips ::ffff: IP and defaults to share_access', () => {
  const line = nx({
    EventID: 5145,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'dave',
    ShareName: '\\\\*\\IPC$',
    RelativeTargetName: 'srvsvc',
    IpAddress: '::ffff:192.168.5.5',
    IpPort: '49888',
  })
  const p = parsed(line).parsed
  assert.equal(p.src_ip, '192.168.5.5')
  assert.equal(p.event_action, 'share_access')
})

// ── 5140 share connect ──
test('Windows 5140 (share connect) → share_connect + share_name + src_ip', () => {
  const line = nx({
    EventID: 5140,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'erin',
    SubjectDomainName: 'CORP',
    ShareName: '\\\\*\\Finance$',
    ShareLocalPath: '\\??\\D:\\Finance',
    IpAddress: '10.20.30.41',
    IpPort: '50122',
    AccessMask: '0x1',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 5140)
  assert.equal(p.event_action, 'share_connect')
  assert.equal(p.share_name, '\\\\*\\Finance$')
  assert.equal(p.src_ip, '10.20.30.41')
  assert.equal(p.src_port, 50122)
})

// ── any other EID → defensive win_<EID> ──
// 4799 (security-enabled local group membership enumerated) is intentionally NOT
// one of the enriched EIDs, so it must still fall to the defensive default.
test('Windows unmapped EID → defensive win_<eid> action, fields kept', () => {
  const line = nx({
    EventID: 4799,
    Computer: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'frank',
    SubjectDomainName: 'CORP',
    IpAddress: '10.0.0.9',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4799)
  assert.equal(p.event_action, 'win_4799')
  assert.equal(p.src_ip, '10.0.0.9')
  assert.equal(p.src_user, 'CORP\\frank')
})

// ── @timestamp derived from EventTime ──
test('Windows EventTime → @timestamp ISO', () => {
  const line = nx({
    EventID: 4663,
    Computer: 'FS01',
    Channel: 'Security',
    EventTime: '2026-06-24 11:22:33',
    SubjectUserName: 'g',
    ObjectName: 'C:\\x',
    AccessMask: '0x1',
  })
  const p = parsed(line).parsed
  assert.match(p['@timestamp'], /^2026-06-24T/)
  assert.equal(p.win_event_time, '2026-06-24 11:22:33')
})

// ── malformed / partial JSON must NOT be claimed as parsed ──
test('Windows: malformed/partial JSON is not claimed by windows.js', () => {
  // Truncated mid-object (e.g. a torn TCP record) — windows.detect must reject.
  const partial = '{"EventID":4663,"Computer":"FS01","Channel":"Secur'
  assert.equal(windows.detect(partial), false)
  const r = dispatch(partial)
  // No parser should confidently parse a truncated object.
  if (r) assert.notEqual(r.kind, 'parsed')
})

// ── NON-Windows JSON must fall through to json.js, NOT windows.js ──
test('Non-Windows JSON is NOT claimed by windows.js → falls to json.js', () => {
  // An app log that happens to be JSON with no numeric EventID + Windows marker.
  const line = JSON.stringify({
    source: { ip: '10.5.5.5', port: 5555 },
    destination: { ip: '93.184.216.34', port: 443 },
    event: { action: 'allow' },
    observer: { vendor: 'sophos' },
    message: 'allowed flow',
  })
  assert.equal(windows.detect(line), false)
  const r = parsed(line)
  assert.equal(r.family, 'json') // json.js, not windows-nxlog
  assert.equal(r.parsed.src_ip, '10.5.5.5')
})

// ── JSON with EventID but NO Windows marker must NOT be claimed (falls to json) ──
test('JSON with numeric EventID but no Windows marker → falls to json.js', () => {
  const line = JSON.stringify({ EventID: 1, app: 'myservice', message: 'hi' })
  assert.equal(windows.detect(line), false)
  const r = dispatch(line)
  // json.js claims any leading-{ object; it must be json, not windows-nxlog.
  assert.ok(r && r.kind === 'parsed')
  assert.equal(r.family, 'json')
})

// ════════════════ WINDOWS ENDPOINT / DESKTOP ENRICHMENT ════════════════════
// Rich handling for the desktop/endpoint EIDs that previously fell to the
// defensive 'win_<EID>' default. Ported logon/process field logic from
// openwec.js. The sender host MUST be populated on every event.

// ── 4624 successful logon: action + logon_type label + src_user from Target ──
test('Windows 4624 (logon) → login + logon_type label + Target src_user + host', () => {
  const line = nx({
    EventID: 4624,
    Hostname: 'WS-FINANCE-07',
    Computer: 'WS-FINANCE-07.corp.local',
    Channel: 'Security',
    ProviderName: 'Microsoft-Windows-Security-Auditing',
    EventTime: '2026-06-24 09:15:01',
    SubjectUserName: 'WS-FINANCE-07$', // the machine account requesting the logon
    SubjectDomainName: 'CORP',
    TargetUserName: 'jdoe',
    TargetDomainName: 'CORP',
    LogonType: '10', // remote_interactive (RDP)
    IpAddress: '10.20.30.40',
    IpPort: '50514',
    LogonProcessName: 'User32',
    AuthenticationPackageName: 'Negotiate',
    WorkstationName: 'WS-FINANCE-07',
  })
  const r = parsed(line)
  assert.equal(r.family, 'windows-nxlog')
  const p = r.parsed
  assert.equal(p.win_event_id, 4624)
  assert.equal(p.event_action, 'login')
  assert.equal(p.event_category, 'auth')
  // src_user comes from TargetUserName (who logged on), not the machine account.
  assert.equal(p.src_user, 'CORP\\jdoe')
  assert.equal(p.logon_type, 10)
  assert.equal(p.logon_type_label, 'remote_interactive')
  assert.equal(p.src_ip, '10.20.30.40')
  assert.equal(p.src_port, 50514)
  assert.equal(p.logon_process, 'User32')
  assert.equal(p.auth_package, 'Negotiate')
  // host = the computer that SENT it (the "who sent it" fix).
  assert.equal(p.host, 'WS-FINANCE-07.corp.local')
  assert.equal(p.hostname, 'WS-FINANCE-07.corp.local')
})

// ── 4624 interactive logon with IpAddress '-' → src_ip null ──
test('Windows 4624 interactive logon (LogonType 2, IpAddress "-") → no src_ip', () => {
  const line = nx({
    EventID: 4624,
    Computer: 'WS-01',
    Channel: 'Security',
    TargetUserName: 'localadmin',
    TargetDomainName: 'WS-01',
    LogonType: '2',
    IpAddress: '-', // console logon — no network IP
  })
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'login')
  assert.equal(p.logon_type, 2)
  assert.equal(p.logon_type_label, 'interactive')
  assert.equal(p.src_ip, undefined) // '-' must NOT become a bogus src_ip
  assert.equal(p.src_user, 'WS-01\\localadmin')
})

// ── 4625 failed logon: failure_reason from SubStatus ──
test('Windows 4625 (failed logon) → login_failed + failure_reason + src_ip', () => {
  const line = nx({
    EventID: 4625,
    Computer: 'WS-02.corp.local',
    Hostname: 'WS-02',
    Channel: 'Security',
    TargetUserName: 'administrator',
    TargetDomainName: 'CORP',
    LogonType: '3',
    IpAddress: '203.0.113.66',
    IpPort: '44512',
    Status: '0xC000006D',
    SubStatus: '0xC000006A', // bad password
    LogonProcessName: 'NtLmSsp',
    AuthenticationPackageName: 'NTLM',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4625)
  assert.equal(p.event_action, 'login_failed')
  assert.equal(p.event_category, 'auth')
  assert.equal(p.src_user, 'CORP\\administrator')
  assert.equal(p.src_ip, '203.0.113.66')
  assert.equal(p.src_port, 44512)
  assert.equal(p.failure_reason, '0xC000006D') // FailureReason absent → Status
  assert.equal(p.logon_process, 'NtLmSsp')
  assert.equal(p.auth_package, 'NTLM')
  assert.equal(p.host, 'WS-02.corp.local')
})

// ── 4634 logoff ──
test('Windows 4634 (logoff) → logoff + src_user', () => {
  const line = nx({
    EventID: 4634,
    Computer: 'WS-03',
    Channel: 'Security',
    TargetUserName: 'jdoe',
    TargetDomainName: 'CORP',
    LogonType: '2',
  })
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'logoff')
  assert.equal(p.src_user, 'CORP\\jdoe')
})

// ── 4648 explicit-credential logon ──
test('Windows 4648 (explicit creds) → login_explicit + target_server', () => {
  const line = nx({
    EventID: 4648,
    Computer: 'WS-04',
    Channel: 'Security',
    SubjectUserName: 'jdoe',
    SubjectDomainName: 'CORP',
    TargetUserName: 'svc_backup',
    TargetDomainName: 'CORP',
    TargetServerName: 'SQL01',
    IpAddress: '10.0.0.50',
  })
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'login_explicit')
  assert.equal(p.src_user, 'CORP\\svc_backup') // TargetUserName
  assert.equal(p.target_server, 'SQL01')
  assert.equal(p.src_ip, '10.0.0.50')
})

// ── 4672 special privileges ──
test('Windows 4672 (special privileges) → special_privileges + src_user', () => {
  const line = nx({
    EventID: 4672,
    Computer: 'DC01.corp.local',
    Channel: 'Security',
    SubjectUserName: 'administrator',
    SubjectDomainName: 'CORP',
    PrivilegeList: 'SeSecurityPrivilege\n\t\t\tSeBackupPrivilege',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4672)
  assert.equal(p.event_action, 'special_privileges')
  assert.equal(p.event_category, 'privilege')
  assert.equal(p.src_user, 'CORP\\administrator')
  assert.equal(p.win_privilege_list, 'SeSecurityPrivilege SeBackupPrivilege')
  assert.equal(p.host, 'DC01.corp.local')
})

// ── 4688 process create: process_name + command_line + parent ──
test('Windows 4688 (process create) → process_create + process/command/parent', () => {
  const line = nx({
    EventID: 4688,
    Computer: 'WS-05.corp.local',
    Hostname: 'WS-05',
    Channel: 'Security',
    SubjectUserName: 'jdoe',
    SubjectDomainName: 'CORP',
    NewProcessName: 'C:\\Windows\\System32\\cmd.exe',
    CommandLine: 'cmd.exe /c whoami',
    ParentProcessName: 'C:\\Windows\\explorer.exe',
    NewProcessId: '0x1a2c',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4688)
  assert.equal(p.event_action, 'process_create')
  assert.equal(p.event_category, 'process')
  assert.equal(p.process_name, 'C:\\Windows\\System32\\cmd.exe')
  assert.equal(p.command_line, 'cmd.exe /c whoami')
  assert.equal(p.parent_process_name, 'C:\\Windows\\explorer.exe')
  assert.equal(p.src_user, 'CORP\\jdoe')
  assert.equal(p.win_process_id, '0x1a2c')
  assert.equal(p.host, 'WS-05.corp.local')
})

// ── 4720 account created: target_user vs src_user (actor) ──
test('Windows 4720 (account created) → account_created + target_user + actor', () => {
  const line = nx({
    EventID: 4720,
    Computer: 'DC01.corp.local',
    Channel: 'Security',
    SubjectUserName: 'administrator', // the admin who created it
    SubjectDomainName: 'CORP',
    TargetUserName: 'newhire01', // the account created
    TargetDomainName: 'CORP',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4720)
  assert.equal(p.event_action, 'account_created')
  assert.equal(p.event_category, 'identity')
  assert.equal(p.target_user, 'CORP\\newhire01')
  assert.equal(p.src_user, 'CORP\\administrator') // SubjectUserName = actor
  assert.equal(p.host, 'DC01.corp.local')
})

// ── 4724 password reset (account-lifecycle family) ──
test('Windows 4724 (password reset) → password_reset', () => {
  const line = nx({
    EventID: 4724,
    Computer: 'DC01',
    Channel: 'Security',
    SubjectUserName: 'helpdesk',
    SubjectDomainName: 'CORP',
    TargetUserName: 'jdoe',
    TargetDomainName: 'CORP',
  })
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'password_reset')
  assert.equal(p.target_user, 'CORP\\jdoe')
  assert.equal(p.src_user, 'CORP\\helpdesk')
})

// ── 4732 added to local group ──
test('Windows 4732 (added to group) → group_member_added + group_name', () => {
  const line = nx({
    EventID: 4732,
    Computer: 'WS-06',
    Channel: 'Security',
    SubjectUserName: 'administrator',
    SubjectDomainName: 'CORP',
    MemberSid: 'S-1-5-21-111-222-333-1104',
    MemberName: 'CN=jdoe,CN=Users,DC=corp,DC=local',
    TargetUserName: 'Administrators', // the group
    TargetDomainName: 'Builtin',
  })
  const p = parsed(line).parsed
  assert.equal(p.event_action, 'group_member_added')
  assert.equal(p.event_category, 'identity')
  assert.equal(p.target_user, 'CN=jdoe,CN=Users,DC=corp,DC=local') // MemberName
  assert.equal(p.group_name, 'Builtin\\Administrators')
})

// ── 4740 account lockout ──
test('Windows 4740 (lockout) → account_lockout + target_user', () => {
  const line = nx({
    EventID: 4740,
    Computer: 'DC01.corp.local',
    Channel: 'Security',
    SubjectUserName: 'DC01$',
    SubjectDomainName: 'CORP',
    TargetUserName: 'jdoe',
    TargetDomainName: 'WS-FINANCE-07', // source computer on 4740
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 4740)
  assert.equal(p.event_action, 'account_lockout')
  assert.equal(p.event_category, 'identity')
  assert.equal(p.target_user, 'jdoe')
  assert.equal(p.win_workstation, 'WS-FINANCE-07')
  assert.equal(p.host, 'DC01.corp.local')
})

// ── 1102 audit log cleared ──
test('Windows 1102 (audit log cleared) → audit_log_cleared + actor', () => {
  const line = nx({
    EventID: 1102,
    Computer: 'DC01.corp.local',
    Channel: 'Security',
    SubjectUserName: 'administrator',
    SubjectDomainName: 'CORP',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 1102)
  assert.equal(p.event_action, 'audit_log_cleared')
  assert.equal(p.event_category, 'tampering')
  assert.equal(p.src_user, 'CORP\\administrator')
})

// ── 7045 service install (System log) ──
test('Windows 7045 (service installed) → service_installed + service_name/path', () => {
  const line = nx({
    EventID: 7045,
    Computer: 'WS-07.corp.local',
    Hostname: 'WS-07',
    Channel: 'System',
    ProviderName: 'Service Control Manager',
    ServiceName: 'EvilSvc',
    ImagePath: 'C:\\Windows\\Temp\\evil.exe',
    ServiceType: 'user mode service',
    StartType: 'auto start',
  })
  const p = parsed(line).parsed
  assert.equal(p.win_event_id, 7045)
  assert.equal(p.event_action, 'service_installed')
  assert.equal(p.event_category, 'service')
  assert.equal(p.service_name, 'EvilSvc')
  assert.equal(p.service_path, 'C:\\Windows\\Temp\\evil.exe')
  assert.equal(p.win_service_type, 'user mode service')
  assert.equal(p.win_start_type, 'auto start')
  assert.equal(p.win_channel, 'System')
  assert.equal(p.host, 'WS-07.corp.local')
})

// ── host is populated on a file-access event too (regression on the "who sent it" fix) ──
test('Windows host/hostname populated on every event (sender identity)', () => {
  const line = nx({
    EventID: 4663,
    Computer: 'FS01.corp.local',
    Hostname: 'FS01',
    Channel: 'Security',
    SubjectUserName: 'jdoe',
    SubjectDomainName: 'CORP',
    ObjectName: 'C:\\Share\\a.txt',
    AccessMask: '0x1',
  })
  const p = parsed(line).parsed
  assert.equal(p.host, 'FS01.corp.local')
  assert.equal(p.hostname, 'FS01.corp.local')
})
