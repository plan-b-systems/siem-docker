const dgram = require('node:dgram');
const net = require('node:net');
const fs = require('node:fs');
const { Client } = require('@opensearch-project/opensearch');
// Pluggable multivendor parser stack (CEF, LEEF, JSON, Check Point kv, Palo
// Alto CSV, Cisco, Aruba, OpenWEC, DNS). Pure functions, no OpenSearch import.
const { dispatch: dispatchExtended } = require('./parsers');
// FortiGate kv parser — pure module, called as the post-dispatch FortiGate
// step (mirrors the cloud receiver's inline FortiGate layering) but kept in one
// unit-testable place.
const fortigateParser = require('./parsers/fortigate');
// Generic heuristic firewall fallback — last-resort src/dst/port/action
// extractor for vendors we have no dedicated parser for. Run explicitly here
// (NOT in the dispatch list) so it sits AFTER FortiGate kv + RFC parsers,
// mirroring the cloud receiver's layering.
const genericParser = require('./parsers/generic');

// ── Config ──────────────────────────────────────────────
const SYSLOG_UDP_PORT = 514;
const SYSLOG_TCP_PORT = 1514;
const OPENSEARCH_URL = process.env.OPENSEARCH_URL || 'http://opensearch:9200';
const CLIENT_ID = process.env.CLIENT_ID || 'UNKNOWN';
const CLIENT_NAME = process.env.CLIENT_NAME || 'Unknown Client';
const RETENTION_DAYS = parseInt(process.env.RETENTION_DAYS || '730', 10);

// SentinelOne API puller config (parity with the cloud edr-puller). The
// integration credentials are delivered by the license-checker to
// S1_INTEGRATION_FILE; this service polls the S1 API and writes normalized
// events into the same logs-* indices as syslog.
const S1_INTEGRATION_FILE = process.env.S1_INTEGRATION_FILE || '/data/s1_integration.json';
const S1_POLL_INTERVAL_SEC = parseInt(process.env.S1_POLL_INTERVAL_SEC || '300', 10);
const S1_LOOKBACK_SEC = parseInt(process.env.S1_LOOKBACK_SEC || '900', 10);
const S1_MAX_EVENTS = parseInt(process.env.S1_MAX_EVENTS || '1000', 10);

// ── OpenSearch client ───────────────────────────────────
const osClient = new Client({ node: OPENSEARCH_URL });

// ── Syslog parser ───────────────────────────────────────
const SEVERITY_NAMES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];
const FACILITY_NAMES = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];

function parseSyslog(raw) {
  const msg = raw.toString('utf-8').trim();
  const receiveTime = new Date().toISOString();
  const result = { raw: msg, timestamp: receiveTime, syslog_timestamp: null };

  // Pull PRI up-front so facility/severity are available regardless of which
  // parser fires (extended parsers may not see the leading <PRI> header).
  const priMatchEarly = msg.match(/^<(\d{1,3})>/);
  if (priMatchEarly) {
    const pri = parseInt(priMatchEarly[1]);
    result.facility = Math.floor(pri / 8);
    result.severity = pri % 8;
  }

  // Try extended parsers first (CEF, LEEF, JSON, Check Point kv, Palo Alto CSV,
  // Cisco, Aruba, OpenWEC, DNS). dispatch() returns one of:
  //   {kind:'parsed', parsed, family}     — successful parse
  //   {kind:'quarantine', family, reason} — parser claimed but failed strictly
  //   null                                — no parser claimed; fall through
  // On-prem is single-tenant with no quarantine index/API, so a claimed-but-
  // failed parse falls through to the raw store with a debug log.
  const extended = dispatchExtended(msg);
  if (extended && extended.kind === 'parsed') {
    // ingest_source defaults to 'syslog' for the firewall families; the Windows
    // (openwec) parser sets its own 'wef'/'sysmon' value which we must not clobber.
    if (!extended.parsed.ingest_source) extended.parsed.ingest_source = 'syslog';
    return Object.assign(result, extended.parsed);
  }
  if (extended && extended.kind === 'quarantine') {
    console.debug(`[parser] ${extended.family} claimed but failed (${extended.reason}); storing raw`);
  }

  // Try RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
  const rfc5424 = msg.match(/^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)/s);
  if (rfc5424) {
    const pri = parseInt(rfc5424[1]);
    result.facility = Math.floor(pri / 8);
    result.severity = pri % 8;
    result.version = parseInt(rfc5424[2]);
    result.syslog_timestamp = rfc5424[3] === '-' ? null : rfc5424[3];
    // Use syslog timestamp if present and valid
    if (result.syslog_timestamp && result.syslog_timestamp !== '-') {
      const parsed = new Date(result.syslog_timestamp);
      if (!isNaN(parsed.getTime())) result.timestamp = parsed.toISOString();
    }
    result.source = rfc5424[4];
    result.application = rfc5424[5] === '-' ? null : rfc5424[5];
    result.pid = rfc5424[6] === '-' ? null : rfc5424[6];
    result.message = rfc5424[8] || '';
    return result;
  }

  // Try RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG
  const rfc3164 = msg.match(/^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)/s);
  if (rfc3164) {
    const pri = parseInt(rfc3164[1]);
    result.facility = Math.floor(pri / 8);
    result.severity = pri % 8;
    result.syslog_timestamp = rfc3164[2];
    result.source = rfc3164[3];
    result.message = rfc3164[4];

    // Extract app name from message (e.g., "sshd[1234]: msg")
    const appMatch = result.message.match(/^(\S+?)(?:\[(\d+)\])?:\s*(.*)/s);
    if (appMatch) {
      result.application = appMatch[1];
      result.pid = appMatch[2] || null;
      result.message = appMatch[3];
    }
    return result;
  }

  // Try FortiGate key=value format: date=... time=... devname=... logid=... type=... ...
  // FULL field mapping (src_ip/dst_ip/event_action/ports/protocol/policy/...) via
  // the pure fortigate parser module — not just source/app/severity.
  if (fortigateParser.detect(msg)) {
    const forti = fortigateParser.parse(msg);
    forti.parser_name = 'fortigate-kv';
    // The module sets severity from kv.level when present; keep the leading
    // <PRI>-derived severity (set up-front above) only when the module didn't.
    if (forti.severity === undefined && result.severity !== undefined) {
      forti.severity = result.severity;
    }
    return Object.assign(result, forti);
  }

  // Generic heuristic firewall fallback — for any vendor we have no dedicated
  // parser for, still regex-extract src/dst IPs, ports, protocol, and an action
  // keyword so unknown firewalls yield the common normalized fields. Runs AFTER
  // FortiGate kv + RFC parsers. Conservative detect() avoids hijacking plain
  // application syslog (sshd/cron/etc), which the RFC path above already handled.
  if (genericParser.detect(msg)) {
    try {
      const g = genericParser.parse(msg);
      if (g) {
        g.parser_name = 'generic-firewall';
        g.ingest_source = 'syslog';
        return Object.assign(result, g);
      }
    } catch (err) {
      console.debug(`[parser:generic] error: ${err.message}`);
    }
  }

  // Fallback: unparseable — store raw message as-is
  result.source = 'unknown';
  result.message = msg;
  return result;
}

// ── Index into OpenSearch ───────────────────────────────
async function indexLog(parsed, sourceIP) {
  const now = new Date();
  const indexName = `logs-${CLIENT_ID.toLowerCase()}-${now.getFullYear()}.${String(now.getMonth() + 1).padStart(2, '0')}`;

  const doc = {
    '@timestamp': parsed.timestamp,
    client_id: CLIENT_ID,
    client_name: CLIENT_NAME,
    source_ip: sourceIP,              // transport IP (who sent the syslog)
    source: parsed.source,
    application: parsed.application || null,
    pid: parsed.pid || null,
    facility: parsed.facility != null ? FACILITY_NAMES[parsed.facility] || String(parsed.facility) : null,
    facility_code: parsed.facility,
    severity: parsed.severity != null ? SEVERITY_NAMES[parsed.severity] || String(parsed.severity) : null,
    severity_code: parsed.severity,
    message: parsed.message,
    raw: parsed.raw,
    // ── Normalized fields (identical names to the cloud receiver so the
    // dashboard + MDR engine work unchanged) ──
    device_vendor: parsed.device_vendor || null,
    device_product: parsed.device_product || null,
    parser_name: parsed.parser_name || null,
    ingest_source: parsed.ingest_source || null,
    event_action: parsed.event_action || null,
    event_category: parsed.event_category || null,
    event_subtype: parsed.event_subtype || null,
    src_ip: parsed.src_ip || null,
    dst_ip: parsed.dst_ip || null,
    src_port: parsed.src_port ?? null,
    dst_port: parsed.dst_port ?? null,
    src_user: parsed.src_user || null,
    src_domain: parsed.src_domain || null,
    src_country: parsed.src_country || null,
    dst_country: parsed.dst_country || null,
    src_mac: parsed.src_mac || null,
    network_protocol: parsed.network_protocol || null,
    network_service: parsed.network_service || null,
    fw_policy_id: parsed.fw_policy_id || null,
    fw_rule_name: parsed.fw_rule_name || null,
    fw_risk_score: parsed.fw_risk_score ?? null,
    fw_risk_level: parsed.fw_risk_level || null,
    bytes_sent: parsed.bytes_sent ?? null,
    bytes_received: parsed.bytes_received ?? null,
    src_interface: parsed.src_interface || null,
    dst_interface: parsed.dst_interface || null,
    session_id: parsed.session_id || null,
    // ── CEF ──
    cef_version: parsed.cef_version ?? null,
    cef_signature_id: parsed.cef_signature_id || null,
    cef_name: parsed.cef_name || null,
    cef_severity: parsed.cef_severity ?? null,
    device_version: parsed.device_version || null,
    // ── LEEF ──
    leef_version: parsed.leef_version ?? null,
    leef_event_id: parsed.leef_event_id || null,
    leef_severity: parsed.leef_severity ?? null,
    // ── Check Point ──
    cp_sic_name: parsed.cp_sic_name || null,
    cp_blade: parsed.cp_blade || null,
    cp_inzone: parsed.cp_inzone || null,
    cp_outzone: parsed.cp_outzone || null,
    // ── Palo Alto ──
    pan_log_type: parsed.pan_log_type || null,
    pan_subtype: parsed.pan_subtype || null,
    pan_serial: parsed.pan_serial || null,
    pan_threat_id: parsed.pan_threat_id || null,
    pan_threat_misc: parsed.pan_threat_misc || null,
    pan_threat_category: parsed.pan_threat_category || null,
    pan_direction: parsed.pan_direction || null,
    pan_url: parsed.pan_url || null,
    pan_url_category: parsed.pan_url_category || null,
    pan_event_id: parsed.pan_event_id || null,
    pan_auth_type: parsed.pan_auth_type || null,
    pan_auth_event_type: parsed.pan_auth_event_type || null,
    pan_userid_factor: parsed.pan_userid_factor || null,
    pan_userid_event: parsed.pan_userid_event || null,
    pan_module: parsed.pan_module || null,
    pan_object: parsed.pan_object || null,
    // ── Cisco ──
    cisco_facility: parsed.cisco_facility || null,
    cisco_mnemonic: parsed.cisco_mnemonic || null,
    // ── Aruba ──
    aruba_symbol_id: parsed.aruba_symbol_id || null,
    aruba_module: parsed.aruba_module || null,
    aruba_ssid: parsed.aruba_ssid || null,
    aruba_bssid: parsed.aruba_bssid || null,
    // ── DNS ──
    dns_qname: parsed.dns_qname || null,
    dns_qtype: parsed.dns_qtype || null,
    dns_client_ip: parsed.dns_client_ip || null,
    dns_response_code: parsed.dns_response_code || null,
    // ── Windows (OpenWEC) — emitted when a Windows event is forwarded ──
    win_event_id: parsed.win_event_id ?? null,
    win_channel: parsed.win_channel || null,
    win_provider: parsed.win_provider || null,
    logon_type: parsed.logon_type ?? null,
    win_logon_type: parsed.win_logon_type ?? null,
    win_process_name: parsed.win_process_name || null,
    win_command_line: parsed.win_command_line || null,
    win_parent_process_name: parsed.win_parent_process_name || null,
    process_name: parsed.process_name || null,
    command_line: parsed.command_line || null,
    parent_process_name: parsed.parent_process_name || null,
    account_name: parsed.account_name || null,
    account_domain: parsed.account_domain || null,
  };

  try {
    await osClient.index({ index: indexName, body: doc });
  } catch (err) {
    console.error(`[opensearch] Index error: ${err.message}`);
  }
}

// ── Ensure index template exists ────────────────────────
async function ensureIndexTemplate() {
  try {
    await osClient.indices.putTemplate({
      name: 'plan-b-logs',
      body: {
        index_patterns: ['logs-*'],
        settings: {
          number_of_shards: 1,
          number_of_replicas: 0,
          'index.refresh_interval': '5s',
        },
        mappings: {
          properties: {
            '@timestamp': { type: 'date' },
            client_id: { type: 'keyword' },
            client_name: { type: 'keyword' },
            source_ip: { type: 'ip', ignore_malformed: true },
            source: { type: 'keyword' },
            application: { type: 'keyword' },
            pid: { type: 'keyword' },
            facility: { type: 'keyword' },
            facility_code: { type: 'integer' },
            severity: { type: 'keyword' },
            severity_code: { type: 'integer' },
            message: { type: 'text' },
            raw: { type: 'text', index: false },
            // ── Normalized firewall / network fields (identical names to the
            // cloud receiver so the dashboard + MDR engine work unchanged) ──
            device_vendor: { type: 'keyword' },
            device_product: { type: 'keyword' },
            device_version: { type: 'keyword' },
            parser_name: { type: 'keyword' },
            ingest_source: { type: 'keyword' },
            event_action: { type: 'keyword' },
            event_category: { type: 'keyword' },
            event_subtype: { type: 'keyword' },
            src_ip: { type: 'ip', ignore_malformed: true },
            dst_ip: { type: 'ip', ignore_malformed: true },
            src_port: { type: 'integer' },
            dst_port: { type: 'integer' },
            src_user: { type: 'keyword' },
            src_domain: { type: 'keyword' },
            src_country: { type: 'keyword' },
            dst_country: { type: 'keyword' },
            src_mac: { type: 'keyword' },
            network_protocol: { type: 'keyword' },
            network_service: { type: 'keyword' },
            fw_policy_id: { type: 'keyword' },
            fw_rule_name: { type: 'keyword' },
            fw_risk_score: { type: 'integer' },
            fw_risk_level: { type: 'keyword' },
            bytes_sent: { type: 'long' },
            bytes_received: { type: 'long' },
            src_interface: { type: 'keyword' },
            dst_interface: { type: 'keyword' },
            session_id: { type: 'keyword' },
            // ── CEF ──
            cef_version: { type: 'integer' },
            cef_signature_id: { type: 'keyword' },
            cef_name: { type: 'keyword' },
            cef_severity: { type: 'integer' },
            // ── LEEF ──
            leef_version: { type: 'integer' },
            leef_event_id: { type: 'keyword' },
            leef_severity: { type: 'integer' },
            // ── Check Point ──
            cp_sic_name: { type: 'keyword' },
            cp_blade: { type: 'keyword' },
            cp_inzone: { type: 'keyword' },
            cp_outzone: { type: 'keyword' },
            // ── Palo Alto ──
            pan_log_type: { type: 'keyword' },
            pan_subtype: { type: 'keyword' },
            pan_serial: { type: 'keyword' },
            pan_threat_id: { type: 'keyword' },
            pan_threat_misc: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 2048 } } },
            pan_threat_category: { type: 'keyword' },
            pan_direction: { type: 'keyword' },
            pan_url: { type: 'text', fields: { keyword: { type: 'keyword', ignore_above: 2048 } } },
            pan_url_category: { type: 'keyword' },
            pan_event_id: { type: 'keyword' },
            pan_auth_type: { type: 'keyword' },
            pan_auth_event_type: { type: 'keyword' },
            pan_userid_factor: { type: 'keyword' },
            pan_userid_event: { type: 'keyword' },
            pan_module: { type: 'keyword' },
            pan_object: { type: 'keyword' },
            // ── Cisco ──
            cisco_facility: { type: 'keyword' },
            cisco_mnemonic: { type: 'keyword' },
            // ── Aruba ──
            aruba_symbol_id: { type: 'keyword' },
            aruba_module: { type: 'keyword' },
            aruba_ssid: { type: 'keyword' },
            aruba_bssid: { type: 'keyword' },
            // ── DNS ──
            dns_qname: { type: 'keyword' },
            dns_qtype: { type: 'keyword' },
            dns_client_ip: { type: 'ip', ignore_malformed: true },
            dns_response_code: { type: 'keyword' },
            // ── Windows (OpenWEC) ──
            win_event_id: { type: 'integer' },
            win_channel: { type: 'keyword' },
            win_provider: { type: 'keyword' },
            logon_type: { type: 'integer' },
            win_logon_type: { type: 'integer' },
            win_process_name: { type: 'keyword' },
            win_command_line: { type: 'text' },
            win_parent_process_name: { type: 'keyword' },
            process_name: { type: 'keyword' },
            command_line: { type: 'text' },
            parent_process_name: { type: 'keyword' },
            account_name: { type: 'keyword' },
            account_domain: { type: 'keyword' },
          },
        },
      },
    });
    console.log('[opensearch] Index template "plan-b-logs" created');
  } catch (err) {
    console.error(`[opensearch] Template error: ${err.message}`);
  }
}

// ── ISM Policy for retention ────────────────────────────
async function ensureISMPolicy() {
  const policyName = 'plan-b-retention';
  try {
    // Check if policy exists
    let exists = false;
    try {
      await osClient.transport.request({
        method: 'GET',
        path: `/_plugins/_ism/policies/${policyName}`,
      });
      exists = true;
    } catch (e) {
      // 404 = doesn't exist, that's fine
    }

    const policy = {
      policy: {
        description: `Plan-B SIEM log retention: delete indices older than ${RETENTION_DAYS} days`,
        default_state: 'hot',
        states: [
          {
            name: 'hot',
            actions: [],
            transitions: [
              {
                state_name: 'delete',
                conditions: { min_index_age: `${RETENTION_DAYS}d` },
              },
            ],
          },
          {
            name: 'delete',
            actions: [{ delete: {} }],
            transitions: [],
          },
        ],
        ism_template: [
          {
            index_patterns: ['logs-*'],
            priority: 100,
          },
        ],
      },
    };

    if (exists) {
      await osClient.transport.request({
        method: 'PUT',
        path: `/_plugins/_ism/policies/${policyName}`,
        body: policy,
      });
      console.log(`[opensearch] ISM policy "${policyName}" updated (${RETENTION_DAYS} days)`);
    } else {
      await osClient.transport.request({
        method: 'PUT',
        path: `/_plugins/_ism/policies/${policyName}`,
        body: policy,
      });
      console.log(`[opensearch] ISM policy "${policyName}" created (${RETENTION_DAYS} days)`);
    }
  } catch (err) {
    console.error(`[opensearch] ISM policy error: ${err.message}`);
  }
}

// ── SentinelOne API puller ──────────────────────────────
// Reads the integration config the license-checker delivers to
// S1_INTEGRATION_FILE and polls S1 /threats + /activities, normalizing into
// the same canonical shape as syslog so the dashboard renders them with no
// changes. Deterministic _id + _create gives storage-layer dedupe across
// overlapping polls. Dormant when no config file is present (e.g. before the
// MSP has provisioned the S1 API token in the portal).

function readS1Config() {
  try {
    if (!fs.existsSync(S1_INTEGRATION_FILE)) return null;
    const cfg = JSON.parse(fs.readFileSync(S1_INTEGRATION_FILE, 'utf-8'));
    if (!cfg || !cfg.host || !cfg.token || !cfg.site_id) return null;
    return cfg;
  } catch (err) {
    console.error(`[s1] failed to read ${S1_INTEGRATION_FILE}: ${err.message}`);
    return null;
  }
}

function s1NormaliseHost(host) {
  let h = String(host).replace(/\/+$/, '');
  if (!h.startsWith('http')) h = `https://${h}`;
  return h;
}

function s1SeverityFromClassification(c) {
  if (!c) return { label: 'warning', code: 4 };
  const lc = String(c).toLowerCase();
  if (lc.includes('malware') || lc.includes('ransomware') || lc.includes('exploit')) return { label: 'critical', code: 2 };
  if (lc.includes('suspicious') || lc.includes('anomaly')) return { label: 'warning', code: 4 };
  if (lc.includes('benign')) return { label: 'info', code: 6 };
  return { label: 'warning', code: 4 };
}

function s1BaseBody(cfg, ts, severity) {
  // No real source_ip on EDR events — leave it unset (the field is mapped as
  // `ip` and would reject a non-IP value).
  return {
    '@timestamp': ts,
    client_id: CLIENT_ID,
    client_name: CLIENT_NAME,
    source: `SentinelOne · ${cfg.site_name || 'unknown-site'}`,
    application: 'edr',
    facility: 'local0',
    facility_code: 16,
    severity: severity.label,
    severity_code: severity.code,
    device_vendor: 'sentinelone',
    device_product: 'singularity',
    event_category: 'edr',
    ingest_source: 'edr-puller',
    ingested_at: new Date().toISOString(),
  };
}

function s1ThreatToDoc(cfg, t) {
  const ts = t.createdAt || t.updatedAt || new Date().toISOString();
  const cls = t.threatInfo && t.threatInfo.classification;
  const sev = s1SeverityFromClassification(cls);
  return {
    id: `s1-threat-${t.id}`,
    timestamp: ts,
    body: {
      ...s1BaseBody(cfg, ts, sev),
      event_action: 'threat',
      event_subtype: cls || 'unknown',
      hostname: (t.agentRealtimeInfo && t.agentRealtimeInfo.agentComputerName) || null,
      message: (t.threatInfo && t.threatInfo.threatName) || 'S1 threat detected',
      raw: JSON.stringify(t),
    },
  };
}

function s1ActivityToDoc(cfg, a) {
  const ts = a.createdAt || new Date().toISOString();
  const sev = { label: 'info', code: 6 };
  return {
    id: `s1-activity-${a.id}`,
    timestamp: ts,
    body: {
      ...s1BaseBody(cfg, ts, sev),
      event_action: 'activity',
      event_subtype: String(a.activityType != null ? a.activityType : 'unknown'),
      hostname: a.agentName || null,
      message: a.primaryDescription || 'S1 activity',
      raw: JSON.stringify(a),
    },
  };
}

async function s1Get(host, token, path) {
  const res = await fetch(`${s1NormaliseHost(host)}${path}`, {
    headers: { Authorization: `ApiToken ${token}`, Accept: 'application/json' },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    const err = new Error(`S1 GET ${res.status}: ${body.slice(0, 200)}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

async function s1WriteDoc(doc) {
  // Index by the event's own month, matching the syslog convention + ISM policy.
  const yyyymm = doc.timestamp.slice(0, 7).replace('-', '.');
  const index = `logs-${CLIENT_ID.toLowerCase()}-${yyyymm}`;
  try {
    await osClient.create({ index, id: doc.id, body: doc.body });
    return 'written';
  } catch (err) {
    const status = (err.meta && err.meta.statusCode) || err.statusCode;
    if (status === 409) return 'duplicate'; // already written by an overlapping poll
    console.error(`[s1] write failed for ${doc.id}: ${err.message}`);
    return 'failed';
  }
}

let s1Running = false;

async function s1PollCycle() {
  const cfg = readS1Config();
  if (!cfg) return; // dormant — no integration delivered yet
  if (s1Running) return; // previous cycle still in flight
  s1Running = true;
  try {
    const sinceIso = new Date(Date.now() - S1_LOOKBACK_SEC * 1000).toISOString();
    const half = Math.floor(S1_MAX_EVENTS / 2);
    const siteId = encodeURIComponent(cfg.site_id);
    const since = encodeURIComponent(sinceIso);
    const feeds = [
      { label: 'threats', toDoc: s1ThreatToDoc,
        path: `/web/api/v2.1/threats?siteIds=${siteId}&createdAt__gte=${since}&limit=${half}&sortBy=createdAt&sortOrder=desc` },
      { label: 'activities', toDoc: s1ActivityToDoc,
        path: `/web/api/v2.1/activities?siteIds=${siteId}&createdAt__gte=${since}&limit=${half}&sortBy=createdAt&sortOrder=desc` },
    ];

    let written = 0, duplicates = 0, failed = 0;
    // Pull each feed independently — a read-only token often 403s on /threats
    // but can still read /activities; one feed's gap must not drop the other.
    for (const feed of feeds) {
      try {
        const res = await s1Get(cfg.host, cfg.token, feed.path);
        const data = (res && res.data) || [];
        for (const item of data) {
          const r = await s1WriteDoc(feed.toDoc(cfg, item));
          if (r === 'written') written++;
          else if (r === 'duplicate') duplicates++;
          else failed++;
        }
      } catch (err) {
        if (err.status === 403) {
          console.warn(`[s1] ${feed.label} feed not permitted (403) — grant "${feed.label === 'threats' ? 'Threats' : 'Activity'}: View" to the SentinelOne API user`);
        } else {
          console.error(`[s1] ${feed.label} feed pull failed: ${err.message}`);
        }
      }
    }
    console.log(`[s1] cycle: written=${written} duplicates=${duplicates} failed=${failed} site=${cfg.site_id}`);
  } finally {
    s1Running = false;
  }
}

function startS1Poller() {
  // First cycle 15s after boot (let OpenSearch settle), then every interval.
  setTimeout(() => { s1PollCycle().catch((e) => console.error(`[s1] cycle error: ${e.message}`)); }, 15_000);
  setInterval(() => { s1PollCycle().catch((e) => console.error(`[s1] cycle error: ${e.message}`)); }, S1_POLL_INTERVAL_SEC * 1000);
  console.log(`[s1] poller armed — interval ${S1_POLL_INTERVAL_SEC}s, lookback ${S1_LOOKBACK_SEC}s, config ${S1_INTEGRATION_FILE}`);
}

// ── Handle incoming syslog message ──────────────────────
function handleMessage(data, sourceIP) {
  const parsed = parseSyslog(data);
  indexLog(parsed, sourceIP);
}

// ── Stats ───────────────────────────────────────────────
let stats = { udp: 0, tcp: 0 };

setInterval(() => {
  if (stats.udp + stats.tcp > 0) {
    console.log(`[stats] UDP: ${stats.udp} | TCP: ${stats.tcp} | Client: ${CLIENT_NAME} (${CLIENT_ID})`);
    stats = { udp: 0, tcp: 0 };
  }
}, 60_000);

// ── UDP Server ──────────────────────────────────────────
const udpServer = dgram.createSocket('udp4');

udpServer.on('message', (data, rinfo) => {
  stats.udp++;
  handleMessage(data, rinfo.address);
});

udpServer.on('error', (err) => {
  console.error(`[udp] Error: ${err.message}`);
});

udpServer.bind(SYSLOG_UDP_PORT, '0.0.0.0', () => {
  console.log(`[udp] Listening on 0.0.0.0:${SYSLOG_UDP_PORT}`);
});

// ── TCP Server ──────────────────────────────────────────
const tcpServer = net.createServer((socket) => {
  const sourceIP = socket.remoteAddress.replace('::ffff:', '');
  let buffer = '';

  socket.on('data', (chunk) => {
    buffer += chunk.toString();

    while (buffer.length > 0) {
      // Try octet-counting
      const octetMatch = buffer.match(/^(\d{1,6}) (<\d+>)/);
      if (octetMatch) {
        const msgLen = parseInt(octetMatch[1]);
        const prefixLen = octetMatch[1].length + 1;
        if (buffer.length < prefixLen + msgLen) break;
        const msg = buffer.substring(prefixLen, prefixLen + msgLen).trim();
        buffer = buffer.substring(prefixLen + msgLen);
        if (msg) {
          stats.tcp++;
          handleMessage(Buffer.from(msg), sourceIP);
        }
        continue;
      }

      // Try newline-delimited
      const nlIndex = buffer.indexOf('\n');
      if (nlIndex !== -1) {
        const line = buffer.substring(0, nlIndex).trim();
        buffer = buffer.substring(nlIndex + 1);
        if (line) {
          stats.tcp++;
          handleMessage(Buffer.from(line), sourceIP);
        }
        continue;
      }

      break;
    }

    // Prevent buffer overflow
    if (buffer.length > 50 * 1024 * 1024) {
      console.warn(`[tcp] Buffer overflow from ${sourceIP}, flushing`);
      buffer = '';
    }
  });

  socket.on('close', () => { buffer = ''; });
  socket.on('error', (err) => {
    console.debug(`[tcp] Socket error from ${sourceIP}: ${err.message}`);
  });
});

tcpServer.listen(SYSLOG_TCP_PORT, '0.0.0.0', () => {
  console.log(`[tcp] Listening on 0.0.0.0:${SYSLOG_TCP_PORT}`);
});

// ── Start ───────────────────────────────────────────────
async function start() {
  console.log('');
  console.log('Plan-B Systems SIEM v2 - Syslog Receiver');
  console.log('=========================================');
  console.log(`  Client:    ${CLIENT_NAME} (${CLIENT_ID})`);
  console.log(`  OpenSearch: ${OPENSEARCH_URL}`);
  console.log(`  Retention:  ${RETENTION_DAYS} days`);
  console.log(`  UDP:        0.0.0.0:${SYSLOG_UDP_PORT}`);
  console.log(`  TCP:        0.0.0.0:${SYSLOG_TCP_PORT}`);
  console.log('');

  await ensureIndexTemplate();
  await ensureISMPolicy();
  startS1Poller();
}

start();
