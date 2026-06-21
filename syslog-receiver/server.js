const dgram = require('node:dgram');
const net = require('node:net');
const fs = require('node:fs');
const { Client } = require('@opensearch-project/opensearch');

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

  // Try FortiGate key=value format
  const fortiMatch = msg.match(/(?:date=|devname=|logid=|type=)/);
  if (fortiMatch) {
    const kv = {};
    const kvRegex = /(\w+)=("(?:[^"\\]|\\.)*"|[^\s"]+)/g;
    let m;
    while ((m = kvRegex.exec(msg)) !== null) {
      kv[m[1]] = m[2].replace(/^"|"$/g, '');
    }

    result.source = kv.devname || kv.srcname || 'fortigate';
    result.application = kv.type || kv.subtype || null;
    result.message = msg;

    const levelMap = { emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, information: 6, debug: 7 };
    if (kv.level && levelMap[kv.level] !== undefined) {
      result.severity = levelMap[kv.level];
    }

    if (kv.date && kv.time) {
      result.syslog_timestamp = `${kv.date} ${kv.time}`;
    }

    const priMatch = msg.match(/^<(\d{1,3})>/);
    if (priMatch) {
      const pri = parseInt(priMatch[1]);
      result.facility = Math.floor(pri / 8);
      if (result.severity === undefined) result.severity = pri % 8;
    }

    return result;
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
    source_ip: sourceIP,
    source: parsed.source,
    application: parsed.application || null,
    pid: parsed.pid || null,
    facility: parsed.facility != null ? FACILITY_NAMES[parsed.facility] || String(parsed.facility) : null,
    facility_code: parsed.facility,
    severity: parsed.severity != null ? SEVERITY_NAMES[parsed.severity] || String(parsed.severity) : null,
    severity_code: parsed.severity,
    message: parsed.message,
    raw: parsed.raw,
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
            source_ip: { type: 'ip' },
            source: { type: 'keyword' },
            application: { type: 'keyword' },
            pid: { type: 'keyword' },
            facility: { type: 'keyword' },
            facility_code: { type: 'integer' },
            severity: { type: 'keyword' },
            severity_code: { type: 'integer' },
            message: { type: 'text' },
            raw: { type: 'text', index: false },
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
