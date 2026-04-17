# Plan-B Systems SIEM v2

On-premises SIEM with branded dashboard, AI-powered log analysis, and automated license management. No Graylog — fully custom stack.

---

## Architecture

```
  Network Devices (syslog UDP:514 / TCP:1514)
                    │
  ┌─────────────────▼──────────────────┐
  │  plan-b-syslog (Node.js 22)        │  Parses RFC 3164/5424/FortiGate
  │  UDP:514 + TCP:1514                │  Writes directly to OpenSearch
  └─────────────────┬──────────────────┘
                    │
  ┌─────────────────▼──────────────────┐
  │  plan-b-opensearch (2.18.0)        │  Log storage + search
  │  ISM policy for 730-day retention  │  Internal network only
  └─────────────────┬──────────────────┘
                    │
  ┌─────────────────▼──────────────────┐
  │  plan-b-dashboard (Next.js 14)     │  Branded UI, dark theme
  │  http://<IP>:3000                  │  HE/EN bilingual
  │  AI Chat (Claude API)              │
  └────────────────────────────────────┘
  ┌────────────────────────────────────┐
  │  plan-b-license (Python 3.12)      │  Daily license check
  │  Delivers encrypted AI API key     │  Health reporting
  └────────────────────────────────────┘
```

---

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 40 GB | 200 GB+ |
| OS | Ubuntu 22.04 / Windows 10+ | Ubuntu 24.04 |
| Docker | 24.0+ | latest |

> v2 uses ~2-4 GB less RAM than v1 (no Graylog JVM, no MongoDB).

---

## Quick Deploy

### Windows (via WSL2)

Open **PowerShell as Administrator**:
```powershell
irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/v2/install.ps1 | iex
```

### Linux (Ubuntu/Debian/RHEL)

```bash
curl -fsSL https://raw.githubusercontent.com/plan-b-systems/siem-docker/v2/install-linux.sh | sudo bash
```

### What the installer asks:

| Prompt | Description | Example |
|--------|-------------|---------|
| Client name | Short identifier (no spaces) | `acme-tlv` |
| Client ID | From Plan-B portal | `BYI-tWuwmUCprt0XdX1w` |
| LAN IP | Machine's network IP | `192.168.1.100` |
| Dashboard password | Min 8 chars | `MySecurePass1` |
| Timezone | TZ database name | `Asia/Jerusalem` |
| Retention | Days to keep logs | `730` |
| Data path | External disk (optional) | `/mnt/siem-data` |

### What the installer does:

1. Installs Docker (if missing)
2. Clones the v2 repository
3. Generates JWT secret + bcrypt password hash
4. Tunes OS (vm.max_map_count, ulimits)
5. Builds 3 container images (syslog, dashboard, license-checker)
6. Pulls OpenSearch image
7. Starts all 4 containers
8. Registers auto-start (systemd on Linux, scheduled task on Windows)

---

## Dashboard

**URL:** `http://<LAN_IP>:3000`

### Pages

| Page | Description |
|------|-------------|
| **Overview** | Log count, severity pie chart, top sources, top apps, timeline |
| **Threats** | Emergency/alert/critical/error filter, stacked timeline, source correlation |
| **Forensics** | Full log viewer — search, time range, severity filter, pagination, CSV export |
| **Sources** | Device inventory — log count, last seen, health status, top severity |
| **Health** | System metrics — disk, memory, EPS, OpenSearch cluster, license status |
| **Settings** | Language (HE/EN), timezone, retention, client info, OpenSearch status |
| **AI Chat** | Claude-powered log analysis (floating widget, bottom-right) |

### AI Chat

The AI assistant can:
- Search and analyze logs using natural language (Hebrew or English)
- Generate OpenSearch queries automatically
- Correlate events across sources
- Build attack timelines
- Provide actionable security recommendations

AI is powered by Claude (Anthropic). The API key is delivered encrypted via the daily license check — no manual key management needed.

**Budget:** Controlled per client from the Plan-B cloud portal (STARTER=50/day, PRO=200/day, UNLIMITED).

---

## Log Sources

| Protocol | Port | Use Case |
|----------|------|----------|
| Syslog UDP | 514 | Switches, routers, firewalls (standard) |
| Syslog TCP | 1514 | Servers, reliable delivery |

### Supported formats
- RFC 5424 (modern syslog with ISO timestamps)
- RFC 3164 (legacy BSD syslog)
- FortiGate key=value format (auto-detected)

### FortiGate example
```
config log syslogd setting
    set status enable
    set server "<SIEM_IP>"
    set port 514
    set facility local0
end
```

---

## License Checker

Validates the Plan-B subscription **daily at 12:00 local time**.

| State | Services | Check interval |
|-------|----------|----------------|
| `NORMAL` | All running | Daily at 12:00 |
| `GRACE_PERIOD` | All running (7-day grace) | Daily at 12:00 |
| `EXPIRED` | Syslog + Dashboard stopped | Every 10 minutes |

When license is active and client has an AI tier:
1. Sends `CLIENT_SECRET` as Bearer token
2. Receives encrypted Anthropic API key
3. Decrypts and writes to shared volume
4. Dashboard reads key for AI Chat

```bash
# View license status
docker exec plan-b-license-checker cat /data/license_state.json

# View AI key status
docker exec plan-b-dashboard cat /data/ai_key.json

# Force re-check
docker restart plan-b-license-checker
```

---

## Client Onboarding (for Plan-B technicians)

### 1. Create client in cloud portal
1. Login to `siemsys.plan-b.systems/admin`
2. Clients → New → fill company name, email, phone
3. Create ON_PREM subscription (monthly or yearly)
4. Set AI tier (NONE/STARTER/PRO/UNLIMITED)
5. Generate client secret (client detail → On-Prem License → Generate)
6. Copy **Client ID** and **Client Secret**

### 2. Deploy on-prem
1. Run the one-liner installer on client's machine
2. Enter: Client Name, **Client ID**, LAN IP, dashboard password
3. Wait ~10 minutes for deployment

### 3. Configure log sources
1. Point firewalls/switches/servers to send syslog to `<LAN_IP>:514` (UDP) or `:1514` (TCP)
2. Verify logs appear in Dashboard → Forensics page

### 4. Enable AI (optional)
1. Add `CLIENT_SECRET=<secret>` to `/opt/plan-b-siem/config.env`
2. Restart license checker: `docker restart plan-b-license-checker`
3. AI Chat becomes available within 30 seconds

### 5. Verify
- Dashboard: `http://<LAN_IP>:3000` — login, check all pages
- Logs flowing: Forensics page shows incoming events
- AI working: click the blue bot icon, ask "security summary"
- Health: Health page shows green status, EPS > 0

---

## Configuration

All settings in `/opt/plan-b-siem/config.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `CLIENT_NAME` | Site identifier | *(required)* |
| `CLIENT_ID` | License ID from portal | *(required)* |
| `HOST_IP` | Machine LAN IP | *(required)* |
| `DASHBOARD_PASSWORD` | Admin password | *(required)* |
| `TIMEZONE` | Local timezone | `Asia/Jerusalem` |
| `RETENTION_DAYS` | Log retention | `730` |
| `OPENSEARCH_HEAP_SIZE` | RAM for OpenSearch | `2g` |
| `SYSLOG_UDP_PORT` | Syslog UDP | `514` |
| `SYSLOG_TCP_PORT` | Syslog TCP | `1514` |
| `DASHBOARD_PORT` | Dashboard web | `3000` |
| `LICENSE_API_URL` | Cloud API | `https://siemsys.plan-b.systems/api/license/check` |
| `CLIENT_SECRET` | For AI key delivery | *(from portal)* |
| `DATA_PATH` | External storage | *(empty = Docker volumes)* |

---

## Useful Commands

```bash
# Stack status
docker compose --env-file config.env ps

# Live logs
docker compose --env-file config.env logs -f

# Restart a service
docker restart plan-b-dashboard

# Check log count
docker exec plan-b-opensearch curl -s localhost:9200/logs-*/_count

# Check disk usage
docker exec plan-b-opensearch curl -s localhost:9200/_nodes/stats/fs | python3 -m json.tool

# Health check
./resilience/health-check.sh

# Stop everything
docker compose --env-file config.env down

# Start everything
docker compose --env-file config.env up -d
```

---

## v1 vs v2

| Feature | v1 (main branch) | v2 (v2 branch) |
|---------|-------------------|----------------|
| Stack | Graylog + MongoDB + OpenSearch | Dashboard + Syslog + OpenSearch |
| Containers | 4 (+ MongoDB) | 4 (no MongoDB) |
| RAM | 8 GB minimum | 4 GB minimum |
| UI | Graylog web interface | Custom branded dashboard |
| AI | Via cloud only | On-prem AI Chat |
| Language | Graylog default (EN) | HE/EN bilingual |
| Theme | Light | Dark |
| Deploy | `irm .../main/install.ps1 \| iex` | `irm .../v2/install.ps1 \| iex` |

Both versions use the same cloud license API. v1 clients are unaffected by v2.

---

## Support

Plan-B Systems — https://plan-b.systems
Email: support@plan-b.systems
