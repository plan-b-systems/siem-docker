# Plan-B Systems SIEM v2.1

On-premises SIEM appliance with a branded dashboard, syslog ingestion, OpenSearch storage, automated license management, and optional AI-powered log analysis.

v1/Graylog is retired. The supported deployment path is the v2.1 stack from the `main` branch.

## Architecture

```
Network devices
  | syslog UDP:514 / TCP:1514
  v
plan-b-syslog (Node.js)
  | parsed RFC 3164/5424/FortiGate logs
  v
plan-b-opensearch (OpenSearch 2.x)
  | logs, settings, retention policies
  v
plan-b-dashboard (Next.js)

plan-b-license-checker (Python)
  | daily license check + encrypted AI key delivery
  v
Plan-B cloud license API
```

## Containers

| Container | Purpose | Exposure |
|-----------|---------|----------|
| `plan-b-opensearch` | Log storage, search, retention | Internal Docker network |
| `plan-b-syslog` | Syslog receiver and parser | UDP `514`, TCP `1514` |
| `plan-b-dashboard` | Web UI, health, forensics, AI chat | HTTP `3000` |
| `plan-b-license-checker` | License validation and AI key delivery | Internal Docker network |

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB+ |
| Disk | 40 GB | 200 GB+ |
| OS | Ubuntu 22.04/24.04 or Windows 10/11 with WSL2 | Ubuntu 24.04 |
| Docker | 24.0+ | Latest |

## One-Line Install

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install-linux.sh | sudo bash
```

Windows, from PowerShell as Administrator:

```powershell
irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install.ps1 | iex
```

Detailed guides:

| Platform | Guide |
|----------|-------|
| Ubuntu/Linux | [UBUNTU-DEPLOY.md](UBUNTU-DEPLOY.md) |
| Windows | [WINDOWS-DEPLOY.md](WINDOWS-DEPLOY.md) |

## Installer Prompts

| Prompt | Description | Example |
|--------|-------------|---------|
| Client name | Short site identifier, no spaces | `acme-tlv` |
| Client ID | License ID from Plan-B portal | `BYI-tWuwmUCprt0XdX1w` |
| LAN IP | Appliance network IP | `192.168.1.100` |
| Dashboard password | Initial admin password | `MySecurePass1` |
| Timezone | TZ database name | `Asia/Jerusalem` |
| Retention | Days to keep logs | `730` |
| Data path | Optional external storage path | `/mnt/siem-data` |

## Dashboard

URL:

```text
http://<LAN_IP>:3000
```

Primary pages:

| Page | Purpose |
|------|---------|
| Overview | Log volume, severity distribution, top sources, timeline |
| Threats | High-severity filters, attack timeline, source correlation |
| Forensics | Searchable log viewer, filters, pagination, CSV export |
| Sources | Device inventory, last seen, health, severity summary |
| Health | Disk, memory, EPS, OpenSearch, license status |
| Settings | Language, timezone, retention, client info, OpenSearch status |
| AI Chat | Claude-powered log investigation when licensed |

## Log Sources

| Protocol | Port | Use case |
|----------|------|----------|
| Syslog UDP | `514` | Firewalls, switches, routers |
| Syslog TCP | `1514` | Servers and reliable delivery |

Supported parsing includes RFC 5424, RFC 3164, and FortiGate key=value logs.

Example rsyslog forwarding:

```text
*.* @@<SIEM_IP>:1514
```

Example FortiGate:

```text
config log syslogd setting
    set status enable
    set server "<SIEM_IP>"
    set port 514
    set facility local0
end
```

## License Checker

The license checker validates the Plan-B subscription daily at 12:00 local time.

| State | Services | Check interval |
|-------|----------|----------------|
| `NORMAL` | All running | Daily at 12:00 |
| `GRACE_PERIOD` | All running during grace | Daily at 12:00 |
| `EXPIRED` | Syslog and dashboard stopped | Every 10 minutes |

Useful commands:

```bash
docker exec plan-b-license-checker cat /data/license_state.json
docker restart plan-b-license-checker
```

## Configuration

The installer writes `/opt/plan-b-siem/config.env`.

Important variables:

| Variable | Description |
|----------|-------------|
| `CLIENT_NAME` | Site identifier |
| `CLIENT_ID` | License ID from Plan-B portal |
| `HOST_IP` | Appliance LAN IP |
| `DASHBOARD_PASSWORD` | Initial dashboard password |
| `TIMEZONE` | Local timezone |
| `RETENTION_DAYS` | Log retention period |
| `OPENSEARCH_HEAP_SIZE` | OpenSearch JVM heap |
| `SYSLOG_UDP_PORT` | Syslog UDP port |
| `SYSLOG_TCP_PORT` | Syslog TCP port |
| `DASHBOARD_PORT` | Dashboard web port |
| `LICENSE_API_URL` | Plan-B cloud license endpoint |
| `CLIENT_SECRET` | Optional secret for AI key delivery |
| `DATA_PATH` | Optional external storage path |

## Useful Commands

```bash
# Stack status
docker compose --env-file config.env ps

# Live logs
docker compose --env-file config.env logs -f

# Restart dashboard
docker restart plan-b-dashboard

# Check log count
docker exec plan-b-opensearch curl -s localhost:9200/logs-*/_count

# Health check
./resilience/health-check.sh

# Stop everything
docker compose --env-file config.env down

# Start everything
docker compose --env-file config.env up -d
```

## Repository Layout

```text
siem-docker/
├── install-linux.sh              # Linux one-line bootstrap
├── deploy-ubuntu.sh              # Linux interactive deploy
├── install.ps1                   # Windows one-line bootstrap
├── deploy-windows.ps1            # Windows deploy
├── docker-compose.yml            # Linux compose stack
├── docker-compose.windows.yml    # Windows/WSL compose stack
├── config.env.template           # Installer config template
├── dashboard/                    # Next.js dashboard
├── syslog-receiver/              # Node.js syslog receiver
├── license-checker/              # Python license checker
├── resilience/                   # Health checks and auto-start helpers
├── UBUNTU-DEPLOY.md
└── WINDOWS-DEPLOY.md
```

## Support

Plan-B Systems - https://plan-b.systems
