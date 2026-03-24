# Plan-B Systems SIEM Stack

Production-ready, on-premises SIEM appliance based on **Graylog 7.2**, **OpenSearch 2.x**, and **MongoDB 7.0**, fully containerised with Docker Compose.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Docker Host (Ubuntu 22/24 LTS)       │
│                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │   Graylog    │  │ OpenSearch   │  │  MongoDB   │ │
│  │   7.2 (TLS)  │◄─│   2.18       │  │   7.0      │ │
│  │  :9000       │  │  :9200       │  │  :27017    │ │
│  └──────┬───────┘  └──────────────┘  └────────────┘ │
│         │                                             │
│  ┌──────┴───────────────────────────────────────┐   │
│  │          License Checker (Python)             │   │
│  │  Daily 12:00 → plan-b.systems API            │   │
│  │  Controls Graylog + OpenSearch via Docker SDK │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
         ▲           ▲
  Syslog UDP/TCP   GELF UDP/TCP
  (firewalled)     (firewalled)
```

---

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 100 GB | 1 TB (NVMe) |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Docker | 24.0+ | latest |
| Docker Compose | v2.20+ | latest |

---

## Quick Start

### 1. Install Docker and Compose plugin

```bash
curl -fsSL https://get.docker.com | sh
apt-get install -y docker-compose-plugin gettext-base openssl
```

### 2. Clone / copy the stack to the target machine

```bash
scp -r graylog-siem/ technician@192.168.1.100:/opt/plansb-siem
ssh technician@192.168.1.100
cd /opt/plansb-siem
```

### 3. Configure for this client

```bash
cp config.env.template config.env
nano config.env          # fill in all values
```

Key variables to set:

| Variable | Description | Example |
|----------|-------------|---------|
| `CLIENT_NAME` | Short site identifier | `acme-tlv` |
| `CLIENT_ID` | License ID from Plan-B portal | `SITE-0042` |
| `GRAYLOG_HOSTNAME` | FQDN or IP of this appliance | `siem.acme.local` |
| `GRAYLOG_ADMIN_PASSWORD` | Admin UI password | *(strong password)* |
| `TIMEZONE` | Local timezone | `Asia/Jerusalem` |
| `RETENTION_DAYS` | Days of logs to keep | `365` |
| `OPENSEARCH_HEAP_SIZE` | Half of host RAM | `4g` |

### 4. Install

```bash
sudo ./install.sh
```

The installer will:
- Validate prerequisites and config
- Auto-generate all secrets (appended to `config.env`)
- Generate a self-signed TLS certificate with a local CA
- Tune the OS (`vm.max_map_count`, ulimits)
- Pull and start all containers
- Configure Graylog inputs via REST API
- Register a systemd service for auto-start on boot

### 5. Access the UI

```
https://<GRAYLOG_HOSTNAME>:9000
Username: admin
Password: <value of GRAYLOG_ADMIN_PASSWORD in config.env>
```

Import `certs/ca.crt` into your browser / OS certificate store to trust the TLS certificate.

---

## Reconfiguration

After editing `config.env`:

```bash
sudo ./reconfigure.sh
```

This gracefully restarts only the affected services. No data is lost.

---

## Log Sources

Send logs to the appliance on these ports (configure in `config.env`):

| Protocol | Default Port | Use Case |
|----------|-------------|----------|
| Syslog UDP | 514 | Switches, routers, firewalls |
| Syslog TCP | 1514 | Servers, reliable delivery |
| GELF UDP | 12201 | Application logs |
| GELF TCP | 12202 | Application logs (reliable) |

Example syslog forwarding (rsyslog):
```
*.* @<SIEM_IP>:514
```

---

## License Checker

The `license-checker` container validates the Plan-B subscription daily at **12:00 local time**.

### State machine

```
NORMAL ──────────────── API active=true ──────────► NORMAL
  │                                                    ▲
  │ API unreachable                                    │ active=true
  ▼                                                    │
GRACE_PERIOD                                       EXPIRED
  │                                                    │
  │ grace elapsed / active=false                       │
  └────────────────────────────────────────────────►  │
                                                       │ check every 10 min
                                                       └──────────────────►
```

| State | Services | Check interval |
|-------|----------|----------------|
| `NORMAL` | All running | Daily at 12:00 |
| `GRACE_PERIOD` | All running | Daily at 12:00 |
| `EXPIRED` | Graylog + OpenSearch stopped | Every 10 minutes |

> MongoDB is **never** stopped so that existing log data is preserved.

License check logs: `docker exec plansb-license-checker cat /data/license_checker.log`

State file: `docker exec plansb-license-checker cat /data/license_state.json`

---

## Useful Commands

```bash
# Stack status
docker compose --env-file config.env ps

# Live logs (all services)
docker compose --env-file config.env logs -f

# Graylog logs only
docker compose --env-file config.env logs -f graylog

# License checker logs
docker compose --env-file config.env logs -f license-checker

# Stop the stack
docker compose --env-file config.env down

# Start the stack
docker compose --env-file config.env up -d

# Rotate TLS certificate
rm certs/graylog.{crt,key,csr}
sudo ./reconfigure.sh
```

---

## Security & Compliance

### Israeli Privacy Protection Law – Amendment 13

| Requirement | Implementation |
|-------------|----------------|
| Access control & authentication | Graylog RBAC; admin password SHA-256 hashed |
| Audit trail | Graylog built-in audit log (`audit_log_enabled = true`) |
| Log integrity | Daily index rotation + read-only enforcement after rotation; OpenSearch immutable shards |
| Retention policy | Configurable `RETENTION_DAYS`; automatic deletion of aged indices |
| Encryption in transit | TLS 1.2/1.3 on Graylog web UI (self-signed CA) |
| Data localisation | All data stored on-premises; no cloud sync |
| Outbound traffic | Only the license check API call (`LICENSE_API_URL`) |

### Hardening checklist (post-install)

- [ ] Change `GRAYLOG_ADMIN_PASSWORD` from default after first login
- [ ] Create role-based users in Graylog; disable direct admin account for daily use
- [ ] Restrict firewall: only allow Syslog/GELF ports from known source IPs
- [ ] Import `certs/ca.crt` into endpoint certificate stores
- [ ] Schedule periodic backup of Docker volumes (MongoDB + OpenSearch data)
- [ ] Enable OS disk encryption (`cryptsetup`) for GDPR/Amendment 13 data-at-rest

---

## Backup and Restore

### Backup volumes

```bash
# Stop services gracefully
docker compose --env-file config.env stop graylog opensearch

# Dump MongoDB
docker exec plansb-mongodb mongodump --archive | gzip > backup-mongodb-$(date +%F).gz

# Snapshot OpenSearch data volume
docker run --rm -v plansb_opensearch-data:/data -v $(pwd):/backup \
    busybox tar czf /backup/backup-opensearch-$(date +%F).tar.gz /data

# Restart
docker compose --env-file config.env start opensearch graylog
```

### Restore MongoDB

```bash
gzip -dc backup-mongodb-YYYY-MM-DD.gz | docker exec -i plansb-mongodb mongorestore --archive
```

---

## Troubleshooting

**Graylog fails to start (journal error)**
```bash
docker compose --env-file config.env logs graylog | grep -i error
# Common fix: delete corrupt journal
docker compose --env-file config.env stop graylog
docker volume rm plansb_graylog-journal
docker compose --env-file config.env up -d graylog
```

**OpenSearch out of disk space**
```bash
# Check disk usage
docker exec plansb-opensearch curl -s localhost:9200/_cat/indices?v
# Manually delete oldest index
docker exec plansb-opensearch curl -s -X DELETE localhost:9200/graylog_0
```

**License checker shows EXPIRED but license is renewed**
```bash
# Force immediate re-check
docker restart plansb-license-checker
```

**TLS certificate expired**
```bash
rm certs/graylog.{crt,key,csr}
sudo ./reconfigure.sh
```

---

## File Structure

```
graylog-siem/
├── docker-compose.yml          # Service definitions
├── config.env.template         # Configuration template
├── config.env                  # Active config (generated by install.sh)
├── install.sh                  # First-time installer
├── reconfigure.sh              # Apply config changes
├── license-checker/
│   ├── Dockerfile
│   ├── checker.py              # License state machine
│   └── requirements.txt
├── graylog/
│   └── graylog.conf.template   # Graylog config template
├── certs/
│   ├── generate-certs.sh       # TLS cert generator
│   ├── ca.crt                  # Local CA (import into browsers)
│   ├── graylog.crt             # Server certificate
│   └── graylog.key             # Server private key (chmod 600)
└── README.md
```

---

## Support

Plan-B Systems — internal use only.
