# Plan-B Systems SIEM v2.1 — Ubuntu/Linux Deployment Guide

## Quick Install (One-Liner)

SSH into the Ubuntu machine as root and run:

```bash
curl -fsSL https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install-linux.sh | sudo bash
```

The script will:
1. Install git and Docker (if not present)
2. Clone the siem-docker repo from `main` to `/opt/plan-b-siem`
3. Prompt for client details (name, ID, LAN IP, password, timezone, retention)
4. Auto-detect RAM and set OpenSearch heap size
5. Deploy 4 containers: OpenSearch, Syslog Receiver, Dashboard, License Checker
6. Configure retention policies and auto-start on boot

**Total time: ~5 minutes** (mostly Docker image pulls).

After install, access the dashboard at `http://<LAN_IP>:3000`.

---

## Prerequisites

- Ubuntu 22.04 or 24.04 LTS (fresh install recommended)
- Minimum 4 GB RAM, 40 GB free disk
- Recommended: 8 GB RAM, 200 GB+ disk (for 730-day retention)
- Internet access (for pulling Docker images)
- A Client ID from the Plan-B portal (https://siemsys.plan-b.systems)

---

## What Gets Deployed

SIEM v2.1 is a 4-container Docker stack:

| Container | Purpose | Ports |
|-----------|---------|-------|
| `plan-b-opensearch` | Log storage and search engine | Internal only |
| `plan-b-syslog` | Receives syslog from client devices | UDP 514, TCP 1514 |
| `plan-b-dashboard` | Web UI — log viewer, AI chat, threats | HTTP 3000 |
| `plan-b-license-checker` | License validation + AI key delivery | Internal only |

---

## Manual Installation (Step by Step)

### Step 1 — Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable docker && sudo systemctl start docker
```

### Step 2 — Clone the Repository

```bash
sudo git clone -b main https://github.com/plan-b-systems/siem-docker.git /opt/plan-b-siem
cd /opt/plan-b-siem
```

### Step 3 — Run the Deployment Script

```bash
sudo ./deploy-ubuntu.sh
```

The script will interactively ask for:
- **Client name** — short name, no spaces (e.g., `acme-tlv`)
- **Client ID** — from the Plan-B portal
- **Machine LAN IP** — auto-detected, confirm or change
- **Dashboard admin password** — minimum 8 characters
- **Timezone** — default: `Asia/Jerusalem`
- **Log retention days** — default: 730 (2 years)
- **External data path** — optional, for dedicated storage drive

### Step 4 — Access the Dashboard

Open a browser and go to:

```
http://<LAN_IP>:3000
```

Login with the admin password you set during deployment.

---

## Configure Log Sources

Point client devices to the SIEM server on these ports:

| Source Type | Protocol | Port |
|-------------|----------|------|
| Firewalls (FortiGate, Palo Alto, etc.) | Syslog UDP | 514 |
| Linux servers (rsyslog) | Syslog TCP | 1514 |
| Windows (NXlog) | Syslog TCP | 1514 |

Example rsyslog config:
```
*.* @@<SIEM_IP>:1514
```

Example FortiGate:
```
config log syslogd setting
    set server "<SIEM_IP>"
    set port 514
end
```

---

## Firewall (if UFW is enabled)

```bash
sudo ufw allow 3000/tcp    # Dashboard
sudo ufw allow 514/udp     # Syslog UDP
sudo ufw allow 1514/tcp    # Syslog TCP
```

---

## After Reboot

The stack starts automatically via systemd. Nothing to do.

Manual start if needed:
```bash
cd /opt/plan-b-siem
docker compose up -d
```

---

## Useful Commands

```bash
# Stack status
docker compose -f /opt/plan-b-siem/docker-compose.yml ps

# Live logs
docker compose -f /opt/plan-b-siem/docker-compose.yml logs -f

# Stop the stack
docker compose -f /opt/plan-b-siem/docker-compose.yml down

# Start the stack
docker compose -f /opt/plan-b-siem/docker-compose.yml up -d

# Check OpenSearch indices
docker exec plan-b-opensearch curl -s http://localhost:9200/_cat/indices?v

# Check disk usage
df -h
```

---

## Troubleshooting

**Dashboard not loading**
```bash
docker ps                         # Check all containers running
docker logs plan-b-dashboard      # Check for errors
```

**Logs not appearing**
- Verify source device is sending to the correct IP and port
- Check: `docker logs plan-b-syslog` for connection activity
- Verify firewall allows UDP 514 / TCP 1514

**OpenSearch won't start**
```bash
# Check logs
docker logs plan-b-opensearch

# Most common: vm.max_map_count too low
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
docker restart plan-b-opensearch
```

**License checker shows EXPIRED**
```bash
docker restart plan-b-license-checker
```

---

## Deployment Checklist

- [ ] Ubuntu 22.04/24.04 installed and SSH accessible
- [ ] Docker installed and running
- [ ] Client ID obtained from Plan-B portal
- [ ] `curl ... | sudo bash` or `./deploy-ubuntu.sh` completed
- [ ] All 4 containers running (`docker ps`)
- [ ] Dashboard accessible at `http://<IP>:3000`
- [ ] Firewall ports open (if UFW enabled)
- [ ] At least one log source sending data
- [ ] Admin password documented
