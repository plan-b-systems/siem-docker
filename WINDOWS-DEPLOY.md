# Plan-B Systems SIEM v2.1 — Windows Deployment Guide

## Quick Install (One-Liner)

Open **PowerShell as Administrator** and run:

```powershell
irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install.ps1 | iex
```

The script will:
1. Download siem-docker v2.1 from GitHub
2. Install WSL2 + Docker (if not present)
3. Prompt for client details (name, ID, LAN IP, password, timezone, retention)
4. Deploy 4 containers: OpenSearch, Syslog Receiver, Dashboard, License Checker
5. Configure Windows Firewall and port forwarding
6. Set up auto-start on boot

**Total time: ~10-15 minutes** (mostly Docker image pulls).

After install, access the dashboard at `http://<LAN_IP>:3000`.

---

## Prerequisites

- Windows 10 (21H2+) or Windows 11 or Windows Server 2019+
- Minimum 8 GB RAM, 200 GB free disk
- Administrator access
- Internet access
- Virtualization enabled in BIOS (check: Task Manager → Performance → CPU → "Virtualization: Enabled")
- A Client ID from the Plan-B portal (https://siemsys.plan-b.systems)

---

## What Gets Deployed

SIEM v2.1 runs inside WSL2 (Windows Subsystem for Linux) as a 4-container Docker stack:

| Container | Purpose | Ports |
|-----------|---------|-------|
| `plan-b-opensearch` | Log storage and search engine | Internal only |
| `plan-b-syslog` | Receives syslog from client devices | UDP 514, TCP 1514 |
| `plan-b-dashboard` | Web UI — log viewer, AI chat, threats | HTTP 3000 |
| `plan-b-license-checker` | License validation + AI key delivery | Internal only |

---

## Manual Installation (Step by Step)

### Step 1 — Enable WSL2

Open **PowerShell as Administrator**:

```powershell
wsl --install
wsl --set-default-version 2
```

Restart when prompted. After reboot:

```powershell
wsl --install -d Ubuntu-24.04
```

Create a Linux username and password when prompted.

### Step 2 — Configure WSL2 Networking

Create `C:\Users\<YourUsername>\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
```

In PowerShell:
```powershell
$content = "[wsl2]`nnetworkingMode=mirrored"
Set-Content -Path "$env:USERPROFILE\.wslconfig" -Value $content
wsl --shutdown
```

### Step 3 — Install Docker in WSL2

Open **Ubuntu terminal** (Start → Ubuntu 24.04):

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
exit
```

Reopen Ubuntu terminal and verify:
```bash
docker version
```

### Step 4 — Deploy the SIEM

```bash
curl -fsSL https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install-linux.sh | sudo bash
```

Follow the prompts for client details.

### Step 5 — Access the Dashboard

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

---

## Windows Firewall

If log sources can't reach the SIEM, open ports in Windows Firewall:

```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "SIEM Dashboard" -Direction Inbound -Protocol TCP -LocalPort 3000 -Action Allow
New-NetFirewallRule -DisplayName "SIEM Syslog UDP" -Direction Inbound -Protocol UDP -LocalPort 514 -Action Allow
New-NetFirewallRule -DisplayName "SIEM Syslog TCP" -Direction Inbound -Protocol TCP -LocalPort 1514 -Action Allow
```

---

## After Reboot

If WSL2 networking is set to mirrored mode, the SIEM auto-starts when WSL boots. To manually start:

1. Open Ubuntu terminal
2. Run:
```bash
cd /opt/plan-b-siem
docker compose up -d
```

---

## Useful Commands (run in Ubuntu terminal)

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
```

---

## Troubleshooting

**"This site can't be reached" from browser**
- Check WSL2 networking mode is `mirrored` (see Step 2)
- Check containers are running: open Ubuntu terminal → `docker ps`
- Check Windows Firewall rules

**Docker not starting in WSL**
```bash
sudo dockerd &>/var/log/dockerd.log &
```

**Not enough memory**
Edit `C:\Users\<Username>\.wslconfig`:
```ini
[wsl2]
networkingMode=mirrored
memory=6GB
```
Then `wsl --shutdown` and reopen Ubuntu.

**OpenSearch won't start**
```bash
sudo sysctl -w vm.max_map_count=262144
docker restart plan-b-opensearch
```

---

## Deployment Checklist

- [ ] Virtualization enabled in BIOS
- [ ] WSL2 installed with Ubuntu 24.04
- [ ] `.wslconfig` with `networkingMode=mirrored`
- [ ] Docker installed in WSL2
- [ ] Client ID obtained from Plan-B portal
- [ ] Deployment script completed
- [ ] All 4 containers running (`docker ps`)
- [ ] Dashboard accessible at `http://<IP>:3000`
- [ ] Windows Firewall ports open
- [ ] At least one log source sending data
- [ ] Admin password documented
