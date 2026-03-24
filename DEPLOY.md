# Plan-B Systems SIEM – Deployment Guide

Step-by-step instructions for deploying the SIEM stack on a fresh Ubuntu machine at a client site.

---

## Prerequisites

- Ubuntu 22.04 or 24.04 LTS (fresh install)
- Minimum 8 GB RAM, 100 GB free disk
- Internet access (for pulling Docker images)
- You know the client's: IP address, hostname, timezone, and have a license ID ready from the Plan-B portal

---

## Step 1 – Install Docker

SSH into the Ubuntu machine and run:

```bash
curl -fsSL https://get.docker.com | sh
apt-get install -y docker-compose-plugin gettext-base openssl git
usermod -aG docker $USER
newgrp docker
```

Verify:
```bash
docker version
docker compose version
```

---

## Step 2 – Clone the Repository

```bash
git clone https://github.com/plan-b-systems/siem-docker.git /opt/plansb-siem
cd /opt/plansb-siem
```

> You will be prompted for your GitHub credentials.
> Use a **Personal Access Token** (not your password) — generate one at:
> GitHub → Settings → Developer settings → Personal access tokens → Classic → `repo` scope.

---

## Step 3 – Configure for the Client

```bash
cp config.env.template config.env
nano config.env
```

Fill in these values:

| Variable | Description | Example |
|----------|-------------|---------|
| `CLIENT_NAME` | Short site name (no spaces) | `acme-tlv` |
| `CLIENT_ID` | License ID from Plan-B portal | `SITE-0042` |
| `GRAYLOG_HOSTNAME` | IP or FQDN of this machine | `192.168.1.50` |
| `HOST_IP` | Same IP as above | `192.168.1.50` |
| `GRAYLOG_ADMIN_PASSWORD` | Strong admin password | `S3cur3P@ss!` |
| `TIMEZONE` | Local timezone | `Asia/Jerusalem` |
| `RETENTION_DAYS` | Days of logs to keep | `365` |
| `OPENSEARCH_HEAP_SIZE` | Half of total RAM | `4g` for 8 GB host |

Leave everything else at defaults unless the client has specific port requirements.

Save and exit (`Ctrl+X` → `Y` → `Enter`).

---

## Step 4 – Run the Installer

```bash
sudo ./install.sh
```

The installer will automatically:
- Generate all secrets and passwords
- Create a self-signed TLS certificate
- Tune the OS for OpenSearch
- Pull all Docker images
- Start all 4 containers
- Configure Graylog inputs (Syslog + GELF)
- Register a systemd service for auto-start on boot

This takes **3–5 minutes** on first run (image download time varies).

When complete you will see:

```
╔══════════════════════════════════════════════════════╗
║              Installation complete!                  ║
╚══════════════════════════════════════════════════════╝
  Graylog UI  : https://<HOSTNAME>:9000
  Username    : admin
  Password    : <your password>
```

---

## Step 5 – Verify the Stack

```bash
docker compose --env-file config.env ps
```

All 4 containers should show `(healthy)`:

```
plansb-graylog           Up (healthy)
plansb-opensearch        Up (healthy)
plansb-mongodb           Up (healthy)
plansb-license-checker   Up (healthy)
```

---

## Step 6 – Access the UI

Open a browser and go to:

```
https://<HOST_IP>:9000
```

Login: `admin` / `<GRAYLOG_ADMIN_PASSWORD>`

> **Certificate warning in browser?**
> The stack uses a self-signed certificate. To remove the warning,
> import `certs/ca.crt` into Windows:
> Run → `certmgr.msc` → Trusted Root Certification Authorities → Import → select `ca.crt`

---

## Step 7 – Configure Log Sources

Point client devices to the SIEM IP on these ports:

| Source type | Protocol | Port | Config example |
|-------------|----------|------|----------------|
| Firewalls, switches, routers | Syslog UDP | 514 | `logging host <SIEM_IP>` |
| Linux servers | Syslog TCP | 1514 | `*.* @@<SIEM_IP>:1514` in rsyslog |
| Windows (NXLog/Winlogbeat) | GELF TCP | 12202 | Set output host/port |
| Applications | GELF UDP | 12201 | Set GELF output |

---

## If the Machine Reboots

The stack starts automatically via systemd. Nothing to do.

To manually start if needed:
```bash
cd /opt/plansb-siem
docker compose --env-file config.env up -d
```

---

## Reconfiguring After Install

If you need to change any settings (IP, hostname, retention, ports):

```bash
cd /opt/plansb-siem
nano config.env          # make your changes
sudo ./reconfigure.sh    # applies changes and restarts affected services
```

---

## Useful Commands

```bash
# Live logs
docker compose --env-file config.env logs -f

# Check license status
docker exec plansb-license-checker cat /data/license_state.json

# Stop the stack
docker compose --env-file config.env down

# Start the stack
docker compose --env-file config.env up -d

# Check disk usage
docker exec plansb-opensearch curl -s localhost:9200/_cat/indices?v
```

---

## Troubleshooting

**"This site can't be reached" from browser**
- Confirm the machine's IP matches `HOST_IP` in config.env
- Check firewall: `ufw allow 9000/tcp`
- Check containers are running: `docker compose --env-file config.env ps`

**Graylog starts then crashes**
```bash
docker compose --env-file config.env logs graylog | grep ERROR
```
Most common cause: not enough RAM. Reduce `OPENSEARCH_HEAP_SIZE` in config.env and rerun `./reconfigure.sh`.

**Search errors / certificate errors in Graylog UI**
The JVM truststore may need rebuilding after a cert change. Run:
```bash
sudo ./reconfigure.sh
```

**License checker shows EXPIRED but license was renewed**
```bash
docker restart plansb-license-checker
```

---

## Deployment Checklist

- [ ] Ubuntu 22.04/24.04 installed and SSH accessible
- [ ] Docker installed and working
- [ ] Repo cloned to `/opt/plansb-siem`
- [ ] `config.env` filled in with client details
- [ ] `sudo ./install.sh` completed successfully
- [ ] All 4 containers showing `(healthy)`
- [ ] Graylog UI accessible in browser
- [ ] At least one log source sending data
- [ ] `ca.crt` imported into client browser/OS
- [ ] Noted admin password in client handover doc
