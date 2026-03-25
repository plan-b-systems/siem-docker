# Plan-B Systems SIEM – Ubuntu/Linux Deployment Guide

Step-by-step instructions for deploying the SIEM stack on a fresh Ubuntu machine at a client site.

---

## Prerequisites

- Ubuntu 22.04 or 24.04 LTS (fresh install)
- Minimum 8 GB RAM, 200 GB free disk (or external drive for 730-day retention)
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

> The repo is public — no credentials required.

---

## Step 3 – (Optional) Set Up External Storage

For 730-day log retention, an external USB/SATA drive is recommended. Skip this step if the internal disk has enough space (200+ GB).

```bash
# 1. Identify the external drive
lsblk

# 2. Format the drive (ONE-TIME — THIS ERASES THE DRIVE)
sudo mkfs.ext4 /dev/sdb1

# 3. Create mount point and mount
sudo mkdir -p /mnt/siem-data
sudo mount /dev/sdb1 /mnt/siem-data

# 4. Make permanent (survives reboot)
echo '/dev/sdb1 /mnt/siem-data ext4 defaults,nofail 0 2' | sudo tee -a /etc/fstab

# 5. Verify
df -h /mnt/siem-data
```

> **Disk sizing guide:** ~10 devices → 200 GB, ~50 devices → 500 GB–1 TB, 200+ devices → 2–4 TB

---

## Step 4 – Configure for the Client

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
| `RETENTION_DAYS` | Days of logs to keep | `730` |
| `DATA_PATH` | External disk mount (leave empty for internal) | `/mnt/siem-data` |
| `OPENSEARCH_HEAP_SIZE` | Half of total RAM | `4g` for 8 GB host |

Leave everything else at defaults unless the client has specific port requirements.

Save and exit (`Ctrl+X` → `Y` → `Enter`).

---

## Step 5 – Run the Installer

```bash
sudo ./install.sh
```

The installer will automatically:
- Generate all secrets and passwords
- Create a self-signed TLS certificate
- Set up external storage directories (if `DATA_PATH` is set)
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
  Retention   : 730 days
  Data path   : /mnt/siem-data (or Docker named volumes)
```

---

## Step 6 – Verify the Stack

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

## Step 7 – Access the UI

Open a browser and go to:

```
https://<HOST_IP>:9000
```

Login: `admin` / `<GRAYLOG_ADMIN_PASSWORD>`

> **Certificate warning in browser?**
> The stack uses a self-signed certificate. To remove the warning,
> import `certs/ca.crt` into the browser or OS certificate store.

---

## Step 8 – Configure Log Sources

Point client devices to the SIEM IP on these ports:

| Source type | Protocol | Port | Config example |
|-------------|----------|------|----------------|
| Firewalls, switches, routers | Syslog UDP | 514 | `logging host <SIEM_IP>` |
| Linux servers | Syslog TCP | 1514 | `*.* @@<SIEM_IP>:1514` in rsyslog |
| Windows (NXLog/Winlogbeat) | GELF TCP | 12202 | Set output host/port |
| Applications | GELF UDP | 12201 | Set GELF output |

---

## Step 9 – Open Firewall (if UFW is enabled)

```bash
sudo ufw allow 9000/tcp    # Graylog Web UI
sudo ufw allow 514/udp     # Syslog UDP
sudo ufw allow 1514/tcp    # Syslog TCP
sudo ufw allow 12201/udp   # GELF UDP
sudo ufw allow 12202/tcp   # GELF TCP
```

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

If you need to change any settings (IP, hostname, retention, ports, storage path):

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
df -h /mnt/siem-data
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

**External drive not mounted after reboot**
```bash
# Check if it's mounted
df -h /mnt/siem-data

# If not, mount manually and check fstab entry
sudo mount /dev/sdb1 /mnt/siem-data
cat /etc/fstab | grep siem-data
```

**OpenSearch out of disk space**
```bash
# Check index sizes
docker exec plansb-opensearch curl -s localhost:9200/_cat/indices?v
# Check disk
df -h /mnt/siem-data
```

---

## Deployment Checklist

- [ ] Ubuntu 22.04/24.04 installed and SSH accessible
- [ ] Docker installed and working
- [ ] External drive mounted at `/mnt/siem-data` (if needed)
- [ ] Repo cloned to `/opt/plansb-siem`
- [ ] `config.env` filled in with client details (including `DATA_PATH` if using external storage)
- [ ] `sudo ./install.sh` completed successfully
- [ ] All 4 containers showing `(healthy)`
- [ ] Graylog UI accessible in browser
- [ ] Firewall ports open (if UFW enabled)
- [ ] At least one log source sending data
- [ ] `ca.crt` imported into client browser/OS
- [ ] Noted admin password in client handover doc
