# Plan-B Systems SIEM – Windows Deployment Guide

## Quick Install (Recommended)

Open **PowerShell as Administrator** and run:

```powershell
irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install.ps1 | iex
```

The script will:
1. Install WSL2 + Ubuntu 24.04 + Docker (if not present)
2. Prompt for client details (name, ID, LAN IP, password, timezone, retention, external data path)
3. Auto-convert Windows data paths to WSL paths (e.g. `D:\SIEMData` → `/mnt/d/SIEMData`)
4. Clone the repo, generate TLS certs, start all containers
5. Configure Graylog inputs, daily index rotation, retention
6. Set up Windows Firewall rules and port forwarding
7. Register auto-start scheduled task
8. Copy CA cert to Desktop for browser import

**Total time: ~10-15 minutes** (mostly Docker image pulls).

After install, access Graylog at `https://<LAN_IP>:9000` with the admin password you chose.

---

## Prerequisites

- Windows 10 (21H2+) or Windows 11 (or Windows Server 2019+)
- Minimum 8 GB RAM, 200 GB free disk (or external disk for 2-year retention)
- Administrator access
- Internet access
- Virtualization enabled in BIOS (check: Task Manager → Performance → CPU → "Virtualization: Enabled")

---

## Step 1 – Enable WSL2

Open **PowerShell as Administrator** and run:

```powershell
wsl --install
wsl --set-default-version 2
```

Restart the machine when prompted.

After reboot, open PowerShell as Administrator again and install Ubuntu:

```powershell
wsl --install -d Ubuntu-24.04
```

When it finishes, Ubuntu will open and ask you to create a Linux username and password. Set these — you'll need them.

---

## Step 2 – Configure WSL2 Networking (Mirrored Mode)

By default, Docker ports in WSL2 are **not** accessible via the machine's LAN IP. This must be fixed so client devices can send logs to the SIEM.

Create the file `C:\Users\<YourUsername>\.wslconfig` with this content:

```ini
[wsl2]
networkingMode=mirrored
```

You can do this in PowerShell:
```powershell
$content = "[wsl2]`nnetworkingMode=mirrored"
Set-Content -Path "$env:USERPROFILE\.wslconfig" -Value $content
```

Then restart WSL2:
```powershell
wsl --shutdown
```

Reopen the Ubuntu terminal after this.

---

## Step 3 – Install Docker in WSL2

Open **Ubuntu terminal** (Start → Ubuntu 24.04) and run:

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Add your user to the docker group
sudo usermod -aG docker $USER

# Install required tools
sudo apt-get install -y git gettext-base openssl

# Log out and back in for group changes
exit
```

Reopen the Ubuntu terminal, then verify:
```bash
docker version
docker compose version
```

---

## Step 4 – Clone the Repository

```bash
sudo git clone https://github.com/plan-b-systems/siem-docker.git /opt/plansb-siem
sudo chown -R $USER:$USER /opt/plansb-siem
cd /opt/plansb-siem
```

> The repo is public — no credentials required.

---

## Step 5 – (Optional) Set Up External Storage

For 730-day log retention, you may want to use a dedicated drive. On Windows/WSL2 you have two options:

### Option A: Use a secondary internal drive (e.g., D:\)

Windows drives are automatically accessible in WSL2 at `/mnt/<drive-letter>`:

```bash
# Create data directory on D: drive
sudo mkdir -p /mnt/d/siem-data
```

Set in `config.env`:
```
DATA_PATH=/mnt/d/siem-data
```

### Option B: Use an external USB drive

1. Connect the USB drive and note the drive letter Windows assigns (e.g., E:)
2. In the Ubuntu terminal:
```bash
sudo mkdir -p /mnt/e/siem-data
```
3. Set in `config.env`:
```
DATA_PATH=/mnt/e/siem-data
```

> **Important:** If using an external USB drive, make sure it's always connected before the SIEM starts. Windows auto-mounts USB drives into WSL2.

> **Disk sizing guide:** ~10 devices → 200 GB, ~50 devices → 500 GB–1 TB, 200+ devices → 2–4 TB

---

## Step 6 – Configure for the Client

```bash
cp config.env.template config.env
nano config.env
```

Fill in these values:

| Variable | Description | Example |
|----------|-------------|---------|
| `CLIENT_NAME` | Short site name (no spaces) | `acme-tlv` |
| `CLIENT_ID` | License ID from Plan-B portal | `SITE-0042` |
| `GRAYLOG_HOSTNAME` | Windows machine's LAN IP | `192.168.1.50` |
| `HOST_IP` | Same IP as above | `192.168.1.50` |
| `GRAYLOG_ADMIN_PASSWORD` | Strong admin password | `S3cur3P@ss!` |
| `TIMEZONE` | Local timezone | `Asia/Jerusalem` |
| `RETENTION_DAYS` | Days of logs to keep | `730` |
| `DATA_PATH` | External/secondary drive (optional) | `/mnt/d/siem-data` |
| `OPENSEARCH_HEAP_SIZE` | Quarter of total RAM on Windows | `2g` for 8 GB host |

> **Note on heap size:** WSL2 shares RAM with Windows itself.
> Use **1/4 of total RAM** (not 1/2 as on Linux) to avoid memory pressure.
> Example: 16 GB machine → use `4g`

Save and exit: `Ctrl+X` → `Y` → `Enter`

---

## Step 7 – Start Docker and Run the Installer

Start the Docker daemon:
```bash
sudo dockerd &>/var/log/dockerd.log &
sleep 3
```

Run the installer:
```bash
sudo ./install.sh
```

The installer will:
- Generate TLS certificates
- Pull and build all Docker images
- Start the SIEM stack (MongoDB, OpenSearch, Graylog, License Checker)
- Configure Graylog inputs and retention
- **Install auto-recovery** (WSL boot script, systemd service, health checks)

When complete you will see:

```
╔══════════════════════════════════════════════════════╗
║              Installation complete!                  ║
╚══════════════════════════════════════════════════════╝
  Graylog UI  : https://<HOST_IP>:9000
  Retention   : 730 days
```

---

## Step 8 – Register Auto-Start on Windows Boot

The installer sets up auto-recovery inside WSL, but Windows needs a scheduled task to start WSL on boot and configure port forwarding.

Open **PowerShell as Administrator** and run:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\PlanB-SIEM\Register-ScheduledTask.ps1"
```

This registers a task that runs at every Windows startup and login:
1. Starts WSL and the Docker daemon
2. Waits for all SIEM containers to be healthy
3. Sets up port forwarding (so the LAN IP works)
4. Configures Windows Firewall rules

---

## Step 9 – Restart WSL to Activate

The installer configured `/etc/wsl.conf` for auto-start. Activate it:

From **PowerShell**:
```powershell
wsl --shutdown
```

Then reopen the Ubuntu terminal. The SIEM stack should start automatically within ~2 minutes.

---

## Step 10 – Verify and Access the UI

Back in the Ubuntu terminal:

```bash
# Quick health check
/opt/plansb-siem/resilience/health-check.sh

# Or check containers directly
docker compose --env-file config.env ps
```

All 4 containers should show `(healthy)`.

Open a browser on the Windows machine and go to:

```
https://<HOST_IP>:9000
```

Login: `admin` / `<GRAYLOG_ADMIN_PASSWORD>`

---

## Trusting the Certificate (Remove Browser Warning)

The stack generates a self-signed certificate. To remove the browser warning, import the CA into Windows:

1. Copy `certs/ca.crt` from the Ubuntu terminal to Windows:
   ```bash
   cp /opt/plansb-siem/certs/ca.crt /mnt/c/Users/<YourWindowsUsername>/Desktop/plansb-ca.crt
   ```
2. On Windows, double-click `plansb-ca.crt` on the Desktop
3. Click **Install Certificate** → **Local Machine** → **Next**
4. Select **"Place all certificates in the following store"** → Browse → **Trusted Root Certification Authorities**
5. Click **Next** → **Finish**
6. Restart the browser

---

## How Auto-Recovery Works

After installation, the SIEM stack recovers automatically from any shutdown (graceful or power loss):

```
Windows boots
  → Scheduled Task runs PlanB-SIEM-Startup.ps1
    → Starts WSL
    → WSL boots with systemd (via wsl.conf)
      → Docker daemon auto-starts
      → Stale processes cleaned (prevents port conflicts)
      → docker compose up -d
    → PowerShell waits for Graylog health
    → Sets up port forwarding (netsh portproxy)
    → Ensures firewall rules exist
```

Additionally, a cron job runs `health-check.sh --fix` every 5 minutes to restart any container that crashes.

**Logs:**
- WSL startup: `/var/log/plansb-siem-startup.log`
- Windows startup: `C:\PlanB-SIEM\startup.log`
- Health checks: `/var/log/plansb-siem-health.log`

---

## Reconfiguring After Install

To change any settings:

```bash
cd /opt/plansb-siem
nano config.env          # make changes
sudo ./reconfigure.sh    # applies changes, restarts affected containers
```

---

## Useful Commands (run in Ubuntu terminal)

```bash
# Stack status
docker compose --env-file config.env ps

# Full health check
/opt/plansb-siem/resilience/health-check.sh

# Live logs
docker compose --env-file config.env logs -f

# Stop the stack
docker compose --env-file config.env down

# Start the stack
docker compose --env-file config.env up -d

# License status
docker exec plansb-license-checker cat /data/license_state.json

# Disk usage
docker exec plansb-opensearch curl -s localhost:9200/_cat/indices?v
```

---

## Troubleshooting

**"This site can't be reached" from browser**

Port forwarding may not be active. From PowerShell as Administrator:
```powershell
# Check current port forwarding rules
netsh interface portproxy show all

# If empty, run the startup script manually:
C:\PlanB-SIEM\PlanB-SIEM-Startup.ps1
```

**Docker daemon not starting in WSL**

```bash
# Check if Docker is running
docker info

# If not, start it manually
sudo dockerd &>/var/log/dockerd.log &

# Or from PowerShell:
wsl -u root dockerd
```

**Containers not starting after reboot**

```bash
# Check container status
docker ps -a

# Run health check with auto-fix
/opt/plansb-siem/resilience/health-check.sh --fix

# Or start manually
cd /opt/plansb-siem && docker compose --env-file config.env up -d
```

**Port conflict (address already in use)**

This happens when stale processes hold ports after a crash:
```bash
# Run the cleanup script
sudo /opt/plansb-siem/resilience/clean-stale-processes.sh

# Then restart
docker compose --env-file config.env up -d
```

**Not enough memory errors**

Limit WSL2's RAM usage. Create/edit `C:\Users\<Username>\.wslconfig`:
```ini
[wsl2]
networkingMode=mirrored
memory=6GB
```
Then reduce `OPENSEARCH_HEAP_SIZE` in `config.env` and run `./reconfigure.sh`.

**Certificate errors in Graylog search** (`SyntaxError: Unexpected token '(', "(certifica"...`)

The CA cert is not in Java's truststore. Run in Ubuntu terminal:
```bash
keytool -importcert -keystore /opt/plansb-siem/graylog/cacerts -storepass changeit -alias plansb-ca -file /opt/plansb-siem/certs/ca.crt -noprompt
cd /opt/plansb-siem && docker compose --env-file config.env restart graylog
```

**External USB drive not accessible in WSL2**

Make sure the drive is connected and assigned a letter in Windows. Then in Ubuntu:
```bash
ls /mnt/e/    # replace 'e' with your drive letter
```
If it doesn't show, restart WSL2: `wsl --shutdown` (from PowerShell), then reopen Ubuntu.

---

## Security Notes

The stack includes these security measures out of the box:

- **MongoDB authentication**: auto-generated password, stored in `config.env`
- **Network isolation**: MongoDB and OpenSearch run on an internal Docker network with no external port exposure
- **TLS**: Graylog web UI uses self-signed TLS (HTTPS only)
- **Index retention**: daily rotation, configurable max days (default 730 = 2 years)
- **License checker**: reports health to the Plan-B portal hourly
- **Web UI access**: configurable via `BIND_ADDRESS` in `config.env` to restrict to LAN IP

---

## Deployment Checklist

- [ ] Virtualization enabled in BIOS
- [ ] WSL2 installed and Ubuntu 24.04 running
- [ ] `.wslconfig` created with `networkingMode=mirrored`
- [ ] Docker installed natively in WSL2 (via get.docker.com)
- [ ] External/secondary drive set up (if needed for storage)
- [ ] Repo cloned to `/opt/plansb-siem`
- [ ] `config.env` filled in with client details (including `DATA_PATH` if using external storage)
- [ ] `sudo ./install.sh` completed successfully
- [ ] All 4 containers showing `(healthy)`
- [ ] Scheduled task registered (`C:\PlanB-SIEM\Register-ScheduledTask.ps1`)
- [ ] WSL restarted (`wsl --shutdown`) to activate auto-start
- [ ] Graylog UI accessible in browser at `https://<IP>:9000`
- [ ] `plansb-ca.crt` imported into Windows certificate store
- [ ] Health check passing: `/opt/plansb-siem/resilience/health-check.sh`
- [ ] At least one log source sending data
- [ ] Admin password noted in client handover doc
