# Plan-B Systems SIEM – Windows Deployment Guide

Step-by-step instructions for deploying the SIEM stack on a Windows 10/11 machine using Docker Desktop with WSL2.

---

## Prerequisites

- Windows 10 (21H2+) or Windows 11
- Minimum 8 GB RAM, 100 GB free disk
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

## Step 2 – Install Docker Desktop

1. Download Docker Desktop from: **https://www.docker.com/products/docker-desktop/**
2. Run the installer — accept defaults, ensure **"Use WSL2 instead of Hyper-V"** is checked
3. Restart when prompted
4. Open Docker Desktop, accept the license, wait for it to show **"Engine running"**

Verify in PowerShell:
```powershell
docker version
docker compose version
```

---

## Step 3 – Configure WSL2 Networking (Mirrored Mode)

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

## Step 4 – Open Ubuntu Terminal

Click **Start → Ubuntu 24.04** (or search for it).

All remaining steps run inside this Ubuntu terminal.

---

## Step 5 – Install Required Tools

Inside the Ubuntu terminal:

```bash
sudo apt-get update && sudo apt-get install -y git gettext-base openssl
```

---

## Step 6 – Clone the Repository

```bash
git clone https://github.com/plan-b-systems/siem-docker.git /opt/plansb-siem
cd /opt/plansb-siem
```

> Use a **Personal Access Token** when prompted for a password.
> Generate one at: GitHub → Settings → Developer settings → Personal access tokens → Classic → `repo` scope.

---

## Step 7 – Configure for the Client

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
| `RETENTION_DAYS` | Days of logs to keep | `365` |
| `OPENSEARCH_HEAP_SIZE` | Quarter of total RAM on Windows | `2g` for 8 GB host |

> **Note on heap size:** Docker Desktop on Windows shares RAM with Windows itself.
> Use **¼ of total RAM** (not ½ as on Linux) to avoid memory pressure.
> Example: 16 GB machine → use `4g`

Save and exit: `Ctrl+X` → `Y` → `Enter`

---

## Step 8 – Run the Installer

```bash
sudo ./install.sh
```

When complete you will see:

```
╔══════════════════════════════════════════════════════╗
║              Installation complete!                  ║
╚══════════════════════════════════════════════════════╝
  Graylog UI  : https://<HOST_IP>:9000
```

---

## Step 9 – Open Windows Firewall Ports

Open **PowerShell as Administrator** on Windows and run:

```powershell
$ports = @(9000, 1514, 12202)
$udpPorts = @(514, 12201)

foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName "PlanB-SIEM-TCP-$port" `
        -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any
}
foreach ($port in $udpPorts) {
    New-NetFirewallRule -DisplayName "PlanB-SIEM-UDP-$port" `
        -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow -Profile Any
}
Write-Host "Firewall rules added."
```

---

## Step 10 – Verify and Access the UI

Back in the Ubuntu terminal:

```bash
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

## Auto-Start on Windows Boot

The SIEM stack needs to start automatically when Windows boots. Create a scheduled task to handle this.

Open **PowerShell as Administrator**:

```powershell
$action = New-ScheduledTaskAction `
    -Execute "wsl.exe" `
    -Argument "-d Ubuntu-24.04 -- bash -c 'cd /opt/plansb-siem && docker compose --env-file config.env up -d'"

$trigger = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
    -TaskName "PlanB-SIEM-Autostart" `
    -Action $action `
    -Trigger $trigger `
    -RunLevel Highest `
    -User "SYSTEM" `
    -Settings $settings `
    -Force

Write-Host "Auto-start task registered."
```

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

WSL2 mirrored networking may not have taken effect. Run in PowerShell as Administrator:
```powershell
# Get WSL2 internal IP
$wsl2ip = (wsl hostname -I).Trim().Split()[0]

# Add port proxy
netsh interface portproxy add v4tov4 listenport=9000 listenaddress=0.0.0.0 connectport=9000 connectaddress=$wsl2ip
netsh interface portproxy add v4tov4 listenport=1514 listenaddress=0.0.0.0 connectport=1514 connectaddress=$wsl2ip
netsh interface portproxy add v4tov4 listenport=12202 listenaddress=0.0.0.0 connectport=12202 connectaddress=$wsl2ip
```

**Docker Desktop not starting**

Open Docker Desktop manually from Start menu. Wait for "Engine running" status before running any docker commands.

**Containers not starting after reboot**

Open Ubuntu terminal and run:
```bash
cd /opt/plansb-siem && docker compose --env-file config.env up -d
```

**Not enough memory errors**

Limit Docker Desktop's RAM usage. Open Docker Desktop → Settings → Resources → Memory → set to 60% of total RAM.
Then reduce `OPENSEARCH_HEAP_SIZE` in `config.env` and run `./reconfigure.sh`.

**Certificate errors in Graylog search**

Run in Ubuntu terminal:
```bash
cd /opt/plansb-siem && sudo ./reconfigure.sh
```

---

## Deployment Checklist

- [ ] Virtualization enabled in BIOS
- [ ] WSL2 installed and Ubuntu 24.04 running
- [ ] Docker Desktop installed and engine running
- [ ] `.wslconfig` created with `networkingMode=mirrored`
- [ ] Repo cloned to `/opt/plansb-siem`
- [ ] `config.env` filled in with client details
- [ ] `sudo ./install.sh` completed successfully
- [ ] All 4 containers showing `(healthy)`
- [ ] Windows Firewall rules added
- [ ] Graylog UI accessible in browser at `https://<IP>:9000`
- [ ] `plansb-ca.crt` imported into Windows certificate store
- [ ] Auto-start scheduled task registered
- [ ] At least one log source sending data
- [ ] Admin password noted in client handover doc
