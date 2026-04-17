# ============================================================
# Plan-B Systems SIEM - Windows One-Shot Deployment
# ============================================================
# Run this script as Administrator on a fresh Windows machine.
# It handles everything: WSL2, Docker, SIEM stack, auto-start.
#
# Usage:
#   1. Open PowerShell as Administrator
#   2. Run: powershell -ExecutionPolicy Bypass -File deploy-windows.ps1
#   3. Answer the prompts
#   4. Wait for completion (~10-15 minutes)
# ============================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# -- Colors --
function Write-Step  { param($msg) Write-Host "`n== $msg ==" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "  [OK]    $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  [WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "  [ERROR] $msg" -ForegroundColor Red }

# -- Progress bar for long-running background tasks --
function Start-WithProgress {
    param(
        [string]$Label,
        [scriptblock]$Task,
        [int]$EstimatedSeconds = 120
    )
    $job = Start-Job -ScriptBlock $Task
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $barWidth = 30

    $fillChar = [string][char]0x2588
    $emptyChar = [string][char]0x2591

    while ($job.State -eq 'Running') {
        $elapsed = $sw.Elapsed.TotalSeconds
        $pct = [math]::Min(95, [math]::Floor(($elapsed / $EstimatedSeconds) * 100))
        $filled = [math]::Floor($barWidth * $pct / 100)
        $empty = $barWidth - $filled
        $bar = ($fillChar * $filled) + ($emptyChar * $empty)
        $mins = [math]::Floor($elapsed / 60)
        $secs = [math]::Floor($elapsed % 60)
        if ($mins -gt 0) { $timeStr = "${mins}m $($secs.ToString('D2'))s" } else { $timeStr = "${secs}s" }
        Write-Host "`r  $Label [$bar] ${pct}% ($timeStr)  " -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 500
    }

    $result = Receive-Job -Job $job
    Remove-Job -Job $job -Force
    $sw.Stop()

    $total = [math]::Floor($sw.Elapsed.TotalSeconds)
    $bar = $fillChar * $barWidth
    Write-Host "`r  $Label [$bar] 100% (${total}s)     " -ForegroundColor Green
    return $result
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Plan-B Systems SIEM v2 - Windows Deployment" -ForegroundColor Cyan
Write-Host "  OpenSearch 2.x + Syslog Receiver + Dashboard" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# -- Admin check --
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "This script must be run as Administrator."
    Write-Host "  Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    exit 1
}

# ============================================================
# 1. Gather client info
# ============================================================
Write-Step "Client Configuration"

$CLIENT_NAME = Read-Host -Prompt "  Client name [short - no spaces - e.g. acme-tlv]"
while ([string]::IsNullOrWhiteSpace($CLIENT_NAME) -or $CLIENT_NAME -match '\s') {
    Write-Warn "Client name cannot be empty or contain spaces"
    $CLIENT_NAME = Read-Host -Prompt "  Client name"
}

$CLIENT_ID = Read-Host -Prompt "  Client ID [from Plan-B portal]"
while ([string]::IsNullOrWhiteSpace($CLIENT_ID)) {
    Write-Warn "Client ID is required"
    $CLIENT_ID = Read-Host -Prompt "  Client ID"
}

# Auto-detect LAN IP
$defaultIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback|vEthernet|WSL" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
$HOST_IP = Read-Host -Prompt "  Machine LAN IP [$defaultIP]"
if ([string]::IsNullOrWhiteSpace($HOST_IP)) { $HOST_IP = $defaultIP }

$ADMIN_PASSWORD = Read-Host -Prompt "  Dashboard admin password [min 8 chars]"
while ([string]::IsNullOrWhiteSpace($ADMIN_PASSWORD) -or $ADMIN_PASSWORD.Length -lt 8) {
    Write-Warn "Password must be at least 8 characters"
    $ADMIN_PASSWORD = Read-Host -Prompt "  Dashboard admin password"
}

# Optional settings with defaults
$TIMEZONE = Read-Host -Prompt "  Timezone [Asia/Jerusalem]"
if ([string]::IsNullOrWhiteSpace($TIMEZONE)) { $TIMEZONE = "Asia/Jerusalem" }

$RETENTION_DAYS = Read-Host -Prompt "  Log retention days [730]"
if ([string]::IsNullOrWhiteSpace($RETENTION_DAYS)) { $RETENTION_DAYS = "730" }

# RAM-based heap calculation
$totalRAM = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
$heapSize = [math]::Max(1, [math]::Floor($totalRAM / 4))
$HEAP = "${heapSize}g"
Write-Ok "Detected ${totalRAM} GB RAM -> OpenSearch heap: ${HEAP}"

$DATA_PATH_RAW = Read-Host -Prompt "  External data path, e.g. D:\SIEMData [leave empty for Docker volumes]"

# Convert Windows path (D:\SIEMData) to WSL path (/mnt/d/SIEMData)
$DATA_PATH = ""
if ($DATA_PATH_RAW) {
    if ($DATA_PATH_RAW -match '^([A-Za-z]):\\(.*)$') {
        $driveLetter = $Matches[1].ToLower()
        $restPath = $Matches[2] -replace '\\', '/'
        $DATA_PATH = "/mnt/$driveLetter/$restPath"
    } elseif ($DATA_PATH_RAW -match '^/mnt/') {
        $DATA_PATH = $DATA_PATH_RAW  # already WSL path
    } else {
        $DATA_PATH = $DATA_PATH_RAW
    }

    # Create the directory on the Windows side if it doesn't exist
    if ($DATA_PATH_RAW -match '^[A-Za-z]:\\') {
        if (-not (Test-Path $DATA_PATH_RAW)) {
            New-Item -ItemType Directory -Path $DATA_PATH_RAW -Force | Out-Null
            Write-Ok "Created data directory: $DATA_PATH_RAW"
        }
    }
}

Write-Host ""
Write-Host "  Configuration Summary:" -ForegroundColor White
Write-Host "  ------------------------------------"
Write-Host "  Client:     $CLIENT_NAME"
Write-Host "  Client ID:  $CLIENT_ID"
Write-Host "  LAN IP:     $HOST_IP"
Write-Host "  Timezone:   $TIMEZONE"
Write-Host "  Retention:  $RETENTION_DAYS days"
Write-Host "  Heap:       $HEAP"
if ($DATA_PATH) { Write-Host "  Data Path:  $DATA_PATH_RAW -> $DATA_PATH (WSL)" }
Write-Host ""

$confirm = Read-Host -Prompt "  Proceed with deployment? [y/n]"
if ($confirm -ne "y") {
    Write-Host "Deployment cancelled." -ForegroundColor Yellow
    exit 0
}

# ============================================================
# 2. Check/Enable WSL2
# ============================================================
Write-Step "WSL2 Setup"

$wslInstalled = $false
try {
    $wslVersion = wsl.exe --version 2>&1
    if ($LASTEXITCODE -eq 0) { $wslInstalled = $true }
} catch {}

if (-not $wslInstalled) {
    Write-Ok "Installing WSL2..."
    wsl --install --no-distribution 2>&1 | Out-Null
    Write-Warn "WSL2 was just installed. You MUST restart Windows, then re-run this script."
    Write-Host "  Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 0
}
Write-Ok "WSL2 is installed"

# Ensure WSL2 is the default
wsl --set-default-version 2 2>&1 | Out-Null

# ============================================================
# 3. Install Ubuntu 24.04
# ============================================================
Write-Step "Ubuntu 24.04"

$distros = (wsl.exe --list --quiet 2>&1) -replace "`0", "" | Where-Object { $_.Trim() -ne "" }
$ubuntuInstalled = $distros | Where-Object { $_ -match "Ubuntu" }

if (-not $ubuntuInstalled) {
    Start-WithProgress -Label "Installing Ubuntu 24.04" -EstimatedSeconds 180 -Task {
        wsl --install -d Ubuntu-24.04 2>&1 | Out-Null
    }
    Write-Warn "Ubuntu was just installed."
    Write-Warn "If an Ubuntu window opened, create a user account (e.g. planbadmin), then close it."
    Write-Host "  Press any key when Ubuntu setup is complete..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Find the Ubuntu distro name
$distros = (wsl.exe --list --quiet 2>&1) -replace "`0", "" | Where-Object { $_.Trim() -ne "" }
$DISTRO = ($distros | Where-Object { $_ -match "Ubuntu" } | Select-Object -First 1).Trim()
if ([string]::IsNullOrWhiteSpace($DISTRO)) {
    Write-Err "Ubuntu distro not found. Install manually: wsl --install -d Ubuntu-24.04"
    exit 1
}
Write-Ok "Using distro: $DISTRO"

# ============================================================
# 4. WSL2 Networking - ensure DNS works
# ============================================================
Write-Step "WSL2 Networking"

# Clean up any broken .wslconfig (e.g. mirrored networking from a previous attempt)
$wslConfig = "$env:USERPROFILE\.wslconfig"
if (Test-Path $wslConfig) {
    $content = Get-Content $wslConfig -Raw
    if ($content -match "networkingMode") {
        Write-Ok "Removing broken networkingMode from .wslconfig"
        $content = $content -replace "networkingMode=.*", ""
        Set-Content -Path $wslConfig -Value $content.Trim() -NoNewline
    }
}

# Ensure WSL auto-generates resolv.conf for DNS
wsl.exe -d $DISTRO -u root -- bash -c "
    if grep -q 'generateResolvConf.*false' /etc/wsl.conf 2>/dev/null; then
        sed -i 's/generateResolvConf.*=.*false/generateResolvConf = true/' /etc/wsl.conf
    fi
" 2>&1 | Out-Null

# Test DNS - if it fails, restart WSL to regenerate resolv.conf
$dnsTest = wsl.exe -d $DISTRO -- bash -c "ping -c1 -W3 github.com >/dev/null 2>&1 && echo OK || echo FAIL" 2>&1
if ($dnsTest -notmatch "OK") {
    Write-Ok "Restarting WSL for DNS fix..."
    wsl --shutdown 2>&1 | Out-Null
    Start-Sleep -Seconds 3

    $retries = 0
    $wslReady = ""
    do {
        $retries++
        Start-Sleep -Seconds 3
        try {
            $wslReady = wsl.exe -d $DISTRO -- echo "ready" 2>&1
        } catch {
            $wslReady = ""
        }
    } while ($wslReady -notmatch "ready" -and $retries -lt 10)

    if ($wslReady -notmatch "ready") {
        Write-Err "WSL failed to restart. Try: wsl --shutdown, then re-run this script."
        exit 1
    }
}
Write-Ok "WSL networking is ready"

# ============================================================
# 5. Install Docker + tools inside WSL
# ============================================================
Write-Step "Installing Docker & Tools in WSL"

$installScript = @'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo "[1/3] Installing system tools..."
apt-get update -qq
apt-get install -y -qq git gettext-base openssl curl dos2unix >/dev/null 2>&1

if command -v docker &>/dev/null; then
    echo "[2/3] Docker already installed: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'checking...')"
else
    echo "[2/3] Installing Docker..."
    curl -fsSL https://get.docker.com | sh 2>&1 | tail -3
fi

# Ensure Docker is running
if ! docker info &>/dev/null; then
    echo "[2/3] Starting Docker daemon..."
    dockerd &>/var/log/dockerd.log &
    sleep 5
fi

# Verify
echo "[3/3] Verifying..."
docker version --format 'Docker {{.Server.Version}}' 2>/dev/null || echo "Docker check pending (will start on next boot)"
docker compose version 2>/dev/null || echo "Docker Compose check pending"
echo "DONE"
'@

# Write script to temp file and execute (piping into wsl.exe is unreliable)
$tmpScript = "C:\PlanB-SIEM\tmp-install.sh"
New-Item -ItemType Directory -Path "C:\PlanB-SIEM" -Force | Out-Null
# Use .NET to write UTF-8 without BOM (PS5 Set-Content -Encoding utf8 adds BOM)
[System.IO.File]::WriteAllText($tmpScript, $installScript, (New-Object System.Text.UTF8Encoding $false))
$distroForJob = $DISTRO
Start-WithProgress -Label "Installing Docker & tools" -EstimatedSeconds 120 -Task {
    wsl.exe -d $using:distroForJob -u root -- bash -c "sed -i 's/\r$//' /mnt/c/PlanB-SIEM/tmp-install.sh && bash /mnt/c/PlanB-SIEM/tmp-install.sh" 2>&1
}
Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
Write-Ok "Docker and tools installed"

# ============================================================
# 6. Clone repo and configure
# ============================================================
Write-Step "Cloning SIEM Repository"

$setupScript = @"
#!/bin/bash
set -e

# Ensure Docker is running
if ! docker info &>/dev/null 2>&1; then
    dockerd &>/var/log/dockerd.log &
    sleep 5
fi

# Clone or update
if [ -d /opt/plan-b-siem/.git ]; then
    echo "Repo exists, pulling latest..."
    cd /opt/plan-b-siem && git fetch origin v2 2>&1 && git checkout v2 2>&1 && git pull origin v2 2>&1 || true

    # Clean generated artifacts from prior install to prevent stale
    # secrets/certs being reused with fresh Docker volumes
    echo "Cleaning previous deployment artifacts..."
    rm -f config.env 2>/dev/null || true
    rm -f certs/graylog.crt certs/graylog.key certs/graylog.csr certs/ca.crt certs/ca.key certs/ca.srl 2>/dev/null || true
    rm -f graylog/cacerts graylog/graylog.conf 2>/dev/null || true
    rm -f docker-compose.override.yml 2>/dev/null || true

    # Clean stale Docker state (containers + volumes from prior install)
    echo "Removing stale Docker containers and volumes..."
    docker compose --env-file config.env.template down -v 2>/dev/null || true
    for c in plan-b-graylog plan-b-mongodb plan-b-opensearch plan-b-license-checker; do
        docker rm -f \$c 2>/dev/null || true
    done
    docker volume ls -q --filter name=plan-b-siem_ | xargs -r docker volume rm 2>/dev/null || true
else
    echo "Cloning repository..."
    git clone -b v2 https://github.com/plan-b-systems/siem-docker.git /opt/plan-b-siem 2>&1
fi

cd /opt/plan-b-siem

# Fix line endings (safety net)
find . -name '*.sh' -exec dos2unix -q {} \; 2>/dev/null || true
find . -name '*.template' -exec dos2unix -q {} \; 2>/dev/null || true
find . -name 'Dockerfile' -exec dos2unix -q {} \; 2>/dev/null || true
dos2unix -q config.env.template 2>/dev/null || true

# Generate config.env
cp config.env.template config.env

sed -i "s|^CLIENT_NAME=.*|CLIENT_NAME=$CLIENT_NAME|" config.env
sed -i "s|^CLIENT_ID=.*|CLIENT_ID=$CLIENT_ID|" config.env
sed -i "s|^HOST_IP=.*|HOST_IP=$HOST_IP|" config.env
sed -i "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD='$ADMIN_PASSWORD'|" config.env
sed -i "s|^TIMEZONE=.*|TIMEZONE=$TIMEZONE|" config.env
sed -i "s|^RETENTION_DAYS=.*|RETENTION_DAYS=$RETENTION_DAYS|" config.env
sed -i "s|^OPENSEARCH_HEAP_SIZE=.*|OPENSEARCH_HEAP_SIZE=$HEAP|" config.env
sed -i "s|^DATA_PATH=.*|DATA_PATH=$DATA_PATH|" config.env

# Fix line endings on generated config too
dos2unix -q config.env 2>/dev/null || true

echo "config.env generated"
echo "DONE"
"@

# Write script to temp file and execute (piping into wsl.exe is unreliable)
$tmpScript = "C:\PlanB-SIEM\tmp-setup.sh"
[System.IO.File]::WriteAllText($tmpScript, $setupScript, (New-Object System.Text.UTF8Encoding $false))
Start-WithProgress -Label "Cloning repo & configuring" -EstimatedSeconds 30 -Task {
    wsl.exe -d $using:distroForJob -u root -- bash -c "sed -i 's/\r$//' /mnt/c/PlanB-SIEM/tmp-setup.sh && bash /mnt/c/PlanB-SIEM/tmp-setup.sh" 2>&1
}
Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
Write-Ok "Repository cloned and configured"

# ============================================================
# 7. Run install.sh
# ============================================================
Write-Step "Running SIEM Installer (this takes 5-10 minutes)"

$result = Start-WithProgress -Label "Building SIEM stack" -EstimatedSeconds 360 -Task {
    wsl.exe -d $using:distroForJob -u root -- bash -c "cd /opt/plan-b-siem && chmod +x install.sh && ./install.sh 2>&1; echo EXIT_CODE=`$?"
}

$exitLine = ($result | Select-String "EXIT_CODE=").ToString()
$exitCode = [int]($exitLine -replace ".*EXIT_CODE=", "")

if ($exitCode -ne 0) {
    Write-Err "install.sh failed with exit code $exitCode"
    Write-Host "  Check the output above for errors." -ForegroundColor Yellow
    Write-Host "  You can re-run: wsl -d $DISTRO -u root -- bash -c 'cd /opt/plan-b-siem && ./install.sh'" -ForegroundColor Yellow
    exit 1
}
Write-Ok "SIEM stack installed"

# ============================================================
# 8. Windows Firewall Rules
# ============================================================
Write-Step "Firewall Rules"

$tcpPorts = @(3000, 1514)
$udpPorts = @(514)

foreach ($port in $tcpPorts) {
    $ruleName = "PlanB-SIEM-TCP-$port"
    $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any 2>&1 | Out-Null
        Write-Ok "Firewall rule: $ruleName"
    } else {
        Write-Ok "Firewall rule exists: $ruleName"
    }
}
foreach ($port in $udpPorts) {
    $ruleName = "PlanB-SIEM-UDP-$port"
    $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow -Profile Any 2>&1 | Out-Null
        Write-Ok "Firewall rule: $ruleName"
    } else {
        Write-Ok "Firewall rule exists: $ruleName"
    }
}

# ============================================================
# 9. Port Forwarding
# ============================================================
Write-Step "Port Forwarding"

$wslIP = (wsl.exe -d $DISTRO -- hostname -I 2>&1).Trim().Split()[0] -replace "`0", ""
Write-Ok "WSL2 IP: $wslIP"

netsh interface portproxy reset 2>&1 | Out-Null
$allPorts = @(3000, 514, 1514)
foreach ($port in $allPorts) {
    netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$wslIP 2>&1 | Out-Null
    Write-Ok "Port forward: 0.0.0.0:${port} -> ${wslIP}:${port}"
}

# ============================================================
# 10. Register Auto-Start Scheduled Task
# ============================================================
Write-Step "Auto-Start Configuration"

# Copy startup script to C:\PlanB-SIEM
$installDir = "C:\PlanB-SIEM"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null

# Copy from repo
$psSource = "\\wsl$\$DISTRO\opt\plan-b-siem\resilience\windows"
if (Test-Path "$psSource\PlanB-SIEM-Startup.ps1") {
    Copy-Item "$psSource\PlanB-SIEM-Startup.ps1" "$installDir\" -Force
    Copy-Item "$psSource\Register-ScheduledTask.ps1" "$installDir\" -Force
} else {
    # Fallback: copy via wsl
    wsl.exe -d $DISTRO -u root -- bash -c "cp /opt/plan-b-siem/resilience/windows/*.ps1 /mnt/c/PlanB-SIEM/" 2>&1 | Out-Null
}

# Register the task
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$installDir\PlanB-SIEM-Startup.ps1`""

$triggerStartup = New-ScheduledTaskTrigger -AtStartup
$triggerLogon = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 2) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName "PlanB-SIEM-Autostart" `
    -Action $action `
    -Trigger @($triggerStartup, $triggerLogon) `
    -RunLevel Highest `
    -User "SYSTEM" `
    -Settings $settings `
    -Force | Out-Null

Write-Ok "Auto-start scheduled task registered"

# ============================================================
# 11. Health Check
# ============================================================
Write-Step "Final Health Check"

Start-Sleep -Seconds 5
$healthResult = wsl.exe -d $DISTRO -u root -- bash -c "/opt/plan-b-siem/resilience/health-check.sh 2>&1" 2>&1
$healthResult | ForEach-Object { Write-Host "  $_" }

# ============================================================
# 12. Copy CA cert to Desktop
# ============================================================
Write-Step "Certificate"

$desktopPath = [Environment]::GetFolderPath("Desktop")
$caCertDest = Join-Path $desktopPath "plan-b-ca.crt"
wsl.exe -d $DISTRO -- bash -c "cat /opt/plan-b-siem/certs/ca.crt" 2>&1 | Set-Content -Path $caCertDest
if (Test-Path $caCertDest) {
    Write-Ok "CA certificate copied to Desktop: plan-b-ca.crt"
    Write-Host "  Double-click it -> Install -> Local Machine -> Trusted Root Certification Authorities" -ForegroundColor Yellow
}

# ============================================================
# Done
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard   : http://${HOST_IP}:3000" -ForegroundColor White
Write-Host "  Password    : $ADMIN_PASSWORD" -ForegroundColor White
Write-Host ""
Write-Host "  Client Name : $CLIENT_NAME" -ForegroundColor Gray
Write-Host "  Client ID   : $CLIENT_ID" -ForegroundColor Gray
Write-Host "  Retention   : $RETENTION_DAYS days" -ForegroundColor Gray
Write-Host ""
Write-Host "  Logs        : C:\PlanB-SIEM\startup.log (Windows)" -ForegroundColor Gray
Write-Host "                /var/log/plan-b-siem-startup.log (WSL)" -ForegroundColor Gray
Write-Host ""
Write-Host "  CA cert on Desktop - import to remove browser warning" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Syslog UDP  : ${HOST_IP}:514" -ForegroundColor Gray
Write-Host "  Syslog TCP  : ${HOST_IP}:1514" -ForegroundColor Gray
Write-Host ""
Write-Host "  The SIEM will auto-start on every boot." -ForegroundColor Green
Write-Host ""
