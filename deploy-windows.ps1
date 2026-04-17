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

# -- Progress bar for long-running commands --
# Runs the command as a System.Diagnostics.Process so WSL/docker calls work.
# $Command is a string (not scriptblock) that gets passed to powershell -Command.
function Start-WithProgress {
    param(
        [string]$Label,
        [string]$Command,
        [int]$EstimatedSeconds = 120
    )
    # Launch as a child powershell process — inherits environment, WSL works
    $outFile = "$env:TEMP\plan-b-progress-$([System.IO.Path]::GetRandomFileName()).txt"
    $proc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$Command | Out-File -FilePath '$outFile' -Encoding utf8`"" `
        -WindowStyle Hidden -PassThru

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $barWidth = 30
    $fillChar = [string][char]0x2588
    $emptyChar = [string][char]0x2591

    while (-not $proc.HasExited) {
        $elapsed = $sw.Elapsed.TotalSeconds
        $pct = [math]::Min(95, [math]::Floor(($elapsed / $EstimatedSeconds) * 100))
        $filled = [math]::Floor($barWidth * $pct / 100)
        $empty = $barWidth - $filled
        $bar = ($fillChar * $filled) + ($emptyChar * $empty)
        $mins = [math]::Floor($elapsed / 60)
        $secs = [math]::Floor($elapsed % 60)
        if ($mins -gt 0) { $timeStr = "${mins}m $([int]$secs)s" } else { $timeStr = "$([int]$secs)s" }
        Write-Host "`r  $Label [$bar] ${pct}% ($timeStr)  " -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 500
    }
    $sw.Stop()

    $total = [math]::Floor($sw.Elapsed.TotalSeconds)
    $bar = $fillChar * $barWidth
    Write-Host "`r  $Label [$bar] 100% (${total}s)     " -ForegroundColor Green

    $result = if (Test-Path $outFile) { Get-Content $outFile -Raw; Remove-Item $outFile -Force } else { "" }
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
# 3. Import Plan-B Docker WSL image
# ============================================================
Write-Step "WSL2 Docker Environment"

$DISTRO = "PlanB-SIEM"
$wslDir = "C:\PlanB-SIEM\wsl"
$rootfsUrl = "https://github.com/plan-b-systems/siem-docker/releases/download/wsl-image-v2/plan-b-docker-wsl.tar.gz"
$rootfsFile = "$env:TEMP\plan-b-docker-wsl.tar.gz"

# Check if our distro already exists
$distros = (wsl.exe --list --quiet 2>&1) -replace "`0", "" | Where-Object { $_.Trim() -ne "" }
$alreadyImported = $distros | Where-Object { $_ -match "PlanB-SIEM" }

if (-not $alreadyImported) {
    New-Item -ItemType Directory -Path $wslDir -Force | Out-Null

    # Download minimal rootfs (~100MB — Debian slim + Docker Engine, no Ubuntu)
    Start-WithProgress -Label "Downloading Docker environment" -EstimatedSeconds 30 -Command "powershell -NoProfile -Command `"Invoke-WebRequest -Uri '$rootfsUrl' -OutFile '$rootfsFile' -UseBasicParsing`""

    if (-not (Test-Path $rootfsFile)) {
        Write-Err "Failed to download WSL image from $rootfsUrl"
        exit 1
    }

    # Import into WSL2 — takes seconds, no interactive prompts
    Write-Ok "Importing WSL image..."
    wsl --import $DISTRO $wslDir $rootfsFile --version 2 2>&1 | Out-Null
    Remove-Item $rootfsFile -Force -ErrorAction SilentlyContinue

    if ($LASTEXITCODE -ne 0) {
        Write-Err "WSL import failed. Try: wsl --unregister PlanB-SIEM, then re-run."
        exit 1
    }
    Write-Ok "WSL Docker environment imported"
} else {
    Write-Ok "PlanB-SIEM WSL distro already exists"
}

# Start Docker daemon (wsl.conf [boot] command handles this on reboot,
# but we need it running now for the first install)
Write-Ok "Starting Docker daemon..."
wsl.exe -d $DISTRO -u root -- bash -c "
    if ! docker info &>/dev/null 2>&1; then
        dockerd &>/var/log/dockerd.log &
        sleep 5
    fi
    docker info &>/dev/null && echo 'Docker ready' || echo 'Docker failed to start'
" 2>&1 | ForEach-Object { Write-Host "  $_" }

# Verify DNS
$dnsTest = wsl.exe -d $DISTRO -- bash -c "curl -sf https://ghcr.io/v2/ >/dev/null 2>&1 && echo OK || echo FAIL" 2>&1
if ($dnsTest -notmatch "OK") {
    Write-Warn "DNS/network issue detected, restarting WSL..."
    wsl --shutdown 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    wsl.exe -d $DISTRO -u root -- bash -c "dockerd &>/var/log/dockerd.log & sleep 5" 2>&1 | Out-Null
}
Write-Ok "Docker environment ready"

# ============================================================
# 4. Clone repo and configure
# ============================================================
Write-Step "Setting Up SIEM"

$setupScript = @"
#!/bin/bash
set -e

SIEM_DIR=/opt/plan-b-siem

# Clone or update repo (needed for compose file, resilience scripts, config template)
if [ -d \$SIEM_DIR/.git ]; then
    echo "Repo exists, pulling latest..."
    cd \$SIEM_DIR && git fetch origin v2 2>&1 && git checkout v2 2>&1 && git pull origin v2 2>&1 || true
    rm -f config.env docker-compose.override.yml 2>/dev/null || true

    # Clean stale containers
    docker compose -f \$SIEM_DIR/docker-compose.windows.yml --env-file \$SIEM_DIR/config.env.template down -v 2>/dev/null || true
    for c in plan-b-syslog plan-b-dashboard plan-b-opensearch plan-b-license-checker; do
        docker rm -f \$c 2>/dev/null || true
    done
    docker volume ls -q --filter name=plan-b-siem_ | xargs -r docker volume rm 2>/dev/null || true
else
    echo "Cloning repository..."
    git clone -b v2 https://github.com/plan-b-systems/siem-docker.git \$SIEM_DIR 2>&1
fi

cd \$SIEM_DIR

# Fix line endings
find . -name '*.sh' -exec dos2unix -q {} \; 2>/dev/null || true
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
dos2unix -q config.env 2>/dev/null || true

# Generate JWT_SECRET
JWT_SEC=\$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)
echo "JWT_SECRET=\$JWT_SEC" >> config.env
echo "config.env generated"

# Host OS tuning for OpenSearch
sysctl -w vm.max_map_count=262144 2>/dev/null || true
if [ ! -f /etc/sysctl.d/99-plan-b-siem.conf ]; then
    cat > /etc/sysctl.d/99-plan-b-siem.conf <<'SYSCTL'
vm.max_map_count=262144
net.core.rmem_max=26214400
net.core.rmem_default=262144
SYSCTL
fi

echo "DONE"
"@

$tmpScript = "C:\PlanB-SIEM\tmp-setup.sh"
New-Item -ItemType Directory -Path "C:\PlanB-SIEM" -Force | Out-Null
[System.IO.File]::WriteAllText($tmpScript, $setupScript, (New-Object System.Text.UTF8Encoding $false))
Start-WithProgress -Label "Cloning repo & configuring" -EstimatedSeconds 30 -Command "wsl.exe -d $DISTRO -u root -- bash -c `"sed -i 's/\r$//' /mnt/c/PlanB-SIEM/tmp-setup.sh && bash /mnt/c/PlanB-SIEM/tmp-setup.sh`""
Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue
Write-Ok "Repository cloned and configured"

# ============================================================
# 7. Pull images and start SIEM stack
# ============================================================
Write-Step "Pulling SIEM Images"

Start-WithProgress -Label "Pulling Docker images" -EstimatedSeconds 90 -Command "wsl.exe -d $DISTRO -u root -- bash -c 'cd /opt/plan-b-siem && docker compose -f docker-compose.windows.yml --env-file config.env pull 2>&1'"
Write-Ok "All images pulled"

Write-Step "Starting SIEM Stack"

$startScript = @'
#!/bin/bash
set -e
cd /opt/plan-b-siem

# Ensure Docker is running
if ! docker info &>/dev/null 2>&1; then
    dockerd &>/var/log/dockerd.log &
    sleep 5
fi

set -a; source config.env; set +a
COMPOSE="docker compose -f docker-compose.windows.yml --env-file config.env"

# Generate password hash using the dashboard image we just pulled
RAW_PW=$(grep "^DASHBOARD_PASSWORD=" config.env | sed "s/^DASHBOARD_PASSWORD=//" | sed "s/^'//;s/'$//")
echo "Generating password hash..."
PW_HASH=$(docker run --rm ghcr.io/plan-b-systems/siem-dashboard:v2 \
    node -e "const b=require('bcryptjs');console.log(b.hashSync(process.argv[1],12))" "$RAW_PW" 2>/dev/null | tail -1)

if [[ -n "$PW_HASH" && "$PW_HASH" == \$2* ]]; then
    sed -i '/^DASHBOARD_PASSWORD_HASH=/d' config.env
    echo "DASHBOARD_PASSWORD_HASH='${PW_HASH}'" >> config.env
    echo "Password hash generated"
else
    echo "WARNING: Could not generate password hash. Got: $PW_HASH"
fi

set -a; source config.env; set +a

# Storage override
if [[ -n "${DATA_PATH:-}" ]]; then
    mkdir -p "${DATA_PATH}/opensearch"
    chown -R 1000:1000 "${DATA_PATH}/opensearch"
    cat > docker-compose.override.yml <<OVERRIDE
services:
  opensearch:
    volumes:
      - ${DATA_PATH}/opensearch:/usr/share/opensearch/data
OVERRIDE
fi

# Start OpenSearch first, wait for healthy
echo "Starting OpenSearch..."
$COMPOSE up -d opensearch
TIMEOUT=180; ELAPSED=0
until $COMPOSE exec -T opensearch curl -sf http://localhost:9200/_cluster/health &>/dev/null; do
    sleep 5; ELAPSED=$((ELAPSED+5))
    [[ $ELAPSED -ge $TIMEOUT ]] && { echo "ERROR: OpenSearch failed to start within ${TIMEOUT}s"; exit 1; }
    echo -n "."
done
echo ""
echo "OpenSearch healthy"

# Start remaining services
echo "Starting syslog receiver and dashboard..."
$COMPOSE up -d syslog-receiver dashboard
sleep 5
echo "Starting license checker..."
$COMPOSE up -d license-checker

# Setup resilience/auto-start
if [[ -x resilience/setup-resilience.sh ]]; then
    bash resilience/setup-resilience.sh "$(pwd)" 2>&1 || true
fi

echo "EXIT_CODE=0"
'@

$tmpScript = "C:\PlanB-SIEM\tmp-start.sh"
[System.IO.File]::WriteAllText($tmpScript, $startScript, (New-Object System.Text.UTF8Encoding $false))
$result = Start-WithProgress -Label "Starting SIEM services" -EstimatedSeconds 120 -Command "wsl.exe -d $DISTRO -u root -- bash -c `"sed -i 's/\r$//' /mnt/c/PlanB-SIEM/tmp-start.sh && bash /mnt/c/PlanB-SIEM/tmp-start.sh`""
Remove-Item $tmpScript -Force -ErrorAction SilentlyContinue

if ($result -match "EXIT_CODE=0") {
    Write-Ok "SIEM stack running"
} else {
    Write-Err "SIEM stack failed to start. Check output above."
    Write-Host "  Re-run: wsl -d $DISTRO -u root -- bash -c 'cd /opt/plan-b-siem && docker compose -f docker-compose.windows.yml --env-file config.env up -d'" -ForegroundColor Yellow
    exit 1
}

# ============================================================
# 7. Windows Firewall Rules
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
# 8. Port Forwarding
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
# 9. Register Auto-Start Scheduled Task
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
# 10. Health Check
# ============================================================
Write-Step "Final Health Check"

Start-Sleep -Seconds 5
$healthResult = wsl.exe -d $DISTRO -u root -- bash -c "/opt/plan-b-siem/resilience/health-check.sh 2>&1" 2>&1
$healthResult | ForEach-Object { Write-Host "  $_" }

# ============================================================
# 11. Copy CA cert to Desktop
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
