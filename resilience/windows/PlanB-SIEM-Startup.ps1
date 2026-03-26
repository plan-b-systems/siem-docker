# ============================================================
# Plan-B Systems SIEM – Windows Boot Startup Script
# Runs as a Scheduled Task at system startup
# Starts WSL, waits for Docker, sets up port forwarding
# ============================================================

$ErrorActionPreference = "Continue"
$LogFile = "C:\PlanB-SIEM\startup.log"

# Ensure log directory exists
New-Item -ItemType Directory -Path "C:\PlanB-SIEM" -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [PlanB-SIEM] $Message" | Out-File -Append -FilePath $LogFile
}

Write-Log "========== Windows boot detected =========="

# ── 1. Start WSL ──
Write-Log "Starting WSL..."
$distro = "Ubuntu-24.04"

# Find the correct distro name
$distros = wsl.exe --list --quiet 2>&1
if ($distros -match "Ubuntu") {
    $distro = ($distros | Where-Object { $_ -match "Ubuntu" } | Select-Object -First 1).Trim()
    # Remove null characters from WSL output
    $distro = $distro -replace "`0", ""
}
Write-Log "Using WSL distro: $distro"

# Start WSL (triggers [boot] command in wsl.conf which starts Docker + SIEM)
wsl.exe -d $distro -- echo "WSL started" 2>&1 | Out-Null
Write-Log "WSL distro started"

# ── 2. Wait for Docker daemon inside WSL ──
Write-Log "Waiting for Docker daemon..."
$timeout = 120
$elapsed = 0
do {
    $result = wsl.exe -d $distro -- docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Docker daemon ready (waited ${elapsed}s)"
        break
    }
    Start-Sleep -Seconds 5
    $elapsed += 5
} while ($elapsed -lt $timeout)

if ($elapsed -ge $timeout) {
    Write-Log "ERROR: Docker daemon failed to start within ${timeout}s"
    exit 1
}

# ── 3. Wait for SIEM containers (wsl-startup.sh should have started them) ──
Write-Log "Waiting for SIEM containers..."
$timeout = 300
$elapsed = 0
do {
    $graylogStatus = (wsl.exe -d $distro -- docker inspect --format '{{.State.Health.Status}}' plansb-graylog 2>&1).Trim() -replace "`0", ""
    if ($graylogStatus -eq "healthy") {
        Write-Log "Graylog is healthy"
        break
    }
    Start-Sleep -Seconds 10
    $elapsed += 10
    Write-Log "Graylog status: $graylogStatus (${elapsed}s)"
} while ($elapsed -lt $timeout)

if ($elapsed -ge $timeout) {
    Write-Log "WARNING: Graylog not healthy after ${timeout}s, continuing with port forwarding..."
}

# ── 4. Set up port forwarding (netsh portproxy) ──
Write-Log "Configuring port forwarding..."

# Get WSL2 IP
$wslIP = (wsl.exe -d $distro -- hostname -I 2>&1).Trim().Split()[0] -replace "`0", ""
Write-Log "WSL2 IP: $wslIP"

if ([string]::IsNullOrEmpty($wslIP)) {
    Write-Log "ERROR: Could not determine WSL2 IP"
    exit 1
}

# Clear existing portproxy rules
netsh interface portproxy reset 2>&1 | Out-Null

# TCP ports
$tcpPorts = @(9000, 514, 1514, 12201, 12202)
foreach ($port in $tcpPorts) {
    netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$wslIP 2>&1 | Out-Null
    Write-Log "Port forwarding: 0.0.0.0:${port} -> ${wslIP}:${port}"
}

# ── 5. Ensure firewall rules exist (idempotent) ──
Write-Log "Checking firewall rules..."

$fwTcpPorts = @(9000, 1514, 12202)
$fwUdpPorts = @(514, 12201)

foreach ($port in $fwTcpPorts) {
    $ruleName = "PlanB-SIEM-TCP-$port"
    $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any 2>&1 | Out-Null
        Write-Log "Created firewall rule: $ruleName"
    }
}
foreach ($port in $fwUdpPorts) {
    $ruleName = "PlanB-SIEM-UDP-$port"
    $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $exists) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow -Profile Any 2>&1 | Out-Null
        Write-Log "Created firewall rule: $ruleName"
    }
}

# ── 6. Final status ──
$containers = wsl.exe -d $distro -- docker ps --format "{{.Names}}: {{.Status}}" 2>&1
Write-Log "Container status:"
foreach ($line in $containers) {
    $clean = ($line -replace "`0", "").Trim()
    if ($clean) { Write-Log "  $clean" }
}

Write-Log "========== Startup complete =========="
