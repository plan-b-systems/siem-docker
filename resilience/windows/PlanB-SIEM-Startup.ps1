# ============================================================
# Plan-B Systems SIEM v2 – Windows Boot Startup Script
# Runs as a Scheduled Task at system startup
# Starts WSL, waits for Docker, sets up port forwarding
# ============================================================

$ErrorActionPreference = "Continue"
$LogFile = "C:\PlanB-SIEM\startup.log"

New-Item -ItemType Directory -Path "C:\PlanB-SIEM" -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [PlanB-SIEM] $Message" | Out-File -Append -FilePath $LogFile
}

Write-Log "========== Windows boot detected =========="

# ── 1. Start WSL ──
Write-Log "Starting WSL..."
$distro = "PlanB-SIEM"

# Verify distro exists
$distros = (wsl.exe --list --quiet 2>&1) -replace "`0", "" | Where-Object { $_.Trim() -ne "" }
if (-not ($distros | Where-Object { $_ -match "PlanB-SIEM" })) {
    Write-Log "ERROR: PlanB-SIEM WSL distro not found"
    exit 1
}

# Start WSL (triggers [boot] command in wsl.conf which starts dockerd)
wsl.exe -d $distro -- echo "WSL started" 2>&1 | Out-Null
Write-Log "WSL distro started"

# ── 2. Wait for Docker daemon ──
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
    Write-Log "ERROR: Docker daemon failed to start within ${timeout}s, attempting manual start..."
    wsl.exe -d $distro -u root -- bash -c "dockerd &>/var/log/dockerd.log &" 2>&1 | Out-Null
    Start-Sleep -Seconds 10
}

# ── 3. Start SIEM containers ──
Write-Log "Starting SIEM stack..."
wsl.exe -d $distro -u root -- bash -c "cd /opt/plan-b-siem && OV=''; [ -f docker-compose.override.yml ] && OV='-f docker-compose.override.yml'; docker compose -f docker-compose.windows.yml `$OV --env-file config.env up -d 2>&1" 2>&1 | Out-Null

# Wait for OpenSearch healthy
$timeout = 300
$elapsed = 0
do {
    $osStatus = (wsl.exe -d $distro -- docker inspect --format '{{.State.Health.Status}}' plan-b-opensearch 2>&1).Trim() -replace "`0", ""
    if ($osStatus -eq "healthy") {
        Write-Log "OpenSearch is healthy"
        break
    }
    Start-Sleep -Seconds 10
    $elapsed += 10
    Write-Log "OpenSearch status: $osStatus (${elapsed}s)"
} while ($elapsed -lt $timeout)

# ── 4. Port forwarding ──
Write-Log "Configuring port forwarding..."

$wslIP = (wsl.exe -d $distro -- hostname -I 2>&1).Trim().Split()[0] -replace "`0", ""
Write-Log "WSL2 IP: $wslIP"

if ([string]::IsNullOrEmpty($wslIP)) {
    Write-Log "ERROR: Could not determine WSL2 IP"
    exit 1
}

netsh interface portproxy reset 2>&1 | Out-Null
$allPorts = @(3000, 514, 1514)
foreach ($port in $allPorts) {
    netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$wslIP 2>&1 | Out-Null
    Write-Log "Port forwarding: 0.0.0.0:${port} -> ${wslIP}:${port}"
}

# ── 5. Firewall rules (idempotent) ──
Write-Log "Checking firewall rules..."

foreach ($port in @(3000, 1514)) {
    $ruleName = "PlanB-SIEM-TCP-$port"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any 2>&1 | Out-Null
        Write-Log "Created firewall rule: $ruleName"
    }
}
foreach ($port in @(514)) {
    $ruleName = "PlanB-SIEM-UDP-$port"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
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
