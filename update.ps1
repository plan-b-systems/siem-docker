# ============================================================
# Plan-B Systems SIEM v2.1 - Safe In-Place Updater (Windows)
# ============================================================
# Updates an existing install WITHOUT wiping data. Pulls the latest
# repo + images and recreates containers; the Docker volumes (logs,
# license keys, dashboard users) are preserved. No reinstall, no
# re-download of the WSL image.
#
# Usage - PowerShell as Administrator:
#   irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/update.ps1 | iex
# ============================================================

$ProgressPreference = "SilentlyContinue"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Run this as Administrator." -ForegroundColor Red
    return
}

$distro = "PlanB-SIEM"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Plan-B Systems SIEM - Safe Updater" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Must already be installed (this is an update, not a fresh install)
$distros = (wsl.exe --list --quiet 2>&1) -replace "`0", "" | Where-Object { $_.Trim() -ne "" }
if (-not ($distros | Where-Object { $_ -match "PlanB-SIEM" })) {
    Write-Host "ERROR: PlanB-SIEM is not installed on this machine." -ForegroundColor Red
    Write-Host "       Use install.ps1 for a fresh install." -ForegroundColor Yellow
    return
}

# Ensure WSL has adequate memory (idempotent; never clobbers an existing .wslconfig)
$totalRAM = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
$wslMem = [math]::Max(4, $totalRAM - 4)
$wslConfigPath = "$env:USERPROFILE\.wslconfig"
$wslConfigChanged = $false
if (-not (Test-Path $wslConfigPath)) {
    Set-Content -Path $wslConfigPath -Value "[wsl2]`nmemory=${wslMem}GB`n" -Encoding ascii
    Write-Host "  [OK] WSL2 memory limit set to ${wslMem} GB (.wslconfig created)" -ForegroundColor Green
    $wslConfigChanged = $true
} else {
    Write-Host "  [..] Existing .wslconfig left as-is (ensure [wsl2] memory >= ${wslMem}GB)" -ForegroundColor Yellow
}

# In-distro update: pull latest repo (config.env + override preserved), pull images, up -d
$updateScript = @'
#!/bin/bash
set -e
cd /opt/plan-b-siem
BRANCH=${SIEM_BRANCH:-main}

if ! docker info &>/dev/null; then
    dockerd &>/var/log/dockerd.log &
    sleep 5
fi

echo "Updating repo from origin/${BRANCH} (config.env + override preserved)..."
git fetch origin "$BRANCH" 2>&1
git checkout -f "$BRANCH" 2>/dev/null || git checkout -f -B "$BRANCH" "origin/$BRANCH"
git reset --hard "origin/$BRANCH" 2>&1
find . -name '*.sh' -exec dos2unix -q {} \; 2>/dev/null || true

OVERRIDE_ARGS=()
[[ -f docker-compose.override.yml ]] && OVERRIDE_ARGS=(-f docker-compose.override.yml)

echo "Pulling updated images..."
docker compose -f docker-compose.windows.yml ${OVERRIDE_ARGS[@]+"${OVERRIDE_ARGS[@]}"} --env-file config.env pull 2>&1

echo "Recreating containers (named volumes preserved - NO data loss)..."
docker compose -f docker-compose.windows.yml ${OVERRIDE_ARGS[@]+"${OVERRIDE_ARGS[@]}"} --env-file config.env up -d 2>&1

echo "UPDATE_DONE"
'@

$tmpDir = "C:\PlanB-SIEM"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$tmpFile = "$tmpDir\update-script.sh"
[System.IO.File]::WriteAllText($tmpFile, ($updateScript -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding $false))

# Apply the memory limit if we just created .wslconfig (requires a WSL restart)
if ($wslConfigChanged) {
    Write-Host "  Restarting WSL to apply the memory limit..." -ForegroundColor Yellow
    wsl.exe --shutdown 2>&1 | Out-Null
    Start-Sleep -Seconds 3
}

Write-Host "Running update inside the SIEM distro..." -ForegroundColor Yellow
$result = wsl.exe -d $distro -u root -- bash -c "sed -i 's/\r$//' /mnt/c/PlanB-SIEM/update-script.sh && bash /mnt/c/PlanB-SIEM/update-script.sh" 2>&1
$result | ForEach-Object { Write-Host "  $_" }
Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

if ($result -match "UPDATE_DONE") {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  UPDATE COMPLETE - data preserved" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Verify OpenSearch data location:" -ForegroundColor Gray
    Write-Host "    wsl -d PlanB-SIEM -u root -- docker exec plan-b-opensearch df -h /usr/share/opensearch/data" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "UPDATE may not have completed cleanly - check the output above." -ForegroundColor Yellow
}
