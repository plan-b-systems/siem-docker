# ============================================================
# Plan-B Systems SIEM – Register Windows Scheduled Task
# Run this once as Administrator after installation
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Plan-B Systems SIEM – Scheduled Task Registration" -ForegroundColor Cyan
Write-Host ""

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# Ensure C:\PlanB-SIEM exists and copy the startup script there
$installDir = "C:\PlanB-SIEM"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null

$scriptSource = Join-Path $PSScriptRoot "PlanB-SIEM-Startup.ps1"
$scriptDest = Join-Path $installDir "PlanB-SIEM-Startup.ps1"

if (Test-Path $scriptSource) {
    Copy-Item -Path $scriptSource -Destination $scriptDest -Force
    Write-Host "  Copied startup script to $scriptDest" -ForegroundColor Green
} elseif (-not (Test-Path $scriptDest)) {
    Write-Host "ERROR: Cannot find PlanB-SIEM-Startup.ps1" -ForegroundColor Red
    Write-Host "  Expected at: $scriptSource" -ForegroundColor Yellow
    exit 1
}

# Register the scheduled task
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$scriptDest`""

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

Write-Host "  Scheduled task 'PlanB-SIEM-Autostart' registered" -ForegroundColor Green
Write-Host ""
Write-Host "The SIEM stack will now auto-start on boot and login." -ForegroundColor Cyan
Write-Host "Startup log: C:\PlanB-SIEM\startup.log" -ForegroundColor Gray
Write-Host ""
