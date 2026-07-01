# ============================================================
# Plan-B Systems SIEM - Register Windows Scheduled Task
# Run this once as Administrator after installation
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Plan-B Systems SIEM - Scheduled Task Registration" -ForegroundColor Cyan
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

# The task MUST run as the interactive user, NOT SYSTEM: the PlanB-SIEM WSL distro
# is per-user and SYSTEM cannot see it, so a SYSTEM-run task fails to start the
# distro after a reboot (original 43h-outage cause). Prompt once for the password
# so the task uses Password logon (runs whether or not the user is logged in).
$taskUserName = "$env:USERDOMAIN\$env:USERNAME"
$taskCred = Get-Credential -UserName $taskUserName -Message "Password for $taskUserName - the SIEM auto-start task runs as this user so it can see the per-user WSL distro"

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
    -User $taskCred.UserName -Password $taskCred.GetNetworkCredential().Password `
    -Settings $settings `
    -Force | Out-Null

Write-Host "  Scheduled task 'PlanB-SIEM-Autostart' registered" -ForegroundColor Green
Write-Host ""
Write-Host "The SIEM stack will now auto-start on boot and login." -ForegroundColor Cyan
Write-Host "Startup log: C:\PlanB-SIEM\startup.log" -ForegroundColor Gray
Write-Host ""
