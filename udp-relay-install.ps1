# ============================================================
# Plan-B Systems SIEM v2 - Install the UDP 514 relay as a
# persistent SYSTEM scheduled task (same context as the
# PlanB-SIEM-Autostart task). Run once:
#   irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/udp-relay-install.ps1 | iex
# IMPORTANT: stop any relay already running in a window first
# (it holds UDP 514), or this task can't bind the port.
# ============================================================
$ErrorActionPreference = 'Stop'
$dir   = 'C:\PlanB-SIEM'
$relay = Join-Path $dir 'udp-relay.ps1'
$url   = 'https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/udp-relay.ps1'

New-Item -ItemType Directory -Path $dir -Force | Out-Null

# Stop any existing relay (task + stray process holding UDP 514) for a clean swap.
Stop-ScheduledTask -TaskName 'PlanB-SIEM-UDP-Relay' -ErrorAction SilentlyContinue | Out-Null
try {
    $busy = (Get-NetUDPEndpoint -LocalPort 514 -ErrorAction SilentlyContinue).OwningProcess
    foreach ($p in $busy) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }
} catch {}
Start-Sleep -Seconds 2

Invoke-RestMethod -Uri $url -OutFile $relay
Write-Host "Downloaded relay -> $relay"

$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$relay`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName 'PlanB-SIEM-UDP-Relay' -Action $action -Trigger $trigger `
    -Settings $settings -RunLevel Highest -User 'SYSTEM' -Force | Out-Null
Start-ScheduledTask -TaskName 'PlanB-SIEM-UDP-Relay'

Write-Host "Registered + started PlanB-SIEM-UDP-Relay (SYSTEM, at startup, auto-restart)."
Write-Host "Relay log: $dir\udp-relay.log"
