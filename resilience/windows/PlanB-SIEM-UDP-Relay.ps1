# ============================================================
# Plan-B Systems SIEM v2 - Windows UDP 514 Relay
# ------------------------------------------------------------
# netsh portproxy forwards TCP only. Senders that use UDP 514
# (Check Point, FortiGate, generic syslog) therefore never reach
# the WSL containers. This relay bridges the gap:
#     host 0.0.0.0:514/udp  ->  WSL <distro>:514/udp
# Runs as a Scheduled Task at startup; loops forever and
# re-resolves the WSL IP every ~15s so it survives WSL restarts.
# ============================================================
$ErrorActionPreference = 'Continue'
$distro = 'PlanB-SIEM'
$port   = 514
$logDir = 'C:\PlanB-SIEM'
$log    = Join-Path $logDir 'udp-relay.log'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
function Write-Log($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [UDP-Relay] $m" | Out-File -Append -FilePath $log }

Write-Log "Starting UDP relay 0.0.0.0:$port -> ${distro}:$port"

# Bind UDP 514, retrying for ~5 min if the port is briefly held (relay hand-off).
$udp = $null
for ($i = 1; $i -le 60; $i++) {
    try { $udp = [System.Net.Sockets.UdpClient]::new($port); break }
    catch {
        Write-Log "bind attempt $i failed (port busy?), retry in 5s: $($_.Exception.Message)"
        Start-Sleep -Seconds 5
    }
}
if (-not $udp) { Write-Log "FATAL: could not bind UDP $port after retries"; exit 1 }
Write-Log "Bound UDP $port"
$udp.Client.ReceiveTimeout = 15000
$fwd       = [System.Net.Sockets.UdpClient]::new()
$any       = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
$wslIP     = $null
$lastCheck = [DateTime]::MinValue
$count     = 0

while ($true) {
    # Resolve the WSL IP every 15s. Read it from the portproxy table (the startup
    # script maintains it there) — that works under the SYSTEM task context, where
    # `wsl -d <distro> -- hostname -I` does NOT. Fall back to wsl when run as the user.
    if (([DateTime]::Now - $lastCheck).TotalSeconds -ge 15) {
        $ip = $null
        foreach ($l in (netsh interface portproxy show all 2>$null)) {
            if ($l -match '^\s*\d{1,3}(\.\d{1,3}){3}\s+\d+\s+(\d{1,3}(\.\d{1,3}){3})\s+\d+') { $ip = $matches[2]; break }
        }
        if (-not $ip) {
            $h = (wsl.exe -d $distro -- hostname -I 2>$null)
            if ($h -and ($h.Trim() -match '^\d{1,3}(\.\d{1,3}){3}')) { $ip = ($h.Trim() -split '\s+')[0] }
        }
        if ($ip -and $ip -ne $wslIP) { $wslIP = $ip; Write-Log "WSL IP -> $wslIP (forwarded $count so far)" }
        $lastCheck = [DateTime]::Now
    }
    try {
        $data = $udp.Receive([ref]$any)
        if ($wslIP) { [void]$fwd.Send($data, $data.Length, $wslIP, $port); $count++ }
    } catch [System.Net.Sockets.SocketException] {
        # ReceiveTimeout fired — loop back to refresh the WSL IP.
    } catch {
        Write-Log "recv error: $($_.Exception.Message)"; Start-Sleep -Milliseconds 500
    }
}
