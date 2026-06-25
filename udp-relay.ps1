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
try {
    $udp = [System.Net.Sockets.UdpClient]::new($port)
} catch {
    Write-Log "FATAL: cannot bind UDP ${port}: $($_.Exception.Message)"
    exit 1
}
$udp.Client.ReceiveTimeout = 15000
$fwd       = [System.Net.Sockets.UdpClient]::new()
$any       = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
$wslIP     = $null
$lastCheck = [DateTime]::MinValue
$count     = 0

while ($true) {
    # Re-resolve the WSL IP every 15s (it changes when WSL restarts).
    if (([DateTime]::Now - $lastCheck).TotalSeconds -ge 15) {
        $ip = (wsl.exe -d $distro -- hostname -I 2>$null)
        if ($ip) { $ip = $ip.Trim().Split(' ')[0] }
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
