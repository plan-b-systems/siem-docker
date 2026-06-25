# Quick UDP 514 path test — sends 10 syslog packets to the SIEM box.
$target = '10.0.0.11'
$port   = 514
$u = [System.Net.Sockets.UdpClient]::new()
1..10 | ForEach-Object {
    $line = "<134>$(Get-Date -Format 'MMM dd HH:mm:ss') udp-path-test seq=$_ msg=relay_check"
    $b = [System.Text.Encoding]::UTF8.GetBytes($line)
    [void]$u.Send($b, $b.Length, $target, $port)
    Start-Sleep -Milliseconds 50
}
$u.Close()
Write-Host "Sent 10 UDP test packets to ${target}:${port}. On the box, [stats] UDP should climb by ~10."
