# Plan-B Systems SIEM v2 - Bootstrap Installer
# Usage: Open PowerShell as Administrator, paste this one-liner:
#   irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/v2/install.ps1 | iex

$ProgressPreference = "SilentlyContinue"

# Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run this as Administrator!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    return
}

$installDir = "C:\PlanB-SIEM"
$zipUrl = "https://github.com/plan-b-systems/siem-docker/archive/refs/heads/v2.zip"
$zipFile = "$installDir\siem-docker.zip"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Plan-B Systems SIEM v2 - Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

try {
    # Clean previous install if exists
    if (Test-Path "$installDir\siem-docker-v2") {
        Write-Host "Removing previous v2 installation..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force "$installDir\siem-docker-v2" -ErrorAction SilentlyContinue
    }

    # Create install directory
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    # Download
    Write-Host "Downloading siem-docker v2 from GitHub..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing

    # Extract
    Write-Host "Extracting..." -ForegroundColor Yellow
    Expand-Archive -Path $zipFile -DestinationPath $installDir -Force
    Remove-Item $zipFile -Force

    # The archive extracts to siem-docker-v2
    $deployScript = "$installDir\siem-docker-v2\deploy-windows.ps1"

    if (-not (Test-Path $deployScript)) {
        Write-Host "ERROR: deploy-windows.ps1 not found after extraction!" -ForegroundColor Red
        Write-Host "Contents of ${installDir}:" -ForegroundColor Yellow
        Get-ChildItem $installDir -Recurse -Depth 1 | ForEach-Object { Write-Host "  $_" }
        Read-Host "Press Enter to exit"
        return
    }

    Write-Host "Starting deployment..." -ForegroundColor Green
    Write-Host ""

    # Run the deployment script
    Set-Location "$installDir\siem-docker-v2"
    & $deployScript
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    Read-Host "Press Enter to exit"
}
