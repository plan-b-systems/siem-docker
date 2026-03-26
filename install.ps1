# Plan-B Systems SIEM - Bootstrap Installer
# Usage: Open PowerShell as Administrator, paste this one-liner:
#   irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Admin check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run this as Administrator!" -ForegroundColor Red
    exit 1
}

$installDir = "C:\PlanB-SIEM"
$zipUrl = "https://github.com/plan-b-systems/siem-docker/archive/refs/heads/main.zip"
$zipFile = "$installDir\siem-docker.zip"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Plan-B Systems SIEM - Bootstrap Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Create install directory
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Download
Write-Host "Downloading siem-docker from GitHub..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing

# Extract
Write-Host "Extracting..." -ForegroundColor Yellow
Expand-Archive -Path $zipFile -DestinationPath $installDir -Force
Remove-Item $zipFile -Force

# The archive extracts to siem-docker-main
$deployScript = "$installDir\siem-docker-main\deploy-windows.ps1"

if (-not (Test-Path $deployScript)) {
    Write-Host "ERROR: deploy-windows.ps1 not found after extraction!" -ForegroundColor Red
    exit 1
}

Write-Host "Starting deployment..." -ForegroundColor Green
Write-Host ""

# Run the deployment script
Set-Location "$installDir\siem-docker-main"
& $deployScript
