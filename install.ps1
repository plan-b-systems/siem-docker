# Plan-B Systems SIEM v2 - Bootstrap Installer
# Usage: Open PowerShell as Administrator, paste this one-liner:
#   irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/v2/install.ps1 | iex

$ProgressPreference = "SilentlyContinue"

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Run this as Administrator!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    return
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Plan-B Systems SIEM v2 - Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$installDir = "C:\PlanB-SIEM"
$tempDir = "$env:TEMP\plansb-install-$(Get-Random)"
$zipUrl = "https://github.com/plan-b-systems/siem-docker/archive/refs/heads/v2.zip"
$zipFile = "$tempDir\siem-docker.zip"

try {
    # Download to temp
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Write-Host "Downloading siem-docker v2 from GitHub..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
    Write-Host "  [OK] Downloaded" -ForegroundColor Green

    # Extract to temp
    Write-Host "Extracting..." -ForegroundColor Yellow
    Expand-Archive -Path $zipFile -DestinationPath $tempDir -Force
    Remove-Item $zipFile -Force
    Write-Host "  [OK] Extracted" -ForegroundColor Green

    # Clean old install
    if (Test-Path $installDir) {
        Write-Host "Cleaning previous installation..." -ForegroundColor Yellow
        # Kill any processes holding locks
        Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($installDir) } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
        if (Test-Path $installDir) {
            Write-Host "  [WARN] Old install partially locked, continuing anyway..." -ForegroundColor Yellow
        } else {
            Write-Host "  [OK] Old install removed" -ForegroundColor Green
        }
    }

    # Move extracted files to install directory
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    # Find the extracted folder (GitHub names it siem-docker-2 or siem-docker-v2)
    $extractedDir = Get-ChildItem -Path $tempDir -Directory | Select-Object -First 1
    if (-not $extractedDir) {
        throw "No folder found after extraction in $tempDir"
    }
    Write-Host "  Found: $($extractedDir.Name)" -ForegroundColor Gray
    Copy-Item -Recurse -Force "$($extractedDir.FullName)\*" "$installDir\" -ErrorAction Stop
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    Write-Host "  [OK] Installed to $installDir" -ForegroundColor Green

    # Verify deploy script exists
    $deployScript = "$installDir\deploy-windows.ps1"
    if (-not (Test-Path $deployScript)) {
        Write-Host "ERROR: deploy-windows.ps1 not found!" -ForegroundColor Red
        Write-Host "Contents:" -ForegroundColor Yellow
        Get-ChildItem $installDir | ForEach-Object { Write-Host "  $($_.Name)" }
        Read-Host "Press Enter to exit"
        return
    }

    Write-Host ""
    Write-Host "Starting deployment..." -ForegroundColor Green
    Write-Host ""

    Set-Location $installDir
    & $deployScript
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
}
finally {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
