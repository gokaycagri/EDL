# This script compacts the Docker Desktop WSL virtual disk (docker_data.vhdx) to reclaim free space.
# IMPORTANT: Run this script from an Administrator PowerShell terminal.

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " WSL/Docker VHDX Disk Compactor" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Check for Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script MUST be run as Administrator. Please open PowerShell as Administrator and run it again."
    Exit
}

# 2. Check path
$vhdxPath = "C:\Users\muhammet.cetin\AppData\Local\Docker\wsl\disk\docker_data.vhdx"
if (-not (Test-Path $vhdxPath)) {
    Write-Error "Could not find the Docker VHDX file at: $vhdxPath"
    Exit
}

$initialSize = [math]::Round((Get-Item $vhdxPath).Length / 1GB, 2)
Write-Host "Current VHDX File Size: $initialSize GB" -ForegroundColor Yellow

# 3. Prompt user to close Docker Desktop
Write-Host "`nPlease close Docker Desktop if it is open, then press ENTER to continue..." -ForegroundColor Cyan
Read-Host

Write-Host "Shutting down WSL and Docker services..." -ForegroundColor Yellow
Stop-Process -Name *docker* -Force -ErrorAction SilentlyContinue
wsl --shutdown

# Wait for WSL to fully close
Start-Sleep -Seconds 5

# 4. Create and run diskpart script
$diskpartScriptPath = "$env:TEMP\diskpart_compact.txt"
$diskpartContent = @"
select vdisk file="$vhdxPath"
attach vdisk readonly
compact vdisk
detach vdisk
"@

Set-Content -Path $diskpartScriptPath -Value $diskpartContent -Encoding Ascii

Write-Host "Compacting disk file (this may take a few minutes)..." -ForegroundColor Yellow
diskpart /s $diskpartScriptPath

# Cleanup
Remove-Item $diskpartScriptPath -ErrorAction SilentlyContinue

# 5. Show results
if (Test-Path $vhdxPath) {
    $finalSize = [math]::Round((Get-Item $vhdxPath).Length / 1GB, 2)
    $saved = $initialSize - $finalSize
    Write-Host "`n==========================================" -ForegroundColor Green
    Write-Host "Compaction Completed!" -ForegroundColor Green
    Write-Host "Initial Size: $initialSize GB" -ForegroundColor White
    Write-Host "Final Size:   $finalSize GB" -ForegroundColor White
    Write-Host "Saved Space:  $saved GB" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
} else {
    Write-Error "VHDX file could not be found after compaction!"
}
