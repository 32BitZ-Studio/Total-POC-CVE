#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blocks driver updates for Intel NUC Performance Driver via Group Policy.
.DESCRIPTION
    Creates a Group Policy device installation restriction that blocks
    driver updates for ACPI\INTC1036, but keeps the device enabled.
    The current base driver remains functional.
.NOTES
    Run as Administrator.
#>

$ErrorActionPreference = "Stop"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Blocking Driver Updates for INTC1036" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Step 1: Create the policy registry keys
Write-Host "[1/3] Creating Group Policy device restriction..." -ForegroundColor Yellow
$restrictionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$denyListPath = "$restrictionPath\DenyDeviceIDs"

New-Item -Path $restrictionPath -Force | Out-Null
New-ItemProperty -Path $restrictionPath -Name "DenyDeviceIDs" -Value 1 -PropertyType DWord -Force | Out-Null
# Note: NOT setting DenyDeviceIDsRetroactive - allows current driver to remain
Write-Host "       Policy keys created" -ForegroundColor Green

# Step 2: Add hardware ID to deny list
Write-Host "[2/3] Adding ACPI\INTC1036 to deny list..." -ForegroundColor Yellow
New-Item -Path $denyListPath -Force | Out-Null
New-ItemProperty -Path $denyListPath -Name "1" -Value "ACPI\INTC1036" -PropertyType String -Force | Out-Null
Write-Host "       Hardware ID blocked from updates" -ForegroundColor Green

# Step 3: Verify
Write-Host "[3/3] Verifying..." -ForegroundColor Yellow
$verify = Get-ItemProperty -Path $denyListPath -ErrorAction SilentlyContinue
if ($verify.'1' -eq 'ACPI\INTC1036') {
    Write-Host "       Group Policy block verified" -ForegroundColor Green
} else {
    Write-Host "       WARNING: Verification failed" -ForegroundColor Red
}

# Show current device status
$device = Get-PnpDevice | Where-Object { $_.InstanceId -like '*INTC1036*' }
if ($device) {
    Write-Host "`nCurrent device status:" -ForegroundColor White
    Write-Host "  Name: $($device.FriendlyName)" -ForegroundColor Gray
    Write-Host "  Status: $($device.Status)" -ForegroundColor Gray
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "`nThe device remains enabled with its current driver," -ForegroundColor White
Write-Host "but Windows Update cannot install new drivers for it." -ForegroundColor White
Write-Host "`nTo revert, run: .\revert-device-gpo.ps1`n" -ForegroundColor Gray
