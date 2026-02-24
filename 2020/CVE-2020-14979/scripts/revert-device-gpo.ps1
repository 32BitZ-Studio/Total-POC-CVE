#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reverts the Group Policy device block and re-enables the Intel NUC Performance Driver.
.DESCRIPTION
    Removes the device installation restriction policy and re-enables ACPI\INTC1036.
    Use this if you need to restore NUC fan/LED control functionality.
.NOTES
    Run as Administrator. Reboot recommended after running.
#>

$ErrorActionPreference = "Stop"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Reverting Intel NUC Performance Driver Block" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Step 1: Remove Group Policy
Write-Host "[1/2] Removing Group Policy device restriction..." -ForegroundColor Yellow
$restrictionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if (Test-Path $restrictionPath) {
    Remove-Item -Path $restrictionPath -Recurse -Force
    Write-Host "       Policy removed" -ForegroundColor Green
} else {
    Write-Host "       Policy not found (already removed)" -ForegroundColor Yellow
}

# Step 2: Re-enable device (if possible)
Write-Host "[2/2] Re-enabling device..." -ForegroundColor Yellow
$device = Get-PnpDevice | Where-Object { $_.InstanceId -like '*INTC1036*' }
if ($device) {
    if ($device.Status -ne 'OK') {
        try {
            Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Host "       Device enabled" -ForegroundColor Green
        } catch {
            # ACPI devices often can't be toggled via PnP
            Write-Host "       Device is ACPI (will re-enable after reboot)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "       Device already enabled" -ForegroundColor Green
    }
} else {
    Write-Host "       Device not found" -ForegroundColor Yellow
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "`nThe Intel NUC Performance Driver block has been removed." -ForegroundColor White
Write-Host "Windows Update may now offer driver updates for this device." -ForegroundColor Yellow
Write-Host "`nA reboot is recommended.`n" -ForegroundColor Yellow
