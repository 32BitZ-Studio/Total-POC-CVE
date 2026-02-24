#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Permanently disables Intel NUC Performance Driver via Group Policy.
.DESCRIPTION
    Creates a Group Policy device installation restriction that blocks
    ACPI\INTC1036 from loading, then disables the device.
    This is the most secure option - eliminates the attack surface entirely.
.NOTES
    Run as Administrator. Reboot recommended after running.
#>

$ErrorActionPreference = "Stop"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Disabling Intel NUC Performance Driver" -ForegroundColor Cyan
Write-Host " via Group Policy Device Restriction" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Step 1: Create the policy registry keys
Write-Host "[1/4] Creating Group Policy device restriction..." -ForegroundColor Yellow
$restrictionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$denyListPath = "$restrictionPath\DenyDeviceIDs"

New-Item -Path $restrictionPath -Force | Out-Null
New-ItemProperty -Path $restrictionPath -Name "DenyDeviceIDs" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $restrictionPath -Name "DenyDeviceIDsRetroactive" -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "       Policy keys created" -ForegroundColor Green

# Step 2: Add hardware ID to deny list
Write-Host "[2/4] Adding ACPI\INTC1036 to deny list..." -ForegroundColor Yellow
New-Item -Path $denyListPath -Force | Out-Null
New-ItemProperty -Path $denyListPath -Name "1" -Value "ACPI\INTC1036" -PropertyType String -Force | Out-Null
Write-Host "       Hardware ID blocked" -ForegroundColor Green

# Step 3: Attempt to disable the device (optional - policy is the real enforcement)
Write-Host "[3/4] Disabling device..." -ForegroundColor Yellow
$device = Get-PnpDevice | Where-Object { $_.InstanceId -like '*INTC1036*' }
if ($device) {
    if ($device.Status -eq 'OK') {
        try {
            Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Host "       Device disabled" -ForegroundColor Green
        } catch {
            # ACPI devices often can't be disabled via PnP - this is expected
            Write-Host "       Device is ACPI (cannot PnP-disable)" -ForegroundColor Yellow
            Write-Host "       Group Policy will block driver loading after reboot" -ForegroundColor Green
        }
    } else {
        Write-Host "       Device already disabled/blocked" -ForegroundColor Green
    }
} else {
    Write-Host "       Device not found (may already be removed)" -ForegroundColor Yellow
}

# Step 4: Verify
Write-Host "[4/4] Verifying..." -ForegroundColor Yellow
$verify = Get-ItemProperty -Path $denyListPath -ErrorAction SilentlyContinue
if ($verify.'1' -eq 'ACPI\INTC1036') {
    Write-Host "       Group Policy block verified" -ForegroundColor Green
} else {
    Write-Host "       WARNING: Verification failed" -ForegroundColor Red
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "`nThe Intel NUC Performance Driver is now:" -ForegroundColor White
Write-Host "  - Blocked by Group Policy (driver will not load after reboot)" -ForegroundColor White
Write-Host "  - Protected from Windows Update driver reinstallation" -ForegroundColor White
Write-Host "`nA reboot is recommended to ensure all changes take effect." -ForegroundColor Yellow
Write-Host "`nTo revert, run: .\revert-device-gpo.ps1`n" -ForegroundColor Gray
