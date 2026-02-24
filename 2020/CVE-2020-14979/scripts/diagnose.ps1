#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Diagnoses Intel NUC WinRing0 vulnerable driver status.
.DESCRIPTION
    Checks for the presence of NucSoftwareStudioService, the vulnerable driver,
    pending Windows Updates, and current device/policy status.
#>

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Intel NUC WinRing0 Diagnostic Report" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Check NucSoftwareStudioService
Write-Host "[1/7] NucSoftwareStudioService..." -ForegroundColor Yellow -NoNewline
$service = Get-Service -Name "NucSoftwareStudioService" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host " FOUND ($($service.Status))" -ForegroundColor Red
} else {
    Write-Host " Not found (good)" -ForegroundColor Green
}

# 2. Check for driver in driver store
Write-Host "[2/7] Driver store (performancedriverextension.inf)..." -ForegroundColor Yellow -NoNewline
$driverInStore = pnputil /enum-drivers | Select-String "performancedriverextension"
if ($driverInStore) {
    Write-Host " FOUND" -ForegroundColor Red
    pnputil /enum-drivers | Select-String "performancedriverextension" -Context 2,2
} else {
    Write-Host " Not found (good)" -ForegroundColor Green
}

# 3. Check for vulnerable driver file
Write-Host "[3/7] OpenHardwareMonitorLib.sys file..." -ForegroundColor Yellow -NoNewline
$driverFiles = Get-ChildItem -Path "C:\Windows\System32\DriverStore\FileRepository" -Recurse -Filter "OpenHardwareMonitorLib.sys" -ErrorAction SilentlyContinue
if ($driverFiles) {
    Write-Host " FOUND" -ForegroundColor Red
    $driverFiles | ForEach-Object { Write-Host "       $_" -ForegroundColor Red }
} else {
    Write-Host " Not found (good)" -ForegroundColor Green
}

# 4. Check ACPI device status
Write-Host "[4/7] Intel NUC Performance Driver device..." -ForegroundColor Yellow -NoNewline
$device = Get-PnpDevice | Where-Object { $_.InstanceId -like '*INTC1036*' }
if ($device) {
    if ($device.Status -eq 'OK') {
        Write-Host " Enabled" -ForegroundColor Yellow
    } elseif ($device.Status -eq 'Error') {
        Write-Host " Disabled (good)" -ForegroundColor Green
    } else {
        Write-Host " $($device.Status)" -ForegroundColor Yellow
    }
    Write-Host "       Device: $($device.FriendlyName)" -ForegroundColor Gray
    Write-Host "       Instance: $($device.InstanceId)" -ForegroundColor Gray
} else {
    Write-Host " Not found" -ForegroundColor Gray
}

# 5. Check Group Policy device block
Write-Host "[5/7] Group Policy device block..." -ForegroundColor Yellow -NoNewline
$denyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
if (Test-Path $denyPath) {
    $deniedDevices = Get-ItemProperty -Path $denyPath -ErrorAction SilentlyContinue
    $intcBlocked = $deniedDevices.PSObject.Properties | Where-Object { $_.Value -like '*INTC1036*' }
    if ($intcBlocked) {
        Write-Host " INTC1036 blocked (good)" -ForegroundColor Green
    } else {
        Write-Host " Policy exists but INTC1036 not in list" -ForegroundColor Yellow
    }
} else {
    Write-Host " Not configured" -ForegroundColor Gray
}

# 6. Check Windows Update driver exclusion
Write-Host "[6/7] Windows Update driver exclusion registry..." -ForegroundColor Yellow -NoNewline
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$excludeDrivers = Get-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
if ($excludeDrivers.ExcludeWUDriversInQualityUpdate -eq 1) {
    Write-Host " Enabled" -ForegroundColor Green
} else {
    Write-Host " Not set" -ForegroundColor Gray
}

# 7. Check pending Windows Updates for Intel extension
Write-Host "[7/7] Pending Intel extension updates..." -ForegroundColor Yellow -NoNewline
try {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $results = $searcher.Search('IsInstalled=0')
    $intelUpdates = $results.Updates | Where-Object { $_.Title -like '*Intel*Extension*' }
    if ($intelUpdates) {
        Write-Host " FOUND" -ForegroundColor Red
        $intelUpdates | ForEach-Object { Write-Host "       $($_.Title)" -ForegroundColor Red }
    } else {
        Write-Host " None pending (good)" -ForegroundColor Green
    }
} catch {
    Write-Host " Could not query" -ForegroundColor Gray
}

# 8. Recent Defender detections
Write-Host "`n[Bonus] Recent Defender WinRing0 detections..." -ForegroundColor Yellow
$threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
    Where-Object { $_.Resources -like '*OpenHardwareMonitorLib*' -or $_.Resources -like '*WinRing0*' } |
    Select-Object -First 3
if ($threats) {
    Write-Host "       Found $($threats.Count) detection(s) in history" -ForegroundColor Yellow
    Write-Host "       (These are historical records - clear via Windows Security if desired)" -ForegroundColor Gray
} else {
    Write-Host "       None found" -ForegroundColor Green
}

Write-Host "`n========================================"  -ForegroundColor Cyan
Write-Host " Diagnosis complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
