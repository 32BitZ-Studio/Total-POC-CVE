#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes NucSoftwareStudioService and hides the Windows Update that reinstalls it.
.DESCRIPTION
    This is the less permanent option. It removes the current installation and
    hides the specific Windows Update version. If Intel releases a new version,
    you'll need to hide that one too.
.NOTES
    Run as Administrator.
#>

$ErrorActionPreference = "Continue"

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Remove and Hide Intel NUC Extension" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Step 1: Stop and delete service
Write-Host "[1/5] Stopping NucSoftwareStudioService..." -ForegroundColor Yellow
$service = Get-Service -Name "NucSoftwareStudioService" -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name "NucSoftwareStudioService" -Force -ErrorAction SilentlyContinue
    sc.exe delete NucSoftwareStudioService | Out-Null
    Write-Host "       Service deleted" -ForegroundColor Green
} else {
    Write-Host "       Service not found (already removed)" -ForegroundColor Green
}

# Step 2: Remove driver from driver store
Write-Host "[2/5] Removing driver from driver store..." -ForegroundColor Yellow
$drivers = pnputil /enum-drivers | Select-String -Pattern "performancedriverextension" -Context 2,0
if ($drivers) {
    # Extract the oem*.inf name
    $oemMatch = $drivers.Context.PreContext | Select-String "oem\d+\.inf"
    if ($oemMatch) {
        $oemInf = ($oemMatch.Matches[0].Value)
        Write-Host "       Found: $oemInf" -ForegroundColor Gray
        pnputil /delete-driver $oemInf /force | Out-Null
        Write-Host "       Driver removed from store" -ForegroundColor Green
    }
} else {
    Write-Host "       Driver not found in store (already removed)" -ForegroundColor Green
}

# Step 3: Delete leftover files
Write-Host "[3/5] Cleaning up driver files..." -ForegroundColor Yellow
$folders = Get-ChildItem -Path "C:\Windows\System32\DriverStore\FileRepository" -Directory -Filter "performancedriverextension*" -ErrorAction SilentlyContinue
if ($folders) {
    foreach ($folder in $folders) {
        try {
            Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
            Write-Host "       Deleted: $($folder.Name)" -ForegroundColor Green
        } catch {
            Write-Host "       Could not delete: $($folder.Name) (may need reboot)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "       No leftover folders found" -ForegroundColor Green
}

# Step 4: Set registry to exclude drivers from Windows Update
Write-Host "[4/5] Setting Windows Update driver exclusion..." -ForegroundColor Yellow
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (!(Test-Path $wuPath)) {
    New-Item -Path $wuPath -Force | Out-Null
}
New-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "       Registry key set" -ForegroundColor Green

# Step 5: Hide the Windows Update
Write-Host "[5/5] Hiding Intel Extension update..." -ForegroundColor Yellow
try {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $results = $searcher.Search('IsInstalled=0')
    $hidden = $false
    foreach ($update in $results.Updates) {
        if ($update.Title -like '*Intel*Extension*') {
            Write-Host "       Found: $($update.Title)" -ForegroundColor Gray
            $update.IsHidden = $true
            $hidden = $true
            Write-Host "       Update hidden" -ForegroundColor Green
        }
    }
    if (!$hidden) {
        Write-Host "       No pending Intel Extension updates found" -ForegroundColor Green
    }
} catch {
    Write-Host "       Could not hide update: $_" -ForegroundColor Red
    Write-Host "       Try using Microsoft's wushowhide.diagcab tool" -ForegroundColor Yellow
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "`nNOTE: This method hides a specific update version." -ForegroundColor Yellow
Write-Host "If Intel releases a new version, it may reappear." -ForegroundColor Yellow
Write-Host "For a permanent solution, use disable-device-gpo.ps1`n" -ForegroundColor Yellow
