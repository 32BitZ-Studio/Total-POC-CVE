# Intel NUC WinRing0 Vulnerable Driver - Permanent Removal Guide

Windows Defender flags `OpenHardwareMonitorLib.sys` (WinRing0 driver) as **VulnerableDriver:WinNT/Winring0** due to [CVE-2020-14979](https://nvd.nist.gov/vuln/detail/CVE-2020-14979). This driver is bundled with Intel's NUC Software Studio service and gets reinstalled via Windows Update.

This repository provides a permanent solution.

## The Problem

1. Intel's `performancedriverextension.inf` installs `NucSoftwareStudioService`
2. The service deploys `OpenHardwareMonitorLib.sys` (WinRing0 kernel driver)
3. Windows Defender detects it as a vulnerable driver (CVE-2020-14979)
4. Windows Update `Intel Corporation - Extension - 1.0.0.38` keeps reinstalling it
5. Standard removal methods don't prevent reinstallation

## Root Cause

The **Intel NUC Performance Driver** (`ACPI\INTC1036`) is an ACPI device that exposes NUC-specific features:
- Fan control (software-adjustable curves)
- LED control (RGB/power LED customization)
- Thermal monitoring
- Power management

The vulnerable extension hooks into this base driver. Windows Update sees the device and offers driver updates for it.

## Solutions (Choose One)

### Option A: Permanently Disable the Device (Recommended)

This disables the ACPI device entirely via Group Policy, preventing any drivers from loading.

Run `scripts/disable-device-gpo.ps1` as Administrator, or manually:

```powershell
# Run as Administrator
.\scripts\disable-device-gpo.ps1
```

### Option B: Block Driver Updates Only

Keeps the base driver but blocks all Windows Update driver installations for this device.

**Trade-offs:**
- Device remains functional with current base driver
- Won't receive future driver updates (security or otherwise)

Run `scripts/block-driver-updates.ps1` as Administrator.

### Option C: Manual Cleanup + Hide Update

Less permanent - requires re-hiding if Intel releases new versions.

Run `scripts/remove-and-hide.ps1` as Administrator.

## Quick Diagnosis

Check your current status:

```powershell
.\scripts\diagnose.ps1
```

## File Locations Reference

| Component | Path |
|-----------|------|
| Service executable | `C:\WINDOWS\System32\DriverStore\FileRepository\performancedriverextension.inf_amd64_*\Service\NucSoftwareStudioService.exe` |
| Vulnerable driver | `...\Service\OpenHardwareMonitorLib.sys` |
| Base driver inf | `oem*.inf` (PerformanceDriver) |
| Extension inf | `performancedriverextension.inf` |

## Verification

After applying any solution, verify:

```powershell
# Check service is gone
sc.exe query NucSoftwareStudioService

# Check no pending Intel extension updates
# (Run scripts/diagnose.ps1 for full status)
```

## Validation Testing

### GPO Block vs Windows Update (Tested 2025-01-17)

**Scenario:** Verify that the Group Policy device block (Option A) survives Windows Update attempting to install the vulnerable driver.

**Test procedure:**
1. Applied GPO block for `ACPI\INTC1036` (device disabled)
2. Removed broad Windows Update driver exclusion registry (normal update behavior)
3. Unhid "Intel Corporation - Extension - 1.0.0.38" in Windows Update
4. Allowed Windows Update to download and install the package
5. Rebooted system

**Results after Windows Update installed the package:**
| Check | Result |
|-------|--------|
| NucSoftwareStudioService | Not found (good) |
| Driver store | `performancedriverextension.inf` staged as `oem17.inf` |
| OpenHardwareMonitorLib.sys | Not extracted (good) |
| Device INTC1036 | **Disabled** - GPO held |
| GPO block registry | Active |

**Key finding:** The GPO device block is the effective protection layer. Windows Update can stage the driver package to the driver store, but it **cannot activate** because the hardware ID is blocked. The vulnerable `.sys` file is never extracted or loaded.

### Complete Cleanup (Tested 2025-01-17)

After confirming the GPO block held, completed full cleanup:

1. Removed staged driver from store: `pnputil /delete-driver oem17.inf`
2. Hid Intel extension update via `wushowhide.diagcab`

**Final verified state:**
| Component | Status |
|-----------|--------|
| NucSoftwareStudioService | Not found ✓ |
| Driver store (performancedriverextension.inf) | Clean ✓ |
| OpenHardwareMonitorLib.sys | Not present ✓ |
| Intel NUC Performance Driver device | Disabled ✓ |
| Group Policy device block | Active (INTC1036 blocked) ✓ |
| Intel extension update | Hidden ✓ |

## Recommendation

> **The hardware ID block alone is sufficient protection.**

Testing demonstrated that blocking `ACPI\INTC1036` via Group Policy prevents the vulnerable driver from ever loading, even when Windows Update successfully downloads and stages the driver package. The service executable and `.sys` file are never extracted because the target device is disabled.

**Recommended minimal configuration:**
- ✓ **GPO device block for `ACPI\INTC1036`** — This is the only required protection
- ✓ Hide Intel extension via wushowhide — Optional, prevents repeated download/staging
- ✗ Broad driver exclusion registry — Not needed, interferes with legitimate driver updates
- ✗ Complex driver store monitoring — Not needed, blocked drivers cannot activate

The simplicity of this approach is its strength: a single registry-based device block provides complete protection without interfering with normal Windows Update functionality for other devices.

## What You Lose (and What Still Works)

When the Intel NUC Performance Driver device (`ACPI\INTC1036`) is disabled:

**No longer available:**
- Intel NUC Software Studio application
- Software-controlled fan curves (custom profiles via Windows)
- Software-controlled LED/RGB customization
- Windows-based thermal monitoring via Intel tools
- Any third-party apps that depend on this driver for NUC-specific features

**Still works normally:**
- BIOS-configured fan profiles (set in BIOS, runs independently)
- BIOS-configured LED settings
- Hardware thermal protection (CPU throttling, emergency shutdown)
- All other system functions, Windows Update, other drivers
- Standard Windows temperature monitoring (Task Manager, other tools)

**Why this is acceptable for most users:**
The NUC Performance Driver primarily enables *software customization* of fan/LED behavior. The BIOS provides default profiles that work without any Windows driver. Most users set fan curves once in BIOS and never touch them again. If you require dynamic Windows-based fan control (e.g., gaming profiles that switch automatically), Option A may not be suitable—consider Option B instead.

## Reverting Changes

### To re-enable the device:
```powershell
# Remove the Group Policy block
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Recurse -Force

# Re-enable the device
$device = Get-PnpDevice | Where-Object { $_.InstanceId -like '*INTC1036*' }
Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false
```

### To unblock driver updates:
```powershell
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Recurse -Force
```

## References

- [CVE-2020-14979 - WinRing0 Privilege Escalation](https://nvd.nist.gov/vuln/detail/CVE-2020-14979)
- [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)

## Contributing

If you have additional findings or improvements, please open an issue or PR.

## License

MIT License - Use at your own risk. Always verify scripts before running as Administrator.
