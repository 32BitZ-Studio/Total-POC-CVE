# GameDriverX64-Killer
- PoC for CVE-2025-61155 vulnerability in GameDriverX64

- As of 2026-02, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `GameDriverX64.sys` SHA256: `9ddae47ff968343a8c32a5344060257fdc08e2a7bdb9a227c8b3a584ee3c9f1e`

> [!TIP]
> The driver will detect virtual machines (such as VBOX, VMWare, XenVMM, KVM) by CPUID and refuse to load if it detects one. If you encounter difficulties in this area, you can use a physical test machine for this PoC.

## Usage

Place `GameDriverX64.sys` in the same directory as the executable.

```text
BYOVD process killer using GameDriverX64 (CVE-2025-61155)

Usage: GameDriverX64-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p GameDriverX64-Killer

# Run
.\GameDriverX64-Killer.exe -n notepad.exe
```

