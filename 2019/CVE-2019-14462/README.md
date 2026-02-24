# seL4 ICS Gateway Demo

A defensive security research project comparing **protocol-break** vs **packet-forwarding** architectures for protecting industrial control systems from cyber attacks.

> **Documentation:**
> - [Network Architecture](docs/NETWORK.md) - Network diagrams and traffic flow
> - [Container Architecture](docs/CONTAINERS.md) - Docker container relationships
> - [CVE Explanations](docs/CVE.md) - Vulnerability details and attack mechanisms

## Research Motivation

Modern ICS/SCADA systems face sophisticated attacks like [FrostyGoop](https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology), which targeted Ukrainian district heating systems via Modbus TCP in January 2024, leaving 600+ households without heat during sub-zero temperatures. Traditional security solutions (firewalls, IDS) use **packet-forwarding** architectures that inspect traffic in-line but maintain a single TCP connection end-to-end.

This project demonstrates an alternative: a **protocol-break** gateway using the formally verified [seL4 microkernel](https://sel4.systems/). By terminating TCP connections and validating protocol semantics before establishing new connections to protected devices, this architecture provides stronger security guarantees.

## Key Findings

| Aspect | Protocol-Break (seL4) | Packet-Forwarding (Snort) |
|--------|----------------------|---------------------------|
| **CVE-2019-14462** | BLOCKED (length validation) | DETECTED (Quickdraw rules) |
| **CVE-2022-0367** | BLOCKED (address validation) | DETECTED (custom rules) |
| **CVE-2022-20685** | IMMUNE (no preprocessor) | VULNERABLE (IDS DoS) |
| **CVE-2024-1086** | IMMUNE (no Linux kernel) | VULNERABLE (shares host kernel) |
| **Unknown variants** | BLOCKED (structural validation) | MISSED (no signature) |
| **TCP state attacks** | BLOCKED (connection terminated) | Possible |
| **Attack surface** | ~1,000 LoC (microkernel) | ~500,000 LoC (Linux + Snort) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Docker Network: ics-untrusted (192.168.96.0/24)                             │
│                                                                             │
│   ┌───────────────────────┐       ┌───────────────────────┐                │
│   │ seL4 Gateway          │       │ Snort IDS             │                │
│   │ Port 502              │       │ Port 503              │                │
│   │                       │       │                       │                │
│   │ • Protocol-break      │       │ • Packet-forwarding   │                │
│   │ • TCP termination     │       │ • Inline inspection   │                │
│   │ • Length validation   │       │ • Rule-based detection│                │
│   └───────────┬───────────┘       └───────────┬───────────┘                │
│               │                               │                             │
├───────────────┼───────────────────────────────┼─────────────────────────────┤
│ Docker Network: ics-protected (192.168.95.0/24)                             │
│               │                               │                             │
│               └───────────────┬───────────────┘                             │
│                               ▼                                             │
│               ┌───────────────────────────────┐                             │
│               │ PLC (District Heating)        │                             │
│               │ Vulnerable libmodbus 3.1.2    │                             │
│               │ Port 5020 (direct access)     │                             │
│               └───────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose v2
- seL4 gateway kernel image (user-provided)
- ~4GB RAM for QEMU

### 1. Add seL4 Image

```bash
# Place your seL4 kernel image at:
gateway/sel4-image/capdl-loader-image-arm-qemu-arm-virt
```

### 2. Build and Run

```bash
# Build all containers
sudo docker compose build

# Start individual containers
sudo docker compose up plc        # PLC only
sudo docker compose up gateway    # seL4 gateway + PLC
sudo docker compose up snort      # Snort IDS + PLC

# Start all
sudo docker compose up
```

### 3. Test Connections

```bash
# Through seL4 gateway (protected - protocol-break)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc localhost 502 | xxd

# Through Snort IDS (protected - packet-forwarding)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc localhost 503 | xxd

# Direct to PLC (unprotected - vulnerable)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc localhost 5020 | xxd
```

## Port Mappings

| Port | Path | Architecture | Protection |
|------|------|--------------|------------|
| 502 | Client → seL4 → PLC | Protocol-break | Validates Modbus structure |
| 503 | Client → Snort → PLC | Packet-forwarding | Rule-based IDS |
| 5020 | Client → PLC (ASAN) | Direct | CVE-2022-0367 mode |
| 5022 | Client → PLC | Direct | CVE-2019-14462 mode (profile: cve14462) |

> **Note:** The default PLC now runs in CVE-2022-0367 mode with ASAN. Use `--profile cve14462` for CVE-2019-14462 testing.

## Vulnerability Demonstrations

### CVE-2019-14462: libmodbus Heap Buffer Overflow

The PLC uses intentionally vulnerable libmodbus 3.1.2. The attack exploits trusted MBAP length fields:

```bash
# Start PLC in CVE-2019-14462 mode
sudo docker compose --profile cve14462 up plc-14462

# Build attack tools
cd cve_tools && make

# Attack unprotected PLC (crashes)
./cve_14462_attack 127.0.0.1 5022

# Attack through seL4 (BLOCKED)
./cve_14462_attack 127.0.0.1 502

# Attack through Snort (DETECTED by Quickdraw rules)
./cve_14462_attack 127.0.0.1 503
```

### CVE-2022-0367: libmodbus Heap Buffer Underflow

A bounds-checking bug in `modbus_mapping_new_start_address()` allows heap underflow via function code 0x17 (Write and Read Registers):

```bash
# Default PLC runs in CVE-2022-0367 mode with ASAN
sudo docker compose up plc

# Build attack tools
cd cve_tools && make

# Attack PLC - ASAN will detect heap-buffer-overflow
./cve_0367_attack 127.0.0.1 5020

# Attack with custom parameters
./cve_0367_attack 127.0.0.1 5020 88 0x4141  # Corrupt tab_registers pointer
./cve_0367_attack 127.0.0.1 5020 72 0xFFFF  # Corrupt nb_registers

# Attack through seL4 (BLOCKED - address validation)
./cve_0367_attack 127.0.0.1 502

# Attack through Snort (DETECTED by custom rules)
./cve_0367_attack 127.0.0.1 503
```

**Technical Details:**
- Server uses `start_registers=100`, valid addresses are 100-109
- Attack sends `write_address < 100`, causing negative array index
- Heap underflow can corrupt `mb_mapping` struct fields including pointers

### CVE-2022-20685: Snort Modbus Preprocessor DoS

Snort 2.9.18 has an integer overflow in its Modbus preprocessor that causes an infinite loop, completely blocking all traffic through the IDS:

```bash
# 1. Verify Snort is working (should return Modbus response)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc -w 2 localhost 503 | xxd

# 2. Attack the Snort IDS
./cve_20685_attack 127.0.0.1 503

# 3. Verify Snort is frozen (should timeout with NO response)
echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01' | nc -w 5 localhost 503 | xxd

# 4. Check Snort CPU (should be 100%)
sudo docker exec ics-snort top -b -n 1 | grep snort

# 5. seL4 is IMMUNE (no Modbus preprocessor to exploit)
./cve_20685_attack 127.0.0.1 502  # No effect on seL4

# 6. Restart Snort after demo
sudo docker compose restart snort
```

**Why this is devastating:** Snort uses NFQUEUE inline mode, meaning packets are held in kernel queue until Snort returns a verdict. When Snort hangs, no verdicts are returned, and ALL traffic stops - not just IDS blindness, but complete denial of service.

### CVE-2024-1086: Linux Kernel Privilege Escalation

A use-after-free in Linux netfilter `nf_tables` (kernels v5.14-v6.6) enables container escape:

```bash
# Check if host is vulnerable
uname -r  # Vulnerable: v5.14 - v6.6 (before patches)

# The exploit is available at:
ls cve_tools/cve-2024-1086/
```

**Why this matters:** Docker containers share the host kernel. If an attacker compromises Snort (e.g., via CVE-2022-20685), they could use CVE-2024-1086 to escape the container and gain root on the host. seL4 is immune because it runs a minimal microkernel, not Linux.

### Demo Scripts

```bash
# Full demo with 4 quadrants (PLC, seL4, Snort, User terminal)
./scripts/demo.sh

# Snort-only demo with 3 panes (PLC, Snort, User terminal)
./scripts/demo-snort.sh
```

### Full Comparison Experiment

```bash
# Run automated comparison
./scripts/run_comparison.sh
```

## Snort Rule Profiles

Multiple Snort configurations are available for benchmarking detection efficiency:

| Profile | Command | Rules | Description |
|---------|---------|-------|-------------|
| **default** | `docker compose up snort` | 12 | Quickdraw (industry standard) |
| quickdraw | `--profile snort-quickdraw` | 12 | Digital Bond Quickdraw only |
| talos | `--profile snort-talos` | 40 | Talos-style with `modbus_func` keywords |
| modbus | `--profile snort-modbus` | 13 | Custom CVE detection rules only |
| combined | `--profile snort-combined` | 65 | All rules combined |

```bash
# Run Snort with specific profile
sudo docker compose --profile snort-talos up

# Compare detection efficiency
sudo docker compose --profile snort-quickdraw up -d
./cve_tools/cve_0367_attack 127.0.0.1 503  # Test detection
sudo docker compose --profile snort-quickdraw down

sudo docker compose --profile snort-combined up -d
./cve_tools/cve_0367_attack 127.0.0.1 503  # Test detection
sudo docker compose --profile snort-combined down
```

### Rule Coverage Comparison

| CVE | Quickdraw | Talos | Custom Modbus |
|-----|:---------:|:-----:|:-------------:|
| CVE-2019-14462 (MBAP length) | ✅ | ✅ | ✅ |
| CVE-2022-0367 (heap underflow) | ❌ | ✅ | ✅ |
| CVE-2022-20685 (Snort DoS) | ❌ | ✅ | ✅ |
| Write operations | ❌ | ✅ | ✅ |
| Reconnaissance | ✅ | ✅ | ✅ |
| DoS function codes | ✅ | ✅ | ❌ |

## Protocol-Break vs Packet-Forwarding

### Packet-Forwarding (Traditional IDS/IPS)

```
Client ────TCP────► Snort ────TCP────► PLC
          (same connection flows through)
```

- Single TCP connection end-to-end
- Attacker can manipulate TCP state
- IDS can be attacked (CVE-2022-20685)
- Requires signatures for each attack variant

### Protocol-Break (seL4 Gateway)

```
Client ────TCP1────► seL4 ────TCP2────► PLC
              (terminates, validates, new connection)
```

- Two independent TCP connections
- Client cannot influence PLC's TCP state
- Validation before any data reaches PLC
- Catches entire classes of malformed input

## Components

| Directory | Description |
|-----------|-------------|
| `gateway/` | seL4 gateway container (QEMU + seL4 kernel) |
| `snort/` | Snort 2.9.18 IDS with multiple rule profiles (vulnerable to CVE-2022-20685) |
| `plc/` | District heating simulation (vulnerable libmodbus 3.1.2, CVE-2022-0367 mode) |
| `cve_tools/` | Attack tools for CVE demonstrations |
| `scripts/` | Utility and experiment scripts |
| `docs/` | Documentation with Mermaid diagrams ([Network](docs/NETWORK.md), [Containers](docs/CONTAINERS.md), [CVEs](docs/CVE.md)) |

### CVE Tools

| Tool | Target | Description |
|------|--------|-------------|
| `cve_14462_attack` | libmodbus | Heap buffer overflow via MBAP length mismatch |
| `cve_0367_attack` | libmodbus | Heap underflow via invalid write address (FC 0x17) |
| `cve_20685_attack` | Snort | Modbus preprocessor infinite loop (DoS) |
| `cve-2024-1086/` | Linux kernel | Privilege escalation via nf_tables (container escape) |

## PLC Simulation

The PLC simulates a district heating controller with multi-master support (thread-per-client architecture, typical of modern PLCs).

### PLC Modes

| Mode | Service | Port | Description |
|------|---------|------|-------------|
| **CVE-2022-0367** | `plc` (default) | 5020 | ASAN build, registers at address 100-109 |
| CVE-2019-14462 | `plc-14462` | 5022 | Normal build, registers at address 0-9 |

```bash
# Default mode (CVE-2022-0367 with ASAN)
sudo docker compose up plc

# CVE-2019-14462 mode
sudo docker compose --profile cve14462 up plc-14462
```

### Modbus Registers

In CVE-2022-0367 mode, registers are at addresses **100-109** (use address 40101 in SCADA tools):

| Address | Register | Description | R/W |
|---------|----------|-------------|-----|
| 100 | HR[0] | Inside temperature (°C ÷10) | R |
| 101 | HR[1] | Valve command (0-100%) | R/W |
| 102 | HR[2] | Temperature setpoint (°C ÷10) | R/W |
| 103 | HR[3] | Mode (0=Manual, 1=Auto) | R/W |
| 104 | HR[4] | Outside temperature (°C ÷10) | R |
| 105-109 | HR[5-9] | Status, position, supply temp, runtime, power | R |

## Security Notice

This project contains **intentionally vulnerable code** for defensive security research. The vulnerable libmodbus 3.1.2 and Snort 2.9.18 are included to demonstrate security concepts.

**Do not deploy unprotected components in production environments.**

## References

### Vulnerabilities
- [CVE-2019-14462](https://nvd.nist.gov/vuln/detail/CVE-2019-14462) - libmodbus heap buffer overflow (MBAP length)
- [CVE-2022-0367](https://nvd.nist.gov/vuln/detail/CVE-2022-0367) - libmodbus heap buffer underflow (start_address)
- [CVE-2022-20685](https://nvd.nist.gov/vuln/detail/CVE-2022-20685) - Snort Modbus preprocessor DoS
- [CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086) - Linux kernel nf_tables privilege escalation

### Security Research
- [Claroty Team82](https://claroty.com/team82/research/blinding-snort-breaking-the-modbus-ot-preprocessor) - Snort CVE-2022-20685 analysis
- [libmodbus Issue #614](https://github.com/stephane/libmodbus/issues/614) - CVE-2022-0367 disclosure
- [CVE-2024-1086 PoC](https://github.com/Notselwyn/CVE-2024-1086) - Kernel exploit with 99.4% success rate

### ICS/SCADA Resources
- [seL4 Microkernel](https://sel4.systems/) - Formally verified microkernel
- [Digital Bond Quickdraw](https://github.com/digitalbond/Quickdraw-Snort) - Industry-standard ICS/SCADA Snort rules
- [Dragos FrostyGoop Report](https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology) - ICS malware analysis (Jan 2024 Ukraine attack)
- [The Record - FrostyGoop](https://therecord.media/frostygoop-malware-ukraine-heat) - 600 Ukrainian households without heat

## License

For authorized defensive security research and educational purposes only.
