# Docker Container Architecture

This document describes the Docker container relationships and internal architecture.

## Container Overview

```mermaid
flowchart TB
    subgraph compose["docker-compose.yml"]
        subgraph plc_container["ics-plc"]
            PLC_APP["heating_controller"]
            LIBMOD["libmodbus 3.1.2\n(vulnerable)"]
            PLC_APP --> LIBMOD
        end

        subgraph gateway_container["ics-gateway"]
            SETUP["setup-network.sh"]
            QEMU["QEMU ARM"]
            SEL4["seL4 Kernel"]
            SETUP --> QEMU
            QEMU --> SEL4
        end

        subgraph snort_container["ics-snort"]
            SNORT_SETUP["setup-network.sh"]
            SNORT_APP["Snort 2.9.18\n(vulnerable)"]
            NFQUEUE["NFQUEUE"]
            SNORT_SETUP --> NFQUEUE
            NFQUEUE --> SNORT_APP
        end
    end

    gateway_container -->|"depends_on"| plc_container
    snort_container -->|"depends_on"| plc_container
```

## Container Dependencies

```mermaid
flowchart LR
    PLC["ics-plc\n(must start first)"]
    GW["ics-gateway"]
    SN["ics-snort"]

    GW -->|"depends_on"| PLC
    SN -->|"depends_on"| PLC
```

| Container | Depends On | Reason |
|-----------|------------|--------|
| ics-plc | - | Base service |
| ics-gateway | ics-plc | Needs PLC to forward traffic to |
| ics-snort | ics-plc | Needs PLC to forward traffic to |

## Network Attachment

```mermaid
flowchart TB
    subgraph Untrusted["ics-untrusted (192.168.96.0/24)"]
        UN_GW["192.168.96.10"]
        UN_SN["192.168.96.20"]
    end

    subgraph Containers[" "]
        GW["ics-gateway"]
        SN["ics-snort"]
        PLC["ics-plc"]
    end

    subgraph Protected["ics-protected (192.168.95.0/24)"]
        PR_GW["192.168.95.10"]
        PR_SN["192.168.95.20"]
        PR_PLC["192.168.95.2"]
    end

    UN_GW --- GW
    UN_SN --- SN
    GW --- PR_GW
    SN --- PR_SN
    PLC --- PR_PLC
```

| Container | ics-untrusted | ics-protected |
|-----------|---------------|---------------|
| ics-gateway | Yes | Yes |
| ics-snort | Yes | Yes |
| ics-plc | No | Yes |

## seL4 Gateway Internal Architecture

The gateway container runs QEMU with the seL4 microkernel inside.

```mermaid
flowchart TB
    subgraph Docker["ics-gateway Container"]
        subgraph Untrusted["Untrusted Side"]
            ETH0["eth0"]
            BR0["br0"]
            TAP0["tap0"]
        end

        ETH0 --> BR0 --> TAP0

        subgraph QEMU["QEMU VM"]
            NET0["net0\n192.168.96.2"]
            subgraph SEL4["seL4 Microkernel"]
                APP["ICS Gateway App\n(validate & forward)"]
            end
            NET1["net1\n192.168.95.1"]
        end

        TAP0 --> NET0
        NET0 --> APP
        APP --> NET1

        subgraph Protected["Protected Side"]
            TAP1["tap1"]
            BR1["br1"]
            ETH1["eth1"]
        end

        NET1 --> TAP1
        TAP1 --> BR1 --> ETH1
    end
```

### Bridge Configuration

| Bridge | Interface | TAP | QEMU NIC | Purpose |
|--------|-----------|-----|----------|---------|
| br0 | eth0 (untrusted) | tap0 | net0 | Client-facing |
| br1 | eth1 (protected) | tap1 | net1 | PLC-facing |

## Snort NFQUEUE Architecture

Snort operates in inline IPS mode using NFQUEUE.

```mermaid
flowchart LR
    IN["Incoming\nPacket"]

    subgraph Docker["ics-snort Container"]
        subgraph Kernel["Linux Kernel"]
            NF["netfilter\nFORWARD chain"]
            NFQ["NFQUEUE"]
        end

        subgraph Userspace["Userspace"]
            SNORT["Snort\n(inspect)"]
        end

        NF --> NFQ
        NFQ -->|"packet"| SNORT
        SNORT -->|"verdict"| NFQ
        NFQ --> NF
    end

    OUT["Outgoing\nPacket"]

    IN --> NF
    NF -->|"ACCEPT"| OUT
```

### How NFQUEUE Works

1. Packet arrives at `netfilter` FORWARD chain
2. iptables rule sends packet to `NFQUEUE`
3. Snort receives packet, inspects with preprocessors
4. Snort returns verdict: `ACCEPT` or `DROP`
5. Kernel forwards or drops based on verdict

**Key point:** Packets are held in queue until Snort responds. If Snort hangs (CVE-2022-20685), all traffic stops.

## PLC Container

Simple container running the vulnerable heating controller.

```mermaid
flowchart TB
    subgraph Docker["ics-plc Container"]
        subgraph App["heating_controller"]
            MODBUS["Modbus TCP Server\nPort 502"]
            SIM["Process Simulation"]
            DISPLAY["Console Display"]
        end

        subgraph Lib["libmodbus 3.1.2"]
            VULN["CVE-2019-14462\nHeap Overflow"]
        end

        MODBUS --> Lib
        SIM --> MODBUS
        DISPLAY --> SIM
    end
```

## Container Capabilities

| Container | Privileged | NET_ADMIN | Reason |
|-----------|------------|-----------|--------|
| ics-gateway | Yes | Yes | Bridge/tap creation, QEMU |
| ics-snort | Yes | Yes | NFQUEUE, iptables |
| ics-plc | No | No | Simple application |
