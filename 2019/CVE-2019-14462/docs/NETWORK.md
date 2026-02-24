# Network Architecture

This document describes the network architecture of the seL4 ICS Gateway Demo.

## Overview

The demo uses two isolated Docker networks to simulate an industrial control system with a security gateway.

```mermaid
flowchart TB
    subgraph Internet["External Network (Host)"]
        Client[/"SCADA Client\n127.0.0.1"/]
    end

    subgraph Untrusted["Docker: ics-untrusted (192.168.96.0/24)"]
        GW_U["seL4 Gateway\n192.168.96.2\nPort 502"]
        Snort_U["Snort IDS\n192.168.96.20\nPort 503"]
    end

    subgraph Protected["Docker: ics-protected (192.168.95.0/24)"]
        GW_P["seL4 Gateway\n192.168.95.1"]
        Snort_P["Snort IDS\n192.168.95.20"]
        PLC["PLC\n192.168.95.2\nPort 502"]
    end

    Client -->|"Port 502"| GW_U
    Client -->|"Port 503"| Snort_U
    Client -->|"Port 5020"| PLC

    GW_U ---|"Protocol Break"| GW_P
    GW_P -->|"New TCP"| PLC

    Snort_U ---|"NFQUEUE"| Snort_P
    Snort_P -->|"Same TCP"| PLC
```

## Traffic Flow Comparison

### Protocol-Break vs Packet-Forwarding

```mermaid
flowchart LR
    subgraph ProtocolBreak["Protocol-Break (seL4)"]
        C1[Client] -->|"TCP₁"| S1[seL4]
        S1 -->|"Terminate\nValidate"| S1
        S1 -->|"TCP₂"| P1[PLC]
    end

    subgraph PacketForward["Packet-Forwarding (Snort)"]
        C2[Client] -->|"TCP"| S2[Snort]
        S2 -->|"Inspect\nForward"| P2[PLC]
    end
```

| Aspect | Protocol-Break | Packet-Forwarding |
|--------|----------------|-------------------|
| TCP Connections | Two independent | One end-to-end |
| State Isolation | Complete | None |
| Validation | Before forwarding | During forwarding |

## Port Mapping

```mermaid
flowchart LR
    subgraph Host["Host Ports"]
        P502["502"]
        P503["503"]
        P5020["5020"]
        P5021["5021"]
    end

    subgraph Containers
        GW["seL4 Gateway"]
        SN["Snort IDS"]
        PLC1["PLC (normal)"]
        PLC2["PLC (ASAN)"]
    end

    P502 --> GW
    P503 --> SN
    P5020 --> PLC1
    P5021 --> PLC2

    GW -->|"Protected"| PLC1
    SN -->|"Protected"| PLC1
```

| Port | Path | Architecture | Protection |
|------|------|--------------|------------|
| 502 | Client → seL4 → PLC | Protocol-break | Validates Modbus structure |
| 503 | Client → Snort → PLC | Packet-forwarding | Rule-based IDS |
| 5020 | Client → PLC | Direct | None (vulnerable) |
| 5021 | Client → PLC (ASAN) | Direct | CVE verification |

## Network Segmentation

### Two-Network Design

```mermaid
flowchart TB
    subgraph Untrusted["ics-untrusted (192.168.96.0/24)"]
        direction LR
        A1["Attacker\nAccess"]
        GW1["Gateway\nFrontend"]
        SN1["Snort\nFrontend"]
    end

    subgraph Protected["ics-protected (192.168.95.0/24)"]
        direction LR
        GW2["Gateway\nBackend"]
        SN2["Snort\nBackend"]
        PLC["PLC"]
    end

    A1 -.->|"Exposed"| GW1
    A1 -.->|"Exposed"| SN1
    A1 -.-x|"Blocked"| PLC

    GW1 --- GW2
    SN1 --- SN2
    GW2 --> PLC
    SN2 --> PLC
```

**Security Benefit:** The PLC is only accessible through the gateway or Snort, never directly from the untrusted network.

## IP Address Summary

| Component | Untrusted Network | Protected Network |
|-----------|-------------------|-------------------|
| seL4 Gateway | 192.168.96.2 | 192.168.95.1 |
| Snort IDS | 192.168.96.20 | 192.168.95.20 |
| PLC | - | 192.168.95.2 |
