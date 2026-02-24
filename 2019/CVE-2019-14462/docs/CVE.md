# CVE Explanations

This document provides detailed explanations of the vulnerabilities demonstrated in this project.

## CVE-2019-14462: libmodbus Heap Buffer Overflow

| Field | Value |
|-------|-------|
| **Affected** | libmodbus <= 3.1.2 |
| **Severity** | High (CVSS 9.8) |
| **Type** | Heap Buffer Overflow |
| **Impact** | Denial of Service, potential RCE |

### Description

The vulnerability exists because libmodbus trusts the `Length` field in the Modbus TCP MBAP header without validating it against the actual received data.

### Attack Mechanism

```mermaid
sequenceDiagram
    participant Attacker
    participant PLC as PLC (libmodbus)
    participant Heap

    Note over PLC: Receives MBAP Header
    Attacker->>PLC: MBAP Header (Length=60)
    PLC->>Heap: malloc(60 bytes)
    Heap-->>PLC: buffer @ 0x1000

    Note over PLC: Trusts Length field!
    Attacker->>PLC: Actual payload (600 bytes)
    PLC->>Heap: memcpy(buffer, data, 600)

    Note over Heap: OVERFLOW!
    Note over Heap: Corrupts adjacent memory
    Note over PLC: CRASH or RCE
```

### Vulnerable Code

Location: `libmodbus 3.1.2 - src/modbus.c`

```c
static int receive_msg(modbus_t *ctx, uint8_t *msg) {
    /* Read MBAP header (7 bytes) */
    rc = recv(ctx->s, msg, 7, 0);

    /* Extract length from header - TRUSTED WITHOUT VALIDATION! */
    length = (msg[4] << 8) | msg[5];

    /* Read remaining data based on declared length */
    rc = recv(ctx->s, msg + 7, length - 1, 0);

    /* BUG: Attacker can send more bytes than declared!
     * The recv() will read up to 'length-1' bytes,
     * but TCP stream may contain more data that
     * gets processed in subsequent calls */
}
```

### Modbus TCP Packet Structure

```mermaid
packet-beta
  0-15: "Transaction ID"
  16-31: "Protocol ID (0x0000)"
  32-47: "Length (LIES!)"
  48-55: "Unit ID"
  56-63: "Function Code"
  64-127: "Data..."
```

### Attack Packet

| Field | Offset | Value | Description |
|-------|--------|-------|-------------|
| Transaction ID | 0-1 | 0x0001 | Request identifier |
| Protocol ID | 2-3 | 0x0000 | Modbus protocol |
| **Length** | 4-5 | **60** | **LIES! Claims 60 bytes** |
| Unit ID | 6 | 0x01 | Slave address |
| Function Code | 7 | 0x03 | Read Holding Registers |
| Overflow Data | 8-607 | 0xDEADBEEF... | **600 bytes of overflow** |

### Exploitation Flow

```mermaid
flowchart TD
    A["Attacker connects to PLC"] --> B["Send MBAP header\nLength = 60"]
    B --> C["PLC allocates 60-byte buffer"]
    C --> D["Send 600 bytes of data"]
    D --> E["libmodbus reads into buffer"]
    E --> F{"Buffer overflow!"}
    F --> G["Heap corruption"]
    G --> H["Crash / Code execution"]

    style F fill:#f00,color:#fff
    style H fill:#f00,color:#fff
```

### Protection Comparison

| Path | Port | Result | Reason |
|------|------|--------|--------|
| Direct | 5020 | **CRASH** | No validation |
| seL4 Gateway | 502 | **BLOCKED** | Length field validated against actual data |
| Snort IDS | 503 | **DETECTED** | Quickdraw rule SID:1111012 |

### Snort Detection Rule

The [Digital Bond Quickdraw](https://github.com/digitalbond/Quickdraw-Snort) rules include MBAP length validation:

```snort
# SID 1111012 - Detects MBAP length mismatch
alert tcp any any <> $MODBUS_SERVER $MODBUS_PORTS ( \
    flow:established; \
    content:"|00 00|"; offset:2; depth:2; \
    byte_jump:2,4; \
    isdataat:0,relative; \
    msg:"QUICKDRAW: Modbus TCP - MBAP Length Mismatch (CVE-2019-14462)"; \
    sid:1111012; \
)
```

**How it works:**
1. `byte_jump:2,4` - Read MBAP length at offset 4, jump forward
2. `isdataat:0,relative` - Check if more data exists after jump
3. If packet has more data than declared length → **ALERT**

### How seL4 Blocks This Attack

```mermaid
flowchart LR
    A["Malicious\nPacket"] --> B["seL4 Gateway"]
    B --> C{"Length field\n== actual size?"}
    C -->|"No"| D["DROP"]
    C -->|"Yes"| E["Forward to PLC"]

    style D fill:#0a0,color:#fff
```

---

## CVE-2022-20685: Snort Modbus Preprocessor DoS

| Field | Value |
|-------|-------|
| **Affected** | Snort < 2.9.19, Snort 3 < 3.1.11.0 |
| **Severity** | High (CVSS 7.5) |
| **Type** | Integer Overflow → Infinite Loop |
| **Impact** | Complete IDS Denial of Service |

### Description

The Snort Modbus preprocessor has an integer overflow vulnerability in the `ModbusCheckRequestLengths()` function. A specially crafted packet causes an infinite loop, freezing Snort and blocking all traffic.

### Attack Mechanism

```mermaid
sequenceDiagram
    participant Attacker
    participant Snort
    participant Kernel as Kernel NFQUEUE

    Attacker->>Kernel: Malicious Modbus packet
    Kernel->>Snort: Packet via NFQUEUE

    Note over Snort: ModbusCheckRequestLengths()
    Note over Snort: record_length = 0xFFFE

    loop Infinite Loop
        Note over Snort: bytes_processed = 7 + (2 * 0xFFFE)
        Note over Snort: = 0x20003
        Note over Snort: Overflow to 0x0003!
        Note over Snort: 3 < tmp_count -> continue
    end

    Note over Kernel: Waiting for verdict...
    Note over Kernel: ALL TRAFFIC BLOCKED!
```

### Vulnerable Code

Location: `Snort 2.9.18 - src/dynamic-preprocessors/modbus/modbus_decode.c`

```c
static int ModbusCheckRequestLengths(modbus_session_data_t *session,
                                     SFSnortPacket *packet) {
    uint16_t bytes_processed = 0;  /* Only 16 bits! */
    uint16_t tmp_count;
    uint16_t record_length;

    /* ... */

    while (bytes_processed < tmp_count) {
        /* Read record_length from packet data */
        record_length = *(uint16_t *)(payload + bytes_processed + 5);

        /* INTEGER OVERFLOW BUG! */
        bytes_processed += 7 + (2 * record_length);

        /*
         * When record_length = 0xFFFE:
         *   7 + (2 * 0xFFFE) = 7 + 0x1FFFC = 0x20003
         *
         * But bytes_processed is uint16_t (max 0xFFFF):
         *   0x20003 & 0xFFFF = 0x0003
         *
         * Loop condition: 3 < tmp_count = TRUE
         * Result: INFINITE LOOP!
         */
    }
}
```

### Integer Overflow Visualization

```mermaid
flowchart TD
    A["record_length = 0xFFFE\n(65,534)"] --> B["Calculate:\n7 + (2 * 0xFFFE)"]
    B --> C["= 7 + 0x1FFFC\n= 0x20003\n(131,075)"]
    C --> D["Truncate to uint16_t\n(max 65,535)"]
    D --> E["0x20003 & 0xFFFF\n= 0x0003\n(3)"]
    E --> F["bytes_processed = 3"]
    F --> G{"Loop condition:\n3 < tmp_count?"}
    G -->|"YES (always)"| H["Continue loop..."]
    H --> A

    style G fill:#f00,color:#fff
    style H fill:#f00,color:#fff
```

### Attack Packet Structure

| Field | Offset | Value | Description |
|-------|--------|-------|-------------|
| Transaction ID | 0-1 | 0x0001 | Request identifier |
| Protocol ID | 2-3 | 0x0000 | Modbus protocol |
| Length | 4-5 | 0x0011 | 17 bytes |
| Unit ID | 6 | 0x01 | Slave address |
| Function Code | 7 | 0x15 | Write File Record |
| Request Length | 8 | 0x0E | 14 bytes |
| Reference Type | 9 | 0x06 | Required value |
| Padding | 10-13 | 0x00 | - |
| **record_length** | 14-15 | **0xFFFE** | **Triggers overflow (1st read)** |
| Padding | 16 | 0x00 | - |
| **record_length** | 17-18 | **0xFFFB** | **Triggers overflow (2nd read)** |
| Padding | 19-22 | 0x00 | - |

### Impact on Traffic

```mermaid
flowchart LR
    subgraph Before["Before Attack"]
        C1["Client"] -->|"Traffic flows"| S1["Snort"]
        S1 -->|"Inspected"| P1["PLC"]
    end

    subgraph After["After Attack"]
        C2["Client"] -->|"Traffic"| S2["Snort\n(100% CPU)\n(Frozen)"]
        S2 -.-x|"BLOCKED"| P2["PLC"]
    end

    style S2 fill:#f00,color:#fff
```

### Why NFQUEUE Makes This Devastating

```mermaid
flowchart TD
    subgraph Normal["Normal Operation"]
        P1["Packet"] --> Q1["NFQUEUE"]
        Q1 --> S1["Snort"]
        S1 -->|"ACCEPT"| Q1
        Q1 --> D1["Delivered"]
    end

    subgraph Attack["After Attack"]
        P2["Packet"] --> Q2["NFQUEUE"]
        Q2 --> S2["Snort\n(frozen)"]
        S2 -.-x|"No verdict"| Q2
        Q2 -.-x|"Queue full"| D2["Dropped"]
    end

    style S2 fill:#f00,color:#fff
    style D2 fill:#f00,color:#fff
```

**Key insight:** In NFQUEUE inline mode, packets are held in the kernel queue until Snort returns a verdict. When Snort hangs, no verdicts are returned, and ALL traffic stops.

### Protection Comparison

| Path | Port | Result | Reason |
|------|------|--------|--------|
| Snort IDS | 503 | **VULNERABLE** | Preprocessor has the bug |
| seL4 Gateway | 502 | **IMMUNE** | No Modbus preprocessor |
| Direct | 5020 | N/A | Snort not in path |

### Why seL4 is Immune

```mermaid
flowchart LR
    subgraph Snort["Snort Architecture"]
        S_IN["Input"] --> S_PRE["Preprocessors\n(Complex parsing)"]
        S_PRE --> S_DET["Detection"]
        S_PRE -.->|"CVE-2022-20685"| S_VULN["Vulnerable!"]
    end

    subgraph seL4["seL4 Architecture"]
        G_IN["Input"] --> G_VAL["Simple Validation\n(Length check only)"]
        G_VAL --> G_FWD["Forward"]
        G_VAL -.->|"No preprocessor"| G_SAFE["Immune"]
    end

    style S_VULN fill:#f00,color:#fff
    style G_SAFE fill:#0a0,color:#fff
```

---

## Security Comparison Summary

```mermaid
flowchart TB
    subgraph Traditional["Traditional IDS (Snort)"]
        T_ATK["Attack Surface:\n~500,000 LoC"]
        T_PRE["Preprocessors\n(vulnerable)"]
        T_RULE["Rules\n(signatures)"]
        T_ATK --> T_PRE --> T_RULE
    end

    subgraph Gateway["Protocol-Break (seL4)"]
        G_ATK["Attack Surface:\n~1,000 LoC"]
        G_VAL["Structural\nValidation"]
        G_FV["Formally\nVerified"]
        G_ATK --> G_VAL --> G_FV
    end

    style T_ATK fill:#faa
    style G_ATK fill:#afa
```

| Aspect | Packet-Forwarding (Snort) | Protocol-Break (seL4) |
|--------|---------------------------|----------------------|
| Attack Surface | ~500,000 LoC | ~1,000 LoC |
| CVE-2019-14462 | Requires rule | Blocked by design |
| CVE-2022-20685 | Vulnerable | Immune |
| Unknown Attacks | Missed (no signature) | Blocked (structural) |
| TCP State | Shared (attackable) | Isolated |
| Verification | Testing only | Formal proofs |
