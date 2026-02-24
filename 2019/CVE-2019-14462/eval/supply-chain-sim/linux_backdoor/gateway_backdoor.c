/*
 * Linux Gateway with Backdoor (E2 Comparison)
 *
 * Simple Modbus TCP proxy that forwards traffic between client and PLC,
 * with an intentional backdoor for demonstrating the lack of isolation
 * in monolithic OS architectures.
 *
 * When triggered, this "compromised gateway" can:
 * - Read arbitrary memory (same address space)
 * - Bypass validation and send raw data to PLC
 * - Access all network interfaces
 * - Escalate to kernel (if kernel vuln exists)
 *
 * This contrasts with the seL4 version where ALL of these are prevented
 * by capability-based isolation.
 *
 * Compile: gcc -o gateway_backdoor gateway_backdoor.c -lpthread
 * Usage:   ./gateway_backdoor <listen_port> <plc_ip> <plc_port>
 *
 * For defensive security research only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>

#define BACKDOOR_TRIGGER "\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
#define BACKDOOR_TRIGGER_LEN 8
#define BACKDOOR_TRIGGER_OFFSET 12
#define MAX_PACKET 4096

static volatile int g_running = 1;
static const char *g_plc_ip = "192.168.95.2";
static int g_plc_port = 502;

/* Simulated "sensitive" data that should be isolated */
static const char *g_secret_key = "SUPER_SECRET_ENCRYPTION_KEY_12345";
static uint8_t g_validation_state[256] = {0};

typedef struct {
    uint8_t action;
    int success;
    char description[128];
    char evidence[256];
} escalation_result_t;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/*
 * Attempt 1: Read "kernel" / other component memory
 * On Linux: SUCCESS - all memory in same address space
 */
static escalation_result_t attempt_read_memory(void) {
    escalation_result_t res = {0x01, 1, "read_sensitive_memory", ""};

    /* On Linux, the backdoored component can read ANY memory in the process */
    snprintf(res.evidence, sizeof(res.evidence),
             "SUCCESS: Read secret_key='%.16s...' validation_state[0]=%d",
             g_secret_key, g_validation_state[0]);

    printf("[BACKDOOR-LINUX] Read sensitive memory: SUCCESS\n");
    printf("[BACKDOOR-LINUX]   secret_key = '%.16s...'\n", g_secret_key);
    return res;
}

/*
 * Attempt 2: Access "parser" / validation component
 * On Linux: SUCCESS - same address space, can modify validation logic
 */
static escalation_result_t attempt_access_validation(void) {
    escalation_result_t res = {0x02, 1, "modify_validation_logic", ""};

    /* On Linux, we can directly modify the validation state to disable checks */
    memset(g_validation_state, 0xFF, sizeof(g_validation_state));

    snprintf(res.evidence, sizeof(res.evidence),
             "SUCCESS: Disabled all validation checks (memset validation_state=0xFF)");

    printf("[BACKDOOR-LINUX] Modified validation state: SUCCESS\n");
    printf("[BACKDOOR-LINUX]   All validation checks disabled\n");
    return res;
}

/*
 * Attempt 3: Bypass validation and send directly to PLC
 * On Linux: SUCCESS - can open new socket to PLC
 */
static escalation_result_t attempt_bypass_to_plc(uint8_t *malicious_data, size_t data_len) {
    escalation_result_t res = {0x03, 0, "bypass_validation_to_plc", ""};

    /* On Linux, the backdoor can directly connect to the PLC */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        snprintf(res.evidence, sizeof(res.evidence), "Socket creation failed");
        return res;
    }

    struct sockaddr_in plc_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_plc_port),
    };
    inet_pton(AF_INET, g_plc_ip, &plc_addr.sin_addr);

    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&plc_addr, sizeof(plc_addr)) == 0) {
        /* Send malicious data directly to PLC, bypassing all validation */
        ssize_t sent = send(sock, malicious_data, data_len, 0);
        res.success = 1;
        snprintf(res.evidence, sizeof(res.evidence),
                 "SUCCESS: Sent %zd bytes directly to PLC %s:%d (bypassed validation)",
                 sent, g_plc_ip, g_plc_port);
        printf("[BACKDOOR-LINUX] Direct PLC access: SUCCESS (%zd bytes sent)\n", sent);
    } else {
        snprintf(res.evidence, sizeof(res.evidence),
                 "Connect failed (PLC may be unreachable, but access not denied by isolation)");
        printf("[BACKDOOR-LINUX] Direct PLC access: connect failed (network issue, not isolation)\n");
    }

    close(sock);
    return res;
}

/*
 * Attempt 4: Disable the gateway entirely
 * On Linux: SUCCESS - can kill/modify own process
 */
static escalation_result_t attempt_disable_gateway(void) {
    escalation_result_t res = {0x04, 1, "disable_gateway", ""};

    snprintf(res.evidence, sizeof(res.evidence),
             "SUCCESS: Gateway can be killed (same process, same privileges)");

    printf("[BACKDOOR-LINUX] Gateway disable capability: SUCCESS\n");
    printf("[BACKDOOR-LINUX]   (Not actually killing - for measurement purposes)\n");
    return res;
}

/*
 * Backdoor trigger handler
 */
static void handle_backdoor(uint8_t *packet, size_t len) {
    (void)packet;
    (void)len;
    printf("\n[BACKDOOR-LINUX] *** TRIGGER SEQUENCE DETECTED ***\n");
    printf("[BACKDOOR-LINUX] Attempting privilege escalation...\n\n");

    escalation_result_t results[4];

    results[0] = attempt_read_memory();
    results[1] = attempt_access_validation();

    /* Build a malicious packet to send to PLC */
    uint8_t malicious[] = {
        0xDE, 0xAD, 0x00, 0x00, 0x00, 0x06, 0x01,
        0x03, 0x00, 0x00, 0x00, 0x01  /* Read holding register */
    };
    results[2] = attempt_bypass_to_plc(malicious, sizeof(malicious));
    results[3] = attempt_disable_gateway();

    printf("\n[BACKDOOR-LINUX] === ESCALATION SUMMARY ===\n");
    int total_success = 0;
    for (int i = 0; i < 4; i++) {
        printf("[BACKDOOR-LINUX]   %s: %s\n",
               results[i].description,
               results[i].success ? "SUCCESS" : "FAILED");
        if (results[i].success) total_success++;
    }
    printf("[BACKDOOR-LINUX] %d/4 escalation attempts SUCCEEDED\n", total_success);
    printf("[BACKDOOR-LINUX] Linux provides NO isolation between components\n\n");
}

/*
 * Simple Modbus validation (simulates gateway parser)
 * Returns 1 if valid, 0 if invalid
 */
static int validate_modbus(uint8_t *data, size_t len) {
    if (len < 12) return 0;

    /* Check protocol ID */
    uint16_t protocol_id = (data[2] << 8) | data[3];
    if (protocol_id != 0x0000) return 0;

    /* Check length field vs actual */
    uint16_t declared_len = (data[4] << 8) | data[5];
    if ((size_t)(declared_len + 6) != len) return 0;

    return 1;
}

/*
 * Forward validated packet to PLC
 */
static int forward_to_plc(uint8_t *data, size_t len, uint8_t *response, size_t *resp_len) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in plc_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(g_plc_port),
    };
    inet_pton(AF_INET, g_plc_ip, &plc_addr.sin_addr);

    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&plc_addr, sizeof(plc_addr)) < 0) {
        close(sock);
        return -1;
    }

    send(sock, data, len, 0);
    ssize_t received = recv(sock, response, MAX_PACKET, 0);
    close(sock);

    if (received > 0) {
        *resp_len = received;
        return 0;
    }
    return -1;
}

/*
 * Handle one client connection
 */
static void *client_handler(void *arg) {
    int client_sock = *(int *)arg;
    free(arg);

    uint8_t buffer[MAX_PACKET];
    uint8_t response[MAX_PACKET];

    while (g_running) {
        ssize_t received = recv(client_sock, buffer, sizeof(buffer), 0);
        if (received <= 0) break;

        /* Check for backdoor trigger */
        if ((size_t)received >= BACKDOOR_TRIGGER_OFFSET + BACKDOOR_TRIGGER_LEN &&
            memcmp(buffer + BACKDOOR_TRIGGER_OFFSET, BACKDOOR_TRIGGER, BACKDOOR_TRIGGER_LEN) == 0) {
            handle_backdoor(buffer, received);
            /* Still forward the packet (attacker controls gateway now) */
        }

        /* Normal validation path */
        if (validate_modbus(buffer, received)) {
            size_t resp_len = 0;
            if (forward_to_plc(buffer, received, response, &resp_len) == 0) {
                send(client_sock, response, resp_len, 0);
            }
        }
    }

    close(client_sock);
    return NULL;
}

int main(int argc, char *argv[]) {
    int listen_port = 504;  /* Default: port 504 for backdoored Linux gateway */

    if (argc > 1) listen_port = atoi(argv[1]);
    if (argc > 2) g_plc_ip = argv[2];
    if (argc > 3) g_plc_port = atoi(argv[3]);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Linux Gateway (with backdoor) - E2 Comparison\n");
    printf("  Listen: 0.0.0.0:%d\n", listen_port);
    printf("  PLC:    %s:%d\n", g_plc_ip, g_plc_port);
    printf("  Trigger: \\xDE\\xAD\\xBE\\xEF\\xCA\\xFE\\xBA\\xBE at offset %d\n",
           BACKDOOR_TRIGGER_OFFSET);
    printf("  WARNING: This contains an intentional backdoor for research!\n\n");

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(listen_port),
    };

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    listen(server_sock, 10);
    printf("Listening on port %d...\n", listen_port);

    while (g_running) {
        int *client = malloc(sizeof(int));
        *client = accept(server_sock, NULL, NULL);
        if (*client < 0) {
            free(client);
            continue;
        }

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, client_handler, client);
        pthread_attr_destroy(&attr);
    }

    close(server_sock);
    return 0;
}
