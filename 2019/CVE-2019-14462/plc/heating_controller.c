/*
 * heating_controller.c - FrostyGoop District Heating Simulation
 *
 * Main program integrating:
 * - Process simulation (thermal model)
 * - Modbus TCP server (vulnerable libmodbus 3.1.2)
 * - Console display
 *
 * Demonstrates CVE-2019-14462 impact on industrial heating systems
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <modbus.h>

#include "process_sim.h"
#include "display.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

#define SERVER_ADDRESS      "0.0.0.0"
#ifndef SERVER_PORT
#define SERVER_PORT         502
#endif
#define NB_REGISTERS        10
#define MAX_CONNECTIONS     64

/* CVE-2022-0367: When using start_registers offset, the bounds check has a bug
 * that allows heap underflow. Enable with -DCVE_2022_0367 compile flag. */
#ifdef CVE_2022_0367
#define START_REGISTERS     100  /* Non-zero to enable CVE-2022-0367 */
#endif

#define LOG_FILE_ENV        "LOG_FILE"
#define DEFAULT_LOG_FILE    "/logs/plc.log"

/* ==========================================================================
 * Global State
 * ========================================================================== */

static volatile sig_atomic_t g_running = 1;
static process_state_t g_process;
static modbus_t *g_modbus_ctx = NULL;
static modbus_mapping_t *g_mb_mapping = NULL;
static FILE *g_log_fp = NULL;
static int g_client_count = 0;
static pthread_mutex_t g_client_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ==========================================================================
 * Logging
 * ========================================================================== */

static void log_msg(const char *level, const char *format, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    va_list args;

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    if (g_log_fp) {
        va_start(args, format);
        fprintf(g_log_fp, "[%s] %s: ", timestamp, level);
        vfprintf(g_log_fp, format, args);
        fprintf(g_log_fp, "\n");
        fflush(g_log_fp);
        va_end(args);
    }
}

/* ==========================================================================
 * Signal Handler
 * ========================================================================== */

static void signal_handler(int signum) {
    log_msg("INFO", "Received signal %d, shutting down...", signum);
    g_running = 0;
}

/* ==========================================================================
 * Process Thread - Physics simulation and display
 * ========================================================================== */

static void *process_thread(void *arg) {
    (void)arg;

    while (g_running) {
        /* Update physics */
        process_update_physics(&g_process);

        /* Run controller if alive */
        if (g_process.controller_running) {
            process_run_controller(&g_process);
        }

        /* Copy to Modbus registers */
        process_to_registers(&g_process, g_mb_mapping->tab_registers);

        /* Update display */
        pthread_mutex_lock(&g_client_mutex);
        int clients = g_client_count;
        pthread_mutex_unlock(&g_client_mutex);

        if (g_process.pipes_burst) {
            display_render_failure(&g_process);
        } else {
            display_render(&g_process, clients, SERVER_ADDRESS, SERVER_PORT);
        }

        /* Sleep for update interval */
        usleep(UPDATE_INTERVAL_MS * 1000);
    }

    return NULL;
}

/* ==========================================================================
 * Modbus Handler - Processes client requests (one thread per client)
 * ========================================================================== */

typedef struct {
    int client_socket;
    int client_id;
} client_thread_args_t;

static void *client_thread(void *arg) {
    client_thread_args_t *args = (client_thread_args_t *)arg;
    int client_socket = args->client_socket;
    int client_id = args->client_id;
    free(args);

    /* Create a new Modbus context for this client */
    modbus_t *ctx = modbus_new_tcp(NULL, 0);
    if (!ctx) {
        log_msg("ERROR", "Client %d: Failed to create context", client_id);
        close(client_socket);
        return NULL;
    }

    modbus_set_socket(ctx, client_socket);

    uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
    int rc;

    log_msg("INFO", "Client %d: Handler thread started", client_id);

    while (g_running && g_process.controller_running) {
        rc = modbus_receive(ctx, query);

        if (rc > 0) {
            log_msg("INFO", "Client %d: Received %d bytes", client_id, rc);

#ifdef TRIGGER_PATTERN_VULN
            /*
             * SIMULATED ZERO-DAY: Crash on Transaction ID = 0xDEAD
             *
             * This simulates a vulnerability triggered by specific non-semantic
             * byte patterns. A protocol-break gateway that performs canonical
             * reconstruction (assigning new Transaction IDs) will prevent this
             * trigger from reaching the PLC.
             *
             * Compile with: -DTRIGGER_PATTERN_VULN
             */
            if (rc >= 2) {
                uint16_t transaction_id = (query[0] << 8) | query[1];
                if (transaction_id == 0xDEAD) {
                    log_msg("ERROR", "Client %d: TRIGGER PATTERN RECEIVED (TID=0xDEAD)! Simulating crash...",
                            client_id);
                    g_process.controller_running = 0;
                    process_controller_crash(&g_process);
                    break;
                }
            }
#endif

            /*
             * VULNERABILITY: CVE-2019-14462
             *
             * modbus_reply() trusts the Length field in the MBAP header.
             * If attacker sends:
             *   - Length field = 60 (small)
             *   - Actual data = 601 bytes (large)
             *
             * A heap buffer overflow occurs, crashing the server.
             */
            rc = modbus_reply(ctx, query, rc, g_mb_mapping);

            if (rc == -1) {
                log_msg("ERROR", "Client %d: modbus_reply failed: %s",
                        client_id, modbus_strerror(errno));
                break;
            }

            /* Check if client wrote to registers */
            process_from_registers(&g_process, g_mb_mapping->tab_registers);

            log_msg("INFO", "Client %d: Sent %d bytes", client_id, rc);

        } else if (rc == -1) {
            /* Connection closed or error */
            break;
        }
    }

    log_msg("INFO", "Client %d: Disconnected", client_id);

    modbus_close(ctx);
    modbus_free(ctx);

    pthread_mutex_lock(&g_client_mutex);
    g_client_count--;
    pthread_mutex_unlock(&g_client_mutex);

    /* Check if we crashed (CVE triggered) */
    if (!g_process.controller_running) {
        log_msg("ERROR", "Controller crashed! Valve frozen at %d%%",
                g_process.valve_actual);
        process_controller_crash(&g_process);
    }

    return NULL;
}

/* ==========================================================================
 * Main Program
 * ========================================================================== */

int main(void) {
    int server_socket = -1;
    pthread_t process_tid;
    int rc;

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Open log file */
    const char *log_path = getenv(LOG_FILE_ENV);
    if (!log_path) log_path = DEFAULT_LOG_FILE;

    g_log_fp = fopen(log_path, "a");
    if (!g_log_fp) {
        fprintf(stderr, "Warning: Could not open log file %s\n", log_path);
    }

    log_msg("INFO", "========================================");
    log_msg("INFO", "FrostyGoop District Heating Simulation");
    log_msg("INFO", "libmodbus 3.1.2 (CVE-2019-14462)");
    log_msg("INFO", "WARNING: This is intentionally vulnerable!");
    log_msg("INFO", "========================================");

    /* Initialize process simulation */
    process_init(&g_process);
    log_msg("INFO", "Process simulation initialized");
    log_msg("INFO", "  Inside temp: %.1f°C", g_process.inside_temp);
    log_msg("INFO", "  Outside temp: %.1f°C", g_process.outside_temp);
    log_msg("INFO", "  Setpoint: %.1f°C", g_process.setpoint);

    /* Create Modbus TCP context */
    g_modbus_ctx = modbus_new_tcp(SERVER_ADDRESS, SERVER_PORT);
    if (!g_modbus_ctx) {
        log_msg("ERROR", "Failed to create Modbus context: %s", modbus_strerror(errno));
        goto cleanup;
    }

    /* Create register mapping */
#ifdef CVE_2022_0367
    /* Use start_address API with non-zero offset to enable CVE-2022-0367 vulnerability */
    g_mb_mapping = modbus_mapping_new_start_address(
        0, 0,                           /* bits: start=0, nb=0 */
        0, 0,                           /* input_bits: start=0, nb=0 */
        START_REGISTERS, NB_REGISTERS,  /* registers: start=100, nb=10 (addresses 100-109) */
        0, 0                            /* input_registers: start=0, nb=0 */
    );
    log_msg("INFO", "CVE-2022-0367 mode: registers at address %d-%d",
            START_REGISTERS, START_REGISTERS + NB_REGISTERS - 1);
#else
    g_mb_mapping = modbus_mapping_new(0, 0, NB_REGISTERS, 0);
#endif
    if (!g_mb_mapping) {
        log_msg("ERROR", "Failed to allocate register mapping: %s", modbus_strerror(errno));
        goto cleanup;
    }

    /* Initialize registers from process state */
    process_to_registers(&g_process, g_mb_mapping->tab_registers);

    /* Start listening */
    server_socket = modbus_tcp_listen(g_modbus_ctx, MAX_CONNECTIONS);
    if (server_socket == -1) {
        log_msg("ERROR", "Failed to listen: %s", modbus_strerror(errno));
        goto cleanup;
    }

    log_msg("INFO", "Modbus TCP server listening on %s:%d", SERVER_ADDRESS, SERVER_PORT);

    /* Start process simulation thread */
    rc = pthread_create(&process_tid, NULL, process_thread, NULL);
    if (rc != 0) {
        log_msg("ERROR", "Failed to create process thread: %d", rc);
        goto cleanup;
    }

    /* Main loop - accept and spawn thread per client */
    int client_id = 0;
    while (g_running) {
        log_msg("INFO", "Waiting for client connection... (%d active)",
                g_client_count);

        /* Accept new connection */
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == -1) {
            if (g_running) {
                log_msg("ERROR", "Accept failed: %s", strerror(errno));
            }
            continue;
        }

        pthread_mutex_lock(&g_client_mutex);
        g_client_count++;
        int current_clients = g_client_count;
        pthread_mutex_unlock(&g_client_mutex);

        client_id++;
        log_msg("INFO", "Client %d connected (%d total)", client_id, current_clients);

        /* Prepare thread arguments */
        client_thread_args_t *args = malloc(sizeof(client_thread_args_t));
        if (!args) {
            log_msg("ERROR", "Failed to allocate thread args");
            close(client_socket);
            pthread_mutex_lock(&g_client_mutex);
            g_client_count--;
            pthread_mutex_unlock(&g_client_mutex);
            continue;
        }
        args->client_socket = client_socket;
        args->client_id = client_id;

        /* Spawn detached thread for this client */
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        rc = pthread_create(&tid, &attr, client_thread, args);
        pthread_attr_destroy(&attr);

        if (rc != 0) {
            log_msg("ERROR", "Failed to create client thread: %d", rc);
            free(args);
            close(client_socket);
            pthread_mutex_lock(&g_client_mutex);
            g_client_count--;
            pthread_mutex_unlock(&g_client_mutex);
        }
    }

    /* Wait for process thread */
    pthread_join(process_tid, NULL);

cleanup:
    log_msg("INFO", "Shutting down... (waiting for %d clients)", g_client_count);

    /* Close server socket to stop accepting new connections */
    if (server_socket != -1) {
        close(server_socket);
    }

    /* Brief wait for client threads to finish */
    for (int i = 0; i < 10 && g_client_count > 0; i++) {
        usleep(100000);  /* 100ms */
    }

    if (g_mb_mapping) {
        modbus_mapping_free(g_mb_mapping);
    }
    if (g_modbus_ctx) {
        modbus_free(g_modbus_ctx);
    }

    process_cleanup(&g_process);

    if (g_log_fp && g_log_fp != stdout) {
        fclose(g_log_fp);
    }

    return EXIT_SUCCESS;
}
