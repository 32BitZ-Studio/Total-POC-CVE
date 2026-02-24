/*
 * display.c - Console Display for District Heating Simulation
 *
 * Renders ASCII art visualization of the heating system
 */

#include "display.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

void display_clear(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

void format_runtime(uint32_t seconds, char *buffer, size_t size) {
    int hours = seconds / 3600;
    int mins = (seconds % 3600) / 60;
    int secs = seconds % 60;
    snprintf(buffer, size, "%02d:%02d:%02d", hours, mins, secs);
}

/* ==========================================================================
 * Temperature Bar Rendering
 * ========================================================================== */

static void render_temp_bar(double temp, double setpoint) {
    /* Bar spans -20 to 40°C (60 degree range) */
    const int bar_width = 20;
    const double temp_min = -20.0;
    const double temp_max = 40.0;

    /* Calculate positions */
    int temp_pos = (int)((temp - temp_min) / (temp_max - temp_min) * bar_width);
    int setpoint_pos = (int)((setpoint - temp_min) / (temp_max - temp_min) * bar_width);

    /* Clamp positions */
    if (temp_pos < 0) temp_pos = 0;
    if (temp_pos >= bar_width) temp_pos = bar_width - 1;
    if (setpoint_pos < 0) setpoint_pos = 0;
    if (setpoint_pos >= bar_width) setpoint_pos = bar_width - 1;

    /* Determine color based on status */
    const char *bar_color;
    if (temp <= TEMP_FROZEN) {
        bar_color = COLOR_RED;
    } else if (temp <= TEMP_CRITICAL) {
        bar_color = COLOR_RED;
    } else if (temp <= TEMP_WARNING) {
        bar_color = COLOR_YELLOW;
    } else {
        bar_color = COLOR_GREEN;
    }

    /* Render bar */
    printf("│ ");
    for (int i = 0; i < bar_width; i++) {
        if (i == setpoint_pos) {
            printf("%s│%s", COLOR_CYAN, COLOR_RESET);
        } else if (i < temp_pos) {
            printf("%s█%s", bar_color, COLOR_RESET);
        } else {
            printf("░");
        }
    }
    printf(" │\n");
}

/* ==========================================================================
 * Main Display Rendering
 * ========================================================================== */

void display_render(const process_state_t *state, int clients,
                    const char *ip, int port) {
    char runtime_str[16];
    format_runtime(state->runtime, runtime_str, sizeof(runtime_str));

    /* Determine status display */
    const char *status_str;
    const char *status_color;
    const char *status_icon;

    switch (state->status) {
        case STATUS_OK:
            status_str = "NORMAL";
            status_color = COLOR_GREEN;
            status_icon = "✓";
            break;
        case STATUS_WARNING:
            status_str = "WARNING";
            status_color = COLOR_YELLOW;
            status_icon = "⚠";
            break;
        case STATUS_CRITICAL:
            status_str = "CRITICAL";
            status_color = COLOR_RED;
            status_icon = "🚨";
            break;
        case STATUS_FROZEN:
        case STATUS_BURST:
            status_str = "FROZEN";
            status_color = COLOR_RED;
            status_icon = "💀";
            break;
        default:
            status_str = "UNKNOWN";
            status_color = COLOR_WHITE;
            status_icon = "?";
    }

    /* PLC status */
    const char *plc_status;
    const char *plc_color;
    if (state->controller_running) {
        plc_status = "RUNNING";
        plc_color = COLOR_GREEN;
    } else {
        plc_status = "CRASHED";
        plc_color = COLOR_RED;
    }

    /* Warning messages */
    const char *warning1 = "";
    const char *warning2 = "";
    if (!state->controller_running) {
        warning1 = "▶ CONTROLLER CRASHED - VALVE NOT RESPONDING";
        if (state->status == STATUS_WARNING) {
            warning2 = "▶ TEMPERATURE DROPPING - HYPOTHERMIA RISK";
        } else if (state->status == STATUS_CRITICAL) {
            warning2 = "▶ PIPE FREEZE IMMINENT - EVACUATE BUILDING";
        }
    }

    /* Clear and render */
    display_clear();

    printf("╔══════════════════════════════════════╗\n");
    printf("║ DISTRICT HEATING - B47/Z3            ║\n");
    printf("║ FrostyGoop (libmodbus 3.1.2)         ║\n");
    printf("╠══════════════════════════════════════╣\n");
    printf("║ Outside: ❄️  %6.1f°C                 ║\n", state->outside_temp);
    printf("╠══════════════════════════════════════╣\n");

    /* Building zone header with status indicators */
    if (state->status >= STATUS_WARNING) {
        printf("║ ZONE      %s%s %s %s%s               ║\n",
               status_color, status_icon, status_icon, status_icon, COLOR_RESET);
    } else {
        printf("║ ZONE                                 ║\n");
    }

    printf("╠──────────────────────────────────────╣\n");
    printf("║ INSIDE TEMP     -20       40°C       ║\n");
    printf("║ ┌──────────────────────┐             ║\n");

    /* Temperature bar */
    render_temp_bar(state->inside_temp, state->setpoint);

    printf("║ └──────────────────────┘             ║\n");

    /* Current temperature display */
    if (state->status >= STATUS_CRITICAL) {
        printf("║    %s%6.1f°C %s%s                       ║\n",
               COLOR_RED, state->inside_temp, status_icon, COLOR_RESET);
    } else if (state->status == STATUS_WARNING) {
        printf("║    %s%6.1f°C %s%s                       ║\n",
               COLOR_YELLOW, state->inside_temp, status_icon, COLOR_RESET);
    } else {
        printf("║    %s%6.1f°C%s (Set:%.1f)               ║\n",
               COLOR_GREEN, state->inside_temp, COLOR_RESET, state->setpoint);
    }

    /* Valve and radiator display */
    const char *valve_color = state->controller_running ? COLOR_GREEN : COLOR_RED;
    const char *valve_warning = state->controller_running ? "" : "⚠";

    printf("╠──────────────────────────────────────╣\n");
    printf("║ ┌───────┐  VALVE: %s%3d%%%s %s           ║\n",
           valve_color, state->valve_actual, COLOR_RESET, valve_warning);

    /* Radiator state based on temperature */
    if (state->inside_temp <= TEMP_CRITICAL) {
        printf("║ │  ICE  │  Supply: %.0f°C             ║\n", state->supply_temp);
    } else if (state->valve_actual > 50) {
        printf("║ │▓▓▓HOT▓│  Supply: %.0f°C             ║\n", state->supply_temp);
    } else if (state->valve_actual > 0) {
        printf("║ │░░WARM░│  Supply: %.0f°C             ║\n", state->supply_temp);
    } else {
        printf("║ │ COLD  │  Supply: %.0f°C             ║\n", state->supply_temp);
    }

    printf("║ └───────┘  Power: %5.1f kW           ║\n", state->heater_power);
    printf("╠══════════════════════════════════════╣\n");

    /* Mode and status line */
    printf("║ %s%s%s %s%s%s%s  %s            ║\n",
           state->mode == MODE_AUTO ? COLOR_GREEN : COLOR_YELLOW,
           state->mode == MODE_AUTO ? "AUTO" : "MANU",
           COLOR_RESET,
           status_color, status_icon, status_str, COLOR_RESET,
           runtime_str);

    /* Warning messages */
    if (strlen(warning1) > 0) {
        printf("║ %s! CONTROLLER CRASHED%s               ║\n", COLOR_RED, COLOR_RESET);
    }
    if (strlen(warning2) > 0) {
        printf("║ %s! TEMP DROPPING%s                    ║\n", COLOR_RED, COLOR_RESET);
    }

    printf("╠══════════════════════════════════════╣\n");
    printf("║ %s:%d C:%d %s%s%s        ║\n",
           ip, port, clients, plc_color, plc_status, COLOR_RESET);
    printf("╚══════════════════════════════════════╝\n");

    fflush(stdout);
}

/* ==========================================================================
 * Failure Screen
 * ========================================================================== */

void display_render_failure(const process_state_t *state) {
    char runtime_str[16];
    format_runtime(state->time_without_control, runtime_str, sizeof(runtime_str));

    display_clear();

    printf("╔══════════════════════════════════════╗\n");
    printf("║ DISTRICT HEATING - B47/Z3            ║\n");
    printf("║ FrostyGoop (libmodbus 3.1.2)         ║\n");
    printf("╠══════════════════════════════════════╣\n");
    printf("║                                      ║\n");
    printf("║  %s╔════════════════════════════╗%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s║ ❄️  PIPES FROZEN / BURST ❄️ ║%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s╠════════════════════════════╣%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s║ Final Temp: %5.1f°C       ║%s    ║\n", COLOR_BG_RED, state->inside_temp, COLOR_RESET);
    printf("║  %s║ No heat:    %s     ║%s    ║\n", COLOR_BG_RED, runtime_str, COLOR_RESET);
    printf("║  %s╠════════════════════════════╣%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s║ DAMAGE:                    ║%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s║  • Burst pipes             ║%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s║  • Water flooding          ║%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s║  • Structure damage        ║%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║  %s╚════════════════════════════╝%s    ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                                      ║\n");
    printf("╠══════════════════════════════════════╣\n");
    printf("║ %sROOT CAUSE:%s CVE-2019-14462         ║\n", COLOR_YELLOW, COLOR_RESET);
    printf("║ %sATTACK:%s FrostyGoop Modbus          ║\n", COLOR_YELLOW, COLOR_RESET);
    printf("╠══════════════════════════════════════╣\n");
    printf("║ %s💀 CATASTROPHIC FAILURE 💀%s          ║\n", COLOR_RED, COLOR_RESET);
    printf("╠══════════════════════════════════════╣\n");
    printf("║ Restart: docker compose restart plc  ║\n");
    printf("╚══════════════════════════════════════╝\n");

    fflush(stdout);
}
