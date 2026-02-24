# FrostyGoop District Heating Simulation

## Overview

This document provides complete implementation details for a vulnerable Modbus TCP controller simulating a district heating system. The simulation is inspired by the FrostyGoop malware attack on Ukrainian heating infrastructure in January 2024.

**Purpose:** Demonstrate the real-world consequences of ICS cyber attacks and the protection provided by the seL4 gateway.

**⚠️ IMPORTANT:** This uses an **unpatched local copy** of libmodbus 3.1.2 with CVE-2019-14462. The official v3.1.2 release on GitHub has been patched and will NOT exhibit the vulnerability. We use the local `libmodbus_3.1.2/` folder which contains the original vulnerable version for this defensive security demonstration.

---

## Background: FrostyGoop Attack

| Field | Details |
|-------|---------|
| Malware | FrostyGoop (aka BUSTLEBERM) |
| Date | January 2024 |
| Target | ENCO heating controllers in Lviv, Ukraine |
| Protocol | Modbus TCP (port 502) |
| Impact | 600+ apartment buildings lost heating for 48 hours |
| Conditions | -20°C winter temperatures |
| Method | Direct Modbus commands to disable heating controllers |

This simulation recreates the scenario where a Modbus controller crash (via CVE-2019-14462) causes heating failure, leading to dangerous temperature drops and potential pipe bursts.

---

## File Structure

```
plc/
├── Dockerfile                  # Multi-stage build (normal + ASAN)
├── heating_controller.c        # Main simulation with process + Modbus
├── process_sim.h               # Process simulation header
├── process_sim.c               # Physics model and controller
├── display.h                   # Console display header
├── display.c                   # ASCII art console rendering
├── start-plc.sh                # Startup script
└── Makefile                    # Build configuration
```

---

## Dockerfile

```dockerfile
# =============================================================================
# FrostyGoop District Heating Simulation
# Vulnerable Modbus TCP Controller (CVE-2019-14462)
# =============================================================================

FROM debian:11 AS base

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpthread-stubs0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# -----------------------------------------------------------------------------
# Build UNPATCHED vulnerable libmodbus 3.1.2 from local copy
#
# IMPORTANT: This is the original vulnerable version with CVE-2019-14462
# The official GitHub release v3.1.2 has been patched and will NOT demonstrate
# the vulnerability. We use a local unpatched copy for this security demonstration.
#
# DO NOT upgrade - vulnerability is intentional for demonstration
# -----------------------------------------------------------------------------
COPY ../libmodbus_3.1.2 /src/libmodbus-3.1.2

RUN cd libmodbus-3.1.2 \
    && ./autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install \
    && ldconfig

# Copy all source files
COPY Makefile /src/
COPY *.c /src/
COPY *.h /src/

# =============================================================================
# Normal build - for crash demonstration
# =============================================================================
FROM base AS normal

RUN make clean && make release

COPY start-plc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-plc.sh

EXPOSE 502

ENV TERM=xterm-256color

CMD ["/usr/local/bin/start-plc.sh"]

# =============================================================================
# ASAN build - for CVE proof (detects heap overflow)
# =============================================================================
FROM base AS asan

RUN make clean && make asan

COPY start-plc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/start-plc.sh

# ASAN options
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_legend=0:color=always
ENV TERM=xterm-256color

EXPOSE 502

CMD ["/usr/local/bin/start-plc.sh"]
```

---

## Makefile

```makefile
# FrostyGoop District Heating Simulation
# Build configuration

CC = gcc
CFLAGS_COMMON = -Wall -Wextra -D_GNU_SOURCE
LDFLAGS = -L/usr/local/lib -lmodbus -lpthread -lm -Wl,-rpath,/usr/local/lib
INCLUDES = -I/usr/local/include/modbus

# Source files
SRCS = heating_controller.c process_sim.c display.c
HDRS = process_sim.h display.h
TARGET = heating_controller

# Release build
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O2

# Debug build
CFLAGS_DEBUG = $(CFLAGS_COMMON) -g -O0 -DDEBUG

# ASAN build
CFLAGS_ASAN = $(CFLAGS_COMMON) -g -O1 -fsanitize=address -fno-omit-frame-pointer

.PHONY: all release debug asan clean

all: release

release: CFLAGS = $(CFLAGS_RELEASE)
release: $(TARGET)

debug: CFLAGS = $(CFLAGS_DEBUG)
debug: $(TARGET)

asan: CFLAGS = $(CFLAGS_ASAN)
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o
```

---

## process_sim.h

```c
/*
 * process_sim.h - District Heating Process Simulation
 * 
 * FrostyGoop-inspired thermal model for building heating system
 */

#ifndef PROCESS_SIM_H
#define PROCESS_SIM_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/* ==========================================================================
 * Process Constants
 * ========================================================================== */

/* Temperature thresholds (°C) */
#define TEMP_SETPOINT_DEFAULT   20.0    /* Default setpoint */
#define TEMP_WARNING            10.0    /* Hypothermia risk */
#define TEMP_CRITICAL           5.0     /* Pipe freeze risk */
#define TEMP_FROZEN             0.0     /* Pipes burst */
#define TEMP_INITIAL_INSIDE     20.0    /* Starting indoor temp */
#define TEMP_OUTSIDE_DEFAULT    -15.0   /* Winter conditions */
#define TEMP_SUPPLY_DEFAULT     90.0    /* District heating supply */

/* Physics parameters - tuned for ~5-8 minutes to failure */
#define HEAT_LOSS_FACTOR        0.015   /* Heat loss coefficient */
#define HEATER_POWER_MAX        80.0    /* Max heating power (kW) */
#define THERMAL_MASS            30.0    /* Building thermal mass */
#define VALVE_SLEW_RATE         5.0     /* Valve movement per second (%) */

/* Timing */
#define UPDATE_INTERVAL_MS      1000    /* Physics update rate */

/* ==========================================================================
 * Status Codes
 * ========================================================================== */

typedef enum {
    STATUS_OK = 0,          /* Normal operation */
    STATUS_WARNING = 1,     /* Below 10°C - hypothermia risk */
    STATUS_CRITICAL = 2,    /* Below 5°C - pipe freeze risk */
    STATUS_FROZEN = 3,      /* Below 0°C - pipes frozen */
    STATUS_BURST = 4        /* Catastrophic - pipes burst */
} process_status_t;

/* ==========================================================================
 * Control Modes
 * ========================================================================== */

typedef enum {
    MODE_MANUAL = 0,        /* Valve controlled by SCADA */
    MODE_AUTO = 1           /* Automatic temperature control */
} control_mode_t;

/* ==========================================================================
 * Process State Structure
 * ========================================================================== */

typedef struct {
    /* Process variables (mapped to Modbus registers) */
    double inside_temp;         /* HR[0]: Indoor temperature (°C) */
    int valve_cmd;              /* HR[1]: Valve command (0-100%) */
    double setpoint;            /* HR[2]: Temperature setpoint (°C) */
    control_mode_t mode;        /* HR[3]: Control mode */
    double outside_temp;        /* HR[4]: Outside temperature (°C) */
    process_status_t status;    /* HR[5]: Process status */
    int valve_actual;           /* HR[6]: Actual valve position (%) */
    double supply_temp;         /* HR[7]: Supply temperature (°C) */
    uint32_t runtime;           /* HR[8]: Runtime in seconds */
    double heater_power;        /* HR[9]: Current power (kW) */
    
    /* Internal state */
    bool controller_running;    /* Is PLC/controller active? */
    uint32_t time_without_control; /* Seconds since controller died */
    bool pipes_burst;           /* Permanent failure flag */
    
    /* Synchronization */
    pthread_mutex_t mutex;
    
} process_state_t;

/* ==========================================================================
 * Function Prototypes
 * ========================================================================== */

/**
 * Initialize process state with default values
 */
void process_init(process_state_t *state);

/**
 * Clean up process state
 */
void process_cleanup(process_state_t *state);

/**
 * Update physics simulation (call every UPDATE_INTERVAL_MS)
 * This runs regardless of controller state
 */
void process_update_physics(process_state_t *state);

/**
 * Run control algorithm (only when controller is alive)
 */
void process_run_controller(process_state_t *state);

/**
 * Signal that controller has crashed
 * Valve will freeze at current position
 */
void process_controller_crash(process_state_t *state);

/**
 * Copy state to Modbus registers (thread-safe)
 * Values are scaled: temperatures × 10 for integer registers
 */
void process_to_registers(process_state_t *state, uint16_t *registers);

/**
 * Update state from Modbus registers (thread-safe)
 * Only updates writable registers: valve_cmd, setpoint, mode
 */
void process_from_registers(process_state_t *state, const uint16_t *registers);

/**
 * Get status string for display
 */
const char* process_status_string(process_status_t status);

#endif /* PROCESS_SIM_H */
```

---

## process_sim.c

```c
/*
 * process_sim.c - District Heating Process Simulation
 * 
 * Implements thermal physics model and bang-bang controller
 */

#include "process_sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ==========================================================================
 * Initialization
 * ========================================================================== */

void process_init(process_state_t *state) {
    memset(state, 0, sizeof(process_state_t));
    
    /* Initialize process variables */
    state->inside_temp = TEMP_INITIAL_INSIDE;
    state->setpoint = TEMP_SETPOINT_DEFAULT;
    state->outside_temp = TEMP_OUTSIDE_DEFAULT;
    state->supply_temp = TEMP_SUPPLY_DEFAULT;
    state->mode = MODE_AUTO;
    state->status = STATUS_OK;
    state->valve_cmd = 50;      /* Start at 50% */
    state->valve_actual = 50;
    state->heater_power = 0.0;
    state->runtime = 0;
    
    /* Internal state */
    state->controller_running = true;
    state->time_without_control = 0;
    state->pipes_burst = false;
    
    /* Initialize mutex */
    pthread_mutex_init(&state->mutex, NULL);
}

void process_cleanup(process_state_t *state) {
    pthread_mutex_destroy(&state->mutex);
}

/* ==========================================================================
 * Physics Simulation
 * ========================================================================== */

void process_update_physics(process_state_t *state) {
    pthread_mutex_lock(&state->mutex);
    
    /* Don't update if pipes have burst (simulation ended) */
    if (state->pipes_burst) {
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    
    double dt = UPDATE_INTERVAL_MS / 1000.0;
    
    /* Increment runtime */
    state->runtime++;
    
    /* Track time without control */
    if (!state->controller_running) {
        state->time_without_control++;
    }
    
    /* =======================================================================
     * Valve Dynamics
     * Valve moves toward command position at VALVE_SLEW_RATE per second
     * If controller is dead, valve stays at last position
     * ======================================================================= */
    if (state->controller_running) {
        int valve_diff = state->valve_cmd - state->valve_actual;
        int max_change = (int)(VALVE_SLEW_RATE * dt);
        
        if (valve_diff > max_change) {
            state->valve_actual += max_change;
        } else if (valve_diff < -max_change) {
            state->valve_actual -= max_change;
        } else {
            state->valve_actual = state->valve_cmd;
        }
    }
    /* When controller is dead, valve_actual stays frozen */
    
    /* Clamp valve position */
    if (state->valve_actual < 0) state->valve_actual = 0;
    if (state->valve_actual > 100) state->valve_actual = 100;
    
    /* =======================================================================
     * Thermal Model
     * 
     * heat_loss: Proportional to (inside - outside) temperature difference
     * heat_gain: From heating valve (0-100% of max power)
     * 
     * Temperature change = (heat_gain - heat_loss) / thermal_mass
     * ======================================================================= */
    
    /* Heat loss to outside environment */
    double heat_loss = (state->inside_temp - state->outside_temp) * HEAT_LOSS_FACTOR;
    
    /* Heat gain from heating system */
    double valve_fraction = state->valve_actual / 100.0;
    double heat_gain = valve_fraction * HEATER_POWER_MAX / THERMAL_MASS;
    
    /* Update temperature */
    state->inside_temp += (heat_gain - heat_loss) * dt;
    
    /* Calculate current heating power for display */
    state->heater_power = valve_fraction * HEATER_POWER_MAX;
    
    /* Clamp temperature to reasonable range */
    if (state->inside_temp < -30.0) state->inside_temp = -30.0;
    if (state->inside_temp > 50.0) state->inside_temp = 50.0;
    
    /* =======================================================================
     * Status Update
     * ======================================================================= */
    if (state->inside_temp <= TEMP_FROZEN) {
        if (state->status != STATUS_BURST) {
            state->status = STATUS_FROZEN;
            /* After some time at frozen, pipes burst */
            if (state->inside_temp <= -2.0) {
                state->status = STATUS_BURST;
                state->pipes_burst = true;
            }
        }
    } else if (state->inside_temp <= TEMP_CRITICAL) {
        state->status = STATUS_CRITICAL;
    } else if (state->inside_temp <= TEMP_WARNING) {
        state->status = STATUS_WARNING;
    } else {
        state->status = STATUS_OK;
    }
    
    pthread_mutex_unlock(&state->mutex);
}

/* ==========================================================================
 * Controller (runs only when PLC is alive)
 * ========================================================================== */

void process_run_controller(process_state_t *state) {
    pthread_mutex_lock(&state->mutex);
    
    if (!state->controller_running || state->pipes_burst) {
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    
    /* Only run automatic control in AUTO mode */
    if (state->mode != MODE_AUTO) {
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    
    /* =======================================================================
     * Simple Bang-Bang Controller with Proportional Band
     * 
     * - If temp < setpoint - 2°C: valve fully open
     * - If temp > setpoint + 2°C: valve fully closed
     * - In between: proportional response
     * ======================================================================= */
    
    double error = state->setpoint - state->inside_temp;
    double deadband = 2.0;
    
    if (error > deadband) {
        /* Too cold - need more heat */
        state->valve_cmd = 100;
    } else if (error < -deadband) {
        /* Too hot - reduce heat */
        state->valve_cmd = 0;
    } else {
        /* Proportional band: map error to valve position */
        /* error = +2 -> valve = 100, error = -2 -> valve = 0 */
        state->valve_cmd = (int)(50.0 + (error / deadband) * 50.0);
    }
    
    /* Clamp valve command */
    if (state->valve_cmd < 0) state->valve_cmd = 0;
    if (state->valve_cmd > 100) state->valve_cmd = 100;
    
    pthread_mutex_unlock(&state->mutex);
}

/* ==========================================================================
 * Controller Crash Handler
 * ========================================================================== */

void process_controller_crash(process_state_t *state) {
    pthread_mutex_lock(&state->mutex);
    
    state->controller_running = false;
    state->time_without_control = 0;
    
    /* 
     * When controller crashes, valve behavior depends on valve type:
     * - Fail-closed (safer): valve goes to 0%
     * - Fail-in-place: valve stays at current position
     * 
     * For dramatic demo, we use fail-closed (valve goes to 0%)
     * This simulates loss of control signal causing valve to close
     */
    state->valve_cmd = 0;
    
    pthread_mutex_unlock(&state->mutex);
}

/* ==========================================================================
 * Modbus Register Interface
 * ========================================================================== */

void process_to_registers(process_state_t *state, uint16_t *registers) {
    pthread_mutex_lock(&state->mutex);
    
    /* Scale temperatures by 10 for integer representation */
    /* e.g., 19.5°C becomes 195 */
    registers[0] = (uint16_t)((int16_t)(state->inside_temp * 10.0) & 0xFFFF);
    registers[1] = (uint16_t)state->valve_cmd;
    registers[2] = (uint16_t)(state->setpoint * 10.0);
    registers[3] = (uint16_t)state->mode;
    registers[4] = (uint16_t)((int16_t)(state->outside_temp * 10.0) & 0xFFFF);
    registers[5] = (uint16_t)state->status;
    registers[6] = (uint16_t)state->valve_actual;
    registers[7] = (uint16_t)(state->supply_temp * 10.0);
    registers[8] = (uint16_t)(state->runtime & 0xFFFF);
    registers[9] = (uint16_t)(state->heater_power * 10.0);
    
    pthread_mutex_unlock(&state->mutex);
}

void process_from_registers(process_state_t *state, const uint16_t *registers) {
    pthread_mutex_lock(&state->mutex);
    
    /* Only update writable registers */
    /* HR[1]: valve_cmd (0-100) */
    if (registers[1] <= 100) {
        state->valve_cmd = registers[1];
    }
    
    /* HR[2]: setpoint (scaled by 10, so 200 = 20.0°C) */
    if (registers[2] <= 400) {  /* Max 40.0°C */
        state->setpoint = registers[2] / 10.0;
    }
    
    /* HR[3]: mode (0 or 1) */
    if (registers[3] <= 1) {
        state->mode = (control_mode_t)registers[3];
    }
    
    pthread_mutex_unlock(&state->mutex);
}

/* ==========================================================================
 * Utility Functions
 * ========================================================================== */

const char* process_status_string(process_status_t status) {
    switch (status) {
        case STATUS_OK:       return "NORMAL";
        case STATUS_WARNING:  return "WARNING";
        case STATUS_CRITICAL: return "CRITICAL";
        case STATUS_FROZEN:   return "FROZEN";
        case STATUS_BURST:    return "BURST";
        default:              return "UNKNOWN";
    }
}
```

---

## display.h

```c
/*
 * display.h - Console Display for District Heating Simulation
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include "process_sim.h"
#include <stdbool.h>

/* ANSI Color Codes */
#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[1;31m"
#define COLOR_GREEN     "\033[1;32m"
#define COLOR_YELLOW    "\033[1;33m"
#define COLOR_BLUE      "\033[1;34m"
#define COLOR_CYAN      "\033[1;36m"
#define COLOR_WHITE     "\033[1;37m"
#define COLOR_BG_RED    "\033[41m"

/* Display dimensions */
#define DISPLAY_WIDTH   78

/**
 * Clear screen and move cursor to home
 */
void display_clear(void);

/**
 * Render the full console display
 * 
 * @param state     Process state to display
 * @param clients   Number of connected Modbus clients
 * @param ip        IP address string
 * @param port      Modbus port number
 */
void display_render(const process_state_t *state, int clients, 
                    const char *ip, int port);

/**
 * Render explosion/failure screen
 */
void display_render_failure(const process_state_t *state);

/**
 * Format runtime as HH:MM:SS
 */
void format_runtime(uint32_t seconds, char *buffer, size_t size);

#endif /* DISPLAY_H */
```

---

## display.c

```c
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
    const int bar_width = 50;
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
    printf("   │      │");
    for (int i = 0; i < bar_width; i++) {
        if (i == setpoint_pos) {
            printf("%s│%s", COLOR_CYAN, COLOR_RESET);
        } else if (i < temp_pos) {
            printf("%s█%s", bar_color, COLOR_RESET);
        } else {
            printf("░");
        }
    }
    printf("│          │\n");
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
    
    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║            DISTRICT HEATING CONTROLLER - BUILDING 47, ZONE 3                 ║\n");
    printf("║               FrostyGoop Target Simulation (libmodbus 3.1.2)                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                              ║\n");
    printf("║   OUTSIDE TEMP     ❄️   %6.1f°C                                              ║\n", state->outside_temp);
    printf("║                                                                              ║\n");
    printf("║   ┌────────────────────────────────────────────────────────────────────┐     ║\n");
    
    /* Building zone header with status indicators */
    if (state->status >= STATUS_WARNING) {
        printf("║   │  BUILDING ZONE                                        %s%s %s %s%s   │     ║\n",
               status_color, status_icon, status_icon, status_icon, COLOR_RESET);
    } else {
        printf("║   │  BUILDING ZONE                                                     │     ║\n");
    }
    
    printf("║   │                                                                    │     ║\n");
    printf("║   │              INSIDE TEMPERATURE                                    │     ║\n");
    printf("║   │      ┌──────────────────────────────────────────────────┐          │     ║\n");
    
    /* Temperature bar */
    printf("║");
    render_temp_bar(state->inside_temp, state->setpoint);
    printf("     ║\n");
    
    printf("║   │      └──────────────────────────────────────────────────┘          │     ║\n");
    printf("║   │      -20        0        10        20        30       40°C         │     ║\n");
    
    /* Current temperature display */
    if (state->status >= STATUS_CRITICAL) {
        printf("║   │                           %s%6.1f°C %s%s                              │     ║\n",
               COLOR_RED, state->inside_temp, status_icon, COLOR_RESET);
    } else if (state->status == STATUS_WARNING) {
        printf("║   │                           %s%6.1f°C %s%s                              │     ║\n",
               COLOR_YELLOW, state->inside_temp, status_icon, COLOR_RESET);
    } else {
        printf("║   │                           %s%6.1f°C%s  (Setpoint: %.1f°C)              │     ║\n",
               COLOR_GREEN, state->inside_temp, COLOR_RESET, state->setpoint);
    }
    
    printf("║   │                                                                    │     ║\n");
    
    /* Valve and radiator display */
    const char *valve_color = state->controller_running ? COLOR_GREEN : COLOR_RED;
    const char *valve_warning = state->controller_running ? "" : " ⚠";
    
    printf("║   │      ┌─────────┐     ┌──────────────┐                              │     ║\n");
    printf("║   │      │ ░░░░░░░ │ ◄── │ VALVE: %s%3d%%%s │ ◄── Supply %.0f°C%s           │     ║\n",
           valve_color, state->valve_actual, COLOR_RESET, state->supply_temp, valve_warning);
    
    /* Radiator state based on temperature */
    if (state->inside_temp <= TEMP_CRITICAL) {
        printf("║   │      │   ICE   │     └──────────────┘                              │     ║\n");
        printf("║   │      │ FORMING │                                                   │     ║\n");
    } else if (state->valve_actual > 50) {
        printf("║   │      │ ▓▓▓▓▓▓▓ │     └──────────────┘                              │     ║\n");
        printf("║   │      │  (HOT)  │                                                   │     ║\n");
    } else if (state->valve_actual > 0) {
        printf("║   │      │ ░░░░░░░ │     └──────────────┘                              │     ║\n");
        printf("║   │      │ (WARM)  │                                                   │     ║\n");
    } else {
        printf("║   │      │         │     └──────────────┘                              │     ║\n");
        printf("║   │      │ (COLD)  │                                                   │     ║\n");
    }
    
    printf("║   │      └─────────┘     Power: %5.1f kW                               │     ║\n", state->heater_power);
    printf("║   │                                                                    │     ║\n");
    printf("║   └────────────────────────────────────────────────────────────────────┘     ║\n");
    printf("║                                                                              ║\n");
    
    /* Mode and status line */
    printf("║   MODE: [%s%s%s]     STATUS: %s%s %s%s     RUNTIME: %s               ║\n",
           state->mode == MODE_AUTO ? COLOR_GREEN : COLOR_YELLOW,
           state->mode == MODE_AUTO ? "AUTO  " : "MANUAL",
           COLOR_RESET,
           status_color, status_icon, status_str, COLOR_RESET,
           runtime_str);
    
    printf("║                                                                              ║\n");
    
    /* Warning messages */
    if (strlen(warning1) > 0) {
        printf("║   %s%-70s%s   ║\n", COLOR_RED, warning1, COLOR_RESET);
    }
    if (strlen(warning2) > 0) {
        printf("║   %s%-70s%s   ║\n", COLOR_RED, warning2, COLOR_RESET);
    }
    if (strlen(warning1) > 0 || strlen(warning2) > 0) {
        printf("║                                                                              ║\n");
    }
    
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Modbus TCP: %s:%-5d | Clients: %d | PLC: %s%-7s%s                       ║\n",
           ip, port, clients, plc_color, plc_status, COLOR_RESET);
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    
    fflush(stdout);
}

/* ==========================================================================
 * Failure Screen
 * ========================================================================== */

void display_render_failure(const process_state_t *state) {
    char runtime_str[16];
    format_runtime(state->time_without_control, runtime_str, sizeof(runtime_str));
    
    display_clear();
    
    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║            DISTRICT HEATING CONTROLLER - BUILDING 47, ZONE 3                 ║\n");
    printf("║               FrostyGoop Target Simulation (libmodbus 3.1.2)                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║                                                                              ║\n");
    printf("║                                                                              ║\n");
    printf("║                     %s██████████████████████████████████%s                       ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                   %s██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██%s                     ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    ❄️  PIPES FROZEN / BURST  ❄️   ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    Final Temperature: %5.1f°C   ░░██%s                   ║\n", COLOR_BG_RED, state->inside_temp, COLOR_RESET);
    printf("║                 %s██░░    Time without heat: %s  ░░██%s                   ║\n", COLOR_BG_RED, runtime_str, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    BUILDING DAMAGE:            ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    • Burst pipes               ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    • Water flooding            ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░    • Structure damage          ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                 %s██░░                                ░░██%s                   ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                   %s██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██%s                     ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                     %s██████████████████████████████████%s                       ║\n", COLOR_BG_RED, COLOR_RESET);
    printf("║                                                                              ║\n");
    printf("║   %sROOT CAUSE:%s Controller crash via CVE-2019-14462 exploit                   ║\n", COLOR_YELLOW, COLOR_RESET);
    printf("║   %sATTACK VECTOR:%s FrostyGoop-style malformed Modbus TCP packet               ║\n", COLOR_YELLOW, COLOR_RESET);
    printf("║                                                                              ║\n");
    printf("║   %s💀 CATASTROPHIC FAILURE - SIMULATION HALTED 💀%s                             ║\n", COLOR_RED, COLOR_RESET);
    printf("║                                                                              ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Restart with: docker-compose restart plc                                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    
    fflush(stdout);
}
```

---

## heating_controller.c

```c
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
#include <modbus.h>

#include "process_sim.h"
#include "display.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

#define SERVER_ADDRESS      "0.0.0.0"
#define SERVER_PORT         502
#define NB_REGISTERS        10
#define MAX_CONNECTIONS     5

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
 * Modbus Handler - Processes client requests
 * ========================================================================== */

static void handle_modbus_client(modbus_t *ctx) {
    uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
    int rc;
    
    while (g_running && g_process.controller_running) {
        rc = modbus_receive(ctx, query);
        
        if (rc > 0) {
            log_msg("INFO", "Received Modbus request: %d bytes", rc);
            
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
                log_msg("ERROR", "modbus_reply failed: %s", modbus_strerror(errno));
                break;
            }
            
            /* Check if client wrote to registers */
            process_from_registers(&g_process, g_mb_mapping->tab_registers);
            
            log_msg("INFO", "Sent Modbus reply: %d bytes", rc);
            
        } else if (rc == -1) {
            /* Connection closed or error */
            break;
        }
    }
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
    g_mb_mapping = modbus_mapping_new(0, 0, NB_REGISTERS, 0);
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
    
    /* Main loop - accept and handle Modbus clients */
    while (g_running) {
        log_msg("INFO", "Waiting for client connection...");
        
        rc = modbus_tcp_accept(g_modbus_ctx, &server_socket);
        if (rc == -1) {
            if (g_running) {
                log_msg("ERROR", "Accept failed: %s", modbus_strerror(errno));
            }
            continue;
        }
        
        pthread_mutex_lock(&g_client_mutex);
        g_client_count++;
        pthread_mutex_unlock(&g_client_mutex);
        
        log_msg("INFO", "Client connected");
        
        /* Handle this client */
        handle_modbus_client(g_modbus_ctx);
        
        pthread_mutex_lock(&g_client_mutex);
        g_client_count--;
        pthread_mutex_unlock(&g_client_mutex);
        
        log_msg("INFO", "Client disconnected");
        
        /* Check if we crashed (CVE triggered) */
        if (!g_process.controller_running) {
            log_msg("ERROR", "Controller crashed! Valve frozen at %d%%", 
                    g_process.valve_actual);
            process_controller_crash(&g_process);
        }
        
        modbus_close(g_modbus_ctx);
    }
    
    /* Wait for process thread */
    pthread_join(process_tid, NULL);
    
cleanup:
    log_msg("INFO", "Shutting down...");
    
    if (g_mb_mapping) {
        modbus_mapping_free(g_mb_mapping);
    }
    if (g_modbus_ctx) {
        modbus_close(g_modbus_ctx);
        modbus_free(g_modbus_ctx);
    }
    if (server_socket != -1) {
        close(server_socket);
    }
    
    process_cleanup(&g_process);
    
    if (g_log_fp && g_log_fp != stdout) {
        fclose(g_log_fp);
    }
    
    return EXIT_SUCCESS;
}
```

---

## start-plc.sh

```bash
#!/bin/bash
#
# FrostyGoop District Heating Simulation
# Startup script
#

set -e

LOG_FILE="${LOG_FILE:-/logs/plc.log}"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Log startup
{
    echo "========================================"
    echo "FrostyGoop District Heating Simulation"
    echo "Starting at $(date)"
    echo "libmodbus 3.1.2 (VULNERABLE)"
    echo "========================================"
} | tee -a "$LOG_FILE"

# Execute the controller
exec /src/heating_controller
```

---

## Docker Compose Service Definition

```yaml
services:
  # Normal PLC (for crash demonstration)
  plc:
    build:
      context: ./plc
      target: normal
    container_name: ics-plc
    hostname: plc
    networks:
      ics-protected:
        ipv4_address: 192.168.95.2
    ports:
      - "5020:502"
    volumes:
      - ./logs:/logs
    environment:
      - LOG_FILE=/logs/plc.log
      - TERM=xterm-256color
    tty: true
    stdin_open: true
    restart: unless-stopped

  # ASAN PLC (for CVE proof)
  plc-asan:
    build:
      context: ./plc
      target: asan
    container_name: ics-plc-asan
    hostname: plc-asan
    ports:
      - "5021:502"
    volumes:
      - ./logs:/logs
    environment:
      - LOG_FILE=/logs/plc-asan.log
      - ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_legend=0
      - TERM=xterm-256color
    tty: true
    stdin_open: true
    restart: unless-stopped
```

---

## Build Instructions

### Build Normal Container

```bash
cd plc/
docker build --target normal -t ics-plc:normal .
```

### Build ASAN Container

```bash
cd plc/
docker build --target asan -t ics-plc:asan .
```

### Build via Docker Compose

```bash
docker-compose build plc plc-asan
```

---

## Testing

### Test 1: Normal Operation

```bash
# Start PLC
docker-compose up plc

# In another terminal, use Open Modscan to connect to localhost:5020
# Read HR[0-9] to see process state
# Watch console display update every second
```

### Test 2: Manual Control via Open Modscan

```bash
# Connect Open Modscan to localhost:5020

# Switch to manual mode:
# Write HR[3] = 0

# Close valve completely:
# Write HR[1] = 0

# Watch temperature drop on console display

# Open valve to recover:
# Write HR[1] = 100
```

### Test 3: CVE Attack (Unprotected)

```bash
# Start PLC
docker-compose up plc

# In another terminal, send exploit
./poc/cve_14462_sender localhost 5020

# Watch console:
# - "PLC: CRASHED" appears
# - Temperature starts dropping
# - After ~5-8 minutes: PIPES FROZEN
```

### Test 4: Protected via seL4 Gateway

```bash
# Start gateway and PLC
docker-compose up gateway plc

# Wait for seL4 to boot (~20 seconds)

# Use Open Modscan via gateway: 192.168.96.2:502
# Normal operation works

# Send exploit through gateway
./poc/cve_14462_sender 192.168.96.2 502

# Gateway blocks attack
# PLC continues normal operation
# Temperature remains stable
```

---

## Register Map Reference

| Register | Name | Range | R/W | Scale | Description |
|----------|------|-------|-----|-------|-------------|
| HR[0] | inside_temp | -300 to 500 | R | ÷10 | Indoor temperature (°C) |
| HR[1] | valve_cmd | 0-100 | R/W | 1 | Valve command (%) |
| HR[2] | setpoint | 0-400 | R/W | ÷10 | Temperature setpoint (°C) |
| HR[3] | mode | 0-1 | R/W | 1 | 0=Manual, 1=Auto |
| HR[4] | outside_temp | -400 to 400 | R | ÷10 | Outside temperature (°C) |
| HR[5] | status | 0-4 | R | 1 | Process status code |
| HR[6] | valve_actual | 0-100 | R | 1 | Actual valve position (%) |
| HR[7] | supply_temp | 0-1000 | R | ÷10 | Supply temperature (°C) |
| HR[8] | runtime | 0-65535 | R | 1 | Runtime (seconds) |
| HR[9] | heater_power | 0-1000 | R | ÷10 | Heating power (kW) |

### Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | Normal operation |
| 1 | WARNING | Below 10°C - hypothermia risk |
| 2 | CRITICAL | Below 5°C - pipe freeze risk |
| 3 | FROZEN | Below 0°C - pipes frozen |
| 4 | BURST | Catastrophic failure |

---

## Timing Parameters

These constants in `process_sim.h` control the simulation speed:

| Parameter | Default | Effect |
|-----------|---------|--------|
| HEAT_LOSS_FACTOR | 0.015 | Higher = faster cooling |
| HEATER_POWER_MAX | 80.0 | Max heating capacity |
| THERMAL_MASS | 30.0 | Higher = slower temp changes |
| UPDATE_INTERVAL_MS | 1000 | Physics update rate |

**With defaults:** Temperature drops from 20°C to 0°C in approximately 5-8 minutes when heating fails at -15°C outside.

To speed up for demo:
```c
#define HEAT_LOSS_FACTOR 0.03   // Double the cooling rate
#define THERMAL_MASS     15.0   // Half the thermal mass
```

---

## Troubleshooting

### Console Display Garbled

```bash
# Ensure TERM is set
export TERM=xterm-256color

# Or run with explicit terminal
docker-compose run --rm -e TERM=xterm-256color plc
```

### Port Already in Use

```bash
# Check what's using port 5020
sudo lsof -i :5020

# Kill if necessary or change port in docker-compose.yml
```

### Container Exits Immediately

```bash
# Check logs
docker-compose logs plc

# Run interactively
docker-compose run --rm plc /bin/bash
```

### ASAN Not Showing Output

```bash
# Run directly without compose
docker run --rm -it \
  -e ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
  -p 5021:502 \
  ics-plc:asan
```

---

## Files Summary

| File | Lines | Description |
|------|-------|-------------|
| Dockerfile | ~60 | Multi-stage build |
| Makefile | ~35 | Build configuration |
| heating_controller.c | ~280 | Main program |
| process_sim.h | ~120 | Process header |
| process_sim.c | ~220 | Physics simulation |
| display.h | ~35 | Display header |
| display.c | ~280 | Console rendering |
| start-plc.sh | ~20 | Startup script |

---

## Claude Code Task

**Task:** Create the `plc/` directory with all files listed above.

1. Create `plc/Dockerfile` (multi-stage build)
2. Create `plc/Makefile` (build configuration)
3. Create `plc/process_sim.h` (process simulation header)
4. Create `plc/process_sim.c` (physics model)
5. Create `plc/display.h` (display header)
6. Create `plc/display.c` (console rendering)
7. Create `plc/heating_controller.c` (main program)
8. Create `plc/start-plc.sh` (startup script)

Test with:
```bash
cd plc/
docker build --target normal -t ics-plc:normal .
docker run --rm -it -p 5020:502 ics-plc:normal
```

---

*Document prepared for Claude Code implementation of FrostyGoop district heating simulation*
