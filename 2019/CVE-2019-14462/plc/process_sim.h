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
