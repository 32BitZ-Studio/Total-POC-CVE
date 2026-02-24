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
