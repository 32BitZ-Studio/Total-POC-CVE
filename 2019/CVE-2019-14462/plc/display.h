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
