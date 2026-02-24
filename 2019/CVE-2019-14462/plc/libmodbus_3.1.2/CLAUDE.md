# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

libmodbus is a C library implementing the Modbus protocol for serial (RTU) and Ethernet (TCP) communication. Licensed under LGPL v2.1 or later.

## Build and Test Commands

### Initial Setup
```bash
./autogen.sh                # Generate configure script (only after cloning or modifying Autotools inputs)
./configure --prefix=/usr/local  # Configure build; add feature flags here as needed
make -j$(nproc)             # Build static/shared libraries and utilities
make install                # Install to system (or use DESTDIR=/tmp/pkg for staging)
sudo ldconfig               # Update library cache after installation
```

### Testing
```bash
make check                  # Run TCP integration test suite

# Manual testing - run these in separate terminals:
cd tests
./unit-test-server          # Terminal 1
./unit-test-client          # Terminal 2 (runs TCP unit tests by default)
```

### Compiling Test Programs Manually
```bash
gcc test-program.c -o test-program `pkg-config --libs --cflags libmodbus`
```

### Documentation
```bash
make htmldoc                # Generate HTML docs in doc/ directory
man libmodbus               # View general library documentation (after installation)
```

## Architecture and Structure

### Core Protocol Implementation
- **src/modbus.c**: Core protocol logic, common functions for all backends
- **src/modbus-tcp.c**: TCP/IP backend implementation
- **src/modbus-rtu.c**: RTU (serial) backend implementation
- **src/modbus-data.c**: Data manipulation utilities (byte swapping, float/bit conversions)

### Public API Headers
- **src/modbus.h**: Main public API - all function prototypes and constants
- **src/modbus-tcp.h**: TCP-specific initialization functions
- **src/modbus-rtu.h**: RTU-specific initialization functions
- **src/modbus-version.h**: Version macros

### Private Headers
- **src/modbus-private.h**: Internal structures and backend function pointers
- **src/modbus-tcp-private.h**: TCP backend internals
- **src/modbus-rtu-private.h**: RTU backend internals

### Backend Architecture Pattern
The library uses a backend abstraction via function pointers (`modbus_backend_t`). Each transport (TCP/RTU) implements:
- `connect()` / `close()`: Connection lifecycle
- `send()` / `recv()`: Low-level I/O
- `check_integrity()`: Protocol validation
- `pre_check_confirmation()`: Response header verification
- `build_request_basis()`: Build protocol-specific headers

New protocol variants should follow this pattern: create separate translation units and register backends via `modbus-private.h`.

### Test Programs
- **tests/unit-test-{client,server}.c**: Protocol conformance testing
- **tests/random-test-{client,server}.c**: Stress testing with randomized queries
- **tests/bandwidth-*.c**: Performance/throughput benchmarks
- **cve-*.c**: Historical vulnerability proof-of-concepts for regression testing

## Coding Conventions

- Four-space indentation, same-line braces, snake_case functions
- Macros use SCREAMING_SNAKE_CASE
- Use fixed-width types: `uint8_t`, `uint16_t`, `size_t` from `<stdint.h>`
- Static helpers or prefix with `_modbus_` for internal functions
- Concise C comments for non-obvious logic only

## Testing Guidelines

- Pair `unit-test-server` and `unit-test-client` for manual validation
- Add new test binaries to `tests/` with fixtures alongside them
- For coverage analysis: compile with `CFLAGS="--coverage"` and generate reports
- `make check` must pass before submitting changes

## Commit Guidelines

- Imperative subjects under 72 characters, optionally scoped (`doc:`, `build:`, `tcp:`, `rtu:`)
- Explain "what" and "why" in commit body
- Reference issues and document verification steps (`make && make check`)
- Update documentation, packaging specs, and CI when touching public APIs
