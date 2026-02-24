# Repository Guidelines

## Project Structure & Module Organization
- Core protocol logic lives under `src/`; isolate new protocol variants in fresh translation units and expose public hooks via `modbus.h`.
- Integration and bandwidth tests reside in `tests/`; store scenario-specific fixtures beside their invoking binaries.
- Documentation sources live in `doc/`; update AsciiDoc when altering public APIs.
- Autotools helpers (`autogen.sh`, `build-aux/`, `m4/`) regenerate build metadata—modify macros here instead of editing generated files.
- Historical CVE proof-of-concepts sit in `cve-*`; review them when evaluating regressions or security fixes.

## Build, Test, and Development Commands
- `./autogen.sh` prepares `configure` after cloning or touching Autotools inputs.
- `./configure --prefix=/usr/local` configures outputs; add feature flags here when needed.
- `make -j$(nproc)` builds static/shared libs and utilities.
- `make check` runs the TCP integration suite from `tests/`.
- `make install DESTDIR=/tmp/pkg` stages artifacts for packaging without polluting the system.

## Coding Style & Naming Conventions
- Use four-space indentation, braces on the same line, and snake_case function names; macros stay SCREAMING_SNAKE_CASE.
- Prefer fixed-width types such as `uint8_t` and `size_t` from `<stdint.h>`.
- Keep helpers static or prefix with `_modbus_` to match existing patterns.
- Leave concise C comments for non-obvious logic; avoid narration of trivial operations.

## Testing Guidelines
- Pair `./unit-test-server` and `./unit-test-client` in separate shells for manual scenarios.
- Extend integration coverage by dropping new binaries (e.g., `fuzzer-client`) into `tests/`, alongside any fixtures.
- For critical paths, compile with coverage flags (`CFLAGS="--coverage"`) and share summaries alongside patches.

## Commit & Pull Request Guidelines
- Write imperative commit subjects under ~72 characters, optionally scoped (e.g., `doc:` or `build:`), and explain the "what" and "why" in the body.
- Reference related issues and note verification steps (`make`, `make check`) in commit or PR descriptions.
- Ensure documentation, packaging specs, and CI scripts track your changes before requesting review.
