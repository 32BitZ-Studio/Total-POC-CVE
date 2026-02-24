# Fuzzing Lab: Enhancing Fuzzing for tmux

> Software Security @ EPFL, Spring 2025

## Abstract

In this lab, we enhanced the fuzzing efforts for the `tmux` terminal multiplexer within Google's OSS-Fuzz infrastructure. We first established a baseline by evaluating the line coverage of the existing `input-fuzzer` harness, both with and without its provided seed corpus, noting comparable initial coverage. Following this, we identified two significant code regions in `tmux` poorly exercised by the baseline fuzzer. To address these coverage gaps, we developed and evaluated two new targeted fuzzing harnesses, `cmd-fuzzer` and `argument-fuzzer`, demonstrating their ability to improve coverage in these previously under-tested areas. As these fuzzing improvements did not uncover new critical vulnerabilities within the project's timeframe, our crash analysis focused on a known historical vulnerability. We developed a proof-of-concept (PoC) for CVE-2020-27347 (a stack-based buffer overflow), analyzed its root cause, discussed the implemented fix, and assessed its security implications.

## Project Overview and Goals

This project aimed to apply and enhance fuzzing techniques on the `tmux` open-source terminal multiplexer, utilizing the OSS-Fuzz framework. The project encompassed several key stages:

1. **Baseline Evaluation (Part 1):**

   - Understand and evaluate the existing `input-fuzzer` harness for `tmux`.
   - Compare its code coverage performance when run with its default seed corpus versus an empty seed corpus.

2. **Coverage Gap Analysis (Part 2):**

   - Analyze coverage reports from Part 1 to identify significant code regions in `tmux` not adequately exercised by the `input-fuzzer`.
   - Focus on argument parsing (`arguments.c`) and command parsing/execution logic (`cmd-parse.c`, `cmd-*.c` modules) as key areas for improvement.

3. **Fuzzer Improvement (Part 3):**

   - Develop two new, targeted fuzzing harnesses:
     - `argument-fuzzer`: Specifically designed to test the command-line argument parsing logic in `arguments.c`.
     - `cmd-fuzzer`: Designed to test the command parsing and execution pathways, targeting `cmd-parse.c` and various `cmd-*.c` modules.
   - Evaluate the effectiveness of these new harnesses by measuring their achieved code coverage and comparing it against the baseline.

4. **Crash Analysis (Part 4):**
   - Since no new critical vulnerabilities were discovered by the improved fuzzers within the project's timeframe, a known, pre-existing vulnerability in `tmux` (CVE-2020-27347) was selected for in-depth analysis.
   - This involved developing a Proof of Concept (PoC) to reproduce the crash, analyzing its root cause, understanding the applied fix, and assessing its security implications.

## Repository Structure

The final submission is organized as follows (within the `submission/` directory):

```text
submission/
├── README.md                   # This file
├── part_1/                     # Files for Part 1: Baseline Evaluation
│   ├── oss-fuzz.diff           # Diff for removing seed corpus for input-fuzzer
│   ├── project.diff            # (Likely empty or minor for Part 1)
│   ├── remove_seed_corpus.patch # The actual patch file used
│   ├── report/                 # HTML Coverage reports for input-fuzzer
│   │   ├── w_corpus/
│   │   └── wo_corpus/
│   ├── run.w_corpus.sh         # Script to run input-fuzzer with corpus
│   └── run.wo_corpus.sh        # Script to run input-fuzzer without corpus
├── part_3/                     # Files for Part 3: Fuzzer Improvements
│   ├── coverage_noimprove/     # Baseline coverage (e.g., from input-fuzzer without corpus)
│   │   └── ...
│   ├── improve1/               # Improvement 1: argument-fuzzer
│   │   ├── coverage_improve1/  # Coverage report for argument-fuzzer
│   │   ├── oss-fuzz.diff       # OSS-Fuzz config changes for argument-fuzzer
│   │   ├── project.diff        # Tmux changes for argument-fuzzer (e.g., new .cc, Makefile.am)
│   │   └── run.improve1.sh     # Script to run argument-fuzzer
│   └── improve2/               # Improvement 2: cmd-fuzzer
│       ├── coverage_improve2/  # Coverage report for cmd-fuzzer
│       ├── oss-fuzz.diff       # OSS-Fuzz config changes for cmd-fuzzer
│       ├── project.diff        # Tmux changes for cmd-fuzzer
│       └── run.improve2.sh     # Script to run cmd-fuzzer
├── part_4/                     # Files for Part 4: Crash Analysis (CVE-2020-27347)
│   ├── environment/            # Docker environment for PoC
│   │   ├── Dockerfile
│   │   ├── run_tmux_cve_test.sh # Core PoC test logic
│   │   ├── test_fixed.sh
│   │   └── test_vulnerable.sh
│   └── run.poc.sh              # Script to build Docker image and run PoC tests
└── report.pdf                  # The comprehensive project report
```

_(Note: The `scripts/` directory containing `_run_fuzz_core.sh` is a helper and would be part of the root if this README is at the true project root alongside `submission/`)_

## Setup and Usage

All fuzzing campaigns and the CVE PoC reproduction are designed to be run within Docker environments orchestrated by shell scripts.

## Setup and Usage

All fuzzing campaigns and the CVE PoC reproduction are designed to be run within Docker environments orchestrated by shell scripts.

**Prerequisites:**

- Docker installed and running on a Unix-like system.
- `bash` shell and `git` client.
- SSH keys configured for `git@github.com` if the scripts need to clone `oss-fuzz` (they attempt to clone if `oss-fuzz/` is not found in the project root). Alternatively, you can pre-clone `https://github.com/google/oss-fuzz.git` into the project root.

**General Scripting Architecture:**
The project uses a centralized core script, `scripts/_run_fuzz_core.sh` (not included in the `submission/` directory but part of the overall project structure this README assumes). Individual runner scripts located in `submission/part_1/`, `submission/part_3/improve1/`, `submission/part_3/improve2/`, and `submission/part_4/` are responsible for:

1. Setting up the specific test environment by applying run-specific `oss-fuzz.diff` patches to a clean checkout of the `oss-fuzz` repository (expected to be at `../../oss-fuzz` relative to most runner scripts).
2. Exporting configuration variables (like `PROJECT`, `HARNESS`, `LABEL`, paths to project-specific patches, and output directories).
3. Invoking the `_run_fuzz_core.sh` script, which then handles:
   - Applying an optional project-level patch (e.g., to add new fuzzer sources to `tmux`).
   - Building the OSS-Fuzz Docker image (if flagged).
   - Building the specified fuzzer(s) with the chosen sanitizer.
   - Executing the fuzzer for the configured duration (typically 4 hours).
   - Generating and exporting corpus and HTML coverage reports to the designated locations within the `submission/` directory structure.

**Running the Scripts:**
It's generally recommended to execute the runner scripts from the project's root directory to ensure correct relative path resolution for `oss-fuzz/` and output directories.

**1. Part 1: Baseline Evaluation (`input-fuzzer`)**
These scripts evaluate the existing `input-fuzzer` for `tmux`.

```bash
# From the project root directory:
./submission/part_1/run.w_corpus.sh  # Run input-fuzzer with default seed corpus
./submission/part_1/run.wo_corpus.sh # Run input-fuzzer without seed corpus
```

`run.w_corpus.sh` uses the default `tmux` build behavior regarding seeds.
`run.wo_corpus.sh` applies `submission/part_1/remove_seed_corpus.patch` (via its local `oss-fuzz.diff` which would call out to this patch or integrate its changes) to the `oss-fuzz/projects/tmux/build.sh` to ensure no initial seed corpus is used. Coverage reports are exported to `submission/part_1/report/w_corpus/ and submission/part_1/report/wo_corpus/` and `submission/part_1/report/wo_corpus/` respectively.

**2. Part 3: Fuzzer Improvements (`input-fuzzer`)**

- **Improvement 1 (argument-fuzzer)**: Targets arguments.c.

  ```bash
  # From the project root directory:
  ./submission/part_3/improve1/run.improve1.sh
  ```

- **Improvement 2 (cmd-fuzzer)**: Targets cmd-parse.c and command execution.

  ```bash
  # From the project root directory:
  ./submission/part_3/improve2/run.improve2.sh
  ```

Each `run.improveX.sh` script applies its local `oss-fuzz.diff` and sets `PROJECT_PATCH_FILE` to its local `project.diff` (which adds the new fuzzer code to tmux and updates `Makefile.am`). Coverage reports are exported to the respective `submission/part_3/improveX/coverage_improveX/` directories. The `submission/part_3/coverage_noimprove/` directory contains baseline coverage from Part 1 for comparison.

## 3. Part 4: CVE-2020-27347 PoC Reproduction

```bash
# From the project root directory:
./submission/part_4/run.poc.sh
```

This script builds a dedicated Docker image (from `submission/part_4/environment/Dockerfile`) and tests `tmux 3.1b` (vulnerable) against the patched commit `a868bac`.

## Key Findings and Results

(Detailed explanations, figures, and tables can be found in the full report.pdf)

### Part 1 (Baseline - input-fuzzer)

- **With default seed corpus:** 14.00% line coverage (7281/51997 lines), 24.44% function coverage.
- **Without seed corpus:** 13.94% line coverage (7248/51997 lines), 24.31% function coverage.
- The impact of the initial seed corpus was minor for the existing `input-fuzzer`.
- Significant portions of tmux, notably argument parsing (`arguments.c`), command parsing/execution (`cmd-parse.c`, `cmd-*.c`), and client/server logic (`client.c`, `server.c`), were largely unexercised (e.g., `arguments.c` at ~5.8% line coverage).

### Part 3 (Fuzzer Improvements)

- **`argument-fuzzer` (targeting `arguments.c`):** Achieved 66.62% line coverage for `arguments.c`, a substantial increase from the ~5.8% baseline.
- **`cmd-fuzzer` (targeting command parsing & execution):** Increased line coverage for `cmd-parse.c` to 42.58% (from ~27%) and function coverage to 77.78%.
- `arguments.c` coverage also rose to 45.54% through this fuzzer.
- `cmd.c` reached 39.14% line coverage.
- Achieved new or significantly improved coverage in various `cmd-*.c` modules (e.g., `cmd-bind-key.c`, `cmd-set-options.c` to 50% function coverage) and key-handling routines (`key-string.c` to 30% line coverage, `key-bindings.c` to 6.05% line coverage).

### Part 4 (CVE-2020-27347 Analysis)

- Successfully reproduced CVE-2020-27347 (stack buffer overflow in SGR escape sequence parsing) on tmux 3.1b (commit `6a33a12`) using the payload `\033[::::::7::1:2:3::5:6:7:m`.
- Confirmed that tmux commit `a868bac` (which includes the fix and leads to version 3.1c) was not susceptible to the crash.
- The vulnerability, exploitable by writing a crafted sequence to a pane TTY, leads to Denial of Service and has potential for Arbitrary Code Execution. It's rated high severity (CVSS 7.8).

## Challenges Faced

- Ensuring correct tmux startup in a scripted Docker environment, particularly avoiding "not a terminal" errors, required using detached sessions for the CVE PoC.
- Managing the git state (ensuring full clones, clean resets before applying patches) across different test scenarios was critical for reproducible builds of specific tmux versions.
- Developing effective new fuzzing harnesses (`argument-fuzzer`, `cmd-fuzzer`) necessitated a good understanding of tmux's internal argument and command processing logic to target specific unexercised code paths.

## Future Work

- Further enhance the `cmd-fuzzer` to cover a wider array of `cmd-*.c` modules, especially those dealing with complex state interactions like window, layout, or pane manipulations.
- Investigate fuzzing strategies for the tmux client-server communication protocol, potentially involving more complex environment mocking.
- Explore the use of structure-aware fuzzing for the tmux command language, possibly by leveraging grammar definitions from `cmd-parse.y` to generate more syntactically valid and complex command sequences.

## Useful Links

- [tmux Project](https://github.com/tmux/tmux)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
- [CVE-2020-27347](https://www.cve.org/CVERecord?id=CVE-2020-27347)
- [Project Report PDF](./submission/report.pdf) (Path relative to project root)
