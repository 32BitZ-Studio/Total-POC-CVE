# Fork Folder

This folder contains forks of the public repos used.

## OSS-Fuzz

### Starting with OSS-Fuzz

Creating the [oss-fuzz](/forks/oss-fuzz/) folder if it does not exist.
```bash
git clone https://github.com/google/oss-fuzz.git && cd oss-fuzz
```

Build docker image for the project:

```bash
python3 infra/helper.py build_image tmux
```

Build Project fuzzers:
```bash
python3 infra/helper.py build_fuzzers tmux
```

Run a fuzzer and store the result in a corpus directory:
```bash
mkdir -p build/out/corpus
python3 infra/helper.py run_fuzzer tmux input-fuzzer --corpus-dir build/out/corpus
```

Build coverage-instrumented analysis:
```bash
python3 infra/helper.py build_fuzzers --sanitizer coverage tmux
```
The option `--sanitizer coverage` build binaries with code coverage instrumentation.

Generate a coverage report:
```bash
python3 infra/helper.py coverage tmux --corpus-dir build/out/corpus --fuzz-target input-fuzzer
```

Reproduce a crash: 
```bash
python3 infra/helper.py reproduce tmux client-fuzzer build/out/tmux/crash-6002bc54e6a0a43a80a3cea8cc1b7c3dd745d1a0
```

This uses the `llvm-cov` command.

### OSS-Fuzz *Project* Files

In each *project* of *OSS-Fuzz* (subdirectory in `oss-fuzz/projects`) there are the following files:
- `project.yaml`, containing the Project Configuration, so homepage, language, supported Fuzzing Engines, Repository, Sanitizers and other options.
- `Dockerfile`, contains the configuration for the project's image for OSS-Fuzz 
- `build.sh`: compiles the project (in our case *tmux* with fuzzing support and prepares the specified seed corpus). 

### OSS-Fuzzer Commands

- `build_image`: Creates a Docker image for your project, containing all dependencies needed to build the project and its fuzzers. Uses the Dockerfile in your project's directory.
- `build_fuzzers`: Compiles the fuzzers for your project using the previously built Docker image. Requires a build.sh script in your project directory to define how fuzzers are built.
- `run_fuzzer`: Executes a fuzzer locally to test the project or reproduce crashes. Specify a corpus directory (--corpus-dir) to store/reuse test inputs. Use --engine <libfuzzer|afl|coverage> to choose the fuzzing engine (default: libFuzzer).
- `coverage`: Generates a code coverage report for the fuzzers. Requires building fuzzers with `--sanitizer coverage` first. 
- `check_build`: Verifies that the project and fuzzers are built correctly. 
- `shell`: Starts an interactive shell inside the project's Docker container.
- List Fuzzers for *tmux*: 
    ```bash
    python3 infra/helper.py shell tmux
    ls /out/*-fuzzer
    ```

- How to modify the contents of an already existing container?
    - First start the container: `python3 infra/helper.py shell tmux`
    - In *a new terminal* run the Docker command to copy the new files: 
    ```bash
    docker cp projects/tmux/cmd-fuzzer.cc tmux-container:/src/tmux/fuzz/
    docker cp projects/tmux/input-fuzzer.c tmux-container:/src/tmux/fuzz/
    docker cp projects/tmux/input-fuzzer.dict tmux-container:/src/tmux/fuzz/
    docker cp projects/tmux/input-fuzzer.options tmux-container:/src/tmux/fuzz/
    docker cp projects/tmux/Makefile.am tmux-container:/src/tmux/
    ```
     Where `tmux-container` is the ID of the running container. The ID can be found using `docker ps -a --format "{{.Names}}" | grep -v "CONTAINER"`.


## **tmux**

[*OSS-Fuzz Introspector*](https://introspector.oss-fuzz.com/project-profile?project=libssh), the basic dashboard with the useful links for both the project and the fuzzing data. There the number of fuzzers can be found (`Fuzzer count`), as well as `Lines of code`, `Lines covered` or `Code coverage` percentage.

[*tmux* OSS-Fuzz Introspector](https://introspector.oss-fuzz.com/project-profile?project=tmux)

### Current Fuzzing files

- `input-fuzzer.c`: fuzzer targeting tmux's input parsing logic. `LLVMFuzzerTestOneInput` simulates tmux processing fuzzed input data. It does so by:
    1. Creating a *tmux* window.
    2. Feeds fuzzed input (`data`) into tmux input parser (`input_parse_buffer`)
    3. Handles tmux events and cleanup.

    Inputs must be less that `FUZZER_MAXLEN = 512`.
    The fuzzing is focused on input handling.

- `input-fuzzer.dict`: dictionary of common tmux input patterns to guide the fuzzer.
- `input-fuzzer.options`: libFuzzer runtime options.

- `../tmux-fuzzing-corpus` (from `oss-fuzz` directory), [github repo](https://github.com/tmux/tmux-fuzzing-corpus) containing an initial set of input files designed for the fuzz testing. Those files simulate various terminal behaviors. Some of the provided corpus include:
    - `alacritty`, input files derived from the *Alacritty* terminal emulator
    - `esctest`, testing escape sequences
    - `iterm2`, testing *iTerm2* terminal emulator.