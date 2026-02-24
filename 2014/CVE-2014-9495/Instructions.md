# Execution Instructions
Each part of this project is located in a separate directory, and should be run individually.

## How to Run

1. Navigate to the directory of the part you want to run:
```bash
cd Submission/part*/*
```
2. Execute the desired .sh run script:
```bash
./run_script_name.sh
```
> Each run script in the same directory is independent, meaning they do not depend on each other.

## Cleanup Required Between Runs
After running a script:
- You must delete the oss-fuzz directory before running another script.
- This prevents conflicts and ensures each execution starts fresh.

Example:
```bash
rm -rf oss-fuzz
```
Then you can proceed to the next run.

