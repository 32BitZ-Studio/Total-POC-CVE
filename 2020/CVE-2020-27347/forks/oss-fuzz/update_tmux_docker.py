#!/usr/bin/env python3

import subprocess
import glob
import os
import sys
import time

def get_container_name():
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(names) != 1:
            raise SystemExit(f"Error: Expected 1 container, found {len(names)}")
        return names[0]
    except subprocess.CalledProcessError as e:
        print("Error running docker ps -a:", e.stderr)
        sys.exit(1)

def copy_files(container_name, src_dir="projects/tmux", src_root="/src"):
    fuzz_dest = f"{src_root}/tmux/fuzz"
    tmux_dest = f"{src_root}/tmux"

    # Create target directories if they don't exist
    subprocess.run(["docker", "exec", container_name, "mkdir", "-p", fuzz_dest], check=False)
    subprocess.run(["docker", "exec", container_name, "mkdir", "-p", tmux_dest], check=False)

    # Define file types and their destinations
    file_map = {
        "*.c": fuzz_dest,
        "*.cc": fuzz_dest,
        "*.dict": fuzz_dest,
        "*.options": fuzz_dest,
        "*.ac": tmux_dest,
        "*.h": tmux_dest,
        "*.am": tmux_dest,
        "*.y": tmux_dest,
    }

    # Copy files
    for pattern, dest in file_map.items():
        for file in glob.glob(os.path.join(src_dir, pattern)):
            try:
                subprocess.run(["docker", "cp", file, f"{container_name}:{dest}"], check=True)
                print(f"Copied {file} → {dest}")
            except subprocess.CalledProcessError as e:
                print(f"Error copying {file}: {e}")
                sys.exit(1)

def main():
    # Start helper.py in the background
    helper_cmd = ["python3", "infra/helper.py", "shell", "tmux"]
    helper_process = subprocess.Popen(helper_cmd)
    print("Started: python3 infra/helper.py shell tmux")

    # Wait for the container to appear
    container_name = None
    timeout = 30  # seconds
    interval = 1
    elapsed = 0

    while elapsed < timeout:
        try:
            container_name = get_container_name()
            print(f"Found container: {container_name}")
            break
        except SystemExit as e:
            if "Expected 1 container" in str(e):
                time.sleep(interval)
                elapsed += interval
            else:
                print(f"Unexpected error: {e}")
                helper_process.terminate()
                helper_process.wait()
                sys.exit(1)
    else:
        print("Error: Timeout waiting for container to start.")
        helper_process.terminate()
        helper_process.wait()
        sys.exit(1)

    # Copy files
    try:
        copy_files(container_name)
    finally:
        # Kill the container
        print("Killing container...")
        subprocess.run(["docker", "kill", container_name], check=False)

        # Wait for helper.py to exit
        print("Waiting for helper.py to finish...")
        helper_process.wait()

        print("All done.")

if __name__ == "__main__":
    main()