#!/bin/bash

# --- Configuration ---
FINAL_ZIP_NAME="full_wo_corpus_cmd_harness.zip"
SOURCE_ZIP_PATTERN='2025*_wo_corpus_cmd_harness.zip'
MAIN_TEMP_DIR="temp_merged_contents_root"
EXPERIMENTS_DIR="experiments" # Script expects to be run from one level above this, or this dir exists where script is run

# --- Global State ---
# To track if pushd to EXPERIMENTS_DIR was successful for error_exit cleanup
PUSHED_TO_EXPERIMENTS_DIR=0

# --- Helper Functions ---
# Logs an informational message
info() {
  echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Logs a warning message
warn() {
  echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

# Logs an error message and exits the script
error_exit() {
  echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
  # Clean up MAIN_TEMP_DIR if it exists and its path variable is set
  if [ -n "$MAIN_TEMP_DIR_ABS" ] && [ -d "$MAIN_TEMP_DIR_ABS" ]; then
    warn "Attempting to clean up $MAIN_TEMP_DIR_ABS due to error..."
    (rm -rf "$MAIN_TEMP_DIR_ABS") || warn "Failed to remove $MAIN_TEMP_DIR_ABS during error cleanup. Manual intervention may be required."
  fi
  # Attempt to popd if we successfully pushedd earlier
  if [ "$PUSHED_TO_EXPERIMENTS_DIR" -eq 1 ]; then
    popd &>/dev/null
  fi
  exit 1
}

# Gets a unique filename in a target directory by appending _N if needed.
# Usage: new_basename=$(get_unique_filename "target_directory" "original_filename.ext")
# Returns 0 on success (new_basename echoed), 1 on error.
get_unique_filename() {
  local target_dir="$1"
  local original_basename="$2"
  local name_part
  local extension_part="" # Includes the dot if extension exists
  local counter
  local new_basename
  local current_target_path # Renamed from target_path to avoid conflict

  # Ensure target directory exists (it should, but defensive check)
  if ! mkdir -p "$target_dir"; then
    warn "get_unique_filename: Failed to ensure target directory '$target_dir' exists."
    return 1
  fi

  current_target_path="$target_dir/$original_basename"
  # Check if file already exists without any suffix.
  # -L checks for symbolic link (even broken), -e checks for existence (true for valid symlinks).
  # We consider a name taken if any entry (file, dir, link) exists.
  if [ ! -e "$current_target_path" ] && [ ! -L "$current_target_path" ]; then
    echo "$original_basename"
    return 0
  fi

  # Separate name and extension
  # Handles: "file.txt", "archive.tar.gz", ".hiddenfile", "nodotextension"
  if [[ "$original_basename" == .* ]]; then                                            # Starts with a dot
    if [[ "${original_basename#*.}" == "" || "${original_basename#*.}" != *.* ]]; then # e.g. .bashrc or .git (no further dots)
      name_part="$original_basename"
      extension_part=""
    else # e.g. .config.yaml or .tar.gz (hidden file with extension-like parts)
      name_part="${original_basename%.*}"
      extension_part=".${original_basename##*.}"
    fi
  elif [[ "$original_basename" == *.* ]]; then # Contains a dot, not at the beginning
    name_part="${original_basename%.*}"
    extension_part=".${original_basename##*.}"
  else # No dot at all
    name_part="$original_basename"
    extension_part=""
  fi

  counter=1
  while true; do
    new_basename="${name_part}_${counter}${extension_part}"
    current_target_path="$target_dir/$new_basename"
    if [ ! -e "$current_target_path" ] && [ ! -L "$current_target_path" ]; then
      echo "$new_basename"
      return 0
    fi
    counter=$((counter + 1))
    if [ "$counter" -gt 9999 ]; then # Safety break
      warn "get_unique_filename: Exceeded maximum attempts for $original_basename in $target_dir"
      return 1
    fi
  done
}

# --- Main Script ---
info "Starting merge process."

# Change to experiments directory
if [ -d "$EXPERIMENTS_DIR" ]; then
  pushd "${EXPERIMENTS_DIR}" >/dev/null || {
    # Not using error_exit here as PUSHED_TO_EXPERIMENTS_DIR is not set yet
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - Failed to change directory to $EXPERIMENTS_DIR. Exiting." >&2
    exit 1
  }
  PUSHED_TO_EXPERIMENTS_DIR=1
  info "Changed directory to $(pwd)"
else
  info "Directory $EXPERIMENTS_DIR does not exist. Running in current directory: $(pwd)"
  # If EXPERIMENTS_DIR is mandatory and script must not run elsewhere, add error_exit here.
  # For this modification, we allow running in current dir if EXPERIMENTS_DIR is not found.
fi

info "Final zip name: $FINAL_ZIP_NAME"
info "Source zip pattern: $SOURCE_ZIP_PATTERN"
info "Main temporary directory name: $MAIN_TEMP_DIR"

# 1. Setup Main Temporary Directory
if [ -d "$MAIN_TEMP_DIR" ]; then
  info "Removing existing main temporary directory: $MAIN_TEMP_DIR"
  if ! rm -rf "$MAIN_TEMP_DIR"; then
    error_exit "Failed to remove existing $MAIN_TEMP_DIR. Please check permissions or locks."
  fi
fi

info "Creating main temporary directory: $MAIN_TEMP_DIR"
if ! mkdir -p "$MAIN_TEMP_DIR"; then
  error_exit "Failed to create main temporary directory: $MAIN_TEMP_DIR"
fi

MAIN_TEMP_DIR_ABS="$(cd "$MAIN_TEMP_DIR" && pwd)"
if [ -z "$MAIN_TEMP_DIR_ABS" ]; then
  error_exit "Could not determine absolute path for $MAIN_TEMP_DIR after creation."
fi
info "Absolute path for temporary directory: $MAIN_TEMP_DIR_ABS"

# Directory where all files will be merged flatly
FLAT_CONTENTS_DIR_ABS="$MAIN_TEMP_DIR_ABS/all_merged_files"
info "Creating flat contents directory: $FLAT_CONTENTS_DIR_ABS"
if ! mkdir -p "$FLAT_CONTENTS_DIR_ABS"; then
  error_exit "Failed to create flat contents directory: $FLAT_CONTENTS_DIR_ABS"
fi

PROCESSED_ZIP_COUNT=0
SUCCESSFUL_MERGE_COUNT=0 # Number of zips from which at least one file was successfully moved

# 2. Process Each Source Zip
info "Looking for source zip files matching pattern: '$SOURCE_ZIP_PATTERN' in current directory ($(pwd))"
source_zips=($SOURCE_ZIP_PATTERN)

if [ ${#source_zips[@]} -eq 0 ] || ([ "${source_zips[0]}" = "$SOURCE_ZIP_PATTERN" ] && [ ! -e "$SOURCE_ZIP_PATTERN" ]); then
  info "No zip files matching the pattern '$SOURCE_ZIP_PATTERN' were found."
  rm -rf "$MAIN_TEMP_DIR_ABS" 2>/dev/null ||
    warn "Main temporary directory '$MAIN_TEMP_DIR_ABS' was not removed (it might not be empty or an error occurred)."
  info "Merge process finished. No final zip created."
  if [ "$PUSHED_TO_EXPERIMENTS_DIR" -eq 1 ]; then popd >/dev/null; fi
  exit 0
fi

for corpus_zip in "${source_zips[@]}"; do
  if [ ! -f "$corpus_zip" ]; then
    warn "Skipping '$corpus_zip' as it is not a regular file or does not exist (or pattern expanded to itself with no match)."
    continue
  fi

  info "Processing zip file: $corpus_zip"
  PROCESSED_ZIP_COUNT=$((PROCESSED_ZIP_COUNT + 1))

  # Sanitize basename for directory creation: replace non-alphanumeric (except ., _, -) with underscore
  sane_zip_basename=$(basename "$corpus_zip" .zip | sed 's/[^a-zA-Z0-9_.-]/_/g')
  PER_ZIP_TEMP_DIR_ABS="$MAIN_TEMP_DIR_ABS/${sane_zip_basename}_temp_extract"

  info "Creating temporary extraction directory: $PER_ZIP_TEMP_DIR_ABS"
  if ! mkdir -p "$PER_ZIP_TEMP_DIR_ABS"; then
    warn "Failed to create temporary extraction directory $PER_ZIP_TEMP_DIR_ABS for $corpus_zip. Skipping this file."
    continue
  fi

  info "Unzipping $corpus_zip into $PER_ZIP_TEMP_DIR_ABS"
  if unzip -q "$corpus_zip" -d "$PER_ZIP_TEMP_DIR_ABS"; then
    info "Successfully unzipped $corpus_zip. Moving files to $FLAT_CONTENTS_DIR_ABS..."
    files_moved_from_this_zip=0

    # Find all files (not directories) within the extracted content
    find "$PER_ZIP_TEMP_DIR_ABS" -type f -print0 | while IFS= read -r -d $'\0' source_file_path; do
      original_basename=$(basename "$source_file_path")

      unique_target_basename=""
      unique_target_basename=$(get_unique_filename "$FLAT_CONTENTS_DIR_ABS" "$original_basename")
      get_unique_rc=$?

      if [ $get_unique_rc -ne 0 ] || [ -z "$unique_target_basename" ]; then
        warn "Failed to determine unique filename for '$original_basename' from zip '$corpus_zip' (source: $source_file_path). Skipping this file."
        continue # to next file in find loop
      fi

      target_file_path="$FLAT_CONTENTS_DIR_ABS/$unique_target_basename"

      if mv "$source_file_path" "$target_file_path"; then
        # info "Moved: $(basename "$source_file_path") -> $unique_target_basename" # Less verbose
        files_moved_from_this_zip=$((files_moved_from_this_zip + 1))
      else
        warn "Failed to move $source_file_path to $target_file_path."
      fi
    done

    if [ "$files_moved_from_this_zip" -gt 0 ]; then
      SUCCESSFUL_MERGE_COUNT=$((SUCCESSFUL_MERGE_COUNT + 1))
      info "Moved $files_moved_from_this_zip file(s) from $corpus_zip to $FLAT_CONTENTS_DIR_ABS."
    else
      info "No files were moved from $corpus_zip (it might have been empty, contained only empty directories, or failed to generate unique names)."
    fi

    info "Removing temporary extraction directory: $PER_ZIP_TEMP_DIR_ABS"
    rm -rf "$PER_ZIP_TEMP_DIR_ABS"
  else
    warn "Failed to unzip $corpus_zip into $PER_ZIP_TEMP_DIR_ABS. Skipping this file."
    rm -rf "$PER_ZIP_TEMP_DIR_ABS" # Clean up potentially partially created dir
  fi
done

# --- Step 3: Create the final combined zip file ---

if [ "$SUCCESSFUL_MERGE_COUNT" -eq 0 ]; then
  info "Processed $PROCESSED_ZIP_COUNT zip file(s), but no content was successfully merged into '$FLAT_CONTENTS_DIR_ABS'."
  info "Final zip file '$FINAL_ZIP_NAME' will not be created."
  rm -rf "$MAIN_TEMP_DIR_ABS"
  info "Merge process finished."
  if [ "$PUSHED_TO_EXPERIMENTS_DIR" -eq 1 ]; then popd >/dev/null; fi
  exit 0
fi

# Check if FLAT_CONTENTS_DIR_ABS has any content before zipping
# (This is a safeguard; SUCCESSFUL_MERGE_COUNT > 0 should mean it's not empty)
if ! find "$FLAT_CONTENTS_DIR_ABS" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
  info "Flat contents directory '$FLAT_CONTENTS_DIR_ABS' is empty. This is unexpected if merges were successful."
  info "Final zip file '$FINAL_ZIP_NAME' will not be created."
  rm -rf "$MAIN_TEMP_DIR_ABS"
  info "Merge process finished."
  if [ "$PUSHED_TO_EXPERIMENTS_DIR" -eq 1 ]; then popd >/dev/null; fi
  exit 0
fi

info "Consolidated contents from $SUCCESSFUL_MERGE_COUNT out of $PROCESSED_ZIP_COUNT processed zip file(s) into $FLAT_CONTENTS_DIR_ABS."
info "Creating the final zip file: $FINAL_ZIP_NAME (from contents of $FLAT_CONTENTS_DIR_ABS)"

# pwd is EXPERIMENTS_DIR (or original dir if EXPERIMENTS_DIR didn't exist/wasn't entered)
FINAL_ZIP_PATH_ABS="$(pwd)/$FINAL_ZIP_NAME"

ZIP_COMMAND_EXIT_STATUS=1 # Default to failure
(
  cd "$FLAT_CONTENTS_DIR_ABS" || {
    warn "Critical: Could not navigate to $FLAT_CONTENTS_DIR_ABS to create zip."
    exit 1 # Exit the subshell with error
  }
  if zip -ry "$FINAL_ZIP_PATH_ABS" .; then # -q for quiet, -y to store symlinks as links
    info "Successfully created final combined zip file: $FINAL_ZIP_PATH_ABS"
    exit 0 # Success for subshell
  else
    warn "Zip command failed to create '$FINAL_ZIP_PATH_ABS'."
    exit 1 # Failure for subshell
  fi
)
ZIP_COMMAND_EXIT_STATUS=$?

# --- Step 4: Clean up the main temporary directory ---
if [ $ZIP_COMMAND_EXIT_STATUS -eq 0 ]; then
  info "Cleaning up main temporary directory: $MAIN_TEMP_DIR_ABS"
  if ! rm -rf "$MAIN_TEMP_DIR_ABS"; then
    warn "Failed to remove $MAIN_TEMP_DIR_ABS. Please remove it manually."
  else
    info "Main temporary directory removed."
  fi
else
  warn "Main temporary directory '$MAIN_TEMP_DIR_ABS' was NOT removed due to an error ($ZIP_COMMAND_EXIT_STATUS) during final zip creation."
  warn "You may inspect its contents at: $FLAT_CONTENTS_DIR_ABS (within $MAIN_TEMP_DIR_ABS)"
fi

if [ "$PUSHED_TO_EXPERIMENTS_DIR" -eq 1 ]; then
  popd >/dev/null || {
    warn "Failed to return to the original directory. You may need to do this manually."
    # Not exiting with 1 here if main process was otherwise successful
  }
fi

# --- Final Exit ---
if [ $ZIP_COMMAND_EXIT_STATUS -ne 0 ]; then
  # error_exit was not called by zip failure, so call generic error message
  echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - Merge process finished with errors during final zip creation." >&2
  exit 1
else
  info "Merge process finished successfully."
  exit 0
fi
