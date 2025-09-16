#!/usr/bin/env bash
#
# This script is the main entry point for updating translations.
# It's designed to be run in a containerized environment (like Docker) but can also be run locally
# if the necessary dependencies (Python, Git, GitHub CLI) are installed.
#
# It performs the following steps:
# 1. Sets up the environment, including SSH and Git configurations.
# 2. Clones or updates the target repository where translation files are stored.
# 3. Executes the Python translation script (`translate_localization_files.py`).
# 4. Commits any changes to the translation files.
# 5. Creates a pull request on GitHub with the new translations.
#
# The script is designed to be robust, with error handling and cleanup mechanisms.
# It uses `set -e` to exit immediately if a command fails, `set -u` to treat unset
# variables as errors, and `set -o pipefail` to ensure that a pipeline's exit code
# is the exit code of the last command to exit with a non-zero status.

# --- Stream Redirection ---
# Redirect stderr to stdout to ensure all output (including from Python's stderr)
# is captured in the Docker logs. The Python script's TqdmLoggingHandler is
# designed to prevent logging from interfering with progress bars, making this safe.
exec 2>&1
# --- End Stream Redirection ---

set -euo pipefail

# Ensure the PATH includes /usr/local/bin where the Transifex CLI is installed.
export PATH="/usr/local/bin:$PATH"

# Define a consistent prefix for translation branches
TRANSLATION_BRANCH_PREFIX="translation-updates"

# Repository Configuration - Read from environment variables with fallbacks
FORK_REPO_NAME=${FORK_REPO_NAME:-hiciefte/bisq2} 
UPSTREAM_REPO_NAME=${UPSTREAM_REPO_NAME:-bisq-network/bisq2} 
TARGET_BRANCH_FOR_PR=${TARGET_BRANCH_FOR_PR:-main}

# Log file
LOG_DIR="/app/logs"
LOG_FILE="$LOG_DIR/deployment_log.log"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# A simple, robust logging function that prints to stdout.
# Using printf for better portability and to avoid issues with special characters.
log() {
    local message="$1"
    local level="${2:-INFO}" # Default to INFO
    # Get a timestamp in ISO 8601 format.
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    # Print and persist.
    printf "[%s] [%s] %s\n" "$timestamp" "$level" "$message" | tee -a "$LOG_FILE"
}

# Run a command, prefix with '+', and tee its output to the log.
log_cmd() {
  log "+ $*" "DEBUG"
  "$@" 2>&1 | sed 's/^/| /' | tee -a "$LOG_FILE"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Helper function to check for blocking PRs and exit if found.
# It also pings a health check URL on a successful skip.
# Arguments:
#   $1: The reason for skipping (e.g., "Found manually-blocking PR #123").
check_and_exit_if_blocked() {
    log "BLOCKING CONDITION DETECTED: $1" "ERROR"
    log "Aborting translation run. Please resolve the blocking issue." "ERROR"
    # Optional: Add a health check ping for failure here
    exit 0 # Exit cleanly to prevent cron from flagging it as a failure
}

# Check for required tools
for tool in yq git tx curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        log "Required tool '$tool' is not installed." "ERROR"
        exit 1
    fi
done

# --- Pull Request Gate ---
# This gate prevents the script from running if there's already a pending PR.
# It checks for two conditions:
# 1. A manual block: Any open PR on the upstream repo with '[PIPELINE-BLOCK]' in its title.
# 2. An automated block: An open PR from a previous run of this script.

BLOCKING_KEYWORD="[PIPELINE-BLOCK]"
log "Checking for manually-blocked PRs with keyword '$BLOCKING_KEYWORD' in the title..."
if ! command -v gh >/dev/null 2>&1; then
    log "GitHub CLI (gh) not found; PR-blocking checks may be incomplete or skipped." "WARNING"
fi
if command_exists gh && [ -n "${GITHUB_TOKEN:-}" ]; then
  # Use the 'search' flag to query PR titles on the upstream repo.
  # Filter by '@me' which gh resolves to the currently authenticated user.
  MANUAL_BLOCK_PR=$(gh pr list --state open --author "@me" --repo "$UPSTREAM_REPO_NAME" --search "in:title $BLOCKING_KEYWORD" --json number -q '.[0].number' || true)
  if [ -n "$MANUAL_BLOCK_PR" ]; then
      check_and_exit_if_blocked "Found manually-blocking PR #${MANUAL_BLOCK_PR} authored by the bot's account"
  fi
  log "No manually-blocked PRs found."
else
  log "Skipping manual PR-block check (gh not available or GITHUB_TOKEN unset)." "DEBUG"
fi

if command_exists gh && [ -n "${GITHUB_TOKEN:-}" ]; then
  log "Checking for existing open translation PRs on repo '$UPSTREAM_REPO_NAME'..."
  # Note: The 'gh pr list' command requires GITHUB_TOKEN to be in the environment.
  EXISTING_PR_BRANCH=$(gh pr list --state open --author "@me" --repo "$UPSTREAM_REPO_NAME" --json headRefName -q '.[].headRefName' | grep "^${TRANSLATION_BRANCH_PREFIX}" | head -n 1 || true)
  if [ -n "$EXISTING_PR_BRANCH" ]; then
      check_and_exit_if_blocked "Found existing open translation PR from branch: $EXISTING_PR_BRANCH"
  fi
  log "No pending translation PRs found. Proceeding with translation check."
else
  log "Skipping existing-PR check (gh not available or GITHUB_TOKEN unset)." "DEBUG"
fi


# --- Git Repository and Transifex Configuration Validation ---
log "Starting Git and Transifex validation..."
# Load configuration from YAML file
# Use the environment variable if it's set, otherwise default to config.yaml in the CWD.
CONFIG_FILE="${TRANSLATOR_CONFIG_FILE:-config.yaml}"

if [ ! -f "$CONFIG_FILE" ]; then
    log "Configuration file not found at '$CONFIG_FILE'." "ERROR"
    # Attempt to find it in the script's directory as a fallback for local runs.
    SCRIPT_DIR_REAL=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    if [ -f "$SCRIPT_DIR_REAL/$CONFIG_FILE" ]; then
        CONFIG_FILE="$SCRIPT_DIR_REAL/$CONFIG_FILE"
        log "Found config file in script directory: $CONFIG_FILE" "INFO"
    else
        log "Also not found in script directory. Aborting." "ERROR"
        exit 1
    fi
fi
log "Using configuration file: $CONFIG_FILE"

# Helper function to parse values from config.yaml robustly using yq
get_config_value() {
    local key="$1"
    local config_file="$2"
    if ! command -v yq >/dev/null 2>&1; then
        log "Error: 'yq' is required but not found in PATH."
        exit 1
    fi
    # Use yq to safely read the value. `// "__MISSING__"` provides a default for missing keys.
    # The case statement normalizes null/"__MISSING__" to an empty string for downstream checks.
    val=$(yq -r ".$key // \"__MISSING__\"" "$config_file" 2>/dev/null || true)
    case "$val" in
        "__MISSING__"|"null") echo "";;
        true|false) echo "$val";;
        *) echo "$val";;
    esac
}

TARGET_PROJECT_ROOT=$(get_config_value "target_project_root" "$CONFIG_FILE")
INPUT_FOLDER=$(get_config_value "input_folder" "$CONFIG_FILE")
# Read the optional glob filter for selective translation
TRANSLATION_FILTER_GLOB=$(get_config_value "translation_file_filter_glob" "$CONFIG_FILE")
# Read the optional flag to pull source files
PULL_SOURCE_FILES=$(get_config_value "pull_source_files_from_transifex" "$CONFIG_FILE")
DRY_RUN=$(get_config_value "dry_run" "$CONFIG_FILE")

log "Target project root from config: \"$TARGET_PROJECT_ROOT\""
log "Input folder from config: \"$INPUT_FOLDER\""
log "Pull source files from Transifex: ${PULL_SOURCE_FILES:-false}"

if [ -z "$TARGET_PROJECT_ROOT" ] || [ "$TARGET_PROJECT_ROOT" = "null" ]; then
    log "Error: TARGET_PROJECT_ROOT is not set in $CONFIG_FILE or is empty."
    exit 1
fi

if [ ! -d "$TARGET_PROJECT_ROOT" ]; then
    log "Error: Target project root directory does not exist or is not a directory: $TARGET_PROJECT_ROOT"
    exit 1
fi

if [ -z "$INPUT_FOLDER" ] || [ "$INPUT_FOLDER" = "null" ]; then
    log "Error: INPUT_FOLDER is not set in $CONFIG_FILE or is empty."
    exit 1
fi

# Construct the absolute path for INPUT_FOLDER
# If INPUT_FOLDER starts with /, it's considered absolute (within the container context)
# Otherwise, it's relative to TARGET_PROJECT_ROOT
if [[ "$INPUT_FOLDER" == /* ]]; then
    ABSOLUTE_INPUT_FOLDER="$INPUT_FOLDER"
else
    ABSOLUTE_INPUT_FOLDER="$TARGET_PROJECT_ROOT/$INPUT_FOLDER"
fi
# Remove any double slashes that might occur
ABSOLUTE_INPUT_FOLDER=$(echo "$ABSOLUTE_INPUT_FOLDER" | sed 's_//_/_g')

log "Absolute input folder: \"$ABSOLUTE_INPUT_FOLDER\""

if [ ! -d "$ABSOLUTE_INPUT_FOLDER" ]; then
    log "Error: Input folder does not exist or is not a directory: $ABSOLUTE_INPUT_FOLDER (derived from $TARGET_PROJECT_ROOT and $INPUT_FOLDER)"
    exit 1
fi

# Change directory to the target project root
cd "$TARGET_PROJECT_ROOT" || {
    log "Error: Could not change directory to target project root: $TARGET_PROJECT_ROOT"
    exit 1
}

log "Successfully changed directory to $TARGET_PROJECT_ROOT"

log "Verifying Transifex configuration against actual source files..."

TX_CONFIG_FILE=".tx/config"
if [ ! -f "$TX_CONFIG_FILE" ]; then
    log "Warning: Transifex config file not found at '$TARGET_PROJECT_ROOT/$TX_CONFIG_FILE'. Skipping verification."
else
    # Check for unconfigured source files before proceeding.
    # This prevents pulling translations for files that are no longer part of the source.
    #
    log "Checking for source files that are not configured in Transifex..." "INFO"

    # Extract the 'source_file' for each resource from the Transifex config.
    # This gives us the configured source files with their full paths relative to the repo root.
    # Example: i18n/src/main/resources/BtcAddresses.properties
    # Use awk for more reliable INI parsing. It correctly handles spaces around the '='.
    mapfile -t configured_sources < <(awk -F'=' '/^[[:space:]]*source_file[[:space:]]*=/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}' "$TX_CONFIG_FILE")

    # Get the actual English source files present on disk.
    # This correctly identifies files like 'app.properties' while excluding translated files like 'app_de.properties'.
    # A regex is used to specifically exclude files ending in the locale pattern `_ll` or `_ll_CC`.
    mapfile -t actual_sources_full_path < <(
      find "$ABSOLUTE_INPUT_FOLDER" -type f -name '*.properties' \
        -regextype posix-extended \
        -not -regex '.*_[a-z]{2}(_[A-Z]{2})?\.properties$'
    )

    declare -A configured_relative_paths
    for src in "${configured_sources[@]}"; do
        configured_relative_paths["$src"]=1
    done

    unconfigured_files_found=false
    for full_path in "${actual_sources_full_path[@]}"; do
        # Make the path relative to the target project root to match the tx config format
        relative_path=${full_path#"$TARGET_PROJECT_ROOT/"}
        if [[ -z "${configured_relative_paths["$relative_path"]}" ]]; then
            if ! $unconfigured_files_found; then
                log "Found source files not configured in Transifex:" "WARNING"
                unconfigured_files_found=true
            fi
            log "  - $relative_path" "WARNING"
        fi
    done

    if $unconfigured_files_found; then
        log "Aborting due to unconfigured source files. Please update the Transifex config at '$TX_CONFIG_FILE' and push the changes." "ERROR"
        exit 1
    fi
    log "All source files are correctly configured in Transifex." "INFO"
fi

# Determine the default branch and remote to reset against
DEFAULT_BRANCH="${TARGET_BRANCH_FOR_PR:-}"
REMOTE="upstream" # Default to upstream
if ! git remote | grep -q "^${REMOTE}$"; then
    log "Warning: Remote '${REMOTE}' not found. Falling back to 'origin'."
    REMOTE="origin"
    if ! git remote | grep -q "^${REMOTE}$"; then
        log "Error: Remote 'origin' also not found. Cannot proceed."
        exit 1
    fi
fi
log "Using remote: ${REMOTE}"

if [ -z "$DEFAULT_BRANCH" ]; then
  DEFAULT_BRANCH="$(git remote show ${REMOTE} 2>/dev/null | awk -F': ' '/HEAD branch/ {print $2}')"
  DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
fi
log "Using default branch: ${DEFAULT_BRANCH}"

# Reset the repository to a clean state to avoid any conflicts or leftover files.
log "Resetting local repository to a clean state against ${REMOTE}/${DEFAULT_BRANCH} in $TARGET_PROJECT_ROOT"
# Fetch the latest from the determined remote to ensure our reference is current.
git fetch "${REMOTE}"
# Save current branch before switching to default
ORIGINAL_BRANCH=$(git branch --show-current || true)
log "Current branch: $ORIGINAL_BRANCH"
# Check out the default branch and align it with the remote
git checkout -B "${DEFAULT_BRANCH}" "${REMOTE}/${DEFAULT_BRANCH}"
# Clean untracked files and directories, but exclude critical local dev files.
log "Cleaning untracked files, excluding development directories..."
git clean -fde "venv/" -e ".idea/" -e "*.iml" -e "secrets/" -e "docker/.env"

# The entrypoint script already reset the branch to upstream and updated submodules.
# No further git pull or submodule init/update should be necessary here before tx pull.
log "Proceeding with Transifex operations. Current HEAD on ${DEFAULT_BRANCH}:"
git log -1 --pretty=%H

# Step 2: Use Transifex CLI to pull the latest translations
if [[ "${DRY_RUN:-false}" == "true" ]]; then
    log "Dry run is enabled. Skipping Transifex pull." "WARNING"
else
    log "Checking for Transifex CLI"
    log "Current PATH: $PATH"
    log "Which tx: $(which tx || echo 'tx not found in path')"
    if command_exists tx; then
        log "Pulling latest translations from Transifex"
        log "Using Transifex token from environment"
        
        # Debug Transifex configuration
        if [ -f "$TARGET_PROJECT_ROOT/.tx/config" ]; then
            log ".tx/config detected in project directory"
        else
            log "Warning: .tx/config not found in project directory"
        fi
        
        # Pull translations with -t option.
        # The --force (-f) flag ensures local files are overwritten with remote changes.
        TX_PULL_CMD="tx pull -t -f --use-git-timestamps"
        if [[ "$PULL_SOURCE_FILES" == "true" ]]; then
            log "Configuration directs to pull source files as well. Modifying tx command."
            TX_PULL_CMD="tx pull -s -t -f --use-git-timestamps"
        fi

        log "Using tx command: $TX_PULL_CMD"
        log "Listing permissions for current directory ($(pwd)) before tx pull:"
        log_cmd ls -la .
        log "Listing permissions for input folder '${ABSOLUTE_INPUT_FOLDER}' before tx pull:"
        log_cmd ls -la "${ABSOLUTE_INPUT_FOLDER}"
        
        # Start a background process to show that the script is still alive.
        # This is useful because 'tx pull' can be silent for long periods.
        while true; do
            sleep 30
            log "Still waiting for Transifex pull to complete..." "INFO"
        done &
        # Get the process ID of the background loop
        KEEPALIVE_PID=$!

        # When this script exits, kill the background keepalive process.
        # This ensures it doesn't become a zombie process.
        # The kill is made non-fatal to prevent script exit if the PID is already gone.
        trap 'kill "$KEEPALIVE_PID" 2>/dev/null || true' EXIT
        
        # Execute and filter output, but preserve original tx exit code.
        set +e
        { $TX_PULL_CMD 2>&1 | grep -v -E 'Pulling file|Creating download job|File was not found locally'; }
        TX_STATUS=${PIPESTATUS[0]}
        set -e

        # Stop the keepalive process now that tx pull is done.
        # Make the kill non-fatal in case the process has already exited.
        if [ -n "${KEEPALIVE_PID:-}" ]; then
            kill "$KEEPALIVE_PID" 2>/dev/null || true
        fi
        # Remove the trap so it doesn't try to kill a non-existent process on exit.
        trap - EXIT

        if [ $TX_STATUS -ne 0 ]; then
            log "Transifex pull failed (exit $TX_STATUS). See previous logs for details." "ERROR"
            exit $TX_STATUS
        fi

        # Verify that files have been updated
        if ! git status --porcelain | grep -qE '\.(properties|po|mo)$'; then
            log "Error: Transifex pull did not update any translation files (.properties/.po/.mo). This might indicate an issue with the Transifex CLI or the configuration." "ERROR"
            exit 1
        fi

    else
        log "Error: Transifex CLI not found. Please install it manually."
        exit 1
    fi
fi

# Navigate back to the application's root directory to run the python script.
# This ensures that the module path `src.translate_localization_files` is resolved correctly.
if [ -d /app ]; then
  cd /app
  log "Returned to the application root directory: $(pwd)"
else
  log "Warning: /app not found; staying in $(pwd) to run Python."
fi

# Step 3: Run the translation script
log "Running translation script"
# If a filter glob is defined in the config, and it is not the literal string "null",
# export it as an environment variable for the Python script to use.
if [ -n "$TRANSLATION_FILTER_GLOB" ] && [ "$TRANSLATION_FILTER_GLOB" != "null" ]; then
    log "Translation filter is active. Only files matching '$TRANSLATION_FILTER_GLOB' will be translated."
fi
# Export filter glob if set (used by Python translation script)
[ -n "$TRANSLATION_FILTER_GLOB" ] && [ "$TRANSLATION_FILTER_GLOB" != "null" ] && export TRANSLATION_FILTER_GLOB
set +e
python3 -u -m src.translate_localization_files
PY_EXIT=$?
set -e
if [ $PY_EXIT -ne 0 ]; then
  log "Error: Translation script exited with code $PY_EXIT"
  exit $PY_EXIT
fi

# Change back to the target project root for the final git operations.
cd "$TARGET_PROJECT_ROOT"
log "Changed back to target project root: $(pwd)"

# Step 4: Clean up archived translation files before committing
log "Cleaning up archived translation files"
if [ -d "$ABSOLUTE_INPUT_FOLDER/archive" ]; then
    rm -rf "$ABSOLUTE_INPUT_FOLDER/archive"
    log "Deleted archived translation files"
fi

# Step 5: Check if there are any new translations to commit
cd "$TARGET_PROJECT_ROOT"
log "Checking for new translations to commit in $(pwd)"
log "Listing permissions for $TARGET_PROJECT_ROOT before git status:"
ls -la "$TARGET_PROJECT_ROOT"
log "Listing permissions for $TARGET_PROJECT_ROOT/.git before git status:"
ls -la "$TARGET_PROJECT_ROOT/.git"

# Check specifically for changes in translation files
TRANSLATION_CHANGES=$(git status --porcelain | grep -E "\.properties$|\.po$|\.mo$" || true)

if [ -n "$TRANSLATION_CHANGES" ]; then
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log "Dry run is enabled. Skipping commit and pull request creation." "WARNING"
        log "The following changes would have been committed:" "INFO"
        echo "$TRANSLATION_CHANGES"
    else
        # There are translation changes to commit
        BRANCH_NAME="${TRANSLATION_BRANCH_PREFIX}-$(date +%Y-%m-%d-%H%M%S)"
        
        # Set the committer identity to match the author identity.
        # This is crucial for ensuring GitHub correctly verifies the GPG signature.
        log "Setting git committer identity for this commit"
        # Use environment variables for the committer identity, falling back to a generic default.
        # These variables should be set in the docker/.env file.
        git config user.name "${GIT_AUTHOR_NAME:-Translation Bot}"
        git config user.email "${GIT_AUTHOR_EMAIL:-translation-bot@users.noreply.github.com}"
        
        # Create a new branch
        log "Creating new branch: $BRANCH_NAME"
        git checkout -b "$BRANCH_NAME"
        
        # Add translation files that have changed and stage deletions
        log "Staging translation file changes (.properties, .po, .mo) and deletions"
        # Use a pathspec to add all relevant files in the input folder.
        # This is simpler and less prone to errors with special characters than find + xargs.
        REL_INPUT_FOLDER="${ABSOLUTE_INPUT_FOLDER#"$TARGET_PROJECT_ROOT/"}"
        git add -- "$REL_INPUT_FOLDER"/*.properties "$REL_INPUT_FOLDER"/*.po "$REL_INPUT_FOLDER"/*.mo 2>/dev/null || true
        # Stage deletions for removed translation files (use repo-relative pathspec)
        git ls-files -z --deleted -- "$REL_INPUT_FOLDER" \
          | grep -zE '\.(properties|po|mo)$' \
          | xargs -0 -r git rm

        # Commit changes, signing if a key is configured
        if git config --get commit.gpgsign >/dev/null 2>&1 && git config --get user.signingkey >/dev/null 2>&1; then
          log "Committing with GPG signing"
          if ! git commit -S -m "Automated translation update"; then
            log "GPG signing failed; retrying unsigned." "WARNING"
            git commit -m "Automated translation update"
          fi
        else
          log "Committing without GPG signing"
          git commit -m "Automated translation update"
        fi

        # Push the branch to GitHub
        PUSH_OK=0
        if git remote | grep -qx 'origin'; then
          log "Pushing changes to 'origin' remote"
          # Before pushing, derive the owner from the 'origin' remote URL.
          # This ensures the user in the PR head matches the push destination.
          fork_owner=$(git remote get-url origin | sed -E 's#.*[:/](.+)/[^/]+(\.git)?$#\1#')

          if [ -z "$fork_owner" ]; then
              log "Error: Could not determine the fork owner from the 'origin' remote URL. Cannot create PR." "ERROR"
              exit 1
          fi
          log "Determined fork owner for PR head as: '$fork_owner'"

          # If FORK_REPO_NAME is set, validate it matches the remote.
          if [ -n "${FORK_REPO_NAME:-}" ]; then
              fork_repo_owner=$(echo "$FORK_REPO_NAME" | cut -d'/' -f1)
              if [[ "$fork_owner" != "$fork_repo_owner" ]]; then
                  log "Error: The owner of the 'origin' remote ('$fork_owner') does not match the configured FORK_REPO_NAME owner ('$fork_repo_owner')." "ERROR"
                  log "Please align the 'origin' remote with the expected fork repository." "ERROR"
                  exit 1
              fi
          fi

          if git push origin "$BRANCH_NAME"; then
              PUSH_OK=1
          else
              log "Failed to push branch '$BRANCH_NAME' to origin." "ERROR"
          fi
        else
          log "'origin' remote not found; cannot push PR branch. Configure a fork remote named 'origin' or adjust the script." "ERROR"
        fi
        
        # Step 5: Create a GitHub pull request (only if push succeeded)
        if [ "${PUSH_OK:-0}" -ne 1 ]; then
            log "Skipping PR creation because the branch was not pushed." "WARNING"
        else
        log "Creating GitHub pull request to $UPSTREAM_REPO_NAME"
        PR_TITLE="Automated Translation Update - $(date +'%Y-%m-%d %H:%M:%S')"
        PR_BODY="This pull request was automatically generated by the translation script and contains the latest translation updates from Transifex and OpenAI.

This PR is from branch \`$BRANCH_NAME\` on the \`$FORK_REPO_NAME\` fork and targets the \`$TARGET_BRANCH_FOR_PR\` branch on \`$UPSTREAM_REPO_NAME\`."

        # Check for a skipped files report and prepend it to the PR body if it exists.
        # The python script generates this file if any files fail validation.
        SKIPPED_FILES_REPORT="/app/logs/skipped_files_report.log"
        if [ -s "$SKIPPED_FILES_REPORT" ]; then
            log "Found skipped files report. Prepending to PR description."
            REPORT_CONTENT=$(cat "$SKIPPED_FILES_REPORT")
            PR_BODY=$(printf "%s\n\n%s" "$REPORT_CONTENT" "$PR_BODY")
        fi

        # Check if gh cli is installed
        if command_exists gh; then
            # Check if GITHUB_TOKEN is set
            if [ -z "$GITHUB_TOKEN" ]; then
                log "Error: GITHUB_TOKEN is not set. Cannot create pull request."
            else
                # Create pull request using gh cli
                log "Attempting to create PR: $FORK_REPO_NAME:$BRANCH_NAME -> $UPSTREAM_REPO_NAME:$TARGET_BRANCH_FOR_PR"
                
                PR_URL=$(gh pr create \
                    --title "$PR_TITLE" \
                    --body "$PR_BODY" \
                    --repo "$UPSTREAM_REPO_NAME" \
                    --base "$TARGET_BRANCH_FOR_PR" \
                    --head "${fork_owner}:$BRANCH_NAME")
                
                PR_CREATE_EXIT_CODE=$?

                if [ $PR_CREATE_EXIT_CODE -eq 0 ]; then
                    log "Successfully created pull request: $PR_URL"
                else
                    log "Error: Failed to create pull request (Exit Code: $PR_CREATE_EXIT_CODE). Please check gh cli authentication, GITHUB_TOKEN permissions, and repository settings."
                fi
            fi
        else
            log "GitHub CLI (gh) not found. Cannot create pull request." "ERROR"
        fi
        fi
    fi
else
    log "No translation changes to commit"
fi

# Go back to original branch
if [ -n "$ORIGINAL_BRANCH" ] && [ "$ORIGINAL_BRANCH" != "$DEFAULT_BRANCH" ]; then
  log "Returning to original branch: $ORIGINAL_BRANCH"
  log "Listing permissions for $TARGET_PROJECT_ROOT/.git before checkout $ORIGINAL_BRANCH:"
  ls -la "$TARGET_PROJECT_ROOT/.git"
  git checkout --force "$ORIGINAL_BRANCH"
else
  log "Staying on ${DEFAULT_BRANCH} (no original branch to return to)."
fi

# Re-initialize and update submodules after returning to original branch
log "Re-initializing and updating git submodules after returning to original branch"
git submodule init
git submodule update --recursive

# No virtual environment to deactivate

# Send a heartbeat ping to the health check URL if it is configured
if [ -n "${HEALTHCHECK_URL:-}" ]; then
    log "Sending successful heartbeat to health check URL..."
    # Use curl with options to fail silently and handle connection timeouts
    curl -fsS --retry 3 --max-time 10 "$HEALTHCHECK_URL" > /dev/null || log "Warning: Health check ping failed."
fi

log "Translation update script finished successfully."
exit 0