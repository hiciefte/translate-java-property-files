#!/bin/bash

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

# Function to log messages
log() {
    # Use "$*" to log all arguments as a single string
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [UPDATE_SCRIPT] $*" | tee -a "$LOG_FILE"
}

# Helper function to check for blocking PRs and exit if found.
# It also pings a health check URL on a successful skip.
# Arguments:
#   $1: The reason for skipping (e.g., "Found manually-blocking PR #123").
check_and_exit_if_blocked() {
    local reason="$1"
    log "$reason. Skipping current run."
    if [ -n "${HEALTHCHECK_URL:-}" ]; then
        log "Sending successful (skipped) heartbeat to health check URL..."
        curl -fsS --retry 3 --max-time 10 "$HEALTHCHECK_URL" > /dev/null || log "Warning: Health check ping failed on skipped run."
    fi
    exit 0
}

# --- Pull Request Gate ---
# This gate prevents the script from running if there's already a pending PR.
# It checks for two conditions:
# 1. A manual block: Any open PR on the upstream repo with '[PIPELINE-BLOCK]' in its title.
# 2. An automated block: An open PR from a previous run of this script.

BLOCKING_KEYWORD="[PIPELINE-BLOCK]"
log "Checking for manually-blocked PRs with keyword '$BLOCKING_KEYWORD' in the title..."
# Use the 'search' flag to query PR titles on the upstream repo.
# Filter by '@me' which gh resolves to the currently authenticated user.
MANUAL_BLOCK_PR=$(gh pr list --state open --author "@me" --repo "$UPSTREAM_REPO_NAME" --search "in:title $BLOCKING_KEYWORD" --json number -q '.[0].number' || true)

if [ -n "$MANUAL_BLOCK_PR" ]; then
    check_and_exit_if_blocked "Found manually-blocking PR #${MANUAL_BLOCK_PR} authored by the bot's account"
fi
log "No manually-blocked PRs found."

log "Checking for existing open translation PRs on repo '$UPSTREAM_REPO_NAME'..."
# Note: The 'gh pr list' command requires GITHUB_TOKEN to be in the environment.
# We query by author ('@me') against the UPSTREAM repository, then filter by branch name prefix.
# The '|| true' ensures the script doesn't exit if grep finds no matches.
# 'head -n 1' ensures we only ever get one branch name, even if something unexpected happens.
EXISTING_PR_BRANCH=$(gh pr list --state open --author "@me" --repo "$UPSTREAM_REPO_NAME" --json headRefName -q '.[].headRefName' | grep "^${TRANSLATION_BRANCH_PREFIX}" | head -n 1 || true)

if [ -n "$EXISTING_PR_BRANCH" ]; then
    check_and_exit_if_blocked "Found existing open translation PR from branch: $EXISTING_PR_BRANCH"
fi

log "No pending translation PRs found. Proceeding with translation check."

log "Update script started. Checking for TX_TOKEN..."

# Check if TX_TOKEN is already set in the environment
if [ -n "$TX_TOKEN" ]; then
    log "TX_TOKEN is already set in the environment."
else
    log "TX_TOKEN not found in environment. Attempting to load from .env files..."
    # Load environment variables from .env file if it exists
    ENV_FILE=".env"
    HOME_ENV_FILE="$HOME/.env"

    if [ -f "$HOME_ENV_FILE" ]; then
        log "Loading environment variables from $HOME_ENV_FILE"
        set -a  # automatically export all variables
        # shellcheck source=~/.env
        source "$HOME_ENV_FILE"
        set +a  # disable auto-export
        log "Environment variables potentially loaded from $HOME_ENV_FILE."
    elif [ -f "$ENV_FILE" ]; then
        log "Loading environment variables from $ENV_FILE (in PWD: $(pwd))"
        set -a  # automatically export all variables
        # shellcheck source=./.env
        source "$ENV_FILE"
        set +a  # disable auto-export
        log "Environment variables potentially loaded from $ENV_FILE."
    else
        log "No .env file found in current directory or home directory."
    fi
fi

# Ensure TX_TOKEN is set now (either from initial env or sourced from file)
if [ -z "$TX_TOKEN" ]; then
    log "Error: TX_TOKEN environment variable is not set and could not be loaded from .env files."
    log "Please ensure TX_TOKEN is available as an environment variable or in a .env file."
    log "For Docker, ensure it's passed via docker-compose.yml environment section from your host's .env file."
    exit 1
fi

# Export TX_TOKEN explicitly to be absolutely sure (though set -a during source should do it)
export TX_TOKEN
log "TX_TOKEN is confirmed set and exported."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to determine Python command to use
get_python_cmd() {
    if command_exists python3.9; then
        echo "python3.9"
    elif command_exists python3; then
        echo "python3"
    elif command_exists python; then
        echo "python"
    else
        echo ""
    fi
}

# Function to check Python version
check_python_version() {
    local python_cmd="$1"
    $python_cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
}

# Virtual environment directory - use appuser's home directory
# Ensure HOME is set; it should be /home/appuser for the appuser
APPUSER_HOME=${HOME:-/home/appuser} # Default to /home/appuser if HOME isn't robustly set
VENV_DIR="$APPUSER_HOME/.venv"

# Function to setup and activate virtual environment
setup_venv() {
    # shellcheck disable=SC2034  # Unused variable warning
    local python_cmd="$1"
    
    # Check if venv module is available
    if ! $python_cmd -c "import venv" 2>/dev/null; then
        log "Python venv module not found. Installing python3-venv..."
        # Try to install python3-venv package
        if command_exists apt-get; then
            sudo apt-get update && sudo apt-get install -y python3.9-venv || {
                log "Failed to install python3.9-venv. Please install it manually: sudo apt-get install python3.9-venv"
                exit 1
            }
        else
            log "Cannot install python3.9-venv automatically. Please install it manually."
            exit 1
        fi
    fi
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        log "Creating Python virtual environment in $VENV_DIR"
        $python_cmd -m venv "$VENV_DIR"
    fi
    
    # Activate virtual environment
    log "Activating virtual environment"
    # shellcheck disable=SC1091  # Not following: source
    source "$VENV_DIR/bin/activate"
    
    # Verify virtual environment is active
    log "Using Python from: $(which python)"
    
    # Upgrade pip in the virtual environment
    log "Upgrading pip in virtual environment"
    python -m pip install --upgrade pip
    
    # Install setuptools required for many packages
    log "Installing setuptools in virtual environment"
    python -m pip install setuptools wheel
}

# Load configuration from YAML file
CONFIG_FILE="config.yaml" # This should be /app/config.yaml, which is config.docker.yaml mounted

# Helper function to parse values from config.yaml robustly using yq
get_config_value() {
    local key="$1"
    local config_file="$2"
    # Use yq to safely read the value. The -e flag exits with non-zero status if the key is not found.
    # The '|| true' prevents the script from exiting if a key is not found (for optional keys).
    yq -e ".$key" "$config_file" || true
}

TARGET_PROJECT_ROOT=$(get_config_value "target_project_root" "$CONFIG_FILE")
INPUT_FOLDER=$(get_config_value "input_folder" "$CONFIG_FILE")
# Read the optional glob filter for selective translation
TRANSLATION_FILTER_GLOB=$(get_config_value "translation_file_filter_glob" "$CONFIG_FILE")

log "Target project root from config: \"$TARGET_PROJECT_ROOT\""
log "Input folder from config: \"$INPUT_FOLDER\""

if [ -z "$TARGET_PROJECT_ROOT" ]; then
    log "Error: TARGET_PROJECT_ROOT is not set in $CONFIG_FILE or is empty."
    exit 1
fi

if [ ! -d "$TARGET_PROJECT_ROOT" ]; then
    log "Error: Target project root directory does not exist or is not a directory: $TARGET_PROJECT_ROOT"
    exit 1
fi

if [ -z "$INPUT_FOLDER" ]; then
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

log "Starting deployment process"
log "Target project root: $TARGET_PROJECT_ROOT"
log "Input folder: $INPUT_FOLDER" # Added log for input folder

# Check Python environment
PYTHON_CMD=$(get_python_cmd)
if [ -z "$PYTHON_CMD" ]; then
    log "Error: Python is not installed. Please install Python 3."
    exit 1
fi
log "Using system Python command: $PYTHON_CMD"

# Check Python version
PYTHON_VERSION=$(check_python_version "$PYTHON_CMD")
log "Python version: $PYTHON_VERSION"

# Setup and activate virtual environment
setup_venv "$PYTHON_CMD"

# Install dependencies in virtual environment
log "Installing Python dependencies in virtual environment"

# First install critical dependencies
log "Installing core dependencies first"
python -m pip install setuptools wheel six urllib3 PyYAML || {
    log "Warning: Failed to install core dependencies. This may cause further issues."
}

# Uninstall any previous Transifex packages to avoid conflicts
log "Uninstalling any previous Transifex packages"
python -m pip uninstall -y transifex-client transifex || {
    log "Note: No previous Transifex packages found to uninstall"
}

# Install tiktoken directly first
log "Installing tiktoken package"
python -m pip install tiktoken || {
    log "Warning: Failed to install tiktoken. This may cause issues with the translation script."
}

# Then install the rest of the requirements
if [ -f "requirements.txt" ]; then
    log "Installing remaining dependencies from requirements.txt"
    python -m pip install -r requirements.txt --ignore-installed || {
        log "Warning: Failed to install some Python dependencies. Some functionality may be limited."
    }
fi

# Verify tiktoken installation
if ! python -c "import tiktoken; print('tiktoken is installed')" > /dev/null 2>&1; then
    log "Error: tiktoken module could not be imported despite installation attempt."
    log "Trying alternative installation method..."
    python -m pip install tiktoken --no-binary tiktoken || {
        log "Warning: Alternative installation of tiktoken failed."
    }
    
    # Check again
    if ! python -c "import tiktoken; print('tiktoken is installed')" > /dev/null 2>&1; then
        log "Error: Could not install tiktoken. The translation script may fail."
    else
        log "Successfully installed tiktoken with alternative method."
    fi
fi

# Check if target project root exists
if [ ! -d "$TARGET_PROJECT_ROOT" ]; then
    log "Error: Target project root directory not found: $TARGET_PROJECT_ROOT"
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
    log "INFO" "Checking for source files that are not configured in Transifex..."

    # Extract the 'source_file' for each resource from the Transifex config.
    # This gives us the configured source files with their full paths relative to the repo root.
    # Example: i18n/src/main/resources/BtcAddresses.properties
    mapfile -t configured_sources < <(yq e '.[].projects.bisq.resources[].source_file' "$TX_CONFIG_FILE")

    # Get the actual English source files present on disk.
    # We use find and then remove the input folder prefix to get paths relative to the input folder,
    # which should match the format in the Transifex config.
    shopt -s globstar
    mapfile -t actual_sources_full_path < <(find "$ABSOLUTE_INPUT_FOLDER" -type f -name '*_en.properties')

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
                log "WARNING" "Found source files not configured in Transifex:"
                unconfigured_files_found=true
            fi
            log "WARNING" "  - $relative_path"
        fi
    done

    if $unconfigured_files_found; then
        log "ERROR" "Aborting due to unconfigured source files. Please update the Transifex config at '$TX_CONFIG_FILE' and push the changes."
        exit 1
    fi
    log "INFO" "All source files are correctly configured in Transifex."
fi

# Reset the repository to a clean state to avoid any conflicts or leftover files.
log "Resetting local repository to a clean state against upstream/main in $TARGET_PROJECT_ROOT"
# Fetch the latest from upstream to ensure our reference is current.
git fetch upstream
# Reset to the upstream main branch, discarding all local changes and commits.
git reset --hard upstream/main
# Clean untracked files and directories, but exclude critical local dev files.
log "Cleaning untracked files, excluding development directories..."
git clean -fde "venv/" -e ".idea/" -e "*.iml" -e "secrets/" -e "docker/.env"

# Save the current branch (should be main as set by entrypoint)
ORIGINAL_BRANCH=$(git branch --show-current)
log "Current branch (should be main): $ORIGINAL_BRANCH"
if [ "$ORIGINAL_BRANCH" != "main" ]; then
    log "Warning: Expected to be on main branch, but on $ORIGINAL_BRANCH. Checking out main."
    git checkout main
fi

# The entrypoint script already reset main to upstream/main and updated submodules.
# No further git pull or submodule init/update should be necessary here before tx pull.
log "Proceeding with Transifex operations. Current HEAD:"
git log -1 --pretty=%H

# Step 2: Use Transifex CLI to pull the latest translations
log "Checking for Transifex CLI"
log "Current PATH: $PATH"
log "Which tx: $(which tx || echo 'tx not found in path')"
if command_exists tx; then
    log "Pulling latest translations from Transifex"
    log "Using Transifex token from environment"
    
    # Debug Transifex configuration
    log "Checking Transifex configuration"
    if [ -f "$TARGET_PROJECT_ROOT/.tx/config" ]; then
        log ".tx/config exists in project directory"
        log ".tx/config contents (without sensitive data):"
        grep -v "password" "$TARGET_PROJECT_ROOT/.tx/config"
    else
        log "Warning: .tx/config not found in project directory"
    fi
    
    # Pull translations with -t option
    log "Using tx pull -t -f --use-git-timestamps command"
    log "Listing permissions for current directory ($(pwd)) before tx pull:"
    ls -la .
    log "Listing permissions for ./i18n/src/main/resources before tx pull:"
    ls -la ./i18n/src/main/resources
    tx pull -t -f --use-git-timestamps || {
        log "Error during tx pull. Exiting."
        exit 1
    }
    log "Successfully pulled translations"
else
    log "Error: Transifex CLI not found. Please install it manually."
    exit 1
fi

# Navigate back to the translation script directory
cd - > /dev/null
log "Returned to the translation script directory"

# Step 3: Run the translation script with the virtual environment Python
log "Running translation script"
# If a filter glob is defined in the config, export it as an environment variable
# for the Python script to use.
if [ -n "$TRANSLATION_FILTER_GLOB" ]; then
    log "Translation filter is active. Only files matching '$TRANSLATION_FILTER_GLOB' will be translated."
    export TRANSLATION_FILTER_GLOB
fi
"$VENV_DIR/bin/python" src/translate_localization_files.py || {
    log "Error: Failed to run translation script. Exiting."
    exit 1
}

# Step 4: Clean up archived translation files before committing
log "Cleaning up archived translation files"
if [ -d "$INPUT_FOLDER/archive" ]; then # This now uses the cleaned INPUT_FOLDER
    rm -rf "$INPUT_FOLDER/archive"
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
    # There are translation changes to commit
    BRANCH_NAME="${TRANSLATION_BRANCH_PREFIX}-$(date +%Y-%m-%d-%H%M%S)"
    
    # Create a new branch
    log "Creating new branch: $BRANCH_NAME"
    git checkout -b "$BRANCH_NAME"
    
    # Add only translation files
    log "Adding translation files to git"
    # Be specific about the path and ignore errors for optional types
    git add i18n/src/main/resources/*.properties || log "Warning: No *.properties files found to add in i18n/src/main/resources/."

    # Commit changes with GPG signing
    log "Committing changes with GPG signing"
    git commit -S -m "Automated translation update"
    
    # Push the branch to GitHub
    log "Pushing changes to origin ($FORK_REPO_NAME)"
    git push origin "$BRANCH_NAME"
    
    # Step 5: Create a GitHub pull request
    log "Creating GitHub pull request to $UPSTREAM_REPO_NAME"
    PR_TITLE="Automated Translation Update - $(date +'%Y-%m-%d %H:%M:%S')"
    PR_BODY="This pull request was automatically generated by the translation script and contains the latest translation updates from Transifex and OpenAI.

This PR is from branch \`$BRANCH_NAME\` on the \`$FORK_REPO_NAME\` fork and targets the \`$TARGET_BRANCH_FOR_PR\` branch on \`$UPSTREAM_REPO_NAME\`."

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
                --head "$(echo $FORK_REPO_NAME | cut -d'/' -f1):$BRANCH_NAME")
            
            PR_CREATE_EXIT_CODE=$?

            if [ $PR_CREATE_EXIT_CODE -eq 0 ]; then
                log "Successfully created pull request: $PR_URL"
            else
                log "Error: Failed to create pull request (Exit Code: $PR_CREATE_EXIT_CODE). Please check gh cli authentication, GITHUB_TOKEN permissions, and repository settings."
            fi
        fi
    else
        log "Error: GitHub CLI (gh) not found. Cannot create pull request."
    fi
else
    log "No translation changes to commit"
fi

# Go back to original branch
log "Returning to original branch: $ORIGINAL_BRANCH"
log "Listing permissions for $TARGET_PROJECT_ROOT/.git before checkout $ORIGINAL_BRANCH:"
ls -la "$TARGET_PROJECT_ROOT/.git"
git checkout --force "$ORIGINAL_BRANCH"

# Re-initialize and update submodules after returning to original branch
log "Re-initializing and updating git submodules after returning to original branch"
git submodule init
git submodule update --recursive

log "Deactivating virtual environment"
deactivate || true

# Send a heartbeat ping to the health check URL if it is configured
if [ -n "$HEALTHCHECK_URL" ]; then
    log "Sending successful heartbeat to health check URL..."
    # Use curl with options to fail silently and handle connection timeouts
    curl -fsS --retry 3 --max-time 10 "$HEALTHCHECK_URL" > /dev/null || log "Warning: Health check ping failed."
fi

log "Translation update script finished successfully."
exit 0