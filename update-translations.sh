#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

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
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

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

# Helper function to parse values from config.yaml robustly using awk
get_config_value() {
    local key="$1"
    local config_file="$2"
    awk -F': *| *#.*' -v k="^$key:" '$0 ~ k {gsub(/^[ \t'"'"'"]+|[ \t'"'"'"]+$/, "", $2); print $2; exit}' "$config_file"
}

TARGET_PROJECT_ROOT=$(get_config_value "target_project_root" "$CONFIG_FILE")
INPUT_FOLDER=$(get_config_value "input_folder" "$CONFIG_FILE")

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

# Construct the absolute path for INPUT_FOLDER relative to TARGET_PROJECT_ROOT
ABSOLUTE_INPUT_FOLDER="$TARGET_PROJECT_ROOT/$INPUT_FOLDER"
# Remove any double slashes that might occur if INPUT_FOLDER starts with /
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

# Navigate to the target project root
cd "$TARGET_PROJECT_ROOT"
log "Changed directory to target project root: $(pwd)"
log "Listing permissions for $TARGET_PROJECT_ROOT before stash:"
ls -la "$TARGET_PROJECT_ROOT"
log "Listing permissions for $TARGET_PROJECT_ROOT/.git before stash:"
ls -la "$TARGET_PROJECT_ROOT/.git"
log "Ensuring repository is in a clean state..."

# Save the current branch (should be main as set by entrypoint)
ORIGINAL_BRANCH=$(git branch --show-current)
log "Current branch (should be main): $ORIGINAL_BRANCH"
if [ "$ORIGINAL_BRANCH" != "main" ]; then
    log "Warning: Expected to be on main branch, but on $ORIGINAL_BRANCH. Checking out main."
    git checkout main
fi

# Stash any unexpected local changes (though entrypoint should have left it clean)
log "Stashing any lingering changes to ensure a clean state..."
log "DEBUG: Before stash command"
set +e
STASH_RESULT=$(git stash push -u -m "Auto-stashed by update-translations.sh" 2>&1)
STASH_EXIT_CODE=$?
log "DEBUG: After stash command"
set -e
log "DEBUG: git stash exit code: $STASH_EXIT_CODE"
log "DEBUG: git stash output: $STASH_RESULT"
if [[ $STASH_EXIT_CODE -ne 0 ]]; then
    log "Warning: git stash failed with exit code $STASH_EXIT_CODE. Output: $STASH_RESULT"
fi
log "DEBUG: After stash result logic"
STASH_NEEDED=0
if [[ $STASH_RESULT != "No local changes to save" ]]; then
    STASH_NEEDED=1
    log "Lingering changes were stashed."
else
    log "No lingering changes to stash; repository is clean."
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
    log "Using tx pull -t --use-git-timestamps command"
    log "Listing permissions for current directory ($(pwd)) before tx pull:"
    ls -la .
    log "Listing permissions for ./i18n/src/main/resources before tx pull:"
    ls -la ./i18n/src/main/resources
    tx pull -t --use-git-timestamps || log "Failed to pull translations from Transifex, continuing with script"
else
    log "Error: Transifex CLI not found. Please install it manually."
    exit 1
fi

# Navigate back to the translation script directory
cd - > /dev/null
log "Returned to the translation script directory"

# Step 3: Run the translation script with the virtual environment Python
log "Running translation script"
python src/translate_localization_files.py || {
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
    BRANCH_NAME="translation-update-$(date +'%Y%m%d-%H%M%S')"
    
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
                # Push updated translations back to Transifex ONLY if PR was successful
                log "Pushing updated translations to Transifex"
                tx push -t || {
                    log "Warning: Failed to push translations to Transifex despite successful PR."
                }
            else
                log "Error: Failed to create pull request (Exit Code: $PR_CREATE_EXIT_CODE). Please check gh cli authentication, GITHUB_TOKEN permissions, and repository settings."
                log "Skipping push to Transifex due to PR creation failure."
            fi
        fi
    else
        log "Error: GitHub CLI (gh) not found. Cannot create pull request."
        log "Skipping push to Transifex due to missing GitHub CLI."
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

# Pop the stash if we stashed changes earlier
if [ $STASH_NEEDED -eq 1 ]; then
    log "Popping stashed changes"
    git stash pop
fi

log "Deactivating virtual environment"
deactivate || true

log "Deployment process completed successfully" 