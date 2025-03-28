#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Log file
LOG_FILE="deployment_log.log"

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

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

# Virtual environment directory
VENV_DIR=".venv"

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

# Load environment variables from .env file if it exists
ENV_FILE=".env"
HOME_ENV_FILE="$HOME/.env"

if [ -f "$HOME_ENV_FILE" ]; then
    log "Loading environment variables from $HOME_ENV_FILE"
    set -a  # automatically export all variables
    # shellcheck source=~/.env
    source "$HOME_ENV_FILE"
    set +a  # disable auto-export
    log "TX_TOKEN loaded from $HOME_ENV_FILE"
elif [ -f "$ENV_FILE" ]; then
    log "Loading environment variables from $ENV_FILE"
    set -a  # automatically export all variables
    # shellcheck source=./.env
    source "$ENV_FILE"
    set +a  # disable auto-export
    log "TX_TOKEN loaded from $ENV_FILE"
else
    log "Error: No .env file found in current directory or home directory"
    log "Please create a .env file with your Transifex API token:"
    log "echo 'TX_TOKEN=your_transifex_api_token' > ~/.env"
    exit 1
fi

# Ensure TX_TOKEN is set and exported
if [ -z "$TX_TOKEN" ]; then
    log "Error: TX_TOKEN environment variable is not set"
    log "Please create a .env file with your Transifex API token:"
    log "echo 'TX_TOKEN=your_transifex_api_token' > ~/.env"
    exit 1
fi

# Export TX_TOKEN explicitly
export TX_TOKEN
log "TX_TOKEN is set and exported"

# Create or update .transifexrc with the token
log "Setting up Transifex configuration"
cat > ~/.transifexrc << EOF
[https://www.transifex.com]
hostname = https://www.transifex.com
username = api
password = $TX_TOKEN
EOF
log "Created/updated ~/.transifexrc"

# Verify .transifexrc permissions
chmod 600 ~/.transifexrc
log "Set correct permissions on ~/.transifexrc"

# Load configuration from YAML file
CONFIG_FILE="config.yaml"
TARGET_PROJECT_ROOT=$(grep -oP 'target_project_root: \K.*' "$CONFIG_FILE" | tr -d "'" | tr -d '"')
INPUT_FOLDER=$(grep -oP 'input_folder: \K.*' "$CONFIG_FILE" | tr -d "'" | tr -d '"')

log "Starting deployment process"
log "Target project root: $TARGET_PROJECT_ROOT"

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

# Install tiktoken directly first
log "Installing tiktoken package"
python -m pip install tiktoken || {
    log "Warning: Failed to install tiktoken. This may cause issues with the translation script."
}

# Now install the latest transifex client from GitHub
log "Installing latest Transifex client from GitHub"
python -m pip install git+https://github.com/transifex/transifex-client.git@master || {
    log "Warning: Failed to install latest Transifex client from GitHub. Trying PyPI version..."
    python -m pip install "transifex-client<0.14.0" || {
        log "Warning: Failed to install transifex-client from PyPI. Will try system package if available."
        # Try to install with apt if on Ubuntu/Debian
        if command_exists apt-get; then
            log "Attempting to install transifex-client via apt..."
            sudo apt-get update && sudo apt-get install -y transifex-client || {
                log "Failed to install transifex-client via apt. Transifex operations will be skipped."
            }
        fi
    }
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
log "Changed directory to target project root"

# Save the current branch to restore it later
ORIGINAL_BRANCH=$(git branch --show-current)
log "Current branch: $ORIGINAL_BRANCH"

# Initialize and update submodules to make sure they're in a clean state
log "Initializing and updating git submodules"
git submodule init
git submodule update --recursive

# Stash any changes including untracked files
log "Stashing any changes including untracked files"
STASH_RESULT=$(git stash push -u -m "Auto-stashed by translation script")
STASH_NEEDED=0
if [[ $STASH_RESULT != "No local changes to save" ]]; then
    STASH_NEEDED=1
    log "Changes were stashed"
else
    log "No changes to stash"
fi

# Step 1: Checkout the main branch and pull the latest changes
log "Checking out main branch with force (to bypass untracked files conflicts)"
git checkout --force main
git pull origin main

# Re-initialize and update submodules after checkout
log "Re-initializing and updating git submodules after branch change"
git submodule init
git submodule update --recursive

# Step 2: Use Transifex CLI to pull the latest translations
log "Checking for Transifex CLI"
if command_exists tx; then
    log "Pulling latest translations from Transifex"
    log "Using Transifex token from environment"
    
    # Get transifex version to determine correct options
    TX_VERSION=$(tx --version 2>&1 | grep -oP 'transifex-client/\K[0-9.]+' || echo "unknown")
    log "Detected Transifex client version: $TX_VERSION"
    
    # Debug Transifex configuration
    log "Checking Transifex configuration"
    if [ -f ~/.transifexrc ]; then
        log "~/.transifexrc exists"
        log "~/.transifexrc permissions: $(ls -l ~/.transifexrc)"
    else
        log "Warning: ~/.transifexrc does not exist"
    fi
    
    # Pull translations with appropriate options for the version
    if [[ "$TX_VERSION" == "unknown" ]]; then
        # Try without options first
        log "Using default pull command"
        tx pull || log "Failed to pull translations from Transifex, continuing with script"
    elif [[ $(printf '%s\n' "0.14.0" "$TX_VERSION" | sort -V | head -n1) == "0.14.0" ]]; then
        # Version 0.14.0 or higher supports -t option
        log "Using -t option for version $TX_VERSION"
        tx pull -t || log "Failed to pull translations from Transifex, continuing with script"
    else
        # For older versions use --all
        log "Using --all option for version $TX_VERSION"
        tx pull --all || log "Failed to pull translations from Transifex, continuing with script"
    fi
else
    log "Warning: Transifex CLI not found. Skipping translation pull from Transifex."
    log "To install Transifex CLI, try one of these methods:"
    log "1. Inside virtual environment: python -m pip install 'transifex-client<0.14.0'"
    log "2. System-wide: sudo apt-get install transifex-client (on Debian/Ubuntu)"
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
if [ -d "$INPUT_FOLDER/archive" ]; then
    rm -rf "$INPUT_FOLDER/archive"
    log "Deleted archived translation files"
fi

# Step 5: Check if there are any new translations to commit
cd "$TARGET_PROJECT_ROOT"
log "Checking for new translations to commit"
if [ -n "$(git status --porcelain)" ]; then
    # There are changes to commit
    BRANCH_NAME="translations-update-$(date +'%Y%m%d%H%M%S')"
    
    # Create a new branch
    log "Creating new branch: $BRANCH_NAME"
    git checkout -b "$BRANCH_NAME"
    
    # Add all changes
    log "Adding translation files to git"
    git add .
    
    # Commit changes with GPG signing
    log "Committing changes with GPG signing"
    git commit -S -m "Update translations $(date +'%Y-%m-%d')"
    
    # Push the branch to GitHub
    log "Pushing branch to GitHub"
    git push origin "$BRANCH_NAME"
    
    # Check for GitHub CLI
    if command_exists gh; then
        # Create a pull request
        log "Creating pull request"
        PR_TITLE="Update translations $(date +'%Y-%m-%d')"
        PR_BODY="Automated translation update from $(date +'%Y-%m-%d')."
        
        # Using GitHub CLI to create PR
        gh pr create --title "$PR_TITLE" --body "$PR_BODY" --base main
        log "Pull request created successfully"
    else
        log "Warning: GitHub CLI not found. Pull request not created."
        log "To create a PR manually, visit: https://github.com/hiciefte/bisq2/compare/main...$BRANCH_NAME"
    fi
    
    # Go back to original branch
    log "Returning to original branch: $ORIGINAL_BRANCH"
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
else
    log "No changes to commit"
    
    # Go back to original branch if we're not already on it
    if [ "$(git branch --show-current)" != "$ORIGINAL_BRANCH" ]; then
        log "Returning to original branch: $ORIGINAL_BRANCH"
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
    fi
fi

log "Deactivating virtual environment"
deactivate || true

log "Deployment process completed successfully" 