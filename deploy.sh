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

# Load environment variables from .env file if it exists
ENV_FILE=".env"
if [ -f "$ENV_FILE" ]; then
    log "Loading environment variables from $ENV_FILE"
    set -a  # automatically export all variables
    source "$ENV_FILE"
    set +a  # disable auto-export
fi

# Load configuration from YAML file
CONFIG_FILE="config.yaml"
TARGET_PROJECT_ROOT=$(grep -oP 'target_project_root: \K.*' "$CONFIG_FILE" | tr -d "'" | tr -d '"')
INPUT_FOLDER=$(grep -oP 'input_folder: \K.*' "$CONFIG_FILE" | tr -d "'" | tr -d '"')

log "Starting deployment process"
log "Target project root: $TARGET_PROJECT_ROOT"

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
    if [ -z "$TX_TOKEN" ]; then
        log "Warning: TX_TOKEN environment variable is not set. Transifex pull may fail."
        log "Make sure the TX_TOKEN is set in your .env file"
    else
        log "TX_TOKEN is set, proceeding with Transifex operations"
    fi
    # Export TX_TOKEN again just to be sure it's available for the tx command
    export TX_TOKEN="$TX_TOKEN"
    tx pull -t || log "Failed to pull translations from Transifex, continuing with script"
else
    log "Warning: Transifex CLI not found. Skipping translation pull from Transifex."
    log "To install Transifex CLI, run: pip install transifex-client"
fi

# Navigate back to the translation script directory
cd - > /dev/null
log "Returned to the translation script directory"

# Step 3: Run the translation script
log "Running translation script"
python src/translate_localization_files.py

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

log "Deployment process completed successfully" 