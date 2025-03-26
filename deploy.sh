#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Log file
LOG_FILE="deployment_log.log"

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

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
git submodule update

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

# Handling remaining untracked files that might conflict with checkout
UNTRACKED_FILES=$(git ls-files --others --exclude-standard)
if [ -n "$UNTRACKED_FILES" ]; then
    log "Detected untracked files that might conflict with checkout"
    # Ask user if they want to proceed with removing untracked files
    read -p "Untracked files detected that may conflict with checkout. Do you want to clean them? (y/n): " CLEAN_RESPONSE
    
    if [[ $CLEAN_RESPONSE == "y" || $CLEAN_RESPONSE == "Y" ]]; then
        log "Cleaning untracked files"
        git clean -fd
    else
        log "User chose not to clean untracked files. Using force checkout"
        USE_FORCE_CHECKOUT=1
    fi
fi

# Step 1: Checkout the main branch and pull the latest changes
log "Checking out main branch and pulling latest changes"
if [ -n "$USE_FORCE_CHECKOUT" ]; then
    git checkout --force main
else
    git checkout main
fi
git pull origin main

# Re-initialize and update submodules after checkout
log "Re-initializing and updating git submodules after branch change"
git submodule init
git submodule update

# Step 2: Use Transifex CLI to pull the latest translations
log "Pulling latest translations from Transifex"
if [ -z "$TX_TOKEN" ]; then
    log "Warning: TX_TOKEN environment variable is not set. Transifex pull may fail."
fi
tx pull -t

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
    
    # Create a pull request
    log "Creating pull request"
    PR_TITLE="Update translations $(date +'%Y-%m-%d')"
    PR_BODY="Automated translation update from $(date +'%Y-%m-%d')."
    
    # Using GitHub CLI to create PR
    gh pr create --title "$PR_TITLE" --body "$PR_BODY" --base main
    
    # Go back to original branch
    log "Returning to original branch: $ORIGINAL_BRANCH"
    if [ -n "$USE_FORCE_CHECKOUT" ]; then
        git checkout --force "$ORIGINAL_BRANCH"
    else
        git checkout "$ORIGINAL_BRANCH"
    fi
    
    # Re-initialize and update submodules after returning to original branch
    log "Re-initializing and updating git submodules after returning to original branch"
    git submodule init
    git submodule update
    
    # Pop the stash if we stashed changes earlier
    if [ $STASH_NEEDED -eq 1 ]; then
        log "Popping stashed changes"
        git stash pop
    fi
    
    log "Pull request created successfully"
else
    log "No changes to commit"
    
    # Go back to original branch if we're not already on it
    if [ "$(git branch --show-current)" != "$ORIGINAL_BRANCH" ]; then
        log "Returning to original branch: $ORIGINAL_BRANCH"
        if [ -n "$USE_FORCE_CHECKOUT" ]; then
            git checkout --force "$ORIGINAL_BRANCH"
        else
            git checkout "$ORIGINAL_BRANCH"
        fi
        
        # Re-initialize and update submodules after returning to original branch
        log "Re-initializing and updating git submodules after returning to original branch"
        git submodule init
        git submodule update
        
        # Pop the stash if we stashed changes earlier
        if [ $STASH_NEEDED -eq 1 ]; then
            log "Popping stashed changes"
            git stash pop
        fi
    fi
fi

log "Deployment process completed successfully" 