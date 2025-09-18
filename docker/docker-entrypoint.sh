#!/bin/bash
#
# Entrypoint script for the Translate Java Property Files service.
# This script handles initial setup, privilege dropping, and Git repository management.
#
# Configuration Environment Variables for Repository Resilience:
# - REPO_CLEANUP_STRATEGY: auto (default), force, skip
#   * auto/force: Clean local changes before checkout
#   * skip: Attempt checkout with existing changes (may fail)
# - REPO_STASH_CHANGES: true (default), false
#   * true: Stash local changes before cleanup
#   * false: Directly perform hard reset without stashing
# - REPO_PRESERVE_STASH: true (default), false
#   * true: Keep stash entries for manual recovery
#   * false: Drop stash after successful checkout
#

# --- Strict Mode ---
set -euo pipefail

# --- Log Function ---
# Defined at the top to be available for all parts of the script.
log() {
    local message="$1"
    local level="${2:-INFO}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint] [$level] $message"
}

if ! id -u appuser >/dev/null 2>&1; then
  if [ "${ALLOW_RUN_AS_ROOT:-false}" = "true" ]; then
    log "User 'appuser' not found. Falling back to root since ALLOW_RUN_AS_ROOT is true." "WARNING"
    # Use root's UID/GID as a safe default when appuser is missing and root is allowed.
    APPUSER_UID="${APPUSER_UID:-0}"
    APPUSER_GID="${APPUSER_GID:-0}"
  else
    log "User 'appuser' does not exist in the image. Set ALLOW_RUN_AS_ROOT=true to fall back to root (not recommended)." "ERROR"
    exit 1
  fi
else
  APPUSER_UID="${APPUSER_UID:-$(id -u appuser)}"
  APPUSER_GID="${APPUSER_GID:-$(id -g appuser)}"
fi

# --- Unified Helper Functions ---

# Set up SSH host keys for secure git operations.
setup_ssh() {
    local user_home="${APPUSER_HOME:-/home/appuser}"
    log "Configuring SSH..."
    mkdir -p "${user_home}/.ssh"

    if [ "${ALLOW_INSECURE_SSH:-false}" = "true" ]; then
        log "WARNING: ALLOW_INSECURE_SSH is true. Host key verification is disabled." "WARNING"
        echo -e "Host github.com\n\tBatchMode yes\n\tStrictHostKeyChecking no\n\tUserKnownHostsFile=/dev/null" > "${user_home}/.ssh/config"
    else
        KNOWN_HOSTS_PATH="${PINNED_KNOWN_HOSTS_PATH:-/etc/ssh/ssh_known_hosts}"
        if [ ! -r "$KNOWN_HOSTS_PATH" ] || ! grep -q "github.com" "$KNOWN_HOSTS_PATH"; then
            log "ERROR: The pinned SSH known_hosts file is missing or invalid." "ERROR"
            log "To run in an insecure mode for development, set ALLOW_INSECURE_SSH=true." "ERROR"
            exit 1
        fi
        log "SSH is configured for strict host key checking using pinned known_hosts at $KNOWN_HOSTS_PATH."
    fi

    # Ensure correct ownership and permissions, but only chown if running as root.
    if [ "$(id -u)" -eq 0 ]; then
        chown -R "${APPUSER_UID}:${APPUSER_GID}" "${user_home}/.ssh" || log "Warning: unable to chown ${user_home}/.ssh" "WARNING"
    fi
    # These chmod operations are safe for appuser to run on its own files.
    chmod 700 "${user_home}/.ssh"
    chmod 600 "${user_home}/.ssh/config" 2>/dev/null || true # Might not exist in secure mode
    chmod 600 "${user_home}/.ssh/known_hosts" 2>/dev/null || true # Might not exist in insecure mode
}

# Helper function to ensure log directory exists and has correct permissions.
ensure_logs_dir() {
  local mode="${LOG_DIR_MODE:-0755}"
  mkdir -p /app/logs
  # Check if ownership is incorrect.
  if find /app/logs -mindepth 0 -maxdepth 0 \( ! -uid "$APPUSER_UID" -o ! -gid "$APPUSER_GID" \) -print -quit | read -r; then
    # Only attempt to chown if running as root.
    if [ "$(id -u)" -eq 0 ]; then
      chown -R "${APPUSER_UID}:${APPUSER_GID}" /app/logs || log "Warning: unable to chown /app/logs; continuing" "WARNING"
    fi
  fi
  chmod "$mode" /app/logs || log "Warning: Could not set permissions on /app/logs. Continuing..." "WARNING"
}

# --- Main Execution Logic ---
# The script acts as a gate:
# 1. If run as root, it fixes permissions and then re-executes itself as appuser.
# 2. If run as non-root (appuser), it performs the git operations and runs the main command.

for bin in git ssh gosu; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "Required binary '$bin' not found in PATH." "ERROR"; exit 1
  fi
done

if [ "$(id -u)" -ne 0 ]; then
    # --- appuser Execution Block ---
    log "Starting entrypoint script as user: $(whoami)"

    # Ensure logs and SSH are configured correctly before proceeding.
    ensure_logs_dir
    setup_ssh
    export GIT_TERMINAL_PROMPT=0

    TARGET_REPO_DIR="${TARGET_REPO_DIR:-/target_repo}"

    # --- Git Configuration ---
    log "Configuring git user..."
    GIT_USER_NAME=$(git config --global --get user.name || echo "bisq-bot")
    GIT_USER_EMAIL=$(git config --global --get user.email || echo "bisq-bot@users.noreply.github.com")
    if command -v gpg >/dev/null 2>&1; then
      GPG_SIGNING_KEY="$(gpg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^sec/ {print $5; exit}')"
    else
      GPG_SIGNING_KEY=""
      log "gpg not found; commit signing will be disabled." "WARNING"
    fi

    git config --global user.name "$GIT_USER_NAME"
    git config --global user.email "$GIT_USER_EMAIL"

    if [ -n "$GPG_SIGNING_KEY" ]; then
        git config --global user.signingkey "$GPG_SIGNING_KEY"
        git config --global commit.gpgsign true 
        log "Git user configured with GPG signing key."
    else
        git config --global --unset-all user.signingkey >/dev/null 2>&1 || true
        git config --global commit.gpgsign false 
        log "Git user configured without a GPG signing key; commit signing disabled."
    fi

    # --- Repository Initialization/Update ---
    if [ -d "$TARGET_REPO_DIR/.git" ]; then
        if [ ! -w "$TARGET_REPO_DIR" ]; then
          log "Error: $TARGET_REPO_DIR is not writable by $(whoami). Ensure correct ownership/permissions." "ERROR"
          exit 1
        fi
        log "Repository already exists in $TARGET_REPO_DIR. Updating..."
        cd "$TARGET_REPO_DIR"
    else
        if [ -e "$TARGET_REPO_DIR" ] && [ ! -w "$TARGET_REPO_DIR" ]; then
          log "Error: $TARGET_REPO_DIR exists but is not writable by $(whoami)." "ERROR"
          exit 1
        fi
        log "No repository found in $TARGET_REPO_DIR. Cloning from fork..."
        # Use parameter expansion with error message for required variables
        FORK_REPO_URL="git@github.com:${FORK_REPO_NAME:?FORK_REPO_NAME must be set}.git"
        git clone "$FORK_REPO_URL" "$TARGET_REPO_DIR"
            cd "$TARGET_REPO_DIR"
    fi

    # --- Git Remote and Branch Harmonization ---
    REMOTE=""
    if git remote | grep -q "^upstream$"; then
        REMOTE="upstream"
    elif git remote | grep -q "^origin$"; then
        REMOTE="origin"
    fi

    if ! git remote | grep -q "^upstream$"; then
        if [ -n "${UPSTREAM_REPO_NAME:-}" ]; then
            log "Adding 'upstream' remote from UPSTREAM_REPO_NAME..."
            git remote add upstream "https://github.com/${UPSTREAM_REPO_NAME}.git"
            REMOTE="upstream"
        elif [ -z "$REMOTE" ]; then
            log "Error: No 'upstream' or 'origin' remote found, and UPSTREAM_REPO_NAME is not set." "ERROR" >&2
            exit 1
        fi
    fi
    if [ -z "$REMOTE" ]; then
        REMOTE="origin"
    fi

    log "Using remote: ${REMOTE}"
    log "Fetching latest changes from ${REMOTE}..."
    git fetch --prune --tags "$REMOTE"

    DEFAULT_BRANCH="${TARGET_BRANCH_FOR_PR:-}"
    if [ -z "$DEFAULT_BRANCH" ]; then
      DEFAULT_BRANCH="$(git remote show "$REMOTE" 2>/dev/null | awk -F': ' '/HEAD branch/ {print $2}')"
      DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
      # If remote doesn't have that branch, try 'master'
      if ! git ls-remote --exit-code --heads "$REMOTE" "$DEFAULT_BRANCH" >/dev/null 2>&1; then
        if git ls-remote --exit-code --heads "$REMOTE" master >/dev/null 2>&1; then
          DEFAULT_BRANCH="master"
        fi
      fi
    fi
    log "Using default branch: ${DEFAULT_BRANCH}"

    # Pre-flight repository health check
    check_repository_health() {
      local repo_dir="$1"

      if [ ! -d "$repo_dir/.git" ]; then
        log "Repository health check: No .git directory found, this appears to be a fresh clone"
        return 0
      fi

      log "Repository health check: Examining current state..."

      # Check for uncommitted changes
      local has_changes=false
      if ! git diff --quiet 2>/dev/null; then
        log "Repository health check: Modified files detected"
        has_changes=true
      fi

      if ! git diff --cached --quiet 2>/dev/null; then
        log "Repository health check: Staged changes detected"
        has_changes=true
      fi

      # Check for untracked files that might interfere
      if git ls-files --others --exclude-standard | head -1 | grep -q .; then
        log "Repository health check: Untracked files found"
      else
        log "Repository health check: No untracked files"
      fi

      # Check current branch
      local current_branch
      current_branch=$(git branch --show-current 2>/dev/null || echo "detached")
      log "Repository health check: Currently on branch/state: $current_branch"

      # Report overall health
      if [ "$has_changes" = true ]; then
        log "Repository health check: Repository has uncommitted changes - cleanup will be performed" "WARNING"
        return 1
      else
        log "Repository health check: Repository is clean"
        return 0
      fi
    }

    # Perform health check
    if check_repository_health "$(pwd)"; then
        repo_health_status=0
    else
        repo_health_status=1
    fi

    # Configuration options for cleanup strategy
    REPO_CLEANUP_STRATEGY="${REPO_CLEANUP_STRATEGY:-auto}"  # auto, force, skip
    REPO_STASH_CHANGES="${REPO_STASH_CHANGES:-true}"       # true, false
    REPO_PRESERVE_STASH="${REPO_PRESERVE_STASH:-true}"     # true, false

    log "Checking out '${DEFAULT_BRANCH}' and resetting to match '${REMOTE}/${DEFAULT_BRANCH}'..."
    if git rev-parse --verify --quiet "refs/remotes/${REMOTE}/${DEFAULT_BRANCH}" >/dev/null; then
      # Check for local changes that might interfere with checkout
      if ! timeout 30 git diff --quiet 2>/dev/null || ! timeout 30 git diff --cached --quiet 2>/dev/null; then
        if [ "$REPO_CLEANUP_STRATEGY" = "skip" ]; then
          log "Local changes detected but REPO_CLEANUP_STRATEGY=skip. Attempting checkout as-is..." "WARNING"
        elif [ "$REPO_CLEANUP_STRATEGY" = "force" ] || [ "$REPO_CLEANUP_STRATEGY" = "auto" ]; then
          log "Local changes detected in repository. Performing cleanup for resilient recovery..." "WARNING"

          # Log what changes we're about to discard for debugging
          if ! git diff --quiet; then
            log "Modified files found (count: $(git diff --name-only | wc -l))"
          fi
          if ! git diff --cached --quiet; then
            log "Staged changes found (count: $(git diff --cached --name-only | wc -l))"
          fi

          # Save current state for potential recovery (but don't fail if stash fails)
          if [ "$REPO_STASH_CHANGES" = "true" ]; then
            STASH_MSG="Auto-stash before translation pipeline reset - $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
            if git stash push -u -m "$STASH_MSG" 2>/dev/null; then
              log "Local changes stashed as: $STASH_MSG"
              if [ "$REPO_PRESERVE_STASH" = "false" ]; then
                log "REPO_PRESERVE_STASH=false, stash will be dropped after successful checkout"
              fi
            else
              log "Could not stash changes, proceeding with hard reset" "WARNING"
            fi
          else
            log "REPO_STASH_CHANGES=false, proceeding directly to hard reset" "WARNING"
          fi

          # Force reset to clean state
          git reset --hard HEAD 2>/dev/null || true
          git clean -fd 2>/dev/null || true
        fi
      fi

      # Now attempt the checkout - should succeed after cleanup
      if ! git checkout -B "$DEFAULT_BRANCH" "${REMOTE}/${DEFAULT_BRANCH}"; then
        log "Error: Failed to checkout '${DEFAULT_BRANCH}' even after cleanup. Repository may be in inconsistent state." "ERROR" >&2
        log "Manual intervention may be required. Check git status in /target_repo" "ERROR" >&2
        exit 1
      fi

      log "Successfully reset repository to clean state: ${REMOTE}/${DEFAULT_BRANCH}"

      # Clean up stash if requested
      if [ "$REPO_PRESERVE_STASH" = "false" ] && [ "$REPO_STASH_CHANGES" = "true" ]; then
        if git stash list | grep -q "Auto-stash before translation pipeline reset"; then
          if git stash drop "stash@{0}" 2>/dev/null; then
            log "Temporary stash dropped as requested"
          else
            log "Could not drop stash, leaving for manual cleanup" "WARNING"
          fi
        fi
      fi
    else
      log "Error: remote branch '${REMOTE}/${DEFAULT_BRANCH}' not found." "ERROR" >&2
      exit 1
    fi

    # --- Final Steps ---
    log "Repository is up to date."

    if [ "$#" -eq 0 ]; then
      log "Error: no command provided to exec. Set CMD in Dockerfile or command in docker-compose.yml." "ERROR" >&2; exit 1
    fi
    log "Handing off to the main container command: $*"
    # Hand off to the intended command (e.g., update-translations.sh)
    exec "$@"

else
    # --- Root Execution Block ---
    log "Running as root. Ensuring directories exist and have correct permissions..."

    # Ensure the home directory for appuser exists and has correct ownership.
    mkdir -p /home/appuser
    chown "${APPUSER_UID}:${APPUSER_GID}" /home/appuser

    # Ensure log directory exists and has correct permissions.
    ensure_logs_dir

    # Fix permissions on the target repository if it's a mounted volume
    if [ -d "/target_repo" ]; then
        # Only fix entries with mismatched ownership; don't follow symlinks.
        if [ "${CHOWN_TARGET_REPO_RECURSIVE:-false}" = "true" ]; then
          chown -R "${APPUSER_UID}:${APPUSER_GID}" /target_repo
        else
          find /target_repo -maxdepth 1 \( ! -uid "$APPUSER_UID" -o ! -gid "$APPUSER_GID" \) -exec chown -h "${APPUSER_UID}:${APPUSER_GID}" {} +
        fi
    fi

    # Fix ownership of the .env file if it exists; do not follow symlinks and don't fail hard.
    if [ -e "/app/docker/.env" ]; then
        if [ -L "/app/docker/.env" ]; then
            log "Refusing to chown symlink /app/docker/.env; not following." "WARNING"
        else
            chown -h "${APPUSER_UID}:${APPUSER_GID}" "/app/docker/.env" \
              || log "Warning: unable to chown /app/docker/.env; continuing" "WARNING"
            chmod 640 "/app/docker/.env" \
              || log "Warning: unable to chmod /app/docker/.env; continuing" "WARNING"
        fi
    fi

    # When running as root (ALLOW_RUN_AS_ROOT=true), silence Git ownership warnings for /target_repo.
    if [ "${ALLOW_RUN_AS_ROOT:-false}" = "true" ]; then
      git config --global --add safe.directory /target_repo || true
    fi

    # Set up SSH. This is done as root to ensure correct ownership of created files.
    setup_ssh

    # Attempt to switch to the appuser.
    # If this fails (e.g., on Docker for Mac), check the ALLOW_RUN_AS_ROOT flag.
    log "Permissions fixed. Re-executing as appuser..."

    # Set HOME and USER explicitly for gosu to ensure a clean environment for git and other tools.
    export HOME=/home/appuser
    export USER=appuser

    # Use gosu to drop privileges and re-execute this same script as the appuser.
    # The script will then enter the `if [ "$(id -u)" -ne 0 ]` block.
    if ! exec gosu appuser "$0" "$@"; then
        log "Warning: gosu failed to switch to appuser." "WARNING"
        if [ "${ALLOW_RUN_AS_ROOT:-false}" = "true" ]; then
            log "ALLOW_RUN_AS_ROOT=true; continuing as root." "WARNING"
            if [ "$#" -eq 0 ]; then
              log "Error: no command provided to exec. Set CMD in Dockerfile or command in docker-compose.yml." "ERROR" >&2
              exit 1
            fi
            exec "$@"
        else
            log "Refusing to continue as root. Set ALLOW_RUN_AS_ROOT=true to override." "ERROR"
            exit 1
        fi
    fi
fi 