#!/bin/bash
#
# Entrypoint script for the Translate Java Property Files service.
# This script handles initial setup, privilege dropping, and Git repository management.
#

# --- Strict Mode ---
set -euo pipefail

# --- Log Function ---
# Defined at the top to be available for all parts of the script.
log() {
    # Use "$*" to log all arguments as a single string, preserving quotes and spaces.
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint] $*"
}

setup_ssh() {
    log "Configuring SSH..."

    # By default, SSH is configured to fail if the host key does not match the baked-in known_hosts.
    # On the server, this provides strong protection against man-in-the-middle attacks.
    # For local development or in environments where the host key might change, this check can be bypassed.
    if [ "${ALLOW_INSECURE_SSH:-false}" = "true" ]; then
        log "WARNING: ALLOW_INSECURE_SSH is true. Host key verification will use ssh-keyscan at runtime."
        # This configuration is written to the user's local SSH config, not the system-wide one.
        mkdir -p /home/appuser/.ssh
        echo -e "Host github.com\n\tStrictHostKeyChecking no\n\tUserKnownHostsFile=/dev/null" > /home/appuser/.ssh/config
        chown -R appuser:appuser /home/appuser/.ssh
        chmod 700 /home/appuser/.ssh
        chmod 600 /home/appuser/.ssh/config
    else
        # Verify that the baked-in known_hosts file exists and is correctly configured.
        if [ ! -r /etc/ssh/ssh_known_hosts ] || ! grep -q "github.com" /etc/ssh/ssh_known_hosts; then
            log "ERROR: The pinned SSH known_hosts file is missing or does not contain a key for github.com."
            log "To run in an insecure mode for local development, set the environment variable ALLOW_INSECURE_SSH=true."
            exit 1
        fi
        log "SSH is configured for strict host key checking using the baked-in known_hosts file."
        # System-wide SSH config will enforce this automatically if no user config overrides it.
    fi
}

ensure_logs_dir() {
  local mode="${LOG_DIR_MODE:-0755}"
  mkdir -p /app/logs
  if find /app/logs -mindepth 1 -maxdepth 1 \( ! -uid "$APPUSER_UID" -o ! -gid "$APPUSER_GID" \) -print -quit | read -r; then
    chown -R appuser:appuser /app/logs || log "Warning: unable to chown /app/logs; continuing"
  fi
  chmod "$mode" /app/logs || log "Warning: Could not set permissions on /app/logs. Continuing..."
}

# --- Root-Level Execution ---
# This block runs only if the container is started as root (UID 0).
if [ "$(id -u)" -eq 0 ]; then
    log "Running as root. Ensuring directories exist and have correct permissions..."

    if ! id -u appuser >/dev/null 2>&1; then
        log "Error: required user 'appuser' not found; cannot drop privileges." >&2
        exit 1
    fi
    APPUSER_UID=$(id -u appuser)
    APPUSER_GID=$(id -g appuser)

    TARGET_REPO_DIR="${TARGET_REPO_DIR:-/target_repo}"
    mkdir -p "$TARGET_REPO_DIR"

    # Guarded, portable chown for the target repository directory
    CURRENT_OWNER=$(ls -ldn "$TARGET_REPO_DIR" | awk '{print $3":"$4}')
    if [ "$CURRENT_OWNER" != "$APPUSER_UID:$APPUSER_GID" ]; then
        chown -R appuser:appuser "$TARGET_REPO_DIR"
    fi

    # Harden log directory setup
    if [ -e /app/logs ] && [ ! -d /app/logs ]; then
        log "Error: /app/logs exists but is not a directory" >&2; exit 1
    fi
    LOG_DIR_MODE="${LOG_DIR_MODE:-0755}"
    if ! [[ "$LOG_DIR_MODE" =~ ^(0?[0-7]{3,4}|[ugoa]*[-+=][rwxXstugo,]+)$ ]]; then
        log "Warning: invalid LOG_DIR_MODE '$LOG_DIR_MODE' provided; defaulting to 0755"
        LOG_DIR_MODE="0755"
    fi
    ensure_logs_dir

    # Root-specific setup continues...
    log "Setting up appuser-specific environment..."

    setup_ssh

    log "Permissions fixed. Re-executing as appuser..."
    
    # Debug: Check if appuser exists and get its details
    log "Debug: Checking appuser details..."
    id appuser || log "Warning: id appuser failed"
    ls -la /home/appuser || log "Warning: ls /home/appuser failed"
    
    if command -v gosu >/dev/null 2>&1; then
        log "Using gosu to switch to appuser..."
        if exec gosu appuser "$0" "$@" 2>/dev/null; then
            :
        else
            log "Warning: gosu failed to switch to appuser." "WARNING"
            if [ "${ALLOW_RUN_AS_ROOT:-false}" = "true" ]; then
              log "ALLOW_RUN_AS_ROOT=true; continuing as root."
            else
              log "Refusing to continue as root. Set ALLOW_RUN_AS_ROOT=true to override." "ERROR"
              exit 1
            fi
        fi
    elif command -v su-exec >/dev/null 2>&1; then
        log "Using su-exec to switch to appuser..."
        if exec su-exec appuser "$0" "$@" 2>/dev/null; then
            :
        else
            log "Warning: su-exec failed to switch to appuser." "WARNING"
            if [ "${ALLOW_RUN_AS_ROOT:-false}" = "true" ]; then
              log "ALLOW_RUN_AS_ROOT=true; continuing as root."
            else
              log "Refusing to continue as root. Set ALLOW_RUN_AS_ROOT=true to override." "ERROR"
              exit 1
            fi
        fi
    else
        log "Error: neither 'gosu' nor 'su-exec' found in PATH." >&2
        exit 1
    fi
fi

# --- Appuser-Level Execution ---
export HOME="${HOME:-/home/appuser}"
mkdir -p "$HOME"

[ -d /app/logs ] || mkdir -p /app/logs
if [ -w /app/logs ]; then
  LOG_DIR_MODE="${LOG_DIR_MODE:-0755}"
  if ! [[ "$LOG_DIR_MODE" =~ ^(0?[0-7]{3,4}|[ugoa]*[-+=][rwxXstugo,]+)$ ]]; then
      log "Warning: invalid LOG_DIR_MODE '$LOG_DIR_MODE' provided; defaulting to 0755"
      LOG_DIR_MODE="0755"
  fi
  chmod "$LOG_DIR_MODE" /app/logs || log "Warning: Could not set permissions on /app/logs. Continuing..."
fi

# Ensure the log directory exists and is owned by appuser
if [ -d "/app/logs" ]; then
    chown -R appuser:appuser /app/logs
fi

# Attempt to switch to the appuser.
# If this fails (e.g., on Docker for Mac), check the ALLOW_RUN_AS_ROOT flag.
log "[Entrypoint] Using gosu to switch to appuser..."
if ! gosu appuser "$0" "$@"; then
    log "Warning: gosu failed to switch to appuser." "WARNING"
    if [ "${ALLOW_RUN_AS_ROOT:-false}" = "true" ]; then
      log "ALLOW_RUN_AS_ROOT=true; continuing as root."
    else
      log "Refusing to continue as root. Set ALLOW_RUN_AS_ROOT=true to override." "ERROR"
      exit 1
    fi
fi

log "Starting entrypoint script as user: $(whoami)"

# If running as root (e.g., ALLOW_RUN_AS_ROOT=true in local dev), allow git to operate on /target_repo
if [ "$(id -u)" -eq 0 ]; then
    git config --global --add safe.directory /target_repo || true
fi

TARGET_REPO_DIR="${TARGET_REPO_DIR:-/target_repo}"

# --- Git Configuration ---
log "Configuring git user..."
GIT_USER_NAME=$(git config --global --get user.name || echo "bisq-bot")
GIT_USER_EMAIL=$(git config --global --get user.email || echo "bisq-bot@users.noreply.github.com")
GPG_SIGNING_KEY=$(gpg --list-secret-keys --with-colons 2>/dev/null | grep '^sec' | cut -d: -f5 | head -n1 || true)

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
      log "Error: $TARGET_REPO_DIR is not writable by $(whoami). Ensure correct ownership/permissions."
      exit 1
    fi
    log "Repository already exists in $TARGET_REPO_DIR. Updating..."
    cd "$TARGET_REPO_DIR"
else
    if [ -e "$TARGET_REPO_DIR" ] && [ ! -w "$TARGET_REPO_DIR" ]; then
      log "Error: $TARGET_REPO_DIR exists but is not writable by $(whoami)."
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
        log "Error: No 'upstream' or 'origin' remote found, and UPSTREAM_REPO_NAME is not set." >&2
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

log "Checking out '${DEFAULT_BRANCH}' and resetting to match '${REMOTE}/${DEFAULT_BRANCH}'..."
if git rev-parse --verify --quiet "refs/remotes/${REMOTE}/${DEFAULT_BRANCH}" >/dev/null; then
  git checkout -B "$DEFAULT_BRANCH" "${REMOTE}/${DEFAULT_BRANCH}"
else
  log "Error: remote branch '${REMOTE}/${DEFAULT_BRANCH}' not found." >&2
  exit 1
fi

# --- Final Steps ---
log "Repository is up to date."

if [ "$#" -eq 0 ]; then
  log "Error: no command provided to exec. Set CMD in Dockerfile or command in docker-compose.yml." >&2; exit 1
fi
log "Handing off to the main container command: $*"
exec "$@" 