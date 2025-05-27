#!/bin/bash
set -e

# Log function for this script
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint] $1"
}

# This script can be invoked in two main ways:
# 1. As root (by Docker CMD/ENTRYPOINT): It performs initial setup (repo clone, permissions, starts cron)
#    and then typically execs 'sleep infinity' or another CMD.
# 2. As appuser (by cron, or 'su appuser -c "entrypoint_script some_command"'):
#    It sets up the appuser environment (XDG_RUNTIME_DIR, GPG) and then execs 'some_command'.

if [ "$(id -u)" -ne 0 ]; then
    # --- APPUSER EXECUTION BLOCK ---
    # This block runs if the script is executed by a non-root user (e.g., appuser).
    # It prepares the environment for commands like update-translations.sh.

    APPUSER_UID_FOR_XDG_SETUP=$(id -u) # Current user's UID
    APPUSER_LOGIN_NAME=$(id -un)

    # Define a logger for this specific execution path
    log_appuser_exec() {
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint/appuser-exec ($APPUSER_LOGIN_NAME)] $1"
    }

    log_appuser_exec "Running as appuser ($(id -u):$(id -g)). Preparing to execute: '$@'."

    export XDG_RUNTIME_DIR="/run/user/${APPUSER_UID_FOR_XDG_SETUP}"
    log_appuser_exec "XDG_RUNTIME_DIR set to: $XDG_RUNTIME_DIR"
    mkdir -p "${XDG_RUNTIME_DIR}/gnupg"
    chmod 700 "${XDG_RUNTIME_DIR}" "${XDG_RUNTIME_DIR}/gnupg"

    log_appuser_exec "Setting up GPG agent..."
    export GPG_TTY=$(tty)
    log_appuser_exec "GPG_TTY set to: $GPG_TTY"

    log_appuser_exec "Attempting to kill existing gpg-agent, dirmngr, keyboxd processes for user $(id -u)..."
    pkill -u "$(id -u)" gpg-agent || log_appuser_exec "No gpg-agent processes to kill or pkill failed."
    pkill -u "$(id -u)" dirmngr || log_appuser_exec "No dirmngr processes to kill or pkill failed."
    pkill -u "$(id -u)" keyboxd || log_appuser_exec "No keyboxd processes to kill or pkill failed."
    sleep 0.5 # Reduced sleep

    log_appuser_exec "Removing stale GPG sockets from $XDG_RUNTIME_DIR/gnupg/ and $HOME/.gnupg/"
    rm -f "${XDG_RUNTIME_DIR}"/gnupg/S.*
    rm -f "$HOME/.gnupg/S.*"

    log_appuser_exec "Removing potential GPG lock files from $HOME/.gnupg/"
    rm -f "$HOME/.gnupg/.~lock.*" # Common pattern for temp lock files by some apps
    rm -f "$HOME/.gnupg/pubring.kbx.~lock"
    rm -f "$HOME/.gnupg/trustdb.gpg.~lock"
    # Keyboxd specific locks (if any, usually handles internally or via sockets)
    # If keyboxd uses its own daemon socket, ensure it's also cleared or keyboxd is reset.
    # For now, pkill of keyboxd and socket removal should be primary.

    log_appuser_exec "Ensuring GPG agent is started using 'gpg-connect-agent /bye'..."
    if gpg-connect-agent /bye &> /dev/null; then
        log_appuser_exec "gpg-connect-agent /bye successful. Agent is running."
    else
        log_appuser_exec "gpg-connect-agent /bye returned non-zero. Attempting to start agent explicitly."
        gpg-agent --homedir ~/.gnupg --daemon --quiet --allow-preset-passphrase || log_appuser_exec "gpg-agent --daemon also returned non-zero; agent might be running or failed."
    fi

    GPG_AGENT_SOCKET="${XDG_RUNTIME_DIR}/gnupg/S.gpg-agent"
    if [ -S "$GPG_AGENT_SOCKET" ]; then
        log_appuser_exec "GPG agent socket confirmed at $GPG_AGENT_SOCKET."
    else
        log_appuser_exec "Warning: GPG agent socket NOT found at $GPG_AGENT_SOCKET after setup attempts."
    fi
    
    log_appuser_exec "Executing user command: $@"
    exec "$@"

else
    # --- ROOT EXECUTION BLOCK ---
    log "Starting initial entrypoint setup as root..."

    TARGET_REPO_DIR="/target_repo"
    FORK_REPO_URL="https://github.com/hiciefte/bisq2.git"
    UPSTREAM_REPO_URL="https://github.com/bisq-network/bisq2.git"

    APPUSER_UID=${HOST_UID:-1000} # From docker-compose build/env
    APPUSER_GID=${HOST_GID:-1000} # From docker-compose build/env

    log "Container running as $(id -u):$(id -g) (expected root)."
    log "Target appuser UID: $APPUSER_UID, GID: $APPUSER_GID (from HOST_UID/HOST_GID env vars)."

    mkdir -p "$TARGET_REPO_DIR"

    if [ -d "$TARGET_REPO_DIR/.git" ]; then
        log "Target directory $TARGET_REPO_DIR already contains a .git folder. Configuring remotes and updating..."
        cd "$TARGET_REPO_DIR"
        git config --global --add safe.directory "$TARGET_REPO_DIR" || log "Warning: Failed to add safe.directory to root's global git config."

        if git remote get-url origin 2>/dev/null | grep -q "$FORK_REPO_URL"; then
            log "Origin remote already correctly set to $FORK_REPO_URL"
        else
            log "Setting origin remote to $FORK_REPO_URL"
            git remote set-url origin "$FORK_REPO_URL" || git remote add origin "$FORK_REPO_URL"
        fi

        if git remote get-url upstream 2>/dev/null | grep -q "$UPSTREAM_REPO_URL"; then
            log "Upstream remote already correctly set to $UPSTREAM_REPO_URL"
        else
            log "Setting upstream remote to $UPSTREAM_REPO_URL"
            git remote add upstream "$UPSTREAM_REPO_URL" || git remote set-url upstream "$UPSTREAM_REPO_URL"
        fi

        log "Fetching all from origin and upstream..."
        git fetch origin --prune || log "Warning: Git fetch origin failed."
        git fetch upstream --prune || log "Warning: Git fetch upstream failed."

        log "Checking out main branch and resetting to upstream/main..."
        current_branch=$(git branch --show-current)
        if [ "$current_branch" != "main" ]; then
            git checkout main || git checkout -b main origin/main # Ensure main exists and tracks origin/main initially
        fi
        git reset --hard upstream/main || log "Warning: Failed to reset main to upstream/main."
        
        log "Updating submodules based on upstream/main..."
        git submodule sync --recursive || log "Warning: git submodule sync failed."
        git submodule update --init --recursive || log "Warning: git submodule update failed."
    else
        log "Target directory $TARGET_REPO_DIR is empty or not a git repository. Cloning $FORK_REPO_URL as origin..."
        git clone --recurse-submodules "$FORK_REPO_URL" "$TARGET_REPO_DIR"
        if [ $? -ne 0 ]; then
            log "Error: Failed to clone repository $FORK_REPO_URL into $TARGET_REPO_DIR."
            exit 1
        fi
        cd "$TARGET_REPO_DIR"
        git config --global --add safe.directory "$TARGET_REPO_DIR" || log "Warning: Failed to add safe.directory to root's global git config."

        log "Adding upstream remote $UPSTREAM_REPO_URL..."
        git remote add upstream "$UPSTREAM_REPO_URL"
        if [ $? -ne 0 ]; then
            log "Warning: Failed to add upstream remote."
        fi
        log "Fetching upstream and setting local main to upstream/main..."
        git fetch upstream --prune
        current_branch=$(git branch --show-current)
        if [ "$current_branch" != "main" ]; then
            git checkout main || git checkout -b main origin/main
        fi
        git reset --hard upstream/main
        git submodule sync --recursive
        git submodule update --init --recursive
        log "Repository cloned, upstream configured, and main branch aligned with upstream/main."
    fi

    log "Setting up system-wide git safe.directory for /target_repo (for appuser)..."
    git config --system --add safe.directory /target_repo || log "Warning: Failed to set system-wide git safe.directory."

    cd /app

    log "Setting ownership of $TARGET_REPO_DIR to appuser ($APPUSER_UID:$APPUSER_GID)..."
    chown -R "$APPUSER_UID":"$APPUSER_GID" "$TARGET_REPO_DIR"
    if [ $? -ne 0 ]; then
        log "Warning: Failed to chown $TARGET_REPO_DIR to appuser."
    fi

    XDG_DIR_APPUSER_SETUP_BY_ROOT="/run/user/${APPUSER_UID}" # Used for root setup
    log "Preparing XDG_RUNTIME_DIR for appuser (by root): $XDG_DIR_APPUSER_SETUP_BY_ROOT"
    mkdir -p "${XDG_DIR_APPUSER_SETUP_BY_ROOT}/gnupg"
    chown -R "${APPUSER_UID}:${APPUSER_GID}" "${XDG_DIR_APPUSER_SETUP_BY_ROOT}"
    chmod -R 700 "${XDG_DIR_APPUSER_SETUP_BY_ROOT}"
    log "Set ownership of ${XDG_DIR_APPUSER_SETUP_BY_ROOT} to ${APPUSER_UID}:${APPUSER_GID} and permissions to 700."
    ls -ld "${XDG_DIR_APPUSER_SETUP_BY_ROOT}" "${XDG_DIR_APPUSER_SETUP_BY_ROOT}/gnupg"

    log "GPG key import is now handled during Docker image build. Skipping GPG data copy from host."

    log "Git user.name, user.email, and signingkey are configured for appuser during Docker image build."

    CRON_PID_FILE="/var/run/crond.pid"
    log "Checking cron daemon status..."
    if [ -f "$CRON_PID_FILE" ]; then
        CRON_PID=$(cat "$CRON_PID_FILE")
        if ps -p "$CRON_PID" > /dev/null; then
            log "Cron daemon is already running with PID $CRON_PID."
        else
            log "Stale cron PID file found. Removing $CRON_PID_FILE and attempting to start cron."
            rm -f "$CRON_PID_FILE"
            if /usr/sbin/cron; then
                log "Cron daemon started."
            else
                log "Error: Failed to start cron daemon after removing stale PID file."
            fi
        fi
    else
        log "Cron PID file not found. Attempting to start cron daemon..."
        if /usr/sbin/cron; then
            log "Cron daemon started."
        else
            log "Error: Failed to start cron daemon."
        fi
    fi

    log "Root setup complete. Handing over to CMD: $@"
    if [ "$#" -gt 0 ]; then
        exec "$@"
    else
        log "No specific command provided to entrypoint. Defaulting to 'sleep infinity'."
        exec sleep infinity
    fi
fi 