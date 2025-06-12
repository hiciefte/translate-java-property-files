#!/bin/bash
set -euo pipefail

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

    # Explicitly set HOME for appuser context, ensuring GPG and other tools find their config correctly.
    # While often set correctly by su/cron, being explicit is safer.
    export HOME="/home/appuser"

    APPUSER_UID_FOR_XDG_SETUP=$(id -u) # Current user's UID
    APPUSER_LOGIN_NAME=$(id -un)

    # Define a logger for this specific execution path
    log_appuser_exec() {
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] [Entrypoint/appuser-exec ($APPUSER_LOGIN_NAME)] $1"
    }

    log_appuser_exec "Running as appuser ($(id -u):$(id -g)). Preparing to execute command."
    if [ "$#" -gt 0 ]; then
        log_appuser_exec "Command and arguments to execute:"
        for arg in "$@"; do
            log_appuser_exec "  $arg"
        done
    else
        log_appuser_exec "No command/arguments provided to execute."
    fi

    export XDG_RUNTIME_DIR="/run/user/${APPUSER_UID_FOR_XDG_SETUP}"
    log_appuser_exec "XDG_RUNTIME_DIR set to: $XDG_RUNTIME_DIR"
    mkdir -p "${XDG_RUNTIME_DIR}/gnupg"
    chmod 700 "${XDG_RUNTIME_DIR}" "${XDG_RUNTIME_DIR}/gnupg"

    log_appuser_exec "Setting up GPG agent..."
    GPG_TTY_CMD_OUTPUT=$(tty 2>/dev/null || echo "") # Handle non-tty environments
    export GPG_TTY="$GPG_TTY_CMD_OUTPUT"
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
    gpg_connect_agent_exit_code=0
    gpg-connect-agent /bye &> /dev/null || gpg_connect_agent_exit_code=$?
    if [ $gpg_connect_agent_exit_code -eq 0 ]; then
        log_appuser_exec "gpg-connect-agent /bye successful (Exit Code: $gpg_connect_agent_exit_code). Agent is running."
    else
        log_appuser_exec "gpg-connect-agent /bye failed (Exit Code: $gpg_connect_agent_exit_code). Attempting to start agent explicitly."
        gpg_agent_daemon_exit_code=0
        gpg-agent --homedir ~/.gnupg --daemon --quiet --allow-preset-passphrase || gpg_agent_daemon_exit_code=$?
        if [ $gpg_agent_daemon_exit_code -eq 0 ]; then
            log_appuser_exec "gpg-agent --daemon successful (Exit Code: $gpg_agent_daemon_exit_code)."
        else
            log_appuser_exec "gpg-agent --daemon also failed (Exit Code: $gpg_agent_daemon_exit_code); agent might be running or truly failed."
        fi
    fi

    GPG_AGENT_SOCKET="${XDG_RUNTIME_DIR}/gnupg/S.gpg-agent"
    if [ -S "$GPG_AGENT_SOCKET" ]; then
        log_appuser_exec "GPG agent socket confirmed at $GPG_AGENT_SOCKET."
    else
        log_appuser_exec "Warning: GPG agent socket NOT found at $GPG_AGENT_SOCKET after setup attempts."
    fi
    
    log_appuser_exec "Configuring git based on environment variables..."
    if [ -n "$GIT_AUTHOR_NAME" ]; then
        git config --global user.name "$GIT_AUTHOR_NAME"
        log_appuser_exec "Set git user.name to '$GIT_AUTHOR_NAME'"
    else
        log_appuser_exec "Warning: GIT_AUTHOR_NAME not set. Git user.name may be unset or default."
    fi

    if [ -n "$GIT_AUTHOR_EMAIL" ]; then
        git config --global user.email "$GIT_AUTHOR_EMAIL"
        log_appuser_exec "Set git user.email to '$GIT_AUTHOR_EMAIL'"
    else
        log_appuser_exec "Warning: GIT_AUTHOR_EMAIL not set. Git user.email may be unset or default. GPG verification on GitHub will likely fail."
    fi

    if [ -n "$GIT_SIGNING_KEY" ]; then
        git config --global user.signingkey "$GIT_SIGNING_KEY"
        # Ensure commit.gpgsign is true if a key is provided; it might have been set in Dockerfile already
        git config --global commit.gpgsign true 
        log_appuser_exec "Set git user.signingkey to '$GIT_SIGNING_KEY' and ensured commit.gpgsign is true."
    else
        # If no signing key is provided, explicitly disable GPG signing for commits
        git config --global commit.gpgsign false 
        log_appuser_exec "Warning: GIT_SIGNING_KEY not set. Git commit signing (commit.gpgsign) explicitly set to false."
    fi

    log_appuser_exec "Executing user command..."
    if [ "$#" -gt 0 ]; then
        log_appuser_exec "Command and arguments being executed:"
        for arg in "$@"; do
            log_appuser_exec "  $arg"
        done
        exec "$@"
    else
        log_appuser_exec "No command/arguments provided to execute. Exiting appuser block."
        # Exit successfully as no command was intended to be run by appuser directly
        exit 0
    fi

else
    # --- ROOT EXECUTION BLOCK ---
    log "Starting initial entrypoint setup as root..."

    TARGET_REPO_DIR="/target_repo"
    # Use HTTPS for default initial clone by root if FORK_REPO_URL is not set in .env
    # The script will later change origin to SSH format if FORK_REPO_NAME is set.
    FORK_REPO_URL_FOR_ROOT_CLONE="${FORK_REPO_URL:-https://github.com/hiciefte/bisq2.git}"
    # FORK_REPO_URL from .env (expected to be SSH for appuser) is still respected if provided.
    # If FORK_REPO_URL is set in .env, that's what root will attempt to use for clone.
    # The primary variable for operations is FORK_REPO_URL.
    # If FORK_REPO_URL is NOT set, then FORK_REPO_URL_FOR_ROOT_CLONE provides an HTTPS default.

    # Determine the effective UPSTREAM_REPO_URL for root operations (prefer HTTPS)
    # As of recent changes, UPSTREAM_REPO_URL from .env is expected to be HTTPS.
    # The default in the script also reflects this.
    ACTUAL_UPSTREAM_URL_FOR_ROOT="${UPSTREAM_REPO_URL:-https://github.com/bisq-network/bisq2.git}"
    log "Using upstream URL for root operations: $ACTUAL_UPSTREAM_URL_FOR_ROOT"

    FORK_REPO_NAME="${FORK_REPO_NAME:-hiciefte/bisq2}" # Used for setting SSH remote URL

    APPUSER_UID=${HOST_UID:-1000}
    APPUSER_GID=${HOST_GID:-1000}

    log "Container running as $(id -u):$(id -g) (expected root)."
    log "Target appuser UID: $APPUSER_UID, GID: $APPUSER_GID (from HOST_UID/HOST_GID env vars)."
    log "Fork Repo URL: $FORK_REPO_URL_FOR_ROOT_CLONE"
    log "Upstream Repo URL (for root ops): $ACTUAL_UPSTREAM_URL_FOR_ROOT"
    log "Fork Repo Name for SSH: $FORK_REPO_NAME"

    mkdir -p "$TARGET_REPO_DIR"

    # Configure SSH for root user to accept new host keys automatically for git clone
    log "Configuring SSH for root to auto-accept GitHub host key..."
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    echo -e "Host github.com\\n  StrictHostKeyChecking no\\n  UserKnownHostsFile=/dev/null" > /root/.ssh/config
    chmod 600 /root/.ssh/config
    log "SSH configured for root."

    # System-wide configuration to trust the target repository directory, done by root.
    # This should be done *before* any git operations are attempted in that directory by root.
    log "Adding $TARGET_REPO_DIR to system-wide Git safe.directory configuration..."
    git config --system --add safe.directory "$TARGET_REPO_DIR"
    log "System-wide Git safe.directory configuration updated."

    if [ -d "$TARGET_REPO_DIR/.git" ]; then
        log "Target directory $TARGET_REPO_DIR already contains a .git folder. Configuring remotes and updating..."
        cd "$TARGET_REPO_DIR"
        # (global call removed in favor of system-wide configuration above)
        # git config --global --add safe.directory "$TARGET_REPO_DIR" || log "Warning: Failed to add safe.directory to root's global git config."

        # Use the FORK_REPO_URL from .env (expected to be SSH) for an existing repo check
        # or the FORK_REPO_NAME to construct the SSH URL.
        EXPECTED_ORIGIN_SSH_URL="git@github.com:${FORK_REPO_NAME}.git"
        CURRENT_FORK_URL_TO_CHECK="${FORK_REPO_URL:-$EXPECTED_ORIGIN_SSH_URL}"

        current_origin_url=$(git remote get-url origin 2>/dev/null || echo "")
        if [ "$current_origin_url" = "$CURRENT_FORK_URL_TO_CHECK" ]; then
            log "Origin remote already correctly set to $CURRENT_FORK_URL_TO_CHECK"
        elif [ "$current_origin_url" = "$EXPECTED_ORIGIN_SSH_URL" ]; then
            log "Origin remote already correctly set to SSH URL $EXPECTED_ORIGIN_SSH_URL"
        else
            log "Setting origin remote to $CURRENT_FORK_URL_TO_CHECK"
            git remote set-url origin "$CURRENT_FORK_URL_TO_CHECK" || git remote add origin "$CURRENT_FORK_URL_TO_CHECK"
        fi
        
        current_upstream_url=$(git remote get-url upstream 2>/dev/null || echo "")
        if [ "$current_upstream_url" = "$ACTUAL_UPSTREAM_URL_FOR_ROOT" ]; then
            log "Upstream remote already correctly set to $ACTUAL_UPSTREAM_URL_FOR_ROOT"
        else
            log "Setting upstream remote to $ACTUAL_UPSTREAM_URL_FOR_ROOT"
            git remote add upstream "$ACTUAL_UPSTREAM_URL_FOR_ROOT" || git remote set-url upstream "$ACTUAL_UPSTREAM_URL_FOR_ROOT"
        fi

        log "Fetching all from origin and upstream..."
        git fetch origin --prune || log "Warning: Git fetch origin failed."
        git fetch upstream --prune || log "Warning: Git fetch upstream failed."

        log "Checking out main branch and resetting to upstream/main..."
        current_branch=$(git branch --show-current || echo "")
        if [ "$current_branch" != "main" ]; then
            git checkout main || git checkout -b main origin/main
        fi
        git reset --hard upstream/main || log "Warning: Failed to reset main to upstream/main."
        
        log "Updating submodules based on upstream/main..."
        git submodule sync --recursive || log "Warning: git submodule sync failed."
        git submodule update --init --recursive || log "Warning: git submodule update failed."

        # Ensure origin URL is SSH for appuser pushes, even if it was an existing repo
        if [ -n "$FORK_REPO_NAME" ]; then
            FORK_REPO_SSH_URL="git@github.com:${FORK_REPO_NAME}.git"
            if [ "$(git remote get-url origin)" != "$FORK_REPO_SSH_URL" ]; then
                log "Changing origin remote URL to SSH: $FORK_REPO_SSH_URL for existing $TARGET_REPO_DIR"
                git remote set-url origin "$FORK_REPO_SSH_URL"
                log "Origin remote URL set to SSH."
            fi
        else
            log "Warning: FORK_REPO_NAME not set. Cannot ensure origin URL is SSH for existing repo. Push might fail for appuser."
        fi

        echo "[Entrypoint] /target_repo/.git exists. Fetching updates..."
        cd "$TARGET_REPO_DIR" || exit
        echo "[Entrypoint] Current commit before fetch:"
        git rev-parse HEAD
        git fetch upstream
        git reset --hard upstream/main
        echo "[Entrypoint] Current commit after reset to upstream/main:"
        git rev-parse HEAD
        echo "[Entrypoint] Verifying contents of i18n/src/main/resources post-update:"
        ls -la i18n/src/main/resources
        cd /

    else
        # For initial clone by root, use FORK_REPO_URL_FOR_ROOT_CLONE if FORK_REPO_URL is not set.
        # If FORK_REPO_URL is set in .env (e.g. to an SSH URL), it will be used here.
        # If FORK_REPO_URL is *not* set, then the HTTPS default FORK_REPO_URL_FOR_ROOT_CLONE is used.
        ACTUAL_CLONE_URL="${FORK_REPO_URL:-$FORK_REPO_URL_FOR_ROOT_CLONE}"
        log "Target directory $TARGET_REPO_DIR is empty or not a git repository. Cloning $ACTUAL_CLONE_URL as origin..."
        
        # Capture output and exit status of git clone
        clone_output=""
        clone_exit_code=0
        if ! clone_output=$(git clone --recurse-submodules "$ACTUAL_CLONE_URL" "$TARGET_REPO_DIR" 2>&1); then
            clone_exit_code=$?
            log "Error: Failed to clone repository $ACTUAL_CLONE_URL into $TARGET_REPO_DIR (Exit Code: $clone_exit_code)."
            log "Clone command output was:"
            echo "$clone_output"
            exit $clone_exit_code
        fi
        log "Clone successful. Output:"
        echo "$clone_output"

        cd "$TARGET_REPO_DIR"
        # (global call removed in favor of system-wide configuration above)
        # git config --global --add safe.directory "$TARGET_REPO_DIR" || log "Warning: Failed to add safe.directory to root's global git config."

        log "Adding upstream remote $ACTUAL_UPSTREAM_URL_FOR_ROOT..."
        git remote add upstream "$ACTUAL_UPSTREAM_URL_FOR_ROOT"
        if [ $? -ne 0 ]; then
            log "Warning: Failed to add upstream remote. It might already exist. Attempting set-url."
            git remote set-url upstream "$ACTUAL_UPSTREAM_URL_FOR_ROOT" || log "Warning: Failed to set-url for upstream remote either."
        fi
        log "Fetching upstream and setting local main to upstream/main..."
        git fetch upstream --prune
        current_branch=$(git branch --show-current || echo "")
        if [ "$current_branch" != "main" ]; then
            git checkout main || git checkout -b main origin/main
        fi
        git reset --hard upstream/main
        git submodule sync --recursive
        git submodule update --init --recursive
        log "Repository cloned, upstream configured, and main branch aligned with upstream/main."

        if [ -n "$FORK_REPO_NAME" ]; then
            FORK_REPO_SSH_URL="git@github.com:${FORK_REPO_NAME}.git"
            log "Changing origin remote URL to SSH: $FORK_REPO_SSH_URL for $TARGET_REPO_DIR"
            git remote set-url origin "$FORK_REPO_SSH_URL"
            log "Origin remote URL set to SSH."
        else
            log "Warning: FORK_REPO_NAME not set in environment. Cannot change origin URL to SSH. Push will likely use HTTPS."
        fi

        echo "[Entrypoint] /target_repo/.git exists. Fetching updates..."
        cd "$TARGET_REPO_DIR" || exit
        echo "[Entrypoint] Current commit before fetch:"
        git rev-parse HEAD
        git fetch upstream
        git reset --hard upstream/main
        echo "[Entrypoint] Current commit after reset to upstream/main:"
        git rev-parse HEAD
        echo "[Entrypoint] Verifying contents of i18n/src/main/resources post-update:"
        ls -la i18n/src/main/resources
        cd /
    fi

    log "Final check and setting of system-wide Git safe.directory for $TARGET_REPO_DIR (if not already caught above)"
    git config --system --get safe.directory | grep -qF "$TARGET_REPO_DIR" || git config --system --add safe.directory "$TARGET_REPO_DIR"

    cd /app

    log "Changing ownership of $TARGET_REPO_DIR to $APPUSER_UID:$APPUSER_GID..."
    chown -R "$APPUSER_UID":"$APPUSER_GID" "$TARGET_REPO_DIR"
    if [ $? -ne 0 ]; then
        log "Warning: Failed to chown $TARGET_REPO_DIR to appuser. This is likely the cause of permission issues."
    else
        log "chown completed on $TARGET_REPO_DIR."
        log "Permissions in $TARGET_REPO_DIR after chown by root:"
        ls -la "$TARGET_REPO_DIR"
        log "Permissions in $TARGET_REPO_DIR/.git after chown by root:"
        ls -la "$TARGET_REPO_DIR/.git"
    fi

    XDG_DIR_APPUSER_SETUP_BY_ROOT="/run/user/${APPUSER_UID}" # Used for root setup
    log "Preparing XDG_RUNTIME_DIR for appuser (by root): $XDG_DIR_APPUSER_SETUP_BY_ROOT"
    mkdir -p "${XDG_DIR_APPUSER_SETUP_BY_ROOT}/gnupg"
    chown -R "${APPUSER_UID}:${APPUSER_GID}" "${XDG_DIR_APPUSER_SETUP_BY_ROOT}"
    chmod -R 700 "${XDG_DIR_APPUSER_SETUP_BY_ROOT}"
    log "Set ownership of ${XDG_DIR_APPUSER_SETUP_BY_ROOT} to ${APPUSER_UID}:${APPUSER_GID} and permissions to 700."
    ls -ld "${XDG_DIR_APPUSER_SETUP_BY_ROOT}" "${XDG_DIR_APPUSER_SETUP_BY_ROOT}/gnupg"

    log "GPG key import is now handled during Docker image build. Skipping GPG data copy from host."
    log "Git user.name, user.email, and signingkey are configured for appuser by this script if run as appuser, or by Dockerfile build args."

    # Ensure /app/logs directory exists and is writable by appuser
    LOGS_DIR="/app/logs"
    log "Ensuring log directory $LOGS_DIR exists and is writable by $APPUSER_UID:$APPUSER_GID..."
    mkdir -p "$LOGS_DIR"
    chown "${APPUSER_UID}:${APPUSER_GID}" "$LOGS_DIR"
    chmod 755 "$LOGS_DIR" # Ensure appuser can write, and others can read/execute (needed for directory listing)
    log "Log directory $LOGS_DIR prepared."
    ls -ld "$LOGS_DIR"

    # Ensure cron daemon is started
    CRON_PID_FILE="/var/run/cron.pid" # Corrected PID file for Debian/Ubuntu
    log "Checking cron daemon status (PID file: $CRON_PID_FILE)..."
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

    log "Root setup complete. Determining CMD to hand over to."
    if [ "$#" -gt 0 ]; then
        log "CMD from Docker/compose and arguments:"
        for arg in "$@"; do
            log "  $arg"
        done
        log "Handing off execution to appuser..."
        exec /usr/sbin/gosu appuser /app/docker/docker-entrypoint.sh "$@"
    else
        log "No specific command provided to entrypoint. Defaulting to 'sleep infinity'."
        exec sleep infinity
    fi
fi 