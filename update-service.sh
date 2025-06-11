#!/bin/bash
#
# Update script for the Translate Java Property Files service.
# This script pulls the latest changes from Git, rebuilds the Docker image
# if necessary, restarts the systemd service, and handles rollbacks on failure.
#

# --- Strict Mode & Error Handling ---
set -Euo pipefail # Same as set -e -E -u -o pipefail
trap 'handle_error ${LINENO} "$BASH_COMMAND"' ERR >&2 # Global error trap

# --- Configuration ---
# Determine the absolute path of the script and the installation directory
SCRIPT_DIR_REAL=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INSTALL_DIR=${TRANSLATOR_INSTALL_DIR:-$SCRIPT_DIR_REAL} # Default to script's directory

COMPOSE_FILE_NAME="docker-compose.yml"
COMPOSE_FILE_PATH="$INSTALL_DIR/docker/$COMPOSE_FILE_NAME"
# Docker Compose automatically picks up .env in the same dir as the compose file for build args & runtime envs
# For systemd, it's explicitly passed.

SYSTEMD_SERVICE_NAME="translator.service"
DOCKER_SERVICE_NAME="translator" # As defined in docker-compose.yml

# Log and state directories for the update script
UPDATE_LOG_ROOT_DIR="$INSTALL_DIR/logs/update_service" # Main log dir for this script
FAILED_UPDATES_DIR="$UPDATE_LOG_ROOT_DIR/failed_updates" # For storing state on rollback

HEALTH_CHECK_RETRIES=6 # Total attempts (e.g., 6 * 10s = 1 min)
HEALTH_CHECK_INTERVAL=10 # seconds

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Logging Functions ---
# Usage: log_message "My message" [INFO|WARNING|ERROR]
log_message() {
    local message="$1"
    local level="${2:-INFO}"
    local color="$NC"
    local timestamp

    timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    case "$level" in
        INFO) color="$GREEN" ;;
        WARNING) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        DEBUG) color="$BLUE" ;; # For script's own debug messages
    esac
    echo -e "${color}[$timestamp] [$level] ${message}${NC}" >&2
}

# --- Error Handling Function ---
handle_error() {
    local line_number=$1
    local command=$2
    local script_name
    script_name=$(basename "${BASH_SOURCE[0]}")
    log_message "Error on or near line ${line_number} in ${script_name}: Command '${command}' failed." "ERROR"
    # Rollback will be attempted if PREV_HEAD is set and a FAILED_DIR is created by save_state_for_rollback
    if [[ -n "${PREV_HEAD:-}" && -n "${CURRENT_FAILED_DIR:-}" ]]; then
        log_message "Attempting rollback due to error." "ERROR"
        # shellcheck disable=SC2153 # PREV_HEAD is set before this can be called in update path
        rollback_to_previous_version "$PREV_HEAD" "$CURRENT_FAILED_DIR" "Error during update process (command: $command)"
    else
        log_message "PREV_HEAD or CURRENT_FAILED_DIR not set. Cannot automatically roll back. Manual intervention required." "ERROR"
    fi
    exit 1
}


# --- Prerequisite Checks ---
check_prerequisites() {
    log_message "Checking prerequisites..." "DEBUG"
    local missing_cmds=0
    for cmd in git docker jq curl sudo; do
        if ! command -v "$cmd" &> /dev/null; then
            log_message "$cmd is not installed or not in PATH." "ERROR"
            missing_cmds=$((missing_cmds + 1))
        fi
    done

    if ! docker compose version &> /dev/null; then
        log_message "Docker Compose plugin is not available or not working." "ERROR"
        missing_cmds=$((missing_cmds + 1))
    fi

    if [[ $missing_cmds -gt 0 ]]; then
        log_message "Please install missing prerequisites and try again." "ERROR"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_message "Docker daemon is not running. Please start Docker." "ERROR"
        exit 1
    fi
    log_message "Prerequisites check passed." "INFO"
}

# --- Docker and System Operations ---
perform_system_operation() {
    local operation="$1" # 'stop', 'start', 'restart', 'is-active', 'status'
    local service="$2"
    log_message "Performing sudo systemctl $operation $service..." "INFO"
    # shellcheck disable=SC2086 # We want word splitting for $SUDO_CMD if it's empty
    if sudo systemctl "$operation" "$service"; then
        log_message "sudo systemctl $operation $service completed successfully." "INFO"
        return 0
    else
        log_message "sudo systemctl $operation $service failed." "ERROR"
        # Try to get more status info on failure
        sudo systemctl status "$service" --no-pager -l || true
        return 1
    fi
}

perform_docker_build() {
    log_message "Starting Docker image build (context: $INSTALL_DIR)..." "INFO"
    # docker-compose.yml is in docker/ and has build: context: ..
    # docker/.env will be picked up automatically by docker-compose for build-args.
    if docker compose -f "$COMPOSE_FILE_PATH" build --pull "$DOCKER_SERVICE_NAME"; then
        log_message "Docker image build completed successfully." "INFO"
        return 0
    else
        log_message "Docker image build failed." "ERROR"
        return 1
    fi
}

# --- Health Check ---
# Tries to get the Docker container ID for the service
get_service_container_id() {
    local service_name="$1"
    # This assumes docker compose assigns a predictable name or we can find it
    # Format: <project>_<service>_1. Project name is usually the directory of compose file.
    # Since compose file is in 'docker/', project name is 'docker'.
    # Safer: docker compose ps -q <service_name>
    docker compose -f "$COMPOSE_FILE_PATH" ps -q "$service_name" 2>/dev/null || echo ""
}

check_service_health() {
    log_message "Performing health checks for $SYSTEMD_SERVICE_NAME..." "INFO"
    local retries=$HEALTH_CHECK_RETRIES
    while [[ $retries -gt 0 ]]; do
        if ! sudo systemctl is-active --quiet "$SYSTEMD_SERVICE_NAME"; then
            log_message "$SYSTEMD_SERVICE_NAME is not active." "WARNING"
            sleep "$HEALTH_CHECK_INTERVAL"
            retries=$((retries - 1))
            continue
        fi
        log_message "$SYSTEMD_SERVICE_NAME is active." "INFO"

        local container_id
        container_id=$(get_service_container_id "$DOCKER_SERVICE_NAME")

        if [[ -z "$container_id" ]]; then
            log_message "Could not find container ID for service $DOCKER_SERVICE_NAME." "WARNING"
            sleep "$HEALTH_CHECK_INTERVAL"
            retries=$((retries - 1))
            continue
        fi

        local container_status
        container_status=$(docker ps -f "id=$container_id" --format "{{.Status}}" 2>/dev/null || echo "Not found")
        if [[ "$container_status" =~ ^Up ]]; then
            log_message "Docker container for $DOCKER_SERVICE_NAME (ID: $container_id) is Up (Status: '$container_status')." "INFO"
            # Add a small delay for services to fully initialize if needed
            log_message "Giving service a few seconds to settle..." "DEBUG"
            sleep 5
            # Optional: Check for a specific log message in container or deployment_log.log
            # Example: docker logs "$container_id" --tail 20 | grep "Entrypoint script completed successfully"
            # For now, systemd active and container Up is considered healthy enough for the script.
            log_message "Health check passed for $SYSTEMD_SERVICE_NAME." "INFO"
            return 0
        else
            log_message "Docker container for $DOCKER_SERVICE_NAME (ID: $container_id) is not Up. Status: '$container_status'." "WARNING"
        fi

        log_message "Health check attempt failed. Retries left: $retries. Waiting $HEALTH_CHECK_INTERVAL seconds..." "WARNING"
        sleep "$HEALTH_CHECK_INTERVAL"
        retries=$((retries - 1))
    done

    log_message "Health check failed for $SYSTEMD_SERVICE_NAME after $HEALTH_CHECK_RETRIES attempts." "ERROR"
    sudo systemctl status "$SYSTEMD_SERVICE_NAME" --no-pager -l || true
    local final_container_id
    final_container_id=$(get_service_container_id "$DOCKER_SERVICE_NAME")
    if [[ -n "$final_container_id" ]]; then
      docker logs "$final_container_id" --tail 50 || true
    fi
    return 1
}

# --- Rollback Function ---
save_state_for_rollback() {
    local reason="$1"
    local failed_date
    failed_date=$(date "+%Y%m%d_%H%M%S")
    CURRENT_FAILED_DIR="$FAILED_UPDATES_DIR/$failed_date" # Set global for error handler
    mkdir -p "$CURRENT_FAILED_DIR"

    log_message "Saving current state for debugging to $CURRENT_FAILED_DIR..." "INFO"
    {
        echo "Failure Timestamp: $(date)"
        echo "Failure Reason: $reason"
        echo "Current Git Hash (at time of failure): $(git rev-parse HEAD || echo 'N/A')"
        echo "Attempting to roll back to Git Hash: ${PREV_HEAD:-'N/A'}"
        echo "Working Directory: $(pwd)"
        echo -e "\nGit Status:"
        git status || true
        echo -e "\nLast Git Logs (current branch):"
        git log -n 5 --oneline || true
        echo -e "\nSystemd Service Status ($SYSTEMD_SERVICE_NAME):"
        sudo systemctl status "$SYSTEMD_SERVICE_NAME" --no-pager -l || echo "Failed to get systemd status"
        echo -e "\nDocker Compose PS:"
        docker compose -f "$COMPOSE_FILE_PATH" ps || echo "Failed to get docker compose ps"
        echo -e "\nDocker Logs ($DOCKER_SERVICE_NAME) (last 100 lines):"
        local container_id_for_log
        container_id_for_log=$(get_service_container_id "$DOCKER_SERVICE_NAME")
        if [[ -n "$container_id_for_log" ]]; then
            docker logs "$container_id_for_log" --tail 100 || echo "Failed to get docker logs"
        else
            echo "Container for $DOCKER_SERVICE_NAME not found for log capture."
        fi
    } > "$CURRENT_FAILED_DIR/rollback_info.txt" 2>&1

    log_message "Current state saved. See $CURRENT_FAILED_DIR/rollback_info.txt" "INFO"
}

rollback_to_previous_version() {
    local target_prev_head="$1"
    local failed_dir_path="$2" # Already created by save_state_for_rollback or error handler
    local reason="$3"

    log_message "ROLLBACK INITIATED to Git HEAD $target_prev_head due to: $reason" "ERROR"

    if [[ ! -d "$failed_dir_path" ]]; then
        log_message "Failed directory $failed_dir_path not found. Cannot ensure logs are saved there." "ERROR"
    fi

    perform_system_operation "stop" "$SYSTEMD_SERVICE_NAME" || log_message "Failed to stop $SYSTEMD_SERVICE_NAME during rollback. Continuing..." "WARNING"

    log_message "Resetting Git repository to $target_prev_head..." "INFO"
    if ! git reset --hard "$target_prev_head"; then
        log_message "CRITICAL: git reset --hard to $target_prev_head failed. Manual intervention required." "ERROR"
        log_message "Rollback aborted. State saved in $failed_dir_path" "ERROR"
        exit 2
    fi
    log_message "Git repository reset to $target_prev_head." "INFO"

    log_message "Rebuilding Docker image for the rolled-back version..." "INFO"
    if ! perform_docker_build; then # This will build the version from target_prev_head
        log_message "CRITICAL: Docker build failed for rolled-back version. Manual intervention required." "ERROR"
        log_message "Rollback aborted after git reset. State saved in $failed_dir_path" "ERROR"
        exit 2
    fi

    log_message "Starting systemd service with rolled-back version..." "INFO"
    if ! perform_system_operation "start" "$SYSTEMD_SERVICE_NAME"; then
        log_message "CRITICAL: Failed to start $SYSTEMD_SERVICE_NAME with rolled-back version. Manual intervention required." "ERROR"
        log_message "Rollback aborted after build. State saved in $failed_dir_path" "ERROR"
        exit 2
    fi

    log_message "Verifying service health after rollback..." "INFO"
    if ! check_service_health; then
        log_message "CRITICAL: Health check failed after rollback. Manual intervention required." "ERROR"
        log_message "Service might be unstable. State saved in $failed_dir_path" "ERROR"
        exit 2
    fi

    log_message "ROLLBACK COMPLETED successfully to Git HEAD $target_prev_head." "INFO"
    log_message "Details of the failed update attempt are in: $failed_dir_path" "WARNING"
    exit 1 # Exit with error code to indicate original update failed but rollback succeeded.
}

# --- Change Detection Functions ---
# Files/dirs that, if changed, require a full Docker image rebuild.
REBUILD_TRIGGER_FILES=(
    "docker/Dockerfile"
    "requirements.txt"
    "src/" # Trailing slash implies directory and its contents
    "docker/docker-entrypoint.sh"
    "update-translations.sh" # Copied into image
    "docker/translator-cron" # Copied into image
)

# Files/dirs that, if changed, require a service restart (if not a full rebuild).
# These are typically mounted configuration files.
RESTART_TRIGGER_FILES=(
    "docker/config.docker.yaml" # Mounted as /app/config.yaml
    "glossary.json"             # Mounted as /app/glossary.json
    "docker/.env"               # If runtime env vars are set in compose from this
    "docker/docker-compose.yml" # For runtime changes (ports, volumes, env vars not from file)
)

# Checks if changes between two commits require a Docker image rebuild.
# Usage: needs_rebuild "commit1_hash" "commit2_hash"
needs_rebuild() {
    local head1="$1"
    local head2="$2"
    log_message "Checking for changes requiring rebuild between $head1 and $head2..." "DEBUG"
    for pattern in "${REBUILD_TRIGGER_FILES[@]}"; do
        if git diff --name-only "$head1" "$head2" -- "$pattern" | grep -q .; then
            log_message "Changes detected in '$pattern' requiring rebuild." "INFO"
            return 0 # True, needs rebuild
        fi
    done
    log_message "No changes requiring rebuild found." "DEBUG"
    return 1 # False
}

# Checks if changes between two commits require a service restart (and not a full rebuild).
# Usage: needs_restart_for_config_changes "commit1_hash" "commit2_hash"
needs_restart_for_config_changes() {
    local head1="$1"
    local head2="$2"
    log_message "Checking for config changes requiring restart between $head1 and $head2..." "DEBUG"
    for pattern in "${RESTART_TRIGGER_FILES[@]}"; do
        if git diff --name-only "$head1" "$head2" -- "$pattern" | grep -q .; then
            log_message "Changes detected in '$pattern' requiring service restart." "INFO"
            return 0 # True, needs restart
        fi
    done
    log_message "No config changes requiring restart found." "DEBUG"
    return 1 # False
}


# --- Main Script Logic ---
main() {
    log_message "Starting Update Script for Translate Java Property Files Service" "INFO"
    log_message "Installation Directory: $INSTALL_DIR" "INFO"

    mkdir -p "$UPDATE_LOG_ROOT_DIR"
    mkdir -p "$FAILED_UPDATES_DIR"

    check_prerequisites

    # Check if running with sufficient privileges for systemctl and docker (if not in docker group)
    if [[ "$EUID" -ne 0 ]]; then
      if ! id -nG "$USER" | grep -qw "docker"; then
        log_message "This script needs to run as root or by a user in the 'docker' group, and with sudo access for systemctl." "WARNING"
        log_message "Attempting to use 'sudo' for docker and systemctl commands." "WARNING"
      else
        log_message "User is in 'docker' group. Will use 'sudo' only for systemctl." "INFO"
      fi
    else
      log_message "Running as root." "INFO"
    fi


    cd "$INSTALL_DIR" || { log_message "Failed to change to installation directory: $INSTALL_DIR" "ERROR"; exit 1; }
    log_message "Current working directory: $(pwd)" "INFO"

    if [[ ! -d ".git" ]]; then
        log_message "This is not a Git repository: $INSTALL_DIR" "ERROR"
        exit 1
    fi

    log_message "Checking for local changes..." "INFO"
    local STASHED_CHANGES=false
    if ! git diff-index --quiet HEAD --; then
        log_message "Local uncommitted changes detected. Stashing..." "INFO"
        if git stash push -u -m "Auto-stash by update-service.sh: $(date)"; then
            STASHED_CHANGES=true
            log_message "Local changes stashed." "INFO"
        else
            log_message "Failed to stash local changes. Please commit or resolve them manually." "ERROR"
            exit 1
        fi
    else
        log_message "No local changes detected." "INFO"
    fi

    PREV_HEAD=$(git rev-parse HEAD)
    log_message "Current Git HEAD before pull: $PREV_HEAD" "INFO"

    log_message "Pulling latest changes from Git remote..." "INFO"
    if ! git pull; then
        log_message "git pull failed. Check network connection or repository access." "ERROR"
        if $STASHED_CHANGES; then
            log_message "Attempting to restore stashed changes..." "INFO"
            git stash pop || log_message "Failed to pop stash. 'git stash list' to see stashes." "WARNING"
        fi
        exit 1 # Specific error from git pull, not triggering full error trap rollback yet
    fi

    local CURRENT_HEAD
    CURRENT_HEAD=$(git rev-parse HEAD)
    log_message "Git HEAD after pull: $CURRENT_HEAD" "INFO"

    if [[ "$PREV_HEAD" == "$CURRENT_HEAD" ]]; then
        log_message "Already up to date. No new changes pulled." "INFO"
        if $STASHED_CHANGES; then
            log_message "Restoring stashed changes..." "INFO"
            if ! git stash pop; then
                 log_message "Failed to pop stash. There might be conflicts or stash was empty. Check with 'git stash list'." "WARNING"
            fi
        fi
        log_message "Update script finished. No action required." "INFO"
        exit 0
    fi

    log_message "Changes pulled successfully. Analyzing..." "INFO"
    git log --oneline --no-merges --max-count=10 "${PREV_HEAD}..${CURRENT_HEAD}" || true


    local rebuild_is_needed=false
    if needs_rebuild "$PREV_HEAD" "$CURRENT_HEAD"; then
        rebuild_is_needed=true
    fi

    local restart_for_config_is_needed=false
    if ! $rebuild_is_needed && needs_restart_for_config_changes "$PREV_HEAD" "$CURRENT_HEAD"; then
        restart_for_config_is_needed=true
    fi

    if $STASHED_CHANGES; then
        log_message "Attempting to restore stashed changes before potential build/restart..." "INFO"
        if ! git stash pop; then
            log_message "CRITICAL: Failed to pop stash after pulling changes. Conflicts likely." "ERROR"
            log_message "Please resolve conflicts in $INSTALL_DIR manually and then re-run the update." "ERROR"
            log_message "Alternatively, reset with 'git reset --hard $PREV_HEAD' and clean with 'git stash drop' if the stash is problematic." "ERROR"
            # No automatic rollback here as the working tree is dirty with conflicts.
            exit 1
        fi
        log_message "Stashed changes restored." "INFO"
    fi

    # --- Perform Update ---
    # Initialize CURRENT_FAILED_DIR here so it's available to error trap if subsequent commands fail
    # This variable will be properly populated by save_state_for_rollback if an error occurs in a block
    # that calls it. The global error trap (handle_error) will use it.
    CURRENT_FAILED_DIR=""


    if $rebuild_is_needed; then
        log_message "Rebuild required. Stopping service, building image, starting service." "INFO"
        save_state_for_rollback "Preparing for rebuild" # Sets CURRENT_FAILED_DIR
        perform_system_operation "stop" "$SYSTEMD_SERVICE_NAME"
        perform_docker_build
        perform_system_operation "start" "$SYSTEMD_SERVICE_NAME"
    elif $restart_for_config_is_needed; then
        log_message "Configuration changes detected. Restarting service." "INFO"
        save_state_for_rollback "Preparing for service restart due to config change" # Sets CURRENT_FAILED_DIR
        perform_system_operation "restart" "$SYSTEMD_SERVICE_NAME"
    else
        log_message "No changes requiring rebuild or restart detected." "INFO"
        log_message "Update script finished." "INFO"
        exit 0 # Successfully updated non-critical files
    fi

    log_message "Update action performed. Performing health check..." "INFO"
    if ! check_service_health; then
        # save_state_for_rollback was already called before the action
        # The error trap for check_service_health will call handle_error, which then calls rollback
        log_message "Health check failed after update. Error handler will attempt rollback." "ERROR"
        # This explicit error is to ensure the script exits non-zero if trap doesn't catch it.
        # The trap should catch it.
        exit 1 # Should be caught by trap which initiates rollback
    fi

    log_message "Update completed successfully. Service is healthy." "INFO"
    exit 0
}

# --- Script Entry Point ---
# Call main function and redirect stdout (but not stderr, which log_message uses) to a log file
# This is a simple way to log stdout; more advanced would be tee or processing output.
# Stderr (our logs) will go to console and also to any redirection of the script's stderr.
main "$@" # Pass all arguments to main, though it doesn't use them currently

# End of script 