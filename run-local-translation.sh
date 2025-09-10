#!/bin/bash
set -euo pipefail

# This script runs the translation process locally using a virtual environment.
# It's intended for development and testing purposes.
#
# Usage:
#   ./run-local-translation.sh [path/to/config.yaml]
#
# If no config file path is provided, it defaults to 'config.yaml'.

# --- Configuration & Path Setup ---
# The script determines the project root and changes into it.
PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd "$PROJECT_ROOT"

VENV_DIR="$PROJECT_ROOT/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
PIP_SYNC_BIN="$VENV_DIR/bin/pip-sync"

# Use the first argument as the config file path, or default to 'config.yaml'.
CONFIG_FILE="${1:-config.yaml}"

echo "[info] Using configuration file: $CONFIG_FILE"

# Make the config file path available to the Python script.
export TRANSLATOR_CONFIG_FILE="$CONFIG_FILE"

# Helper function to parse simple key: value pairs from the YAML config file.
get_yaml_value() {
    local key="$1"
    # Use POSIX compliant character classes for grep/sed for better portability.
    grep -E "^[[:space:]]*${key}:[[:space:]]*" "$CONFIG_FILE" | \
    sed -E "s/^[[:space:]]*${key}:[[:space:]]*'([^']*)'?([[:space:]]*#.*)?$/\1/" | \
    sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' # Trim leading/trailing whitespace
}

# Read the optional glob filter from the config and export it for the Python script
TRANSLATION_FILTER_GLOB="$(get_yaml_value "translation_file_filter_glob" || echo "")"
if [ -n "$TRANSLATION_FILTER_GLOB" ] && [ "$TRANSLATION_FILTER_GLOB" != "null" ]; then
  export TRANSLATION_FILTER_GLOB
fi

# --- Pre-flight Checks ---
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[error] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "[error] Python virtual environment not found at '$VENV_DIR'."
    echo "[info] Please run the setup script first: ./setup.sh"
    exit 1
fi

# Ensure Python dependencies are in sync
echo "[info] Verifying Python dependencies..."
if ! "$PIP_SYNC_BIN" "requirements-dev.txt" --quiet; then
    echo "[error] Dependencies are out of sync. Please run './setup.sh' again."
    exit 1
fi

TARGET_ROOT="$(get_yaml_value "target_project_root" || echo "")"
INPUT_FOLDER="$(get_yaml_value "input_folder" || echo "")"

if [ -z "$TARGET_ROOT" ] || [ -z "$INPUT_FOLDER" ]; then
    echo "[error] 'target_project_root' or 'input_folder' not defined in $CONFIG_FILE"
    exit 1
fi

if [ ! -d "$TARGET_ROOT" ] || [ ! -d "$INPUT_FOLDER" ]; then
    echo "[error] Target project root or input folder not found. Check paths in $CONFIG_FILE"
    echo "  - target_project_root: $TARGET_ROOT"
    echo "  - input_folder: $INPUT_FOLDER"
    exit 1
fi

# --- Script Execution ---
echo "[info] Starting translation process..."
exec "$VENV_PYTHON" -m src.translate_localization_files


