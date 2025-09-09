#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT_DIR"

CONFIG_FILE="$PROJECT_ROOT_DIR/config-mobile.yaml"
PYTHON_BIN="python3"
VENV_DIR="$PROJECT_ROOT_DIR/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
PIP_SYNC_BIN="$VENV_DIR/bin/pip-sync"

usage() {
  echo "Usage: $0 [--check] [--no-sync]" 1>&2
  echo "  --check    Run preflight checks only (no install/run)" 1>&2
  echo "  --no-sync  Skip dependency sync (use existing venv packages)" 1>&2
}

ONLY_CHECK=false
SKIP_SYNC=false
for arg in "$@"; do
  case "$arg" in
    --check) ONLY_CHECK=true ;;
    --no-sync) SKIP_SYNC=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" 1>&2; usage; exit 2 ;;
  esac
done

echo "[info] Project root: $PROJECT_ROOT_DIR"

# Python version check (>= 3.11)
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[error] python3 not found in PATH" 1>&2
  exit 1
fi
PY_VER_STR=$($PYTHON_BIN -V 2>&1 | awk '{print $2}')
PY_MAJOR=$(echo "$PY_VER_STR" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER_STR" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
  echo "[error] Python >= 3.11 is required (found $PY_VER_STR)" 1>&2
  exit 1
fi

# Config checks
if [ ! -f "$CONFIG_FILE" ]; then
  echo "[error] Missing $CONFIG_FILE" 1>&2
  exit 1
fi

# Extract key paths from config.yaml (strip inline comments and surrounding quotes)
get_yaml_value() {
  local key="$1"
  local line val
  if command -v yq >/dev/null 2>&1; then
    yq -r ".${key} // empty" "$CONFIG_FILE"
    return
  fi
  line=$(grep -E "^[[:space:]]*${key}[[:space:]]*:" "$CONFIG_FILE" | head -1 || true)
  [ -z "$line" ] && return 1
  # Remove inline comments
  line="${line%%#*}"
  # Extract value after first colon
  val="${line#*:}"
  # Trim whitespace
  val="$(printf '%s' "$val" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  # Remove surrounding single/double quotes if present using Bash parameter ops
  if [[ "$val" == \"*\" ]]; then
    val="${val:1:${#val}-2}"
  elif [[ "$val" == \'*\' ]]; then
    val="${val:1:${#val}-2}"
  fi
  printf '%s' "$val"
}

TARGET_ROOT="$(get_yaml_value "target_project_root" || echo "")"
INPUT_FOLDER="$(get_yaml_value "input_folder" || echo "")"

if [ -z "$TARGET_ROOT" ] || [ -z "$INPUT_FOLDER" ]; then
  echo "[error] target_project_root or input_folder not set in $CONFIG_FILE" 1>&2
  exit 1
fi

if [ ! -d "$TARGET_ROOT" ]; then
  echo "[error] target_project_root not found: $TARGET_ROOT" 1>&2
  exit 1
fi

if [ ! -d "$INPUT_FOLDER" ]; then
  echo "[error] input_folder not found: $INPUT_FOLDER" 1>&2
  exit 1
fi

# OPENAI key check (.env in root has priority, fallback to docker/.env, else env)
ENV_FILE=""
if [ -f "$PROJECT_ROOT_DIR/.env" ]; then
  ENV_FILE="$PROJECT_ROOT_DIR/.env"
elif [ -f "$PROJECT_ROOT_DIR/docker/.env" ]; then
  ENV_FILE="$PROJECT_ROOT_DIR/docker/.env"
fi

if [ -n "$ENV_FILE" ]; then
  if ! grep -q '^OPENAI_API_KEY=' "$ENV_FILE"; then
    echo "[warn] OPENAI_API_KEY not found in $ENV_FILE; relying on environment" 1>&2
  fi
else
  if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "[error] OPENAI_API_KEY not set and no .env or docker/.env present" 1>&2
    exit 1
  fi
fi

echo "[ok] Preflight checks passed"

if $ONLY_CHECK; then
  exit 0
fi

# Setup venv and sync dependencies
if [ ! -d "$VENV_DIR" ]; then
  echo "[info] Creating venv at $VENV_DIR"
  $PYTHON_BIN -m venv "$VENV_DIR"
fi

echo "[info] Upgrading pip"
"$VENV_PYTHON" -m pip install -q --upgrade pip

echo "[info] Installing pip-tools"
"$VENV_PYTHON" -m pip install -q pip-tools

if ! $SKIP_SYNC; then
  if [ -f "$PROJECT_ROOT_DIR/requirements-dev.txt" ]; then
    echo "[info] Syncing development requirements"
    "$PIP_SYNC_BIN" "$PROJECT_ROOT_DIR/requirements-dev.txt"
  else
    echo "[info] requirements-dev.txt not found; syncing requirements.txt"
    "$PIP_SYNC_BIN" "$PROJECT_ROOT_DIR/requirements.txt"
  fi
else
  echo "[info] Skipping dependency sync as requested"
fi

echo "[info] Running translator"
export TRANSLATOR_CONFIG_FILE="$CONFIG_FILE"

# If a filter glob is defined in the config, export it for the Python script
TRANSLATION_FILTER_GLOB="$(get_yaml_value "translation_file_filter_glob" || echo "")"
if [ -n "$TRANSLATION_FILTER_GLOB" ]; then
  export TRANSLATION_FILTER_GLOB
fi

exec "$VENV_PYTHON" -m src.translate_localization_files


