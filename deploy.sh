#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Log file
LOG_FILE="setup_log.log"

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting server setup process"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    log "Error: This script must be run as root"
    exit 1
fi

# Update system packages
log "Updating system packages"
apt-get update && apt-get upgrade -y

# Install required dependencies
log "Installing dependencies"
apt-get install -y python3 python3-pip python3-venv git gpg curl

# Install GitHub CLI
log "Installing GitHub CLI"
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
apt-get update && apt-get install -y gh

# Install Transifex CLI securely
log "Installing Transifex CLI securely..."
TX_INSTALLER_URL="https://raw.githubusercontent.com/transifex/cli/v1.6.17/install.sh"
TX_INSTALLER_SHA256="39fe480b525880aa842a097f8315100c3d5a19233a71befec904ce319205d392"
INSTALLER_PATH="/tmp/install_tx.sh"

curl -sSL --fail "$TX_INSTALLER_URL" -o "$INSTALLER_PATH"

echo "$TX_INSTALLER_SHA256  $INSTALLER_PATH" | sha256sum -c -
if [ $? -ne 0 ]; then
    log "FATAL: Transifex installer checksum mismatch. Aborting for security."
    exit 1
fi

bash "$INSTALLER_PATH"
rm "$INSTALLER_PATH"
log "Transifex CLI installed successfully."

# Check if bisquser exists
if ! id -u bisquser &>/dev/null; then
    log "Error: The bisquser does not exist. Please create it first."
    exit 1
fi

# Create workspace directory
WORKSPACE_DIR="/home/bisquser/workspace"
PROJECT_DIR="$WORKSPACE_DIR/translate-java-property-files"
log "Creating workspace directory: $WORKSPACE_DIR"
mkdir -p "$WORKSPACE_DIR"
chown -R bisquser:bisquser "$WORKSPACE_DIR"

# Log instructions for SSH and GPG keys
log "You'll need to set up SSH and GPG keys for the bisquser if not already done"
log "Run the following commands as the bisquser:"
log "1. ssh-keygen -t ed25519 -C 'bisquser@not-existing-domain.com'"
log "2. gpg --full-generate-key (use bisquser@not-existing-domain.com as email)"
log "Then add these keys to GitHub for the takahiro.nagasawa@proton.me account"

# Clone the repository
log "Clone the repository manually:"
log "su - bisquser"
log "git clone https://github.com/hiciefte/translate-java-property-files.git $PROJECT_DIR"

# Set up Python virtual environment
log "Setting up Python virtual environment"
su - bisquser -c "cd $PROJECT_DIR && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"

# Prepare systemd service files
SERVICE_FILE="/etc/systemd/system/translation-service.service"
TIMER_FILE="/etc/systemd/system/translation-service.timer"

log "Creating systemd service file: $SERVICE_FILE"
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Automated translation service for Java property files
After=network.target

[Service]
Type=oneshot
User=bisquser
WorkingDirectory=/home/bisquser/workspace/translate-java-property-files
ExecStart=/bin/bash /home/bisquser/workspace/translate-java-property-files/deploy.sh
Environment="PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/bisquser/.local/bin"
EnvironmentFile=/home/bisquser/.env

[Install]
WantedBy=multi-user.target
EOF

log "Creating systemd timer file: $TIMER_FILE"
cat > "$TIMER_FILE" << EOF
[Unit]
Description=Run automated translation service daily
Requires=translation-service.service

[Timer]
Unit=translation-service.service
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Create environment file for secrets (to be filled manually)
ENV_FILE="/home/bisquser/.env"
log "Creating environment file template: $ENV_FILE"
cat > "$ENV_FILE" << EOF
OPENAI_API_KEY=your_openai_api_key_here
GITHUB_TOKEN=your_github_token_here
TX_TOKEN=your_transifex_token_here
EOF
chown bisquser:bisquser "$ENV_FILE"
chmod 600 "$ENV_FILE"

log "Environment file created. Please edit $ENV_FILE to add your actual API keys"

# Enable and start the timer
log "Enabling and starting the translation service timer"
systemctl daemon-reload
systemctl enable translation-service.timer
systemctl start translation-service.timer

log "Server setup completed successfully"
log "IMPORTANT: You need to manually:"
log "1. Edit the environment file at $ENV_FILE to add your actual API keys"
log "2. Configure SSH and GPG keys for the bisquser if not already done"
log "3. Make sure both repository directories exist (the translation script repo and the target project repo defined in config.yaml)"
log "4. Set up the TX_TOKEN environment variable for Transifex access (tx init is not needed if .tx directory exists)" 