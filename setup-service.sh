#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Check if Transifex CLI is already installed
if sudo -u bisquser bash -c 'source ~/.bashrc && which tx' &> /dev/null; then
    log "Transifex CLI is already installed"
    TX_VERSION=$(sudo -u bisquser bash -c 'source ~/.bashrc && tx --version')
    log "Current version: $TX_VERSION"
else
    # Install Transifex CLI for bisquser
    log "Installing Transifex CLI for bisquser"
    sudo -u bisquser bash -c 'curl -o- https://raw.githubusercontent.com/transifex/cli/master/install.sh | bash'
    
    if ! sudo -u bisquser bash -c 'source ~/.bashrc && which tx' &> /dev/null; then
        log "Error: Failed to install Transifex CLI"
        exit 1
    fi
    TX_VERSION=$(sudo -u bisquser bash -c 'source ~/.bashrc && tx --version')
    log "Transifex CLI installed successfully (version: $TX_VERSION)"
fi

# Stop and remove existing service and timer
log "Stopping and removing existing service and timer"
sudo systemctl stop translation-service.service translation-service.timer || true
sudo systemctl disable translation-service.service translation-service.timer || true
sudo rm -f /etc/systemd/system/translation-service.service /etc/systemd/system/translation-service.timer
sudo systemctl daemon-reload

# Create new service file
log "Creating systemd service file"
sudo tee /etc/systemd/system/translation-service.service > /dev/null << 'EOL'
[Unit]
Description=Automated translation service for Java property files
After=network.target

[Service]
Type=oneshot
User=bisquser
Environment=HOME=/home/bisquser
Environment=PATH=/home/bisquser/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
Environment=PYTHONPATH=/home/bisquser/workspace/translate-java-property-files
EnvironmentFile=/home/bisquser/.env
WorkingDirectory=/home/bisquser/workspace/translate-java-property-files

# Debug environment
ExecStartPre=/bin/bash -c 'echo "=== Environment Debug ===" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "PATH=$PATH" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "Current directory: $(pwd)" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "User: $(whoami)" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "Home: $HOME" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "Python path: $PYTHONPATH" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "Shell: $SHELL" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "=== End Environment Debug ===" >> /var/log/translation-service.log'

# Check and install Transifex CLI if needed
ExecStartPre=/bin/bash -c 'echo "=== Transifex CLI Check ===" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'if ! command -v tx &> /dev/null; then echo "Error: Transifex CLI not found. Please install it manually using: curl -o- https://raw.githubusercontent.com/transifex/cli/master/install.sh | bash" >> /var/log/translation-service.error.log; exit 1; fi'
ExecStartPre=/bin/bash -c 'echo "tx command location: $(which tx)" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "tx version: $(tx --version)" >> /var/log/translation-service.log'
ExecStartPre=/bin/bash -c 'echo "=== End Transifex CLI Check ===" >> /var/log/translation-service.log'

# Run the script with full shell initialization
ExecStart=/bin/bash -c 'source /home/bisquser/.bashrc && source /home/bisquser/.profile && /home/bisquser/workspace/translate-java-property-files/update-translations.sh'
StandardOutput=append:/var/log/translation-service.log
StandardError=append:/var/log/translation-service.error.log
TimeoutStartSec=300
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOL
log "Service file created"

# Create new timer file
log "Creating systemd timer file"
sudo tee /etc/systemd/system/translation-service.timer > /dev/null << 'EOL'
[Unit]
Description=Run translation service daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOL
log "Timer file created"

# Set proper permissions for log files
log "Setting up log files"
sudo touch /var/log/translation-service.log /var/log/translation-service.error.log
sudo chown bisquser:bisquser /var/log/translation-service.log /var/log/translation-service.error.log
sudo chmod 644 /var/log/translation-service.log /var/log/translation-service.error.log

# Reload systemd to pick up new service files
log "Reloading systemd"
sudo systemctl daemon-reload

# Enable and start the service and timer
log "Enabling and starting systemd service and timer"
sudo systemctl enable translation-service.service translation-service.timer || {
    log "Error: Failed to enable service and timer"
    exit 1
}

sudo systemctl start translation-service.service translation-service.timer || {
    log "Error: Failed to start service and timer"
    log "Checking service status for details:"
    sudo systemctl status translation-service.service | cat
    log "Checking journal logs for details:"
    sudo journalctl -xeu translation-service.service | tail -n 50 | cat
    exit 1
}

# Verify service and timer are running
if ! systemctl is-active translation-service.service >/dev/null 2>&1; then
    log "Error: Service failed to start properly"
    log "Service status:"
    sudo systemctl status translation-service.service | cat
    exit 1
fi

if ! systemctl is-active translation-service.timer >/dev/null 2>&1; then
    log "Error: Timer failed to start properly"
    log "Timer status:"
    sudo systemctl status translation-service.timer | cat
    exit 1
fi

log "Service setup completed successfully" 