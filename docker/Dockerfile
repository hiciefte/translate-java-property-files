FROM ubuntu:24.04

ARG HOST_UID
ARG HOST_GID

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
# Add deadsnakes PPA for Python 3.9 on Ubuntu 24.04
RUN apt-get update && apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    openssh-client \
    gnupg \
    curl \
    python3.9 \
    python3.9-venv \
    python3-pip \
    cron \
    procps \
    psmisc \
    && rm -rf /var/lib/apt/lists/*

# Verify GPG version
RUN gpg --version

# Make python3.9 the default python3 and pip
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1
# The pip3 alternative was causing issues and python3.9 -m pip is used for requirements, so this might not be strictly needed.
# RUN update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.9 1 # Assuming pip3.9 exists

# Install Transifex CLI
# Using direct download for a specific version (e.g., v1.6.6) for the container's architecture
RUN TX_VERSION="v1.6.6" && \
    CONTAINER_ARCH=$(dpkg --print-architecture) && \
    if [ "$CONTAINER_ARCH" = "amd64" ]; then TX_ARCH="linux-amd64"; \
    elif [ "$CONTAINER_ARCH" = "arm64" ]; then TX_ARCH="linux-arm64"; \
    else echo "Unsupported architecture for Transifex CLI: $CONTAINER_ARCH"; exit 1; fi && \
    cd /tmp && \
    curl -Lf -O "https://github.com/transifex/cli/releases/download/${TX_VERSION}/tx-${TX_ARCH}.tar.gz" && \
    tar -xzf "tx-${TX_ARCH}.tar.gz" -C /usr/local/bin tx && \
    rm "tx-${TX_ARCH}.tar.gz" && \
    # Verify installation
    tx --version

# Install GitHub CLI
# gpg --dearmor might need gnupg2 to be installed first, which it is.
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update && apt-get install -y gh --no-install-recommends

# Create a non-root user
RUN groupadd -o -g ${HOST_GID:-1000} appuser && \
    useradd -o -u ${HOST_UID:-1000} -g appuser -s /bin/bash -m appuser && \
    # Create .gnupg directory for appuser with correct permissions
    mkdir -p /home/appuser/.gnupg && \
    chown -R ${HOST_UID:-1000}:${HOST_GID:-1000} /home/appuser/.gnupg && \
    chmod -R 700 /home/appuser/.gnupg

# Create and permission XDG_RUNTIME_DIR for appuser
# UID from HOST_UID is used to ensure it matches appuser's actual UID.
RUN mkdir -p /run/user/${HOST_UID:-1000}/gnupg && \
    chown -R ${HOST_UID:-1000}:${HOST_GID:-1000} /run/user/${HOST_UID:-1000} && \
    chmod -R 700 /run/user/${HOST_UID:-1000}

# === GPG Key Import for Bot ===
# This section assumes you have a 'secrets/gpg_bot_key' directory in your build context (project root)
# containing 'bot_public_key.asc' and 'bot_secret_key.asc' for the Translation Bot.
# Ensure 'secrets/' is in your .gitignore.
COPY secrets/gpg_bot_key/bot_public_key.asc /tmp/bot_public_key.asc
COPY secrets/gpg_bot_key/bot_secret_key.asc /tmp/bot_secret_key.asc

RUN \
    # Import keys as appuser. This will populate /home/appuser/.gnupg
    # Ensure .gnupg dir exists and has correct ownership/permissions (done during useradd)
    echo "Importing GPG keys for appuser..." && \
    su -s /bin/bash -c "gpg --batch --import /tmp/bot_public_key.asc" appuser && \
    su -s /bin/bash -c "gpg --batch --import /tmp/bot_secret_key.asc" appuser && \
    \
    # Set trust for the imported key to ultimate so it can be used for signing without manual intervention.
    # The fingerprint must match the key you generated.
    echo "Setting trust for GPG key E8853EDAEE23096C4DA77732BCE5D7390C470F3C..." && \
    su -s /bin/bash -c "echo 'E8853EDAEE23096C4DA77732BCE5D7390C470F3C:6:' | gpg --batch --import-ownertrust" appuser && \
    \
    # Git config will now be handled by the entrypoint at runtime using environment variables.
    # su -s /bin/bash -c "git config --global user.name 'Translation Bot (via hiciefte)'" appuser && \
    # su -s /bin/bash -c "git config --global user.email 'takahiro.nagasawa@proton.me'" appuser && \
    # su -s /bin/bash -c "git config --global user.signingkey E8853EDAEE23096C4DA77732BCE5D7390C470F3C" appuser && \
    # We can still enable GPG signing by default if a key is expected to be configured by entrypoint.
    su -s /bin/bash -c "git config --global commit.gpgsign true" appuser && \
    \
    # Clean up
    echo "Cleaning up temporary GPG key files..." && \
    rm /tmp/bot_public_key.asc /tmp/bot_secret_key.asc && \
    echo "GPG key import and git config complete for appuser."

WORKDIR /app

# Copy requirements (from project root)
COPY requirements.txt .
# Ensure pip for python3.9 is used
RUN python3.9 -m pip install --no-cache-dir -r requirements.txt

# Copy application code (from project root)
# This will copy src/, update-translations.sh, glossary.json etc. into /app
COPY . .

# Copy cron file (from docker/ in project root, copied relative to /app in container)
# This assumes the cron file is now in the docker directory relative to build context
COPY docker/translator-cron /etc/cron.d/translator-cron

# Copy the GPG test script
# COPY docker/gpg_test_script.sh /app/docker/gpg_test_script.sh

# Give execution rights on the cron job and proper permissions
RUN chmod 0644 /etc/cron.d/translator-cron && \
    crontab /etc/cron.d/translator-cron # && \
    # Ensure scripts are executable
    # chmod +x /app/docker/gpg_test_script.sh

# Ensure scripts are executable and logs directory exists
# Create /target_repo and give appuser ownership
# docker-entrypoint.sh should be in docker/ as well now
RUN touch /app/update-translations.sh /app/docker/docker-entrypoint.sh && \
    chmod +x /app/update-translations.sh /app/docker/docker-entrypoint.sh && \
    echo "Listing permissions for /app and /app/docker:" && \
    ls -la /app && \
    ls -la /app/docker && \
    mkdir -p /app/logs /var/run/crond /target_repo && \
    chown -R appuser:appuser /app/logs /target_repo && \
    chown -R root:root /var/run/crond # Cron needs to write its pid here

# USER appuser # We will run entrypoint as root, then cron as root. Job itself runs as appuser via crontab.

# Set entrypoint (path from /app)
# The entrypoint will handle initial setup (e.g., git clone)
ENTRYPOINT ["/app/docker/docker-entrypoint.sh"]

# Start cron in the foreground. Cron daemon itself usually runs as root.
# The jobs defined in /etc/cron.d/translator-cron are specified to run as 'appuser'
# CMD ["cron", "-f"] 

# Debug CMD
CMD ["sleep", "infinity"] 