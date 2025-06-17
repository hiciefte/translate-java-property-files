FROM ubuntu:24.04

# Set SHELL to fail on pipeline errors
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG HOST_UID
ARG HOST_GID
ARG GPG_KEY_FINGERPRINT_FOR_TRUST
ARG SKIP_GPG_IMPORT=false

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, CLIs, and create non-root user in a single RUN layer to reduce image size
RUN apt-get update && \
    # Install base dependencies and add PPA for Python 3.9
    apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cron \
    curl \
    git \
    gnupg \
    jq \
    python3.9 \
    python3.9-venv \
    python3-pip \
    openssh-client && \
    #
    # Install GitHub CLI
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
    apt-get update && \
    apt-get install -y gh --no-install-recommends && \
    #
    # Download and install yq for YAML processing
    set -eux; \
    YQ_VERSION=v4.44.2; \
    YQ_ARCH="$(dpkg --print-architecture)"; \
    YQ_BINARY="yq_linux_${YQ_ARCH}"; \
    curl -sSL -o /usr/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY}"; \
    if [ "$YQ_ARCH" = "amd64" ]; then \
        YQ_SHA256="2a236a5119747372997f8f8b8a53e9261ea904791e57461460a5e82f73587b1c"; \
    elif [ "$YQ_ARCH" = "arm64" ]; then \
        YQ_SHA256="d05d9dae44503433e668d097143bfeb102ee7e2d486773ae23aaf81256ed54fd"; \
    else \
        echo "Unsupported architecture for yq: $YQ_ARCH" >&2; \
        exit 1; \
    fi; \
    echo "$YQ_SHA256 /usr/bin/yq" | sha256sum -c -; \
    chmod +x /usr/bin/yq; \
    #
    # Download and install gosu for user switching
    set -eux; \
    GOSU_VERSION=1.17; \
    GOSU_ARCH="$(dpkg --print-architecture)"; \
    curl -sSL -o /usr/sbin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$GOSU_ARCH"; \
    if [ "$GOSU_ARCH" = "amd64" ]; then \
        GOSU_SHA256="bbc4136d03ab138b1ad66fa4fc051bafc6cc7ffae632b069a53657279a450de3"; \
    elif [ "$GOSU_ARCH" = "arm64" ]; then \
        GOSU_SHA256="c3805a85d17f4454c23d7059bcb97e1ec1af272b90126e79ed002342de08389b"; \
    else \
        echo "Unsupported architecture: $GOSU_ARCH" >&2; \
        exit 1; \
    fi; \
    echo "$GOSU_SHA256 /usr/sbin/gosu" | sha256sum -c -; \
    chmod +x /usr/sbin/gosu && \
    #
    # Clean up apt cache and remove temporary dependencies
    rm -rf /var/lib/apt/lists/* && \
    apt-get remove -y software-properties-common && \
    apt-get autoremove -y && \
    apt-get clean && \
    #
    # Create a non-root user with the --no-log-init flag
    groupadd -o -g ${HOST_GID:-1000} appuser && \
    useradd --no-log-init -o -u ${HOST_UID:-1000} -g appuser -s /bin/bash -m appuser && \
    #
    # Create directories for GPG and set permissions
    mkdir -p /home/appuser/.gnupg /run/user/${HOST_UID:-1000}/gnupg && \
    chown -R ${HOST_UID:-1000}:${HOST_GID:-1000} /home/appuser/.gnupg /run/user/${HOST_UID:-1000} && \
    chmod -R 700 /home/appuser/.gnupg /run/user/${HOST_UID:-1000}

# Make python3.9 the default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1

# Install Transifex CLI
RUN TX_VERSION="v1.6.17" && \
    CONTAINER_ARCH=$(dpkg --print-architecture) && \
    if [ "$CONTAINER_ARCH" = "amd64" ]; then TX_ARCH="linux-amd64"; \
    elif [ "$CONTAINER_ARCH" = "arm64" ]; then TX_ARCH="linux-arm64"; \
    else echo "Unsupported architecture for Transifex CLI: $CONTAINER_ARCH"; exit 1; fi && \
    curl -Lf -O "https://github.com/transifex/cli/releases/download/${TX_VERSION}/tx-${TX_ARCH}.tar.gz" && \
    tar -xzf "tx-${TX_ARCH}.tar.gz" -C /usr/local/bin tx && \
    rm "tx-${TX_ARCH}.tar.gz" && \
    tx --version

# === GPG Key Import for Bot ===
COPY secrets/gpg_bot_key/bot_public_key.asc /tmp/bot_public_key.asc
COPY secrets/gpg_bot_key/bot_secret_key.asc /tmp/bot_secret_key.asc

RUN if [ "$SKIP_GPG_IMPORT" = "true" ]; then \
      echo "Skipping GPG key import for CI build."; \
    else \
      echo "Importing GPG keys for appuser..." && \
      su - appuser -c "gpg --batch --import /tmp/bot_public_key.asc" && \
      su - appuser -c "gpg --batch --import /tmp/bot_secret_key.asc" && \
      echo "Setting trust for GPG key ${GPG_KEY_FINGERPRINT_FOR_TRUST}..." && \
      su - appuser -c "echo \"${GPG_KEY_FINGERPRINT_FOR_TRUST:?GPG_KEY_FINGERPRINT_FOR_TRUST build argument is not set or empty}:6:\" | gpg --batch --import-ownertrust" && \
      su - appuser -c "git config --global commit.gpgsign true" && \
      echo "GPG key import and git config complete for appuser."; \
    fi && \
    # Clean up temporary files in all cases
    rm -f /tmp/bot_public_key.asc /tmp/bot_secret_key.asc

WORKDIR /app

# Copy source and install python dependencies
COPY requirements.txt .
RUN python3.9 -m pip install --no-cache-dir -r requirements.txt
COPY . .

# Copy cron file (from docker/ in project root, copied relative to /app in container)
# This assumes the cron file is now in the docker directory relative to build context
COPY docker/translator-cron /etc/cron.d/translator-cron

# Copy the GPG test script
# COPY docker/gpg_test_script.sh /app/docker/gpg_test_script.sh

# Set up cron and file permissions
RUN chmod 0644 /etc/cron.d/translator-cron && \
    chmod +x /app/update-translations.sh /app/docker/docker-entrypoint.sh && \
    mkdir -p /app/logs /target_repo && \
    chown -R appuser:appuser /app/logs /target_repo

# Set entrypoint
ENTRYPOINT ["/app/docker/docker-entrypoint.sh"]

# Default command to keep container running
CMD ["sleep", "infinity"] 