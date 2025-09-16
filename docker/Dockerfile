FROM ubuntu:24.04

# Set SHELL to fail on pipeline errors
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG SKIP_GPG_IMPORT=false

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, add repositories, and clean up in a single layer.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gh \
        git \
        jq \
        python3.11 \
        python3.11-venv \
        python3-pip \
        openssh-client && \
    apt-get remove -y software-properties-common && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Download and install yq for YAML processing
RUN set -eux; \
    YQ_VERSION=v4.44.2; \
    YQ_ARCH="$(dpkg --print-architecture)"; \
    YQ_BINARY="yq_linux_${YQ_ARCH}"; \
    curl -sSL -o /usr/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${YQ_BINARY}"; \
    if [ "$YQ_ARCH" = "amd64" ]; then \
        YQ_SHA256="246b781828353a59fb04ffaada241f78a8f3f25c623047b40306def1f6806e71"; \
    elif [ "$YQ_ARCH" = "arm64" ]; then \
        YQ_SHA256="d05d9dae44503433e668d097143bfeb102ee7e2d486773ae23aaf81256ed54fd"; \
    else \
        echo "Unsupported architecture for yq: $YQ_ARCH" >&2; \
        exit 1; \
    fi; \
    echo "$YQ_SHA256 /usr/bin/yq" | sha256sum -c -; \
    chmod +x /usr/bin/yq

# Download and install gosu for user switching
RUN set -eux; \
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
    chmod +x /usr/sbin/gosu

# Create a non-root user 'appuser' with a fixed, non-conflicting UID/GID.
# The home directory is created at /home/appuser.
RUN groupadd --gid 9999 appuser && \
    useradd --uid 9999 --gid 9999 --shell /bin/bash --create-home appuser

# Make python3.11 the default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1

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
# Copy the GPG secret key into a temporary location
COPY secrets/gpg_bot_key/bot_secret_key.asc /tmp/bot_secret_key.asc

# Set correct ownership for the key so appuser can read it.
RUN chown appuser:appuser /tmp/bot_secret_key.asc

# Import the GPG key for the appuser.
# This step is skipped in CI builds by checking the SKIP_GPG_IMPORT build argument.
RUN if [ "$SKIP_GPG_IMPORT" = "true" ]; then \
      echo "Skipping GPG key import for CI build."; \
    else \
      echo "Importing GPG key for appuser..." && \
      # Switch to appuser to import the key into its own keyring
      su - appuser -c "gpg --batch --import /tmp/bot_secret_key.asc" && \
      \
      echo "Determining key fingerprint and setting trust..." && \
      # Programmatically get the fingerprint of the imported key
      FINGERPRINT=$(su - appuser -c "gpg --list-keys --with-colons | grep '^fpr' | cut -d: -f10 | head -n1") && \
      if [ -n "$FINGERPRINT" ]; then \
        # Set ultimate trust on the key
        su - appuser -c "echo \"$FINGERPRINT:6:\" | gpg --batch --import-ownertrust"; \
        echo "GPG key import and trust set for fingerprint: $FINGERPRINT"; \
      else \
        echo "Error: Could not determine GPG key fingerprint after import." >&2; \
        exit 1; \
      fi; \
    fi && \
    # Clean up temporary file in all cases
    rm -f /tmp/bot_secret_key.asc

# Make the .ssh directory and set its permissions.
RUN mkdir -p /home/appuser/.ssh && \
    chmod 700 /home/appuser/.ssh

# Mount the secret key file and copy it into the .ssh directory.
# This method ensures the key is not stored in the image layers.
# Then, set the correct permissions for the key and create an SSH config.
RUN --mount=type=secret,id=deploy_key,target=/tmp/deploy_key \
    cp /tmp/deploy_key /home/appuser/.ssh/deploy_key && \
    chmod 600 /home/appuser/.ssh/deploy_key && \
    chown -R appuser:appuser /home/appuser/.ssh && \
    echo -e "Host github.com\n\tIdentityFile /home/appuser/.ssh/deploy_key\n\tIdentitiesOnly yes" > /home/appuser/.ssh/config && \
    chown appuser:appuser /home/appuser/.ssh/config && \
    chmod 600 /home/appuser/.ssh/config

WORKDIR /app

# Copy source and install python dependencies
COPY requirements.txt .
RUN python3.11 -m pip install --no-cache-dir -r requirements.txt
COPY . .

# Ensure the entrypoint and orchestration script are executable
RUN chmod +x /app/docker/docker-entrypoint.sh /app/update-translations.sh

# Set entrypoint
ENTRYPOINT ["/app/docker/docker-entrypoint.sh"]

# Bake the pinned SSH host keys into the image for enhanced security
COPY docker/ssh_known_hosts /etc/ssh/ssh_known_hosts
RUN chmod 644 /etc/ssh/ssh_known_hosts

# Default command is now the main python script (can be overridden in docker-compose.yml)
CMD ["python3", "-m", "src.translate_localization_files"] 