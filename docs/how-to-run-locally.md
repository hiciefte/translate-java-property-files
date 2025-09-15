# How to Run the Translation Service Locally

There are two ways to run the service on your local machine for testing or development. The Docker method is strongly recommended as it perfectly replicates the production environment and handles all dependencies automatically.

## 1. Local Development with Docker (Recommended)

This method runs the entire `update-translations.sh` orchestration script inside a Docker container. It's the most reliable way to test the full pipeline, including pulling from Transifex, creating commits, and pushing to GitHub.

It uses **SSH Agent Forwarding** to securely use your local, passphrase-protected SSH keys to push to your fork without exposing them to the container.

### One-Time Setup

1.  **Create Docker Override File**: For local development, create a file at `docker/docker-compose.override.yml` with the following content. This file enables the SSH agent forwarding.
    ```yaml
    services:
      translator:
        volumes:
          # Forward the SSH agent socket from the host to the container.
          - ${SSH_AUTH_SOCK}:/ssh-agent
        environment:
          # Tell the SSH client inside the container where to find the agent socket.
          - SSH_AUTH_SOCK=/ssh-agent
    ```
    *(This file is safely ignored by Git via the `.gitignore` file.)*

2.  **Add Your SSH Key to the Agent**: Before your first run, you must add your SSH key to your host machine's SSH agent.

    **On macOS:**
    This command also stores your key's passphrase in the macOS Keychain so you don't have to enter it again.
```