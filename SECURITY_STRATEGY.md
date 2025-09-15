# Security Strategy for the Translation Service

This document outlines the security strategy for the automated translation service, focusing on mitigating risks for both server deployments and local development.

## Core Principles

1.  **Least Privilege**: Components (API tokens, SSH keys) are granted only the permissions necessary for their function.
2.  **Dedicated Credentials**: The service uses dedicated credentials (SSH deploy keys, GPG keys) to limit the blast radius of a compromise.
3.  **Secure by Default**: The default configuration for server deployment is secure, and local development overrides use secure methods like SSH agent forwarding.
4.  **No Secrets in Git**: All sensitive information is stored outside of the Git repository. The project's `.gitignore` file is configured to ignore the `docker/.env` and root `/.env` files, preventing accidental commits of secrets.

## 1. Server Deployment Security

This model is for the automated, scheduled execution of the service on a production server.

### Credential Management

*   **Secrets File (`docker/.env`)**: All secrets—`OPENAI_API_KEY`, `TX_TOKEN`, `GITHUB_TOKEN`, and Git configuration—are stored in a single `docker/.env` file on the host. This file **must**:
    *   Be protected with strict file permissions (`chmod 600 docker/.env`).
    *   **NEVER** be committed to Git (it is listed in `.gitignore`).
*   **SSH Deploy Key**: A dedicated, **passphrase-less** SSH key pair is used for the service.
    *   The private key resides on the host server (e.g., in `~/.ssh/translator_deploy_key`).
    *   The public key is configured as a **Deploy Key** with **write access** on the bot's **forked** GitHub repository. This key is used exclusively for pushing translated commits.
*   **GPG Private Key**: The bot's GPG private key is stored on the host at `secrets/gpg_bot_key/bot_secret_key.asc` and protected with strict file permissions. It is imported into the container's GPG keyring at runtime by the entrypoint script.

### Docker Image and Container Security

*   **Runtime Secrets**: API tokens and other secrets from `docker/.env` are injected into the container as environment variables at runtime.
    *   For interactive sessions, these are available directly.
    *   For automated `cron` jobs, the entrypoint script writes these variables to `/etc/environment` and sets permissions to `600` (`-rw-------`). This is necessary because the `cron` daemon does not inherit the runtime environment, and this file is the standard, secure mechanism for providing it.
*   **Privilege Dropping**: The container starts as `root` to perform initial setup (like cloning the repo and setting permissions) and then drops privileges to a non-root `appuser` to execute the main translation script.
*   **No Persistent Container**: The service runs as a transient container via `docker compose run`, which is triggered by a host-level cron job. The container is created for the job and destroyed upon completion, minimizing its attack surface.

## 2. Local Development Security

This model is for developers running the service on their local machines.

*   **SSH Agent Forwarding**: The `docker-compose.override.yml` file (used only for local runs and gitignored) configures the container to use SSH Agent Forwarding.
    *   **Benefit**: This is highly secure. Your local, passphrase-protected SSH private key **never leaves your host machine**. The container is only given access to the agent's socket, allowing it to perform Git operations without ever handling the key directly.
*   **Local `.env` File**: Local runs can use a local `docker/.env` file for API keys, which is also gitignored.

## Key Revocation Plan

Rapid revocation is critical if a credential is compromised.

1.  **SSH Deploy Key Compromise**:
    1.  Immediately revoke the Deploy Key from the fork's settings on GitHub.
    2.  Delete the compromised SSH key pair from the server.
    3.  Generate a new SSH key pair, add the new public key as a Deploy Key, and update the server's SSH config.

2.  **GPG Signing Key Compromise**:
    1.  Remove the compromised GPG public key from the committer's GitHub account.
    2.  Generate a new GPG key pair.
    3.  Replace the key files in the host's `secrets/gpg_bot_key/` directory.
    4.  Update `GIT_SIGNING_KEY` in `docker/.env`.
    5.  The new key will be imported on the next container run. No image rebuild is required.

3.  **API Token Compromise (`OPENAI_API_KEY`, etc.)**:
    1.  Immediately revoke the compromised token on the respective platform (OpenAI, Transifex, GitHub).
    2.  Generate a new token.
    3.  Update the token in the host's `docker/.env` file.
    4.  The new token will be used on the next scheduled cron run. No container restart is necessary.

## Automated Security Verification (CI/CD)

To proactively enforce security, a GitHub Actions workflow (`.github/workflows/build-verify.yml`) runs on every pull request. This workflow acts as a security gate and performs the following checks:

1.  **Dockerfile Linting (`hadolint`)**: Scans the `Dockerfile` for security best practice violations.
2.  **Dependency Scanning (`pip-audit`)**: Audits `requirements.txt` against a database of known vulnerabilities in Python packages.
3.  **Docker Image Vulnerability Scanning (`Trivy`)**: Scans the final built image for OS and library vulnerabilities.

If a high-severity vulnerability is found, the workflow fails, preventing the merge of insecure code. 