# Security Strategy for the Dockerized Translation Service

This document outlines the security strategy for the automated translation service, focusing on the Dockerized environment and mitigating risks associated with compromised credentials.

## Core Principles

1.  **Least Privilege**: Components (Docker container, `appuser` within the container, API tokens) are granted only the permissions necessary for their function.
2.  **Dedicated Credentials**: Separate, dedicated credentials (SSH keys, GPG keys, API tokens) are used for different purposes to limit the blast radius of a compromise.
3.  **Secure Storage & Handling**: Sensitive information (API keys, private keys) is handled securely, primarily through environment variables and controlled access to files on the host.

## Credential Management

### 1. Host Machine Security (Machine running `docker compose`)

-   **`.env` File Protection**: Sensitive API keys (`OPENAI_API_KEY`, `TX_TOKEN`, `GITHUB_TOKEN`) and Git/GPG configuration (`GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_SIGNING_KEY`, `FORK_REPO_NAME`, etc.) are stored in the `docker/.env` file (relative to the project root) on the host. This file **must**:
    -   Be protected with strict file permissions (e.g., `chmod 600 docker/.env`).
    -   **NEVER** be committed to Git (ensure it's in `.gitignore`).
-   **Host SSH Key (`~/.ssh/translation_bot_github_id_ed25519`)**: The private SSH key used for Git push authentication to the fork is stored on the host. Its permissions should be strict (e.g., `chmod 600`).
-   **Docker Daemon Access**: Access to the Docker daemon on the host should be restricted to authorized users.

### 2. Docker Image and Container Security

-   **No Hardcoded Credentials in Image (except GPG key)**:
    -   API tokens and most Git configuration are passed as environment variables at runtime via `docker-compose.yml` from the host's `docker/.env` file.
    -   **Exception**: The bot's GPG private key (`bot_secret_key.asc`) is copied into the Docker image during the build process from the `secrets/gpg_bot_key/` directory. This makes the security of the build environment and the Docker image itself (if pushed to a registry) critical.
-   **`appuser` within Container**: Operations within the container are performed by a non-root user (`appuser`) created with specific UID/GID matching the host (for volume permission handling).
-   **Volume Mounts**:
    -   `~/.ssh` (host) is mounted read-only into `appuser`'s home for Git push.
    -   `docker/config.docker.yaml` is mounted as `/app/config.yaml`.
    -   `glossary.json` is mounted.
    -   `logs/` directory is mounted for persistent logging.

## Git Authentication and Signing Security Strategy

This strategy separates authentication (pushing to Git) and signing (verifying commit authorship).

1.  **Committer Identity (for "Verified" Commits on GitHub)**:
    -   A specific GitHub account (e.g., `takahiro.nagasawa@proton.me`) is designated as the committer.
    -   The email for this account (`GIT_AUTHOR_EMAIL` in `.env`) must be verified on GitHub.
    -   The bot's GPG public key must be uploaded to this GitHub account.

2.  **Authentication (Git Push to Fork via SSH)**:
    -   A dedicated, passphrase-less SSH key pair (e.g., `~/.ssh/translation_bot_github_id_ed25519` on the host) is used.
    -   The public SSH key is added as a **Deploy Key** with **write access** to the *forked* GitHub repository (e.g., `hiciefte/bisq2`).
    -   The host's `~/.ssh/config` is configured to use this specific key for `github.com`.
    -   The `docker-entrypoint.sh` script ensures the Git remote `origin` in the container points to the SSH URL of the fork.

3.  **Signing (GPG Signed Commits)**:
    -   A dedicated GPG key pair is generated for the bot. The public and secret key files (`bot_public_key.asc`, `bot_secret_key.asc`) are stored in `secrets/gpg_bot_key/` in the project on the host.
    -   These keys are copied into the Docker image during build and imported for `appuser`.
    -   The `docker-entrypoint.sh` configures Git at runtime for `appuser` to use this GPG key (specified by `GIT_SIGNING_KEY` from `.env`) and the committer email (`GIT_AUTHOR_EMAIL`).

## Key Revocation Plan

Rapid revocation is key if a credential is compromised.

1.  **SSH Deploy Key Compromise (for Git Push)**:
    1.  Immediately revoke/delete the Deploy Key from the fork's settings on GitHub.
    2.  Delete the compromised SSH key pair from the host.
    3.  Generate a new SSH key pair on the host.
    4.  Add the new public key as a Deploy Key (with write access) to the fork.
    5.  Update the host's `~/.ssh/config` if the filename changed.
    6.  No container restart is strictly necessary if the `~/.ssh` mount and `~/.ssh/config` point to the new key correctly, but a restart ensures a clean state.

2.  **GPG Signing Key Compromise (Key built into the image)**:
    1.  Generate a GPG revocation certificate for the compromised key (if you have one). Use it if possible.
    2.  Remove the compromised GPG public key from the committer's GitHub account.
    3.  Generate a new GPG key pair locally.
    4.  Replace `bot_public_key.asc` and `bot_secret_key.asc` in the host's `secrets/gpg_bot_key/` directory with the new keys.
    5.  Update `GIT_SIGNING_KEY` in the host's `docker/.env` file with the new key ID.
    6.  **Rebuild the Docker image**: `docker compose -f docker/docker-compose.yml build --no-cache translator`
    7.  **Redeploy/Restart the service**: `docker compose -f docker/docker-compose.yml up -d --force-recreate`
    8.  Add the new GPG public key to the committer's GitHub account.

3.  **API Token Compromise (`OPENAI_API_KEY`, `TX_TOKEN`, `GITHUB_TOKEN`)**:
    1.  Immediately revoke the compromised token on the respective platform (OpenAI, Transifex, GitHub).
    2.  Generate a new token with the same (or least necessary) permissions.
    3.  Update the token in the host's `docker/.env` file.
    4.  Restart the Docker service to pick up the new environment variable: `docker compose -f docker/docker-compose.yml restart translator` or `docker compose -f docker/docker-compose.yml up -d --force-recreate`.

## Access Control

### GitHub Repository Access
-   **GitHub Token (`GITHUB_TOKEN`)**: Use a Classic Personal Access Token with the `repo` scope for the account that will create Pull Requests (this token is used by `gh pr create`).
-   **SSH Deploy Key**: Has write access *only* to the specific forked repository it's installed on. This is more secure than using a user's general SSH key with broader access.

### Branch Protection Rules (Recommended for Upstream Repository)
-   Enable branch protection for the `main` (or target) branch of the *upstream* repository.
-   Require pull requests for changes.
-   Require reviews before merging.
-   Ensure status checks pass (if applicable).

## Monitoring and Auditing

1.  **Commit Verification**: GPG-signed commits result in a "Verified" badge on GitHub, providing a visual audit trail.
2.  **GitHub Activity Monitoring**: Monitor activity for the committer account and deploy key actions.
3.  **Application Logging**: The service produces logs in the `logs/` directory (mounted from the host) for cron jobs, `update-translations.sh`, and `translate_localization_files.py`. Review these logs regularly.

## Regular Security Review

1.  **Key Rotation Schedule**:
    -   SSH Deploy Key: Annually.
    -   GPG Signing Key: Annually (requires image rebuild).
    -   API Tokens: Every 6-12 months or per provider recommendations.
    -   Document the rotation process and track renewal dates.
2.  **Access Review**: Regularly review permissions for API tokens and the Deploy Key. Ensure they adhere to the principle of least privilege.
3.  **Dependency Vulnerability Scanning**: Periodically scan Python dependencies (`requirements.txt`) and the base Docker image for known vulnerabilities.

## Implementation Summary (Current Dockerized Setup)

This summarizes the setup; detailed steps are in `README.md`.

1.  **Host Preparation**:
    -   Create `docker/.env` file (by copying `docker/.env.example` to `docker/.env`) with API keys, Git/GPG config, and host UID/GID.
    -   Generate a dedicated, passphrase-less SSH key (e.g., `~/.ssh/translation_bot_github_id_ed25519`).
    -   Configure host `~/.ssh/config` to use this key for `github.com`.
    -   Generate a dedicated GPG key pair for the bot, placing `bot_public_key.asc` and `bot_secret_key.asc` into `secrets/gpg_bot_key/`.

2.  **GitHub Configuration**:
    -   Add the SSH public key (`translation_bot_github_id_ed25519.pub`) as a **Deploy Key** (with write access) to your *forked* repository.
    -   Add the GPG public key (`bot_public_key.asc`) to the GitHub account that will be the committer (e.g., `takahiro.nagasawa@proton.me`), ensuring the email used in `GIT_AUTHOR_EMAIL` is verified for that account and associated with the GPG key.

3.  **Docker Build & Run**:
    -   `docker compose -f docker/docker-compose.yml build --no-cache translator` (builds image, embedding GPG key).
    -   `docker compose -f docker/docker-compose.yml up -d` (runs service).
    -   The `docker-entrypoint.sh` and `update-translations.sh` scripts handle the rest internally using the provided environment variables and built-in/mounted credentials.

This strategy aims to provide a robust security posture for the automated translation service by leveraging dedicated credentials, Docker's isolation, and clear revocation procedures. 