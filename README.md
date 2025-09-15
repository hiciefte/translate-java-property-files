# Translate Java Property Files

This project automates the translation of Java `.properties` files into multiple languages using OpenAI's GPT-based APIs. It integrates with Git to detect changes, pulls the latest translations from Transifex, performs AI-based translation and review for new strings, and creates a pull request with the results.

The entire process is designed to be run as an automated, scheduled job on a server, but can also be easily run in a local development environment.

## Features

*   **Automated Translation**: Uses OpenAI (e.g., GPT-4o) to translate new or changed strings.
*   **Two-Step Quality Process**: A fast initial translation is followed by a robust, chunked AI review step to ensure consistency and quality while avoiding API rate limits.
*   **Git Integration**: Detects changed files, commits new translations with GPG signatures, and creates pull requests automatically.
*   **Transifex Integration**: Pulls the latest manual translations from Transifex before running the AI pipeline.
*   **Automated Error Reporting**: Validation and linter errors for skipped files are automatically added to the pull request description for high visibility.
*   **Glossary & Style Rules**: Enforces consistent terminology and tone using a `config.yaml` file.
*   **Dockerized Environment**: Runs as a Docker container for consistent and portable deployment.
*   **Secure Local Development**: Supports passphrase-protected SSH keys on macOS and Linux via SSH Agent Forwarding.

---

## 🚀 Getting Started

There are two primary ways to run the translation tool: locally for development/testing or on a server for automated production runs.

### 1. Local Development (Docker Recommended)

This is the easiest and most consistent way to run the full translation pipeline on your local machine. It uses Docker to replicate the server environment and securely uses your local SSH keys via SSH Agent Forwarding.

For a detailed walkthrough, see the **[Local Development Guide](./docs/how-to-run-locally.md)**.

**Prerequisites:**
*   Docker and Docker Compose
*   Your SSH key added to the SSH agent on your host machine.

**One-Time Setup:**

1.  **Enable SSH Agent Forwarding**: For local development, Docker needs access to your host's SSH agent to handle Git operations securely.

    a. **Create a Stable Symlink (macOS users):** Docker for Mac can have trouble mounting the default SSH socket. Create a stable symlink to it by running this command once in your terminal:
    ```bash
    ln -sf $SSH_AUTH_SOCK ~/.ssh/ssh_auth_sock
    ```

    b. **Create Docker Override File**: This file tells Docker to use the SSH agent. Create `docker/docker-compose.override.yml` with the following content:
    ```yaml
    services:
      translator:
        volumes:
          # Forward the SSH agent socket from the host to the container via the stable symlink.
          # Linux users can replace the source with: ${SSH_AUTH_SOCK}
          - ~/.ssh/ssh_auth_sock:/ssh-agent
        environment:
          # Tell the SSH client inside the container where to find the agent socket.
          - SSH_AUTH_SOCK=/ssh-agent
    ```
    *(This file is ignored by Git, so it will not interfere with server deployments.)*

2.  **Add SSH Key to Agent**: This allows the container to use your key without needing your passphrase.
    ```bash
    # On macOS (stores passphrase in Keychain)
    ssh-add --apple-use-keychain ~/.ssh/id_rsa

    # On Linux
    ssh-add ~/.ssh/id_rsa
    ```
    *(Replace `id_rsa` if your key has a different name.)*

**Run the Translation:**
Navigate to the `docker` directory and use `docker compose run`.
```bash
cd docker
docker compose run --rm translator
```
Docker Compose will automatically use the settings in `docker-compose.yml` and merge them with local-only settings from `docker/docker-compose.override.yml` to set up the correct environment.

**macOS Docker Troubleshooting: "Operation not supported" Error**

If you are on macOS and the `docker compose run` command fails with a mount error related to `/private/tmp/...`, it's because the default SSH key mount in `docker-compose.yml` conflicts with the SSH agent forwarding used for local development.

**To fix this:**
1. Open `docker/docker-compose.yml`.
2. Find and comment out the line that mounts the SSH directory:
   ```yaml
   # ...
   volumes:
     # ...
     # COMMENT OUT THE LINE BELOW FOR LOCAL MACOS DEVELOPMENT
     # - ${HOME}/.ssh:/home/appuser/.ssh:ro
     # ...
   ```
3. Run the `docker compose run` command again.

**IMPORTANT:** Do **not** commit this change to Git. This line is required for the server deployment.

### 2. Server Deployment

For setting up the automated translation service on a production server (e.g., a cloud VM), please follow the comprehensive, step-by-step guide:

➡️ **[New Project Deployment Guide](./docs/new-project-deployment.md)**

This guide covers everything from initial server setup and security to configuring the cron job that triggers the translation runs.

### 3. Local Development (Legacy Python Script)

For situations where Docker is not available, you can run the Python script directly using a local script. This method has more dependencies (e.g., `tx` CLI, Python environment) and is not the recommended approach.

**Prerequisites:**
*   Python 3.11+
*   Transifex CLI (`tx`) installed and on your `PATH`.
*   A `config.yaml` file configured for your local paths.

**Run the Script:**
```bash
./run-local-translation.sh /path/to/your/config.yaml
```

---

## 🛠️ Configuration

The service is configured through a combination of YAML files and a single environment file for secrets.

*   **`docker/.env`**: **Secrets.** Contains all sensitive information: API keys, tokens, and Git repository URLs. This file is not checked into version control. Use `docker/.env.example` as a template.
*   **`config.yaml`**: **Local configuration.** Used by `run-local-translation.sh` for local, non-Docker runs.
*   **`docker/config.docker.yaml`**: **Server configuration.** This is the configuration file used by the service when running inside Docker. It points to paths within the container (e.g., `/target_repo`).
*   **`glossary.json`**: **DEPRECATED.** The glossary has been merged into `config.example.yaml`. This file may be removed in the future.

## Troubleshooting

*   **macOS Docker Run Fails (SSH)**: See the "macOS Docker Troubleshooting" section under "Local Development" above.
*   **Validation Errors in Pull Request**: The PR description now includes a report of any files that were skipped due to linter or validation errors. These errors must be fixed manually in the source repository. See `docs/llm/debug-docker-service.md` for more details on common errors.
*   **Server Deployment Issues**: Refer to the detailed deployment guide and the debugging documentation in the `docs/` directory.

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, commit your changes, and open a pull request.
