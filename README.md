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

This is the easiest and most consistent way to test the translation pipeline on your local machine, as it uses Docker to replicate the server environment.

**Prerequisites:**
*   Docker and Docker Compose

**Run the Translation:**
Navigate to the `docker` directory and use `docker compose run`.
```bash
cd docker
docker compose build # Run this once or whenever you change the python scripts
docker compose run --rm translator
```

**NOTE FOR MACOS USERS:** Due to a known issue with how Docker for Mac handles volume mounts for SSH keys, the final step of the script (`git push` and creating a pull request) will fail with a "Permission denied" error. However, the entire translation and validation process will run successfully. You can inspect the results and logs locally. The automated PR creation is intended to be run on the server.

If you need to test the full Git workflow locally on a Mac, please use the "Legacy Python Script" method below, which uses your local Git and SSH setup directly.

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

*   **Local Docker Run Fails on `git push` (macOS)**: This is an expected limitation. Please see the note under the "Local Development" section.
*   **Validation Errors in Pull Request**: The PR description now includes a report of any files that were skipped due to linter or validation errors. These errors must be fixed manually in the source repository. See `docs/llm/debug-docker-service.md` for more details on common errors.
*   **Server Deployment Issues**: Refer to the detailed deployment guide and the debugging documentation in the `docs/` directory.

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, commit your changes, and open a pull request.
