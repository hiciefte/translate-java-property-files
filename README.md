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
*   **Secure Git Authentication**: Uses a baked-in, read-only SSH deploy key to securely interact with Git repositories, avoiding exposure of host-level keys.

---

## 🚀 Getting Started

There are two primary ways to run the translation tool: locally for development/testing or on a server for automated production runs.

### 1. Local Development & Server Deployment (Docker)

This is the only recommended way to run the service. The process is identical for local testing and server deployment, using Docker to create a secure and consistent environment.

**Prerequisites:**
*   Docker and Docker Compose
*   A dedicated SSH keypair to be used as a deploy key.

**One-Time Setup:**
1.  **Create Secrets Directory**: If it doesn't exist, create the directory for the deploy key:
    ```bash
    mkdir -p secrets/deploy_key
    ```
2.  **Provide Deploy Key**: Place your **private** SSH deploy key in the `secrets/deploy_key/` directory. By default, the system looks for a file named `id_ed25519`.
    ```
    secrets/deploy_key/id_ed25519
    ```
    This key **must not** have a passphrase. It will be baked securely into the Docker image.
3.  **Configure Environment**: Copy the example `.env` file and fill in your secrets (API keys, repository URLs).
    ```bash
    cp docker/.env.example docker/.env
    # Now edit docker/.env with your values
    ```
4.  **(Optional) Customize Deploy Key Name**: If your deploy key is not named `id_ed25519`, you can specify its name by adding the `DEPLOY_KEY_NAME` variable to your `docker/.env` file:
    ```
    # In docker/.env
    DEPLOY_KEY_NAME=your_key_name_here
    ```

**Run the Translation:**
Navigate to the `docker` directory and use `docker compose run`.
```bash
cd docker
docker compose build # Run this once or whenever you change the scripts or Dockerfile
docker compose run --rm translator
```

**NOTE:** Because the service uses a baked-in deploy key, the final `git push` step will now work correctly on all platforms, including macOS. The previous SSH agent forwarding workarounds are no longer needed.

### 2. Server Deployment Details

For comprehensive instructions on setting up the automated translation service on a production server (e.g., a cloud VM), including the cron job configuration, please follow the full guide:

➡️ **[New Project Deployment Guide](./docs/new-project-deployment.md)**

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
*   **`glossary.json`**: Provides language-specific translations for key terms to ensure consistency.
*   **`translation_file_filter_glob`** (optional, in `config.yaml`): A glob pattern that limits which changed `.properties` files are processed by the AI translator. This is useful for workflows where you want to pull all updated files from Transifex but only run the AI step on a specific subset (e.g., `mobile_*.properties`).

## Troubleshooting

*   **`Permission denied (publickey)` Errors**: This error during `git push` means the deploy key specified in `secrets/deploy_key/` has not been added to your target GitHub repository's "Deploy Keys" section with write access.
*   **Validation Errors in Pull Request**: The PR description now includes a report of any files that were skipped due to linter or validation errors. These errors must be fixed manually in the source repository. See `docs/llm/debug-docker-service.md` for more details on common errors.
*   **Server Deployment Issues**: Refer to the detailed deployment guide and the debugging documentation in the `docs/` directory.

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, commit your changes, and open a pull request.
