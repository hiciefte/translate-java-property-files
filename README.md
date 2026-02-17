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

The `translator` service is designed to run in a Docker container. This is the only recommended way to run the service. The process is identical for local testing and server deployment, using Docker to create a secure and consistent environment.
Before building locally, enable BuildKit:
```bash
export DOCK-ER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1
```

### 1.1. Deploy Key Setup

The service uses an SSH deploy key to interact with Git repositories.

-   **Generate a new key:** Create a new SSH key specifically for this service (it's recommended to use the `ed25519` algorithm). Do not use a password/passphrase for this key.
-   **Add to GitHub:** Add the public key as a deploy key to the GitHub repository you want to push translations to. **Crucially, you must check "Allow write access."**
-   **Place the key:** Put the private key file in the `secrets/deploy_key/` directory. By default, the system looks for a file named `id_ed25519`.
    ```text
    secrets/deploy_key/id_ed25519
    ```
-   **Custom key name (optional):** If your key file has a different name, you must create a file named `.env` inside the `docker/` directory and specify the filename:
    ```env
    # In docker/.env
    DEPLOY_KEY_NAME=your_key_name_here
    ```

### 1.2. Configuration

-   Copy the `config.example.yaml` to `config.yaml`.
-   Edit `config.yaml` and set the `target_project_root` to the path where the Git repository will be cloned inside the container. This is typically `/target_repo`.
-   Set the `input_folder` to the path (relative to `target_project_root`) where the `.properties` files are located.

### 1.3. Building and Running the Service

Once the deploy key is in place and the configuration is set, you can build and run the service with a single command from the project root:

   ```bash
# To run the full translation and PR creation pipeline
docker compose run --rm translator
```

**NOTE:** The baked-in deploy key must be read-only and scoped to the target repo, rotated regularly, and used only in non-public images. With this in place, `git push` works across platforms; SSH agent forwarding is no longer needed.

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
*   **`process_all_files`** (optional, in `config.yaml`): Defaults to `false`. When `true`, the pipeline scans and processes all translation files under `input_folder` instead of only git-changed files. Useful for one-time ledger bootstrap runs.
*   **`retranslate_identical_source_strings`** (optional, in `config.yaml`): Defaults to `false`. When `false`, the pipeline avoids re-translating existing keys that already match source text unless they were newly synchronized in the current run. Set to `true` to restore legacy behavior.
*   **`translation_key_ledger_file_path`** (optional, in `config.yaml`): File path for a persistent per-key hash ledger. The ledger stores source/target hashes per key and lets the pipeline retranslate only when source text changes, without repeatedly touching already-stable keys.

### Adding New Languages

To add support for a new language to the translation system:

➡️ **[Adding New Locales Guide](./docs/adding-new-locales.md)**

This comprehensive guide covers:
- Determining the correct locale code
- Updating configuration files
- Adding glossary translations
- Testing and validation steps
- Complete real-world examples

## 🔧 Maintenance

### Disk Space Management

Docker-based deployments can accumulate significant disk space over time due to:
- Dangling/unused Docker images from continuous builds
- Build cache accumulation
- Large log files and systemd journals

**Automated cleanup recommended** for production deployments:

- **Weekly Docker cleanup**: Removes old containers, images, volumes, and build cache
- **Daily log rotation**: Keeps 7 days of logs with compression
- **Systemd journal limits**: Cap at 1GB, 7-day retention

**Implementation guides**:
➡️ **[Disk Space Management Guide](./docs/maintenance/disk-space-management.md)** - Complete setup instructions
➡️ **[Docker Cleanup Script](./scripts/docker-cleanup.sh)** - Ready-to-deploy cleanup script

The maintenance documentation includes:
- Automated maintenance scripts and cron job setup
- Log rotation and journal management configuration
- Monitoring commands and troubleshooting procedures
- Real-world impact analysis and best practices

**Monitor disk usage:**
```bash
# Check disk usage
df -h /
docker system df -v

# Verify journal size
journalctl --disk-usage

# View cleanup logs (after setup)
tail -50 logs/docker-cleanup.log
```

## Troubleshooting

*   **`Permission denied (publickey)` Errors**: This error during `git push` means the deploy key specified in `secrets/deploy_key/` has not been added to your target GitHub repository's "Deploy Keys" section with write access.
*   **Validation Errors in Pull Request**: The PR description now includes a report of any files that were skipped due to linter or validation errors. These errors must be fixed manually in the source repository. See `docs/llm/debug-docker-service.md` for more details on common errors.
*   **Server Deployment Issues**: Refer to the detailed deployment guide and the debugging documentation in the `docs/` directory.
*   **Disk Space Issues**: See the [Disk Space Management](#disk-space-management) section above for automated cleanup strategies.

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, commit your changes, and open a pull request.
