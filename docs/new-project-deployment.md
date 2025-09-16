# New Project Deployment Guide

This guide provides a complete walkthrough for deploying a new, isolated instance of the translator tool on a Linux server.

## Prerequisites

1.  **A Linux Server**: A fresh VPS instance (e.g., Ubuntu 22.04) is recommended.
2.  **Docker and Docker Compose**: Ensure they are installed and that **BuildKit is enabled**.
    -   [Install Docker Engine](https://docs.docker.com/engine/install/ubuntu/)
    -   [Install Docker Compose](https://docs.docker.com/compose/install/)
    -   Enable BuildKit by setting these environment variables in your `~/.bashrc` or `~/.profile`:
        ```bash
        export DOCKER_BUILDKIT=1
        export COMPOSE_DOCKER_CLI_BUILD=1
        ```
3.  **Git**: `sudo apt-get update && sudo apt-get install -y git`
4.  **GitHub Deploy Key**: A dedicated SSH key for the service.
    -   Generate one: `ssh-keygen -t ed25519 -C "translator-bot-deploy-key"`
    -   Add the **public key** (`id_ed25519.pub`) as a "Deploy Key" with "Allow write access" in the **forked** GitHub repository's settings (`Settings -> Deploy Keys`).
5.  **GPG Key**: A GPG key for signing commits, in ASCII-armored format.
6.  **API Tokens**:
    -   `OPENAI_API_KEY`: From your OpenAI account.
    -   `TX_TOKEN`: From your Transifex account.
    -   `GITHUB_TOKEN`: A GitHub Personal Access Token with `repo` and `workflow` scopes.

## Step 1: Clone the Project

Clone this repository onto your server.

```bash
git clone <your-repository-url> /opt/translator-service
cd /opt/translator-service
```

## Step 2: Add Secrets

> **Important:** The `secrets/` directory and `docker/.env` file contain sensitive credentials. Ensure they are listed in your `.gitignore` file and are never committed to your repository.

This is a security-critical step. You must place the deploy key, GPG key, and API tokens in the correct locations.

1.  **SSH Deploy Key**:
    -   Copy your **private** SSH key (`id_ed25519`).
    -   Place it into the file at `secrets/deploy_key/id_ed25519`. The filename must match the key type.

2.  **GPG Private Key**:
    -   Copy your ASCII-armored GPG private key.
    -   Paste it into the file at `secrets/gpg_bot_key/bot_secret_key.asc`.

3.  **Create the `.env` File**:
    -   Create a new file at `docker/.env`.
    -   Add the following content, replacing the placeholder values. **Do not use quotes**.

    ```bash
    # === Service Instance Identity ===
    # These names ensure this instance's container and volume don't conflict with others.
    CONTAINER_NAME=translator-my-project
    VOLUME_NAME=target-repo-data-my-project

    # === API Keys and Tokens ===
    GITHUB_TOKEN=ghp_YourGitHubPersonalAccessToken
    OPENAI_API_KEY=sk-YourOpenAI_API_Key
    TX_TOKEN=YourTransifexToken

    # === Git Author Identity ===
    # This name and email will be used for the commit author and committer.
    # The email MUST be a verified email on the GitHub account associated with the GPG key.
    GIT_AUTHOR_NAME="Translation Bot (Takahiro Nagasawa)"
    GIT_AUTHOR_EMAIL=takahiro.nagasawa@proton.me

    # === Git Repository Names ===
    # The 'owner/repo' name of your FORK.
    FORK_REPO_NAME=your-username/your-fork
    # The 'owner/repo' name of the MAIN repository.
    UPSTREAM_REPO_NAME=original-org/original-repo
    ```

4.  **Harden File Permissions**:
    -   Restrict access to all secret files. Directories need execute permissions to be accessible, while files should be read-only for the owner.
    ```bash
    # Set correct permissions for the secrets directory and the files within it
    find secrets -type d -exec chmod 700 {} +
    find secrets -type f -exec chmod 600 {} +
    chmod 600 docker/.env
    ```

## Step 3: Configure the Service

Create and edit the main configuration file for the service.

```bash
# Copy the example config to create your instance-specific config
cp config.example.yaml config.yaml

# Now, edit config.yaml to set the correct paths and repository details.
# At a minimum, you must set:
# - target_project_root: /target_repo
# - input_folder: i18n/src/main/resources
# The paths must be absolute paths inside the container.
nano config.yaml
```

## Step 4: Build the Docker Image

Navigate to the `docker` directory and run the build command. This will create a self-contained image with all dependencies.

> **Note on Security:** The build process uses Docker BuildKit's secret mounting feature. This means your keys are securely accessed only during the build and are **never** stored in the final Docker image layers.

```bash
# Ensure you are in the project root first
cd /opt/translator-service
docker compose --env-file docker/.env -f docker/docker-compose.yml build
```

## Step 5: Perform a Manual Test Run

Before setting up the cron job, it's crucial to test that everything is working correctly.

```bash
# This command will start the service, clone the repo, and run the translation script.
# Monitor the output for any errors.
docker compose --env-file docker/.env -f docker/docker-compose.yml run --rm translator
```

If the run succeeds, you should see a new pull request created in the upstream repository.

## Step 6: Schedule the Cron Job

Once the manual run is successful, schedule the service to run automatically.

1.  Open the root user's crontab for editing:
    ```bash
    sudo crontab -e
    ```
2.  Paste the following line at the bottom of the file. This is a robust example that sets the required environment and uses absolute paths. It will run the translator every day at 3:00 AM.

    ```cron
    # Set a sane environment for the cron job
    SHELL=/bin/bash
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    DOCKER_BUILDKIT=1
    COMPOSE_DOCKER_CLI_BUILD=1

    # Run the translator service daily at 3:00 AM server time.
    # This command ensures the log directory exists and passes the environment file to Compose.
    0 3 * * * cd /opt/translator-service/ && mkdir -p logs && /usr/bin/docker compose --env-file docker/.env -f docker/docker-compose.yml run --rm translator >> /opt/translator-service/logs/cron_job.log 2>&1
    ```
3.  Save and close the file.

**Deployment is now complete.** The service will run automatically on the schedule you've set. You can check the log file at `/opt/translator-service/logs/cron_job.log` to monitor its execution.
