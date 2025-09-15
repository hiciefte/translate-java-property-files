# New Project Deployment Guide

This guide provides a complete walkthrough for deploying a new, isolated instance of the translator tool on a Linux server.

## Prerequisites

1.  **A Linux Server**: A fresh VPS instance (e.g., Ubuntu 22.04) is recommended.
2.  **Docker and Docker Compose**: Ensure they are installed.
    -   [Install Docker Engine](https://docs.docker.com/engine/install/ubuntu/)
    -   [Install Docker Compose](https://docs.docker.com/compose/install/)
3.  **Git**: `sudo apt-get update && sudo apt-get install -y git`
4.  **GitHub Deploy Key**: You must have a dedicated SSH key pair for this service.
    -   Generate one with `ssh-keygen -t ed25519 -C "translator-bot-deploy-key"`.
    -   Add the public key (`~/.ssh/id_ed25519.pub`) as a "Deploy Key" with "Allow write access" in your **forked** GitHub repository's settings (`Settings -> Deploy Keys`).
5.  **GPG Key**: You must have a GPG key pair for signing commits. The private key should be in ASCII-armored format.
6.  **API Tokens**:
    -   `OPENAI_API_KEY`: From your OpenAI account.
    -   `TX_TOKEN`: From your Transifex account.
    -   `GITHUB_TOKEN`: A GitHub Personal Access Token with `repo` scope.

## Step 1: Clone the Project

Clone this repository onto your server.

```bash
git clone <your-repository-url> /opt/translator-service
cd /opt/translator-service
```

## Step 2: Configure the Service

Before adding secrets, you must create the main configuration file for the service.

```bash
# Copy the example config to create your instance-specific config
cp config.example.yaml config.yaml

# Now, edit config.yaml to set the correct paths and repository details.
# At a minimum, you must set:
# - target_project_root
# - input_folder
# You must use absolute paths inside the container, e.g., /target_repo
nano config.yaml
```

## Step 3: Add Secrets and Set Permissions

You need to place the GPG key and create the `.env` file with your API tokens. **This is a security-critical step.**

1.  **GPG Private Key**:
    -   Copy your ASCII-armored GPG private key.
    -   Paste it into the file at `secrets/gpg_bot_key/bot_secret_key.asc`.

2.  **Create the `.env` File**:
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

    # === Git Author and GPG Signing ===
    # This must match the name and email associated with your GPG key.
    GIT_AUTHOR_NAME=Your Bot Name
    GIT_AUTHOR_EMAIL=your-bot-email@example.com
    # Find this with 'gpg --list-secret-keys --keyid-format LONG'
    GIT_SIGNING_KEY=YourGpgKeyId

    # === Git Repository URLs ===
    # The SSH URL of your FORK of the repository.
    FORK_REPO_URL=git@github.com:your-username/your-fork.git
    # The HTTPS URL of the MAIN repository you are translating for.
    UPSTREAM_REPO_URL=https://github.com/original-org/original-repo.git

    # Optional: Explicitly tell the script where to find the config file inside the container.
    # This is recommended for robustness. It should match the volume mount in docker-compose.yml.
    # TRANSLATOR_CONFIG_FILE=/app/config.yaml
    ```

3.  **Harden File Permissions**:
    -   Restrict access to your secret files so only the owner can read them.
    ```bash
    chmod 600 docker/.env secrets/gpg_bot_key/bot_secret_key.asc
    ```

## Step 4: Build the Docker Image

Navigate to the `docker` directory and run the build command. This will create a self-contained image with all dependencies and your GPG key imported and trusted.

```bash
cd /opt/translator-service/docker
docker compose build
```

## Step 5: Perform a Manual Test Run

Before setting up the cron job, it's crucial to test that everything is working correctly.

```bash
# This command will start the service, clone the repo, and run the translation script.
# Monitor the output for any errors.
docker compose run --rm translator
```

If the run succeeds, you should see a new pull request created in your forked repository.

## Step 6: Schedule the Cron Job

Once the manual run is successful, you can schedule the service to run automatically.

1.  Open the root user's crontab for editing:
    ```bash
    sudo crontab -e
    ```
2.  Paste the following line at the bottom of the file. This is a robust example that sets the required environment and uses absolute paths to avoid common cron issues. It will run the translator every day at 3:00 AM.

    ```cron
    # Set a sane environment for the cron job
    SHELL=/bin/bash
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    0 3 * * * cd /opt/translator-service/docker && /usr/bin/docker compose run --rm translator >> /opt/translator-service/logs/cron_job.log 2>&1
    ```
3.  Save and close the file.

**Deployment is now complete.** The service will run automatically on the schedule you've set. You can check the log file at `/opt/translator-service/logs/cron_job.log` to monitor its execution.
