# Translate Java Property Files

This project automates the translation of Java `.properties` files into multiple languages using OpenAI's GPT-based
APIs. It integrates with Git to detect changes in a target project, pulls translations from Transifex, manages a
translation workflow, and then pushes new translations back to Git (creating a pull request) and Transifex. The entire
process is designed to be run automatically via a daily scheduled job within a Docker container.

## 🚀 Quick Start: Cloud Deployment (Recommended)

This guide provides the fastest way to deploy the translation service on a new cloud server (e.g., Ubuntu).

1. **Provision Cloud VM & Initial Setup**:
    * Create a cloud VM (Ubuntu recommended, min. 2 vCPU, 4GB RAM, 20GB disk).
    * Connect to your VM as `root` or a user with `sudo` privileges.
    * Install essential tools:
      ```bash
      sudo apt update
      sudo apt install -y docker.io docker-compose git
      sudo systemctl enable --now docker
      ```

2. **Create a Dedicated Non-Root User**:
    * This user (`translationbot`) will own the project files and run the Docker service.
      ```bash
      sudo adduser translationbot
      sudo usermod -aG docker translationbot 
      ```
    * Switch to the new user:
      ```bash
      su - translationbot 
      ```
      *(You'll perform subsequent steps as `translationbot` unless specified otherwise).*

3. **Clone This Repository**:
    * As `translationbot`, clone the project:
      ```bash
      git clone git@github.com:your-github-username/translate-java-property-files.git /opt/translate-java-property-files 
      cd /opt/translate-java-property-files
      ```
      *(If cloning fails, ensure `translationbot` has SSH access to GitHub. See 'SSH Key Setup for GitHub Access'
      below).*

4. **Configure Environment (`.env` file)**:
    * Copy the example and edit it. Note: The `.env` file should be located in the `docker/` subdirectory.
      ```bash
      cp .env.example docker/.env
      cp docker/.env.example docker/.env
      nano docker/.env
      ```
    * Fill in all required API keys, repository names, GPG key ID, and user/group IDs for `translationbot` (
      `HOST_UID=$(id -u)`, `HOST_GID=$(id -g)`). Refer to comments in `docker/.env.example` and the 'Environment Variables'
      section under 'Detailed Setup'.

5. **Set Up Bot's GPG Key**:
    * The bot needs a GPG key to sign commits. Generate this key pair on your **local machine** (not the server).
    * Follow the steps in 'Bot GPG Key Setup' under 'Detailed Setup'.
    * Securely copy the exported `bot_public_key.asc` and `bot_secret_key.asc` from your local machine to the server at
      `/opt/translate-java-property-files/secrets/gpg_bot_key/`. For example, from your local machine:
      ```bash
      scp -r path/to/your/local/secrets/gpg_bot_key translationbot@your-server-ip:/opt/translate-java-property-files/secrets/
      ```

6. **Set Up SSH Key for Bot's GitHub Access**:
    * The service needs an SSH key to push to your fork of the target repository.
    * Follow instructions in 'SSH Key for GitHub Access' under 'Detailed Setup' to generate a dedicated SSH key (e.g.,
      `~/.ssh/translation_bot_github_id_ed25519`) for the `translationbot` user on the server.
    * Add this key as a Deploy Key with write access to your **forked** repository on GitHub.
    * Ensure `~/.ssh/config` on the server is configured to use this key for `github.com`.
    * Test access: `ssh -T git@github.com` (should show successful authentication).

7. **Build and Run the Docker Service**:
    * As `translationbot` in `/opt/translate-java-property-files`:
      ```bash
      docker compose -f docker/docker-compose.yml build --no-cache
      docker compose -f docker/docker-compose.yml up -d
      ```

8. **Check Logs**:
   ```bash
   tail -f logs/deployment_log.log 
   # Or view all service logs:
   docker compose -f docker/docker-compose.yml logs -f
   ```

This completes the quick setup. The service will now run according to its cron schedule.

---

## Features

* **Automated Translation**: Uses OpenAI (e.g., GPT-4) to translate text.
* **Git Integration**: Detects changed files in a target Git repository and commits new translations (GPG signed and *
  *Verified** on GitHub).
* **Transifex Integration**: Pulls existing translations from Transifex and pushes updated translations back.
* **GitHub Pull Requests**: Automatically creates pull requests for new translations.
* **Glossary Support**: Ensures consistent terminology using a `glossary.json` file.
* **Self-Contained GPG Signing**: Uses a dedicated GPG key built into the Docker image for signing commits.
* **Dockerized Environment**: Runs as a Docker container for consistent and portable deployment.
* **Scheduled Execution**: Utilizes an in-container cron job for daily automated runs.
* **Comprehensive Logging**: Detailed logs for cron execution, script operations, and translation tasks.

## Project Structure

```text
translate-java-property-files/
├── docker/                       # Docker-specific files
│   ├── Dockerfile                # Defines the Docker image
│   ├── docker-compose.yml        # Docker Compose configuration
│   ├── config.docker.yaml        # Configuration for Docker runs
│   ├── translator-cron           # Crontab file for the scheduler
│   └── docker-entrypoint.sh      # Entrypoint script
├── src/                          # Python source code
│   └── translate_localization_files.py # Main translation script
├── secrets/                      # For GPG key (add to .gitignore!)
│   └── gpg_bot_key/
│       ├── bot_public_key.asc
│       └── bot_secret_key.asc
├── .env.example                  # Example environment file -> NOW MOVED TO docker/.env.example
├── docker/.env.example           # Example environment file
├── glossary.json                 # Glossary for translations
├── requirements.txt              # Python dependencies
├── update-translations.sh        # Main orchestration script
├── README.md                     # This file
└── .gitignore
```

## Key Files

Key files are described in more detail in relevant setup sections.

## Prerequisites

Before you begin, ensure you have:

* Access to a server or local machine with `sudo` or `root` privileges for initial setup.
* Docker and Docker Compose installed.
* Git installed.
* A GitHub account.
* An OpenAI API Key.
* A Transifex account and API Token.
* GPG installed on your local machine (for generating the bot's GPG key).

## ⚙️ Detailed Setup and Configuration

This section provides detailed steps for each configuration aspect, referenced by the Quick Start guide.

### 1. Environment Variables (`.env` file)

The service is configured primarily through environment variables defined in a `.env` file. This file should be located at `docker/.env` relative to the project root (e.g., `/opt/translate-java-property-files/docker/.env`).

1. **Create `docker/.env` from Example**:
   The example file `docker/.env.example` is located in the `docker/` directory.
   As the `translationbot` user on your server, navigate to the project root and run:
   ```bash
   cp .env.example docker/.env
   ```
2. **Edit `docker/.env`**:
   ```bash
   nano docker/.env
   ```
   Update all placeholder values with your actual secrets and configuration. Refer to `docker/.env.example` for details on each variable.
    * `OPENAI_API_KEY`, `TX_TOKEN`, `GITHUB_TOKEN`.
    * `FORK_REPO_URL`: SSH URL of your fork of the target repository (e.g.,
      `git@github.com:translationbot/target-repo.git`). The bot needs write access here.
    * `UPSTREAM_REPO_URL`: HTTPS URL of the main upstream repository (e.g.,
      `https://github.com/original-owner/target-repo.git`). This is used by root for read-only fetches and by `gh` for
      PR targeting.
    * `FORK_REPO_NAME`: Short form, e.g., `translationbot/target-repo`.
    * `UPSTREAM_REPO_NAME`: Short form, e.g., `original-owner/target-repo`.
    * `TARGET_BRANCH_FOR_PR`: Usually `main` or `develop`.
    * `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`: For commit attribution. Ensure the email is verified on GitHub and linked
      to the Bot GPG Key for "Verified" commits.
    * `GIT_SIGNING_KEY`: The GPG Key ID of the Bot GPG Key.
    * `HOST_UID`, `HOST_GID`: Run `id -u` and `id -g` as `translationbot` on the server and use these numeric IDs. This
      ensures correct file permissions for Docker volume mounts.

   > **Note on Repository URLs**:
   > * Always use the SSH URL format (`git@github.com:...`) for the `FORK_REPO_URL` to enable push access via the bot's
       SSH key.
   > * The `UPSTREAM_REPO_URL` should be an HTTPS URL (e.g., `https://github.com/original-owner/target-repo.git`). It's
       used by the entrypoint script (as root) for read-only operations and by the `gh` CLI for creating pull requests (
       which handles its own authentication via `GITHUB_TOKEN`).

### 2. SSH Key for GitHub Access (Bot & Server)

The `translationbot` user on your server needs an SSH key to:

1. Clone this `translate-java-property-files` repository (if private, or for consistency).
2. Allow the Docker container (via volume mount of `~/.ssh`) to push translated changes to your **fork** of the target
   repository.

**Setup Steps (as `translationbot` on the server):**

1. **Generate a New SSH Key Pair**:
   (If you don't already have one you want to use for the bot)
   ```bash
   ssh-keygen -t ed25519 -C "translation_bot_$(date +%Y-%m-%d)" -f ~/.ssh/translation_bot_github_id_ed25519
   # Press Enter for no passphrase, and Enter again to confirm.
   ```
   This creates `~/.ssh/translation_bot_github_id_ed25519` (private key) and
   `~/.ssh/translation_bot_github_id_ed25519.pub` (public key).

2. **Add Public Key as Deploy Key to Your GitHub Fork**:
    * Copy the content of the public key: `cat ~/.ssh/translation_bot_github_id_ed25519.pub`
    * Go to your **forked** target repository on GitHub (e.g., `https://github.com/translationbot/target-repo`).
    * Navigate to `Settings` > `Deploy keys` > `Add deploy key`.
    * Give it a `Title` (e.g., "Translation Bot Server Access").
    * Paste the public key.
    * **Crucially, check `Allow write access`**.
    * Click `Add key`.

3. **Configure SSH to Use This Key for GitHub**:
   Edit or create `~/.ssh/config` (as `translationbot`):
   ```ini
   Host github.com
     HostName github.com
     User git
     IdentityFile ~/.ssh/translation_bot_github_id_ed25519
     IdentitiesOnly yes
   ```

4. **Set Permissions**:
   ```bash
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/translation_bot_github_id_ed25519
   chmod 644 ~/.ssh/translation_bot_github_id_ed25519.pub
   chmod 600 ~/.ssh/config  # If you created/modified it
   ```

5. **Test Connection**:
   ```bash
   ssh -T git@github.com
   ```
   You should see a success message including your GitHub username associated with the key, or the deploy key's
   username.

### 3. Bot GPG Key Setup (for Verified Commits)

The bot signs Git commits with a GPG key. This setup is done once on your **local machine**, and the keys are then
copied to the server.

1. **Generate GPG Key Pair (Local Machine)**:
   ```bash
   gpg --batch --gen-key <<EOF
   Key-Type: EDDSA
   Key-Curve: Ed25519
   Subkey-Type: ECDH
   Subkey-Curve: Curve25519
   Name-Real: Translation Bot
   Name-Email: your-verified-github-email@example.com # Use an email verified on GitHub
   Expire-Date: 0
   %no-protection
   %commit
   EOF
   ```
    * Ensure `Name-Email` matches the `GIT_AUTHOR_EMAIL` in `.env` and is verified on your GitHub account.

2. **Identify Key ID (Local Machine)**:
   ```bash
   gpg --list-secret-keys "your-verified-github-email@example.com"
   ```
    * Look for the `sec` line. The **Key ID** is typically the last 16 characters of the fingerprint (e.g.,
      `BCE5D7390C470F3C`). Use this for `GIT_SIGNING_KEY` in `.env`.

3. **Export Keys (Local Machine)**:
   ```bash
   mkdir -p secrets/gpg_bot_key
   gpg --export -a "YOUR_KEY_ID" > secrets/gpg_bot_key/bot_public_key.asc
   gpg --export-secret-key -a "YOUR_KEY_ID" > secrets/gpg_bot_key/bot_secret_key.asc
   ```

4. **Add Public GPG Key to GitHub (Local Machine/Browser)**:
    * Copy the content of `secrets/gpg_bot_key/bot_public_key.asc`.
    * Go to your GitHub account settings > SSH and GPG keys > New GPG key. Paste and add.

5. **Copy Keys to Server**:
   As instructed in the Quick Start, secure copy the `secrets/gpg_bot_key` directory to
   `/opt/translate-java-property-files/secrets/` on the server.
   The `Dockerfile` copies these into the image. Ensure `secrets/` is in your `.gitignore`.

### 4. Application Configuration (`config.yaml` vs `docker/config.docker.yaml`)

* **`config.yaml` (Root)**: For manual/local runs outside Docker. Uses paths relevant to your local system.
* **`docker/config.docker.yaml`**: Specifically for Docker.
    * Mounted into the container as `/app/config.yaml`.
    * `target_project_root`: Set to `/target_repo` (where `docker-entrypoint.sh` clones the target project).
    * `input_folder`: Path within `/target_repo` (e.g., `/target_repo/i18n/src/main/resources`).
    * `glossary_file_path`: Points to `/app/glossary.json`.
    * Queue folders (for processing) are created in `appuser`'s home inside the container.

### 5. Glossary (`glossary.json`)

Place your translation glossary in `glossary.json` in the project root. Example:

```json
{
  "de": {
    "Bitcoin": "Bitcoin",
    "Bisq": "Bisq"
  },
  "es": {
    "Bitcoin": "Bitcoin"
  }
}
```

### 6. Transifex Project Configuration

Ensure the target repository (cloned into `/target_repo` in Docker) has a valid `.tx/config` file for Transifex.
Example:

```ini
[main]
host = https://www.transifex.com

[project.resource_slug] # e.g., bisq2.i18n
file_filter = i18n/src/main/resources/<lang>.properties # Path to translated files
source_file = i18n/src/main/resources/app.properties   # Path to source (English) file
source_lang = en
type = PROPERTIES
```

The `TX_TOKEN` from `.env` is used for authentication.

## 🐳 Running the Translation Service with Docker

Once configured, running the service is straightforward. These commands are run as `translationbot` from
`/opt/translate-java-property-files` on your server.

1. **Build the Docker Image**:
   (Needed initially and after changes to `Dockerfile`, scripts, or GPG keys in `secrets/`)
   ```bash
   docker compose -f docker/docker-compose.yml build --no-cache
   ```

2. **Run the Service**:
   To start the service in detached (background) mode:
   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```
   The `docker-entrypoint.sh` first clones/updates the target repository. The cron job inside the container then handles
   scheduled translations.

3. **Checking Logs**:
   Logs are written to the `./logs/` directory (mounted from `/app/logs/` in the container).
    * `./logs/cron_job.log`: Cron execution.
    * `./logs/deployment_log.log`: From `update-translations.sh`.
    * `./logs/translation_log.log`: From the Python script.
      View live Docker service logs:
   ```bash
   docker compose -f docker/docker-compose.yml logs -f
   ```

4. **Manually Triggering the Translation Job**:
   To test or run translations outside the cron schedule:
   ```bash
   docker exec -it translation_service_runner su -s /bin/bash appuser -c "/app/docker/docker-entrypoint.sh /app/update-translations.sh"
   ```
   *(Replace `translation_service_runner` with your actual container name if different; check with `docker ps`)*.

5. **Stopping the Service**:
   ```bash
   docker compose -f docker/docker-compose.yml down
   ```

## 🛡️ Recommended: Use a Non-Root User for Docker Deployment

For security and correct file permissions, **always run Docker and this service as a dedicated non-root user** (e.g.,
`translationbot`) on your server. The Quick Start guide incorporates this.

* **Why?** Avoids security risks of root access and ensures files created by the container (like logs) have proper
  ownership on the host.
* **How?**
    1. Create the user: `sudo adduser translationbot`
    2. Add to `docker` group: `sudo usermod -aG docker translationbot` (then re-login or `su - translationbot`)
    3. Clone the project and set file ownership (as shown in Quick Start).
    4. Use this user's numeric UID/GID for `HOST_UID` and `HOST_GID` in your `.env` file.

**⚠️ Warning:** Running Docker operations or this service as `root` (or with `HOST_UID=0, HOST_GID=0`) is strongly
discouraged.

## Workflow Overview (Inside Docker)

The daily cron job inside the Docker container executes `/app/update-translations.sh` as `appuser` (after environment
setup by `docker-entrypoint.sh`). The script:

1. Ensures the target repository (`/target_repo`) is up-to-date with its upstream `main` branch.
2. Pulls latest translations from Transifex.
3. Runs the Python script (`src/translate_localization_files.py`) to translate new strings.
4. Commits changes (GPG signed) to a new branch in `/target_repo`.
5. Pushes the branch to your fork on GitHub.
6. Creates a pull request from your fork to the upstream repository.
7. If PR creation is successful, pushes updated source translations to Transifex.

## Troubleshooting

- **Docker Volume Permissions**: If permission errors occur for `./logs` or other mounts, ensure `HOST_UID` and
  `HOST_GID` in `.env` match the `translationbot` user's IDs, and that `translationbot` owns the project directory.
- **API Key Issues**: Double-check keys in `.env`. Ensure tokens have necessary scopes/permissions.
- **GPG Signing**:
    * Verify `GIT_SIGNING_KEY` and `GIT_AUTHOR_EMAIL` in `.env` are correct and match the GPG key details and your
      GitHub verified emails.
    * Ensure GPG keys were correctly copied to `secrets/gpg_bot_key/` before building the image.
- **SSH Key for Git Push**:
    * Confirm the SSH key setup (Deploy Key on fork, `~/.ssh/config` for `translationbot` on server) is correct.
    * Test with `ssh -T git@github.com` as `translationbot`.
    * The host's `~/.ssh` directory (owned by `translationbot`) is mounted read-only into the container.
- **Cron Not Running**: Check Docker logs and `/app/logs/cron_job.log`. Ensure `docker/translator-cron` has a final
  newline.
- **`command not found` (git, tx, gh, python)**: This indicates an issue with the Docker image build or `PATH` setup
  within the container scripts. Rebuild the image.
- **`Error: Input folder does not exist...`**:
    * Ensure `target_project_root` and `input_folder` in `docker/config.docker.yaml` are correct.
    * This can also happen if `tx pull` fails to create the directory. Check `tx pull` logs.

## 🛠️ Advanced Topics & Alternatives

### Managing with systemd on a Server

For robust server deployment, use systemd to manage the Docker Compose service (auto-start on boot, easy
start/stop/status).

1. Create a service file (e.g., `/etc/systemd/system/translator.service`) as `root`:
   ```ini
   [Unit]
   Description=Translation Docker Service
   Requires=docker.service
   After=docker.service

   [Service]
   User=translationbot
   Group=docker
   WorkingDirectory=/opt/translate-java-property-files
   Restart=always
   ExecStart=/usr/bin/docker compose -f docker/docker-compose.yml up
   ExecStop=/usr/bin/docker compose -f docker/docker-compose.yml down

   [Install]
   WantedBy=multi-user.target
   ```
    * Verify the path for `docker` (e.g., `/usr/bin/docker`). The command uses `docker compose` (V2 syntax). If you have an older Docker Compose V1 installation (`docker-compose` with a hyphen), you might need to adjust the command and path (e.g., to `/usr/local/bin/docker-compose`).
    * Adjust `User` and `Group` if different.

2. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable translator.service
   sudo systemctl start translator.service
   sudo systemctl status translator.service
   ```

3. **Managing the Service**:
    * **Check Status & Recent Logs**: `sudo systemctl status translator.service`
    * **View Full Logs (Live)**: `sudo journalctl -u translator.service -f`
    * **Stop the Service**: `sudo systemctl stop translator.service`
    * **Restart the Service**: `sudo systemctl restart translator.service`
    * **Disable Auto-start on Boot**: `sudo systemctl disable translator.service`

   You may need to switch to a user with `sudo` privileges (or be `root`) to execute these commands if you are currently operating as `translationbot`.

### Manual Setup & Usage (Local Development/Testing - Not for Production)

This method is for debugging the Python script locally, outside Docker.

1. **Prerequisites**: Python 3.9+, Git, GnuPG.
2. **Clone this Repository**.
3. **Create Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. **Install Dependencies**: `pip install -r requirements.txt`
5. **Set Environment Variables**: Export `OPENAI_API_KEY`, `TX_TOKEN`.
6. **Configure `config.yaml`**: Edit `config.yaml` (in project root) with local paths.
7. **Run Python Script**: `python src/translate_localization_files.py`
   *(Note: This only runs Python translation. The full Git/Transifex workflow is in `update-translations.sh`)*.

## Contributing

Contributions are welcome! Please fork, branch, commit, and send a pull request.

## License

This project is licensed under the MIT License.

   