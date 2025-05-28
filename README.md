# Translate Java Property Files

This project automates the translation of Java `.properties` files into multiple languages using OpenAI's GPT-based
APIs. It integrates with Git to detect changes in a target project, pulls translations from Transifex, manages a
translation workflow, and then pushes new translations back to Git (creating a pull request) and Transifex. The entire
process is designed to be run automatically via a daily scheduled job within a Docker container.

## Features

- **Automated Translation**: Uses OpenAI (e.g., GPT-4) to translate text.
- **Git Integration**: Detects changed files in a target Git repository and commits new translations (GPG signed and *
  *Verified** on GitHub).
- **Transifex Integration**: Pulls existing translations from Transifex and pushes updated translations back.
- **GitHub Pull Requests**: Automatically creates pull requests for new translations.
- **Glossary Support**: Ensures consistent terminology using a `glossary.json` file.
- **Self-Contained GPG Signing**: Uses a dedicated GPG key built into the Docker image for signing commits. Commits are
  configured to appear as "Verified" on GitHub.
- **Dockerized Environment**: Runs as a Docker container for consistent and portable deployment.
- **Scheduled Execution**: Utilizes an in-container cron job for daily automated runs.
- **Comprehensive Logging**: Detailed logs for cron execution, script operations, and translation tasks.

## Project Structure

```
translate-java-property-files/
├── docker/                       # Docker-specific files
│   ├── Dockerfile                # Defines the Docker image
│   ├── docker-compose.yml        # Docker Compose configuration
│   ├── config.docker.yaml        # Configuration for Docker runs (points to /target_repo)
│   ├── translator-cron           # Crontab file for the in-container scheduler
│   └── docker-entrypoint.sh      # Entrypoint script for Docker container
├── src/                          # Python source code
│   └── translate_localization_files.py # Main translation script
├── secrets/                      # For storing GPG key (add to .gitignore)
│   └── gpg_bot_key/
│       ├── bot_public_key.asc
│       └── bot_secret_key.asc
├── .env.example                  # Example environment file (user must create .env)
├── config.yaml                   # Main configuration file (for local/manual runs)
├── glossary.json                 # Glossary for consistent translations
├── requirements.txt              # Python dependencies
├── update-translations.sh        # Main orchestration script (run by cron/entrypoint)
├── README.md                     # This file
└── .gitignore
```

- **`docker/`**: Contains all files needed to build and run the application with Docker.
    - `Dockerfile`: Builds the image with Python, Git, CLIs (Transifex, GitHub), cron, and imports the dedicated GPG bot
      key.
    - `docker-compose.yml`: Defines the `translator` service, manages environment variables, and volume mounts.
    - `config.docker.yaml`: A version of `config.yaml` with paths set for the Docker environment (points to
      /target_repo).
    - `translator-cron`: Defines the daily cron job that runs the translation process.
    - `docker-entrypoint.sh`: Script executed on container start. Clones/updates the target Bisq repository (e.g.,
      `hiciefte/bisq2`) into `/target_repo` inside the container, sets up the GPG agent, then calls
      `update-translations.sh`.
- **`src/translate_localization_files.py`**: The core Python script handling `.properties` file parsing, OpenAI API
  calls, glossary application, and file manipulation.
- **`secrets/gpg_bot_key/`**: This directory (which **must be added to your `.gitignore` file**) holds the GPG public
  and secret keys for the bot. These keys are copied into the Docker image during build.
- **`update-translations.sh`**: Orchestrates the entire translation workflow: Git operations, Transifex pulls/pushes,
  running the Python translation script, creating GitHub PRs. This is the script executed by the cron job within Docker.
- **`config.yaml`**: Configuration for paths, OpenAI model, etc., when running manually (not in Docker).
- **`docker/config.docker.yaml`**: Used by the Docker setup, with paths like `/target_repo` (where the Bisq project is
  cloned by the entrypoint script) and `/app/glossary.json`.
- **`.env` (user-created)**: Stores sensitive API keys and Docker host UID/GID. **This file is crucial and must be
  created by the user.**
- **`glossary.json`**: Defines term-specific translations for different languages.

## Prerequisites

- **Docker & Docker Compose**: Required to build and run the application using the recommended Docker setup. Download
  from [Docker's website](https://www.docker.com/products/docker-desktop/).
- **Git**: Must be installed on your local machine.
- **GnuPG (GPG)**: Required on your local machine to generate the bot's GPG key pair.
- **API Keys**:
    - **OpenAI API Key**: For accessing OpenAI translation models.
    - **Transifex API Token**: For interacting with your Transifex project.
    - **GitHub Personal Access Token**: A **Classic Personal Access Token** with the full `repo` scope is required. This
      token is used by the `gh` CLI to create pull requests. Fine-grained tokens may not work due to issues selecting
      repositories not directly owned by your account.
- **Target Project Setup**: The target Java project (e.g., `hiciefte/bisq2`) should have a `.tx/config` file configured
  for Transifex.

## Configuration

### 1. Environment Variables (`.env` file)

Create a `.env` file in the **root directory of this project** (`translate-java-property-files/.env`). This file is read
by Docker Compose for build arguments and container environment variables.

```env
# .env
OPENAI_API_KEY=your_openai_api_key_here
TX_TOKEN=your_transifex_api_token_here
GITHUB_TOKEN=your_github_personal_access_token_here

# Git repository details for the entrypoint script and update-translations.sh
FORK_REPO_URL="https://github.com/your-github-username/your-fork-repo-name.git" # e.g., https://github.com/hiciefte/bisq2.git (Used by entrypoint to clone)
UPSTREAM_REPO_URL="https://github.com/upstream-owner/upstream-repo-name.git" # e.g., https://github.com/bisq-network/bisq.git (Used by entrypoint to set upstream remote)

# These are used by update-translations.sh for creating PRs and by entrypoint.sh for setting SSH remote.
# If not set, update-translations.sh uses defaults: hiciefte/bisq2, bisq-network/bisq2, main respectively.
FORK_REPO_NAME="your-github-username/your-fork-repo-name" # e.g., hiciefte/bisq2
UPSTREAM_REPO_NAME="upstream-owner/upstream-repo-name" # e.g., bisq-network/bisq2 (Target for PRs)
TARGET_BRANCH_FOR_PR="main" # e.g., main (Target branch in UPSTREAM_REPO_NAME for PRs)

# Git commit author and GPG signing details (for "Verified" commits)
# Use an email address that is verified on your GitHub account and associated with the bot's GPG key.
GIT_AUTHOR_NAME="Your Name or Bot Name"
GIT_AUTHOR_EMAIL="your-verified-github-email@example.com"
GIT_SIGNING_KEY="YOUR_BOT_GPG_KEY_FINGERPRINT" # e.g., E8853EDAEE23096C4DA77732BCE5D7390C470F3C

# For Docker file permissions on mounted volumes (logs) and appuser creation.
# These MUST be numeric IDs.
# On macOS/Linux, you can find your current UID/GID with: id -u and id -g
HOST_UID=501 # Example: 501
HOST_GID=20  # Example: 20 (staff group on macOS)
```

- Replace placeholders with your actual keys/tokens and your numeric UID/GID.
- `HOST_UID` and `HOST_GID` are used during the Docker build to create an `appuser` with matching IDs, ensuring correct
  file ownership for mounted volumes (like logs) on your host.

### 2. Bot GPG Key Setup (One-time)

The Docker image includes a dedicated GPG key for the bot to sign commits. You need to generate this key pair once and
store it locally. **These key files should NOT be committed to Git.** Commits made by the bot will appear as "Verified"
on GitHub if configured correctly.

1. **Generate GPG Key Pair**:
   On your local machine, run the following command. It will create a new GPG key pair without a passphrase.

   ```bash
    gpg --batch --gen-key <<EOF
    Key-Type: EDDSA
    Key-Curve: Ed25519
    Subkey-Type: ECDH
    Subkey-Curve: Curve25519
    Name-Real: Translation Bot
    Name-Email: your-verified-github-email@example.com
    Expire-Date: 0
    %no-protection
    %commit
    EOF
    ```
    - **Important**: For `Name-Email`, use an email address that is **verified on your GitHub account**. This email will be used as the `GIT_AUTHOR_EMAIL` in your `.env` file and is crucial for getting "Verified" commits on GitHub.
    - If you use a different `Name-Real`, update `GIT_AUTHOR_NAME` in `.env` accordingly.

2.  **Identify Key Fingerprint & Signing Key ID**:
    List your GPG keys to find the fingerprint of the newly created key:
   ```bash
    gpg --list-secret-keys "your-verified-github-email@example.com"
    ```
    - Look for the `sec` line. The long hexadecimal string is the **fingerprint**.
    - The **Signing Key ID** is typically the last 16 characters of the fingerprint (e.g., `BCE5D7390C470F3C`). You will use this for `GIT_SIGNING_KEY` in your `.env` file.

3.  **Add User ID to an Existing Key (Optional)**:
    If you already have a bot GPG key and want to add or change its associated email for verified commits:
    ```bash
    gpg --edit-key YOUR_EXISTING_KEY_FINGERPRINT_OR_ID
    ```
    In the GPG prompt:
    - Type `adduid`.
    - Enter the `Real name` (e.g., Translation Bot).
    - Enter the `Email address` (e.g., `your-verified-github-email@example.com`).
    - Enter an optional `Comment`.
    - Type `O` (Okay).
    - If you want this new User ID to be the primary one, select it using `uid N` (where N is its number), then type `primary`.
    - Type `trust`, choose `5` (ultimate trust), and confirm.
    - Type `save` to save changes and exit.

4.  **Export Keys**:
    Create a directory to store the keys and export them:
   ```bash
    mkdir -p secrets/gpg_bot_key
    gpg --export -a "YOUR_BOT_KEY_FINGERPRINT_OR_ID" > secrets/gpg_bot_key/bot_public_key.asc
    gpg --export-secret-key -a "YOUR_BOT_KEY_FINGERPRINT_OR_ID" > secrets/gpg_bot_key/bot_secret_key.asc
    ```
    Replace `YOUR_BOT_KEY_FINGERPRINT_OR_ID` with the key's fingerprint or ID.

5.  **Add Public GPG Key to GitHub**:
    - Copy the content of `secrets/gpg_bot_key/bot_public_key.asc`.
    - Go to your GitHub account settings -> SSH and GPG keys -> New GPG key.
    - Paste the public key and add it.
    - Ensure the email address used for the GPG key (`Name-Email` during generation, or added via `adduid`) is listed as a verified email address in your GitHub account's email settings.

6.  **Add to `.gitignore`**:
    Ensure your project's `.gitignore` file contains a line to ignore the `secrets` directory:
   ```

    secrets/
    ```
    If `.gitignore` doesn't exist, create it in the project root.

    The `Dockerfile` is already configured to copy these keys from `secrets/gpg_bot_key/` into the image during the build process. The `docker-entrypoint.sh` script then configures Git at runtime to use the GPG key ID specified by the `GIT_SIGNING_KEY` environment variable from your `.env` file.

### 3. Dedicated SSH Key for GitHub Push (One-time)

To allow the bot to push changes to your fork on GitHub via SSH without requiring interactive passphrase entry, you need
to set up a dedicated, passphrase-less SSH key and configure it as a Deploy Key on your GitHub fork.

1. **Generate a New SSH Key Pair**:
   On your local machine (where you run `docker compose`), generate a new ED25519 SSH key pair. When prompted for a
   passphrase, leave it empty:

```bash
    ssh-keygen -t ed25519 -C "translation_bot_github_$(date +%Y-%m-%d)" -f ~/.ssh/translation_bot_github_id_ed25519
    # Press Enter for no passphrase, and Enter again to confirm.
    ```
    This creates `~/.ssh/translation_bot_github_id_ed25519` (private key) and `~/.ssh/translation_bot_github_id_ed25519.pub` (public key).

2.  **Add Public Key as Deploy Key to Your GitHub Fork**:
    - Copy the content of the public key file:
      ```bash
      cat ~/.ssh/translation_bot_github_id_ed25519.pub
      ```
    - Go to your forked repository on GitHub (e.g., `https://github.com/your-username/your-fork-repo-name`).
    - Navigate to `Settings` -> `Deploy keys` -> `Add deploy key`.
    - Give it a `Title` (e.g., "Translation Bot Docker").
    - Paste the public key into the `Key` field.
    - **Crucially, check `Allow write access`**. The bot needs this to push commits.
    - Click `Add key`.

3.  **Configure SSH to Use This Key for GitHub**:
    Edit or create the file `~/.ssh/config` on your local machine (the Docker host) and add the following entry:
    ```
    Host github.com
      HostName github.com
      User git
      IdentityFile ~/.ssh/translation_bot_github_id_ed25519
      IdentitiesOnly yes
    ```
    - This configuration tells SSH to use your new dedicated key when connecting to `github.com`.
    - `IdentitiesOnly yes` ensures that SSH only tries the specified `IdentityFile` and doesn't fall back to other keys that might require a passphrase.

    The `docker-compose.yml` mounts your host's `~/.ssh` directory (read-only) into `/home/appuser/.ssh` in the container. This allows Git running inside the container to use this SSH configuration and the dedicated key for pushing changes.

### 4. Application Configuration (`config.yaml` vs `docker/config.docker.yaml`)

- **`config.yaml`**: This file in the project root is used if you run the Python script manually (see "Manual Setup"). It expects absolute paths for your local system.
- **`docker/config.docker.yaml`**: This file is specifically for the Docker setup.
  - It's mounted into the container at `/app/config.yaml`.
  - `target_project_root` is set to `/target_repo` (where `docker-entrypoint.sh` clones the Bisq project).
  - `input_folder` is relative to `/target_repo` (e.g., `/target_repo/i18n/src/main/resources`).
  - `glossary_file_path` points to `/app/glossary.json` (mounted from the project root).
  - Queue folders are now created in `appuser`'s home directory within the container to avoid permission issues.

### 5. Glossary (`glossary.json`)

Place your translation glossary in `glossary.json` in the project root. Example:
```json
{
  "de": { "Bitcoin": "Bitcoin", "Bisq": "Bisq" },
  "es": { "Bitcoin": "Bitcoin" }
}
```

### 6. Transifex Project Configuration

Ensure the target repository (e.g., `hiciefte/bisq2`, which is cloned into `/target_repo` in Docker) has a valid
`.tx/config` file. Example structure:

```ini
[main]
host = https://www.transifex.com

[bisq2.i18n] # Or your project-resource slug
file_filter = i18n/src/main/resources/<lang>.properties # Path to translated files
source_file = i18n/src/main/resources/app.properties   # Path to source (English) file
source_lang = en
type = PROPERTIES
```

The `update-translations.sh` script uses the `TX_TOKEN` from the `.env` file to authenticate with Transifex.

## Running with Docker (Recommended)

This method encapsulates all dependencies (including GPG setup) and schedules the translation job using an in-container
cron.

1. **Clone this Repository**:
   ```bash
   git clone https://github.com/your-username/translate-java-property-files.git
   cd translate-java-property-files
   ```

2. **Create and Populate `.env` File**:
   As described in "Configuration" (Section 1) above. Ensure `HOST_UID` and `HOST_GID` are your numeric local user/group
   IDs.

3. **Generate and Export Bot GPG Key**:
   Follow the steps in "Configuration" (Section 2: Bot GPG Key Setup) to generate and export the bot's GPG keys into the
   `secrets/gpg_bot_key/` directory. Ensure `secrets/` is in your `.gitignore`.

4. **SSH Keys (for Git Push)**:
   The `docker-compose.yml` mounts your local `~/.ssh` directory into the container (read-only). This allows the script
   to use your SSH identity for `git push` operations to GitHub. Ensure your SSH keys are correctly configured on your
   host machine and loaded in your SSH agent if they are passphrase protected.

5. **Build the Docker Image**:
   From the project root directory:
   ```bash
   docker compose -f docker/docker-compose.yml build --no-cache
   ```
   Using `--no-cache` is recommended if you've updated scripts or keys in `secrets/`.
   This will copy the bot GPG keys into the image.

6. **Run the Service**:
   ```bash
   docker compose -f docker/docker-compose.yml up
   ```
   To run in detached mode (in the background):
   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```
   This starts the container. The `docker-entrypoint.sh` will first clone/update the target Git repository into
   `/target_repo`. The main container process `sleep infinity` (or `cron -f` if you change the CMD), and the
   `translator-cron` file defines the daily job.

7. **Checking Logs**:
   Logs are written to the `./logs/` directory in your project root (mounted from `/app/logs/` in the container):
    - `./logs/cron_job.log`: Output from the cron job execution itself.
    - `./logs/deployment_log.log`: Detailed logs from `update-translations.sh`.
    - `./logs/translation_log.log`: Logs from the Python script `src/translate_localization_files.py`.
      You can also view live logs from the running container:
   ```bash
   docker compose -f docker/docker-compose.yml logs -f
   ```

8. **Manually Triggering the Translation Job (for testing)**:
   If you don't want to wait for the scheduled cron time, you can execute the job manually inside the running container:
   ```bash
   docker exec -it translation_service_runner su -s /bin/bash appuser -c "/app/docker/docker-entrypoint.sh /app/update-translations.sh"
   ```
   (Replace `translation_service_runner` if your container name is different; check with `docker ps`).

9. **Stopping the Service**:
   If running in the foreground, press `Ctrl+C`. If detached, or from another terminal:
   ```bash
   docker compose -f docker/docker-compose.yml down
   ```

## Server Setup for Automated Docker Deployment

To run this Dockerized application on a dedicated Linux server for continuous, automated daily translations:

1. **Provision Server**: A Linux server (e.g., Ubuntu on Digital Ocean) with Docker and Docker Compose installed. Ensure
   GnuPG is also installed on the server if you need to manage GPG keys there, though it's not strictly needed for just
   running the pre-built image.
2. **User Account**: It's recommended to run Docker commands as a non-root user who is part of the `docker` group.
3. **Clone Repository**: Clone this `translate-java-property-files` repository onto the server.
   ```bash
   git clone https://github.com/your-username/translate-java-property-files.git
   cd translate-java-property-files
   ```
4. **Configure `.env` File**:
   Create the `.env` file in the project root on the server.
    - Fill in your production API keys (`OPENAI_API_KEY`, `TX_TOKEN`, `GITHUB_TOKEN`).
    - Set `HOST_UID` and `HOST_GID` to the numeric UID and GID of the user account on the server that will own the
      `./logs` directory (and potentially other mounted files if you add more). You can find these with `id -u` and
      `id -g` for that user. This ensures correct permissions for files written by the container to mounted volumes.
5. **Bot GPG Keys (`secrets/` directory)**:
   Copy the `secrets/` directory (containing `gpg_bot_key/bot_public_key.asc` and `gpg_bot_key/bot_secret_key.asc`) from
   your local machine to the project root on the server. This is needed for the `docker compose build` step on the
   server.
   Ensure `secrets/` is in your server's `.gitignore` if you initialize a new Git repo there for some reason, though
   typically you'd pull from your main repo which should already have `secrets/` ignored.
6. **Host SSH Keys**:
   The container uses your host's SSH keys (mounted from `~/.ssh` of the user running `docker compose`) to push to
   GitHub. Ensure the user account that will run `docker compose` on the server has its SSH keys configured and
   authorized with GitHub for the target repository.
7. **Build the Image on the Server**:
   Navigate to the project root on the server and build the image:
   ```bash
   docker compose -f docker/docker-compose.yml build --no-cache
   ```
8. **Start the Service on the Server**:
   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```
   The service will now run in the background, and the cron job will execute daily.

9. **Manage with systemd (Recommended on Server)**:
   For better management (auto-start on boot, easy start/stop/status), create a systemd service file (e.g.,
   `/etc/systemd/system/translator.service`):
   ```ini
   [Unit]
   Description=Translation Docker Service
   Requires=docker.service
   After=docker.service

   [Service]
   User=your_server_user # The user who owns the project files and runs docker compose
   Group=your_server_group # The group of that user
   WorkingDirectory=/path/to/translate-java-property-files # Project root on server
   Restart=always
   ExecStart=/usr/local/bin/docker-compose -f docker/docker-compose.yml up
   ExecStop=/usr/local/bin/docker-compose -f docker/docker-compose.yml down

   [Install]
   WantedBy=multi-user.target
   ```
    - Replace `your_server_user`, `your_server_group`, and `/path/to/translate-java-property-files`.
    - Ensure `docker-compose` path is correct (it might be `/usr/bin/docker-compose` or other).
    - Then enable and start the service:
      ```bash
      sudo systemctl daemon-reload
      sudo systemctl enable translator.service
      sudo systemctl start translator.service
      sudo systemctl status translator.service
      ```

## Manual Setup & Usage (Local Development/Testing - Not for Production)

This method is primarily for development or debugging the core Python script. It does not use the Docker image's GPG
setup.

1. **Prerequisites**: Python 3.9+, Git, GnuPG.
2. **Clone this Repository**.
3. **Create Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
5. **Set Environment Variables**:
   Export your API keys.

   ```bash
    export OPENAI_API_KEY="your_openai_key"
    export TX_TOKEN="your_transifex_token"
    # GITHUB_TOKEN would be used by update-translations.sh if run manually
    ```
6.  **Configure `config.yaml`**:
    Edit `config.yaml`. Set paths for your local system.
7.  **GPG Setup for Manual Commits**:
    Ensure your local Git and GPG are configured to use your desired GPG key for signing if you run `update-translations.sh` manually.
8.  **Run the Python Script**:
   ```bash
    python src/translate_localization_files.py
    ```
    Note: This only runs Python translation. The full workflow is handled by `update-translations.sh`.

## Workflow Overview (Inside Docker)

The daily cron job inside the Docker container executes `/app/docker/docker-entrypoint.sh` which then calls `/app/update-translations.sh` as `appuser`. This script performs:

1.  **Target Repository Check**: `docker-entrypoint.sh` (as root) clones/updates the target repository into `/target_repo`.
2.  **GPG Agent & Environment**: `docker-entrypoint.sh` (when run by `appuser` or via `su appuser -c entrypoint ...`) ensures the GPG agent is running correctly for `appuser`.
3.  **Git Operations (Target Repo)**: `update-translations.sh` (as `appuser`) navigates to `/target_repo`, stashes changes, checks out `main`, pulls latest.
4.  **Transifex Pull**: Pulls latest translations from Transifex.
5.  **Run Python Translation**: Executes `src/translate_localization_files.py`.
    - Uses `docker/config.docker.yaml` (mounted as `/app/config.yaml`).
    - Translates, writes updated files to `/target_repo`.
6.  **Commit & Push Changes**: `update-translations.sh` creates a new branch, adds, commits (GPG signed using the bot's key built into the image), and pushes changes to GitHub (using host's SSH key).
7.  **Create GitHub PR**: Uses `gh` CLI to create a pull request for the changes.
8.  **Transifex Push**: If the pull request was created successfully in the previous step, the script then pushes the updated source translations to Transifex. This step is skipped if PR creation fails.
9.  **Cleanup**.

## Troubleshooting

- **Docker Volume Permissions**: If you see permission errors for mounted volumes (e.g., `logs/`), ensure `HOST_UID` and `HOST_GID` in your `.env` file match the user owning the directory on the host and are correctly passed as build arguments.
- **API Key Issues**: Double-check keys in `.env`. Ensure tokens have correct permissions.
- **GPG Signing in Docker**:
  - The bot's GPG key is built into the image. Issues are unlikely to be with the key itself once built.
  - If signing fails, check the `docker-entrypoint.sh` `appuser` block that sets up `XDG_RUNTIME_DIR`, `GPG_TTY`, and starts the `gpg-agent`.
  - Ensure the fingerprint in the `Dockerfile`'s GPG import and git config steps matches the generated bot key.
- **SSH Key for Git Push**:
  - Ensure the `~/.ssh` directory of the user running `docker compose` (on host or server) is correctly mounted and contains the necessary SSH keys authorized with GitHub.
  - If SSH keys are passphrase protected, the SSH agent on the host/server must be running and have the keys added.
- **Cron Not Running**:
  - Check `docker logs translation_service_runner` for `cron` daemon messages.
  - Check `/app/logs/cron_job.log` (maps to `./logs/cron_job.log` on host).
  - Ensure `docker/translator-cron` has an empty line at the end.
- **Server Deployment with systemd**:
  - Verify `WorkingDirectory` in the `.service` file.
  - Ensure the `User` and `Group` (if set) in the `.service` file have permissions for the `WorkingDirectory`, `~/.ssh`, and `./logs`.
  - Check systemd journal for errors: `sudo journalctl -u translation-service-docker.service`.

## Contributing

Contributions are welcome! Please fork the repository, create a feature branch, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License.

   