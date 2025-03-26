# Automated Translation System Setup

This document provides a comprehensive guide for setting up the automated translation system on a Digital Ocean server.

## System Overview

The automated translation system performs the following tasks:

1. Pulls the latest changes from the main repository
2. Fetches the latest translations from Transifex
3. Translates any new or modified files using OpenAI's API
4. Commits and signs the changes
5. Creates a Pull Request on GitHub for review

The system runs on a daily schedule using systemd timers and is designed to be secure and maintainable.

## Digital Ocean Server Setup

### 1. Create a Digital Ocean Droplet

1. Log in to your Digital Ocean account
2. Create a new Droplet with:
   - Ubuntu 22.04 LTS (or latest LTS)
   - At least 2GB RAM
   - 1 vCPU
   - 50GB SSD storage
3. Set up SSH keys for secure access
4. Create and assign a reserved IP address

### 2. Initial Server Configuration

After provisioning the server, connect to it via SSH and perform initial security hardening:

```bash
# Update the system
sudo apt update && sudo apt upgrade -y

# Set up a firewall
sudo ufw allow OpenSSH
sudo ufw enable
```

Disable password authentication for better security:
```bash
# Open SSH configuration file
sudo nano /etc/ssh/sshd_config
```

Find these lines in the file and modify them:
```
PasswordAuthentication no
PubkeyAuthentication yes
```

Then restart the SSH service (on Ubuntu, it's called ssh, not sshd):
```bash
# Restart SSH service 
sudo systemctl restart ssh
```

### 3. Run the Setup Script

The `server_setup.sh` script automates most of the installation and configuration process:

1. Copy the setup script to the server:
   ```bash
   scp server_setup.sh user@your-server-ip:~/
   ```

2. Make it executable and run it:
   ```bash
   ssh user@your-server-ip
   chmod +x server_setup.sh
   sudo ./server_setup.sh
   ```

The script will:
- Install required dependencies
- Verify the bisquser account exists
- Configure systemd service and timer
- Prepare the environment for SSH and GPG keys

### 4. Manual Configuration Steps

After the script completes, perform these manual configuration steps:

1. **Switch to the bisquser account**:
   ```bash
   sudo su - bisquser
   ```

2. **Set up SSH and GPG keys** (if not already configured):
   ```bash
   # Generate SSH key
   ssh-keygen -t ed25519 -C "bisquser@not-existing-domain.com" -f ~/.ssh/github_translation_bot
   
   # Generate GPG key
   gpg --full-generate-key
   # Choose RSA and RSA, 4096 bits
   # Use email: bisquser@not-existing-domain.com
   
   # Export the GPG public key
   gpg --list-secret-keys --keyid-format LONG
   # Note the key ID after "sec rsa4096/[KEY_ID]"
   gpg --armor --export [KEY_ID] > ~/translation_bot_gpg.pub
   
   # Configure git
   git config --global user.name "Bisq Translation Bot"
   git config --global user.email "bisquser@not-existing-domain.com"
   git config --global user.signingkey [KEY_ID]
   git config --global commit.gpgsign true
   
   # Create revocation certificate
   gpg --output ~/revocation-certificate.asc --gen-revoke [KEY_ID]
   chmod 600 ~/revocation-certificate.asc
   ```

3. **Configure SSH for GitHub**:
   ```bash
   mkdir -p ~/.ssh
   cat > ~/.ssh/config << EOF
   Host github.com
     IdentityFile ~/.ssh/github_translation_bot
     User git
   EOF
   chmod 600 ~/.ssh/config
   ```

4. **Set up environment file**:
   ```bash
   nano ~/.env
   ```
   Add your API keys:
   ```
   OPENAI_API_KEY=your_openai_api_key_here
   GITHUB_TOKEN=your_github_token_here
   TX_TOKEN=your_transifex_token_here
   ```

5. **Clone repositories**:
   ```bash
   # Create workspace directory
   mkdir -p ~/workspace
   
   # Clone translation script repository
   git clone https://github.com/hiciefte/translate-java-property-files.git ~/workspace/translate-java-property-files
   
   # Clone target project repository as specified in config.yaml
   # (This will be the repository specified in target_project_root in config.yaml)
   ```

6. **Configure Transifex**:
   The `.tx` directory will already exist in the target project repository, so no `tx init` is needed.
   Just make sure the TX_TOKEN environment variable is set in the `.env` file.

7. **Update config.yaml**:
   ```bash
   cd ~/workspace/translate-java-property-files
   nano config.yaml
   ```
   Update paths and settings as needed.

### 5. Test the System

Run the deployment script manually to test the setup:

```bash
cd ~/workspace/translate-java-property-files
bash deploy.sh
```

Watch for any errors and verify that each step works as expected.

## Maintenance

### Monitoring

Set up monitoring for the translation service:

```bash
# Check service status
sudo systemctl status translation-service

# View logs
sudo journalctl -u translation-service

# Check timer status
sudo systemctl status translation-service.timer
```

### Log Rotation

The translation service generates logs in `~/workspace/translate-java-property-files/deployment_log.log`.
Set up log rotation to manage these logs:

```bash
sudo nano /etc/logrotate.d/translation-service
```

Add the following configuration:

```
/home/bisquser/workspace/translate-java-property-files/deployment_log.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 bisquser bisquser
}
```

### Regular Maintenance Tasks

1. **Rotate Keys** (every 6 months):
   - Generate new SSH and GPG keys
   - Update GitHub with the new keys
   - Update server configuration

2. **Update Dependencies** (monthly):
   ```bash
   cd ~/workspace/translate-java-property-files
   source venv/bin/activate
   pip install --upgrade -r requirements.txt
   ```

3. **Backup Configuration** (after changes):
   ```bash
   mkdir -p ~/config_backups
   cp ~/.ssh/config ~/config_backups/ssh_config_$(date +%Y%m%d)
   cp ~/.gnupg/pubring.kbx ~/config_backups/pubring_$(date +%Y%m%d).kbx
   cp ~/.env ~/config_backups/env_$(date +%Y%m%d)
   ```

## Security Considerations

Refer to [SECURITY_STRATEGY.md](SECURITY_STRATEGY.md) for detailed information on:

1. Key management and revocation procedures
2. Mitigating risks of compromised credentials
3. GitHub access control
4. Monitoring for suspicious activity

## Troubleshooting

### Common Issues

1. **GitHub Authentication Failures**:
   - Verify SSH key is correctly configured
   - Check GitHub token permissions
   - Ensure user.email matches the email used for the GPG key

2. **Translation Failures**:
   - Check OpenAI API key validity
   - Verify rate limits haven't been exceeded
   - Review logs for specific error messages

3. **Timer Not Running**:
   - Check timer status: `sudo systemctl status translation-service.timer`
   - Verify timer is enabled: `sudo systemctl is-enabled translation-service.timer`
   - Check system time: `date`

### Getting Help

If you encounter persistent issues:

1. Check the detailed logs: `cat ~/workspace/translate-java-property-files/deployment_log.log`
2. Review systemd journal: `sudo journalctl -u translation-service`
3. Contact the system administrator with relevant log extracts 