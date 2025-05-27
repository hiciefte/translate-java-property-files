# Security Strategy for Translation Service

This document outlines the security strategy for the automated translation service, focusing particularly on mitigating risks associated with compromised credentials.

## Secure Credential Management

### Server-side Security

1. **Dedicated User Account**: The service runs under the `bisquser` account with appropriate permissions.
2. **Environment File Protection**: Sensitive API keys are stored in a protected `.env` file with strict permissions (600).
3. **No Hardcoded Credentials**: No credentials are hardcoded in any scripts or configuration files.
4. **Restricted Access**: The server should use SSH key-based authentication only, with password authentication disabled.

## Git Authentication and Signing Security Strategy

### Separated Authentication and Signing Keys

For enhanced security, we implement a strategy that separates authentication and signing concerns:

1. **GitHub Account**:
   - Use the GitHub account (takahiro.nagasawa@proton.me) for translations
   - This account should have the minimum required permissions to the repository
   - Configure the local git identity with appropriate user name and email

2. **Dedicated Authentication Key**:
   - Generate a dedicated SSH key for repository authentication
   - Register this key with the GitHub account with write access
   - Store the private key securely on the server with appropriate permissions

3. **Dedicated Signing Key**:
   - Generate a separate GPG key for commit signing
   - Register this key with the GitHub account
   - Configure git to use this key for commit signing
   - Store the private key securely on the server

### Key Revocation Plan

The primary advantage of using dedicated keys is the ability to quickly revoke compromised credentials without affecting other operations:

1. **Authentication Key Compromise**:
   - If the SSH authentication key is compromised:
     1. Immediately revoke the key on GitHub
     2. Generate a new SSH key
     3. Register the new key with GitHub
     4. Update the server configuration

2. **Signing Key Compromise**:
   - If the GPG signing key is compromised:
     1. Revoke the key using GPG revocation certificate
     2. Remove the key from GitHub
     3. Generate a new GPG key
     4. Register the new key with GitHub
     5. Update the git configuration on the server

3. **GitHub Token Compromise**:
   - If the GitHub token is compromised:
     1. Immediately revoke the token on GitHub
     2. Generate a new token with the same permissions
     3. Update the `.env` file on the server

## Access Control

### Repository Access

1. **Limited Repository Access**:
   - The GitHub account should have access only to the specific repositories needed
   - Use repository-specific deploy keys when possible instead of account-wide SSH keys

2. **Branch Protection Rules**:
   - Enable branch protection for the main branch
   - Require pull requests for changes to main
   - Require code review before merging
   - Require status checks to pass before merging

## Monitoring and Auditing

1. **Commit Verification**:
   - All commits should be signed with GPG
   - GitHub shows a "Verified" badge for signed commits

2. **Activity Monitoring**:
   - Monitor GitHub activity for the account
   - Set up notifications for suspicious activity

3. **Audit Logging**:
   - Maintain comprehensive logs of all operations
   - Review logs regularly for unusual patterns

## Regular Security Review

1. **Key Rotation**:
   - Rotate all keys (SSH, GPG, API tokens) at least every 6 months
   - Document the rotation process and schedule

2. **Access Review**:
   - Regularly review access permissions
   - Remove unnecessary permissions

## Implementation Instructions

### Setting Up Dedicated SSH and GPG Keys

```bash
# Log in as the bisquser
su - bisquser

# Generate a dedicated SSH key for GitHub authentication
ssh-keygen -t ed25519 -C "bisquser@not-existing-domain.com" -f ~/.ssh/github_translation_bot

# Generate a GPG key for signing
gpg --full-generate-key
# (Choose RSA and RSA, 4096 bits, 0 expiration for simplicity)
# Use email: bisquser@not-existing-domain.com

# Export the GPG public key to add to GitHub
gpg --list-secret-keys --keyid-format=long
# Note the key ID after "sec   rsa4096/[KEY_ID]" (it's the long string of hex characters)
gpg --armor --export [KEY_ID] > ~/translation_bot_gpg.pub

# Configure git to use the GPG key
git config --global user.signingkey [KEY_ID]
git config --global commit.gpgsign true

# Configure git to use the bot identity
git config --global user.name "Bisq Translation Bot"
git config --global user.email "bisquser@not-existing-domain.com"

# Create a GPG revocation certificate for emergency use
gpg --output ~/revocation-certificate.asc --gen-revoke [KEY_ID]
chmod 600 ~/revocation-certificate.asc
```

### Adding Keys to GitHub

1. Add the SSH public key (`~/.ssh/github_translation_bot.pub`) to the GitHub account (takahiro.nagasawa@proton.me)
2. Add the GPG public key (`~/translation_bot_gpg.pub`) to the same GitHub account
3. Generate a GitHub personal access token with appropriate permissions and add it to the `.env` file

### Using the Dedicated SSH Key

Configure SSH to use the dedicated key for GitHub:

```bash
# Create or edit the SSH config file
nano ~/.ssh/config

# Add the following entry
Host github.com
  IdentityFile ~/.ssh/github_translation_bot
  User git
```

This strategy provides a strong security posture while maintaining the ability to recover quickly from credential compromise. 