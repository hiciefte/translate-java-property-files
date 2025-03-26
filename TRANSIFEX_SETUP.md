# Transifex CLI Setup Guide

This guide explains how to set up and configure Transifex CLI integration with our translation workflow.

## Prerequisites

- A Transifex account with access to the project
- Transifex CLI installed on the server (included in the `server_setup.sh` script)

## Environment Variable Setup

Since there's already an existing `.tx` directory in the target project, you don't need to run `tx init`. Instead, simply set up the Transifex API token in your environment:

```bash
# Add to ~/.env file
TX_TOKEN=your_transifex_token_here
```

The deployment script is configured to read this environment variable from the `/home/bisquser/.env` file.

## Project Structure

The target Bisq repository should already have a `.tx` folder with configuration mapping the source files to translations. The configuration typically looks like:

```ini
[main]
host = https://www.transifex.com

[bisq2.i18n]
file_filter = i18n/src/main/resources/<lang>.properties
source_file = i18n/src/main/resources/app.properties
source_lang = en
type = PROPERTIES
```

## Integration with the Automated Workflow

The `deploy.sh` script already includes a step to pull translations from Transifex:

```bash
tx pull -t
```

This command pulls only translations (not source files) from Transifex, using the token from the environment variable.

## Troubleshooting

1. **Authentication Issues**:
   - Ensure your TX_TOKEN environment variable is correctly set in the `.env` file
   - Verify the token has the necessary permissions
   - Check if the token has expired

2. **File Mapping Issues**:
   - Make sure the paths in the `.tx/config` file match your project structure
   - Check that the file_filter pattern correctly matches your translation files

3. **API Rate Limiting**:
   - If you encounter rate limiting, add delays between operations
   - Consider using the `--use-git-timestamps` flag with `tx push` to only push changed files

## Additional Commands

Here are some useful Transifex CLI commands:

- **Pull only specific languages**:
  ```bash
  tx pull -l de,es,fr
  ```

- **Push source files**:
  ```bash
  tx push -s
  ```

- **Push translations**:
  ```bash
  tx push -t
  ```

- **Check status**:
  ```bash
  tx status
  ```

## Further Resources

- [Transifex CLI Documentation](https://docs.transifex.com/client/introduction)
- [Transifex API Documentation](https://docs.transifex.com/api/introduction) 