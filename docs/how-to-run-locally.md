# How to Run the Translation Service Locally

This guide explains how to run the full translation pipeline on your local machine for testing or development.

The only recommended method is to use Docker, as it perfectly replicates the production server environment and handles all dependencies automatically.

## Local Development with Docker

This method runs the entire `update-translations.sh` orchestration script inside a Docker container. It's the most reliable way to test the full pipeline, from pulling from Transifex to creating commits and pushing to GitHub.

### Setup and Execution

The process for running the service locally is **identical** to the server deployment. It uses a baked-in SSH deploy key for all Git operations, which works consistently across all platforms (including macOS).

Please follow the instructions in the main **[README.md](../README.md#1-local-development--server-deployment-docker)** for the one-time setup and execution steps.

There is no longer a need for a separate `docker-compose.override.yml` file or for using `ssh-agent`.