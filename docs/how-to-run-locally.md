# How to Run the Translation Service Locally

This guide explains how to run the full translation pipeline on your local machine for testing or development.

The only recommended method is to use Docker, as it perfectly replicates the production server environment and handles all dependencies automatically.

## Local Development with Docker

This method runs the entire `update-translations.sh` orchestration script inside a Docker container. It's the most reliable way to test the full pipeline, from pulling from Transifex to creating commits and pushing to GitHub.

### Setup and Execution

It is a prerequisite that you have a `secrets/deploy_key/id_ed25519` file with a GitHub deploy key that has write access to the target repository. Please refer to the main `README.md` for detailed instructions on setting this up.

The process for running the service locally is **identical** to the server deployment. It uses a baked-in SSH deploy key for all Git operations, which works consistently across all platforms (including macOS).

Note: Enable Docker BuildKit for builds using secrets:
```bash
export DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1
```

Once the prerequisites are met, you can build and run the service with a single command from the project root:
```bash
docker compose run --rm translator
```

There is no longer a need for a separate `docker-compose.override.yml` file or for using `ssh-agent`.