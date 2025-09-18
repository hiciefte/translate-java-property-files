# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing
```bash
# Run all tests
pytest

# Run specific test types
pytest tests/unit/                    # Unit tests only
pytest tests/integration/            # Integration tests only

# Run single test file
pytest tests/unit/test_core_logic.py

# Run with verbose output
pytest -v
```

### Local Development
```bash
# Run translation pipeline locally (requires Python 3.11+, tx CLI)
./run-local-translation.sh [path/to/config.yaml]

# Docker-based development (recommended)
export DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1
docker compose run --rm translator
```

### Dependency Management
```bash
# Update dependencies (uses pip-tools)
pip-compile requirements.in
pip-compile requirements-dev.in --generate-hashes --output-file=requirements-dev.txt
```

## Architecture Overview

This is an **AI-powered Java Properties translation service** that automates translating `.properties` localization files using OpenAI APIs, with Git/GitHub integration for automated pull requests.

### Core Flow
1. **Change Detection**: `get_changed_translation_files()` uses Git to find modified `.properties` files
2. **Queue Processing**: Files move through `translation_queue/` → AI processing → `translated_queue/`
3. **AI Translation**: Two-pass system (fast translation + thorough review) with glossary enforcement
4. **Git Integration**: Automated commits and PR creation via `update-translations.sh`

### Key Components

**Main Entry Points:**
- `update-translations.sh` - Shell orchestration script (Docker entrypoint)
- `src/translate_localization_files.py` - Core Python translation logic
- `run-local-translation.sh` - Local development runner

**Translation Pipeline:**
- `src/properties_parser.py` - Parses/reassembles Java .properties files
- `src/translation_validator.py` - Validates placeholder consistency, encoding
- `src/logging_config.py` - Centralized logging setup

**Configuration System:**
- `config.yaml` / `docker/config.docker.yaml` - Application settings
- `glossary.json` - Translation consistency rules (brand terms + required translations)
- `docker/.env` - Secrets (API keys, repository URLs)

### Translation Architecture

**Glossary System** (critical for consistency):
- **Brand Glossary**: Terms that must NEVER be translated (`['MuSig', 'Bisq', 'Lightning', 'I2P', 'Tor']`)
- **Translation Glossary**: Required term mappings from `glossary.json` (e.g., `"account": "Konto"` for German)
- Both injected into AI prompts with strict enforcement rules

**Two-Pass AI Processing**:
1. **Fast Translation**: Initial OpenAI API call for new/changed keys
2. **Holistic Review**: Second AI pass for consistency and quality (can use different model)

**Rate Limiting & Concurrency**:
- `AsyncLimiter` for API rate limiting (60 requests/minute default)
- `asyncio.Semaphore` for concurrency control (`MAX_CONCURRENT_API_CALLS`)
- Chunked processing to handle large property files

**File Processing Flow**:
```
Input Folder → Archive → translation_queue/ → AI Processing → translated_queue/ → Back to Input Folder
```

### Testing Architecture

**Pytest Configuration:**
- `pytest.ini` configures async fixture scope
- `tests/conftest.py` provides session-scoped fixtures with path mocking
- Separates unit tests (isolated logic) from integration tests (end-to-end scenarios)

**Test Structure:**
- `tests/unit/` - Core logic, validation, helpers (fast, isolated)
- `tests/integration/` - Full pipeline testing with mock OpenAI responses
- Integration tests use temp directories and comprehensive mocking

### Security & Deployment

**Docker-First Architecture:**
- Production deployment uses SSH deploy keys baked into container
- `docker-compose.yml` with secrets management for deploy keys
- Containerized execution prevents host-level key exposure

**Git Operations:**
- Automated branch creation: `translation-updates-YYYY-MM-DD-HHMMSS`
- GPG-signed commits when configured
- Pull request creation via GitHub CLI with comprehensive descriptions
- Error reporting included in PR descriptions for manual review

### Error Handling & Validation

**Validation Pipeline** (`translation_validator.py`):
- Placeholder parity checking (`{0}`, `{1}`, etc.)
- Encoding/mojibake detection
- Key synchronization between source and target files

**Skipped Files Reporting**:
- Failed files logged to `logs/skipped_files_report.log`
- Report automatically included in PR description
- Prevents broken translations from being committed

### Environment Variables

**Required for Operation:**
- `OPENAI_API_KEY` - OpenAI API access
- `GITHUB_TOKEN` - GitHub PR creation
- `TRANSIFEX_TOKEN` - Pulling existing translations
- `TRANSLATOR_CONFIG_FILE` - Config file path (defaults to `config.yaml`)

**Optional Filtering:**
- `TRANSLATION_FILTER_GLOB` - Process only files matching glob pattern
- `REVIEW_MODEL_NAME` - Override review step model

## Development Notes

**When modifying translation logic:**
- Test both unit tests and integration tests
- Update glossary rules carefully as they affect all translations
- Consider token limits when modifying prompts (`count_tokens()` utility)

**When changing configuration:**
- Both local (`config.yaml`) and Docker (`docker/config.docker.yaml`) configs exist
- Docker paths use `/target_repo` and `/app/` prefixes
- Secrets go in `docker/.env` not committed to repository

**For new language support:**
- Add to `LANGUAGE_CODES` and `LANGUAGE_NAME_TO_CODE` mappings
- Add glossary entries in `glossary.json`
- Test with sample properties files
- Use a TDD approach for fixing bugs and implementing new features
- Make sure to run all python commands in the venv virtual environment