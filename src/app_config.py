"""Application configuration module for the translation service."""
import logging
import os
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

import yaml
from dotenv import load_dotenv
from openai import AsyncOpenAI

from src.logging_config import setup_logger


@dataclass
class AppConfig:
    """Application configuration dataclass."""
    # Core paths
    project_root: str
    target_project_root: str
    input_folder: str
    glossary_file_path: str

    # Model configuration
    model_name: str
    review_model_name: str
    max_model_tokens: int

    # Processing settings
    dry_run: bool
    holistic_review_chunk_size: int
    max_concurrent_api_calls: int

    # Language configuration
    language_codes: Dict[str, str]
    name_to_code: Dict[str, str]
    style_rules: Dict[str, List[str]]
    precomputed_style_rules_text: Dict[str, str]
    brand_glossary: List[str]

    # Queue settings
    translation_queue_folder: str
    translated_queue_folder: str
    preserve_queues_for_debug: bool

    # OpenAI client
    openai_client: Optional[AsyncOpenAI]


def _compute_project_root() -> str:
    """Compute the project root directory."""
    script_real_path = os.path.realpath(__file__)
    script_dir = os.path.dirname(script_real_path)
    return os.path.abspath(os.path.join(script_dir, os.pardir))


def _load_dotenv_files(project_root: str) -> None:
    """Load .env files from project root or docker directory."""
    dotenv_path_project_root = os.path.join(project_root, '.env')
    dotenv_path_docker_dir = os.path.join(project_root, 'docker', '.env')

    if os.path.exists(dotenv_path_project_root):
        load_dotenv(dotenv_path_project_root)
    elif os.path.exists(dotenv_path_docker_dir):
        load_dotenv(dotenv_path_docker_dir)


def _load_yaml_config(project_root: str) -> Dict[str, Any]:
    """Load YAML configuration file with enhanced error handling and path resolution."""
    # If TRANSLATOR_CONFIG_FILE is set (potentially from .env), use it; otherwise, default to 'config.yaml'.
    default_config_path = os.path.join(project_root, 'config.yaml')
    config_file = os.environ.get('TRANSLATOR_CONFIG_FILE', default_config_path)

    # Ensure we have an absolute path for better error reporting
    if not os.path.isabs(config_file):
        config_file = os.path.abspath(config_file)

    config = {}
    try:
        # Check if file exists and is readable
        if not os.path.exists(config_file):
            print(f"Warning: Configuration file '{config_file}' not found. Using default configuration.",
                  file=sys.stderr)
            print(f"Tip: Create a config.yaml file in '{project_root}' or set TRANSLATOR_CONFIG_FILE environment variable.",
                  file=sys.stderr)
            return config

        if not os.access(config_file, os.R_OK):
            print(f"Error: Configuration file '{config_file}' exists but is not readable. Check file permissions.",
                  file=sys.stderr)
            return config

        with open(config_file, 'r', encoding='utf-8') as config_file_stream:
            loaded_config = yaml.safe_load(config_file_stream)
            if loaded_config is None:
                print(f"Warning: Configuration file '{config_file}' is empty. Using default configuration.",
                      file=sys.stderr)
            elif isinstance(loaded_config, dict):
                config = loaded_config
                print(f"Successfully loaded configuration from: {config_file}", file=sys.stderr)
            else:
                print(f"Error: Configuration file '{config_file}' must contain a YAML dictionary. Using defaults.",
                      file=sys.stderr)

    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML in configuration file '{config_file}': {e}", file=sys.stderr)
        print("Please check your YAML syntax. Using default configuration.", file=sys.stderr)
    except (OSError, IOError) as e:
        print(f"Error: Could not read configuration file '{config_file}': {e}", file=sys.stderr)
        print("Using default configuration.", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error loading configuration file '{config_file}': {e}", file=sys.stderr)
        print("Using default configuration.", file=sys.stderr)

    return config


def _setup_logger_from_config(config: Dict[str, Any]) -> logging.Logger:
    """Set up logger based on configuration."""
    log_config = config.get('logging', {})
    log_level_str = log_config.get('log_level', 'INFO').upper()
    log_file_path = log_config.get('log_file_path', 'logs/translation_log.log')
    log_to_console = log_config.get('log_to_console', True)
    return setup_logger(log_level_str, log_file_path, log_to_console)


def _log_dotenv_status(logger: logging.Logger, project_root: str) -> None:
    """Log the status of .env file loading."""
    dotenv_path_project_root = os.path.join(project_root, '.env')
    dotenv_path_docker_dir = os.path.join(project_root, 'docker', '.env')

    if os.path.exists(dotenv_path_project_root):
        logger.info("Loaded environment variables from: %s", dotenv_path_project_root)
    elif os.path.exists(dotenv_path_docker_dir):
        logger.info("Loaded environment variables from: %s", dotenv_path_docker_dir)
    else:
        logger.info(
            "No .env file found in project root ('%s') or in docker/ ('%s'). Relying on system environment variables if any.",
            dotenv_path_project_root,
            dotenv_path_docker_dir
        )


def _build_language_mappings(locales_list: List[Dict[str, str]]) -> tuple[Dict[str, str], Dict[str, str]]:
    """Build language code mappings from supported locales."""
    language_codes: Dict[str, str] = {}
    name_to_code: Dict[str, str] = {}

    for locale in locales_list:
        code = locale.get('code')
        name = locale.get('name')
        if code and name:
            language_codes[code] = name
            name_to_code[name.lower()] = code

    return language_codes, name_to_code


def _precompute_style_rules(style_rules: Dict[str, List[str]], language_codes: Dict[str, str]) -> Dict[str, str]:
    """Pre-compute formatted style rules text for each language."""
    precomputed_style_rules_text: Dict[str, str] = {}

    for code, rules in style_rules.items():
        if rules:
            language_name = language_codes.get(code, code)
            rules_list = "\n".join([f"- {rule}" for rule in rules])
            precomputed_style_rules_text[code] = f"**Language-Specific Quality Checklist ({language_name})**:\n{rules_list}"
        else:
            precomputed_style_rules_text[code] = ""

    return precomputed_style_rules_text


def _create_openai_client(dry_run: bool, logger: logging.Logger) -> Optional[AsyncOpenAI]:
    """Create OpenAI client if not in dry run mode with enhanced error handling."""
    if dry_run:
        logger.info("Running in dry-run mode, OpenAI client will not be initialized")
        return None

    api_key_from_env = os.environ.get('OPENAI_API_KEY')
    if not api_key_from_env:
        logger.critical("CRITICAL: OPENAI_API_KEY environment variable not found.")
        logger.critical("Please set OPENAI_API_KEY or enable dry_run mode in configuration.")
        logger.critical("For dry-run mode, set 'dry_run: true' in your config file.")
        sys.exit(1)

    # Validate API key format
    if not api_key_from_env.startswith('sk-'):
        logger.warning("Warning: OPENAI_API_KEY does not start with 'sk-'. This may be invalid.")

    try:
        client = AsyncOpenAI(api_key=api_key_from_env)
        logger.info("OpenAI client initialized successfully")
        return client
    except Exception as e:
        logger.critical("Failed to initialize OpenAI client: %s", str(e))
        logger.critical("Please check your OPENAI_API_KEY and network connectivity.")
        sys.exit(1)


def load_app_config() -> AppConfig:
    """
    Load application configuration from YAML file and environment variables.

    Returns:
        AppConfig: The loaded application configuration.
    """
    # Compute project root
    project_root = _compute_project_root()

    # Load .env files
    _load_dotenv_files(project_root)

    # Load YAML configuration
    config = _load_yaml_config(project_root)

    # Set up logger
    logger = _setup_logger_from_config(config)

    # Log .env status now that logger is available
    _log_dotenv_status(logger, project_root)

    # Build language mappings
    locales_list = config.get('supported_locales', [])
    language_codes, name_to_code = _build_language_mappings(locales_list)

    # Process style rules
    style_rules = config.get('style_rules', {})
    precomputed_style_rules_text = _precompute_style_rules(style_rules, language_codes)

    # Get configuration values with defaults
    dry_run = config.get('dry_run', False)
    model_name = config.get('model_name', 'gpt-4')
    review_model_name = os.environ.get('REVIEW_MODEL_NAME', config.get('review_model_name', model_name))

    # Holistic review chunk size with environment override
    # Reduced default from 75 to 30 to handle content-heavy files better
    default_chunk_size = config.get('holistic_review_chunk_size', 30)
    holistic_review_chunk_size = int(os.environ.get('HOLISTIC_REVIEW_CHUNK_SIZE', default_chunk_size))

    # Queue folders
    temp_dir = tempfile.gettempdir()
    translation_queue_name = config.get('translation_queue_folder', 'translation_queue')
    translated_queue_name = config.get('translated_queue_folder', 'translated_queue')
    translation_queue_folder = os.path.join(temp_dir, translation_queue_name)
    translated_queue_folder = os.path.join(temp_dir, translated_queue_name)

    # Create OpenAI client
    openai_client = _create_openai_client(dry_run, logger)

    return AppConfig(
        project_root=project_root,
        target_project_root=config.get('target_project_root', '/path/to/default/repo/root'),
        input_folder=config.get('input_folder', '/path/to/default/input_folder'),
        glossary_file_path=config.get('glossary_file_path', 'glossary.json'),
        model_name=model_name,
        review_model_name=review_model_name,
        max_model_tokens=config.get('max_model_tokens', 4000),
        dry_run=dry_run,
        holistic_review_chunk_size=holistic_review_chunk_size,
        max_concurrent_api_calls=config.get('max_concurrent_api_calls', 1),
        language_codes=language_codes,
        name_to_code=name_to_code,
        style_rules=style_rules,
        precomputed_style_rules_text=precomputed_style_rules_text,
        brand_glossary=config.get('brand_technical_glossary', ['MuSig', 'Bisq', 'Lightning', 'I2P', 'Tor']),
        translation_queue_folder=translation_queue_folder,
        translated_queue_folder=translated_queue_folder,
        preserve_queues_for_debug=config.get('preserve_queues_for_debug', False),
        openai_client=openai_client
    )