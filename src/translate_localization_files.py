import asyncio
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from typing import Dict, List, Tuple, Optional

# --- Python Version Check ---
# This script requires Python 3.11 or newer for features like modern asyncio.
if sys.version_info < (3, 11):
    sys.stderr.write("Error: This script requires Python 3.11 or newer.\n")
    sys.stderr.write(f"You are running Python {sys.version.split()[0]}.\n")
    sys.exit(1)
# --- End Version Check ---

import jsonschema
import tiktoken
import yaml
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
from openai import (
    APIConnectionError,
    APIStatusError,
    RateLimitError,
    APITimeoutError,
    OpenAIError
)
from openai import AsyncOpenAI
from openai.types.chat import (
    ChatCompletionSystemMessageParam,
    ChatCompletionUserMessageParam
)
from tqdm.asyncio import tqdm

from src.properties_parser import parse_properties_file, reassemble_file
from src.translation_validator import (
    check_placeholder_parity,
    check_encoding_and_mojibake,
    synchronize_keys
)

# A hardcoded chunk size for the number of keys to be sent in a single
# holistic review API call. This is a safeguard against "request too large"
# token limit errors from the OpenAI API.
HOLISTIC_REVIEW_CHUNK_SIZE = 75

# Define the expected JSON schema for the AI's response in the holistic review.
# This ensures that the AI returns a dictionary where every value is a string.
LOCALIZATION_SCHEMA = {
    "type": "object",
    "patternProperties": {
        "^.*$": {"type": "string"}
    },
    "additionalProperties": False
}

# Determine the correct path to config.yaml relative to the script's location
SCRIPT_REAL_PATH = os.path.realpath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_REAL_PATH)
# Allow overriding the config file path via an environment variable for flexibility.
# If TRANSLATOR_CONFIG_FILE is set, use it; otherwise, default to 'config.yaml'.
_default_config_path = os.path.join(SCRIPT_DIR, '..', 'config.yaml')
CONFIG_FILE = os.environ.get('TRANSLATOR_CONFIG_FILE', _default_config_path)

# Default logging settings if config is unavailable or incomplete
DEFAULT_LOG_FILE_PATH = "logs/translation_log_default.log"
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_TO_CONSOLE = True

config = {}
try:
    with open(CONFIG_FILE, 'r', encoding='utf-8') as config_file_stream:
        loaded_config = yaml.safe_load(config_file_stream)
        if loaded_config:
            config = loaded_config

    logging_config = config.get('logging', {})
    LOG_FILE_PATH = logging_config.get('log_file_path', DEFAULT_LOG_FILE_PATH)
    LOG_LEVEL_STR = logging_config.get('log_level', 'INFO').upper()
    LOG_TO_CONSOLE = logging_config.get('log_to_console', DEFAULT_LOG_TO_CONSOLE)
    LOG_LEVEL = getattr(logging, LOG_LEVEL_STR, DEFAULT_LOG_LEVEL)

except FileNotFoundError:
    print(f"Warning: Configuration file '{CONFIG_FILE}' not found. Using default logging settings.")
    LOG_FILE_PATH = DEFAULT_LOG_FILE_PATH
    LOG_LEVEL = DEFAULT_LOG_LEVEL
    LOG_TO_CONSOLE = DEFAULT_LOG_TO_CONSOLE
except Exception as e:
    print(f"Warning: Error loading or parsing configuration file '{CONFIG_FILE}': {e}. Using default logging settings.")
    LOG_FILE_PATH = DEFAULT_LOG_FILE_PATH
    LOG_LEVEL = DEFAULT_LOG_LEVEL
    LOG_TO_CONSOLE = DEFAULT_LOG_TO_CONSOLE

log_dir_to_create = os.path.dirname(LOG_FILE_PATH)
if log_dir_to_create:
    os.makedirs(log_dir_to_create, exist_ok=True)

handlers = [logging.FileHandler(LOG_FILE_PATH)]
if LOG_TO_CONSOLE:
    handlers.append(logging.StreamHandler())

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers
)

# Load environment variables strategically
# SCRIPT_DIR is .../project_root/src (absolute path)
PROJECT_ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))

dotenv_path_project_root = os.path.join(PROJECT_ROOT_DIR, '.env')
dotenv_path_docker_dir = os.path.join(PROJECT_ROOT_DIR, 'docker', '.env')

if os.path.exists(dotenv_path_project_root):
    load_dotenv(dotenv_path_project_root)
    logging.info("Loaded environment variables from: %s", dotenv_path_project_root)
elif os.path.exists(dotenv_path_docker_dir):
    load_dotenv(dotenv_path_docker_dir)
    logging.info("Loaded environment variables from: %s", dotenv_path_docker_dir)
else:
    logging.info(
        "No .env file found in project root ('%s') or in docker/ ('%s'). Relying on system environment variables if any.",
        dotenv_path_project_root,
        dotenv_path_docker_dir
    )
    # load_dotenv() with no args will search CWD; this is likely redundant if the above checks cover CWD for root.

# Initialize the OpenAI client with your API key
api_key_from_env = os.environ.get('OPENAI_API_KEY')
if not api_key_from_env:
    logging.critical("CRITICAL: OPENAI_API_KEY not found in environment variables. This is required to run the script. Exiting.")
    sys.exit(1)
client = AsyncOpenAI(api_key=api_key_from_env)

# Configuration Parameters (now using the 'config' dictionary loaded above)
# Defaults are provided in .get() for robustness if config file or keys are missing.
REPO_ROOT = config.get('target_project_root', '/path/to/default/repo/root')
INPUT_FOLDER = config.get('input_folder', '/path/to/default/input_folder')
GLOSSARY_FILE_PATH = config.get('glossary_file_path', 'glossary.json')
MODEL_NAME = config.get('model_name', 'gpt-4')
REVIEW_MODEL_NAME = os.environ.get('REVIEW_MODEL_NAME', config.get('review_model_name', MODEL_NAME))

# Decide maximum tokens based on model name or custom logic
MAX_MODEL_TOKENS = 4000  # You can modify this if needed

# Define the translation queue folders
# Use the system's temporary directory for transient data
TEMP_DIR = tempfile.gettempdir() # This will be /tmp inside the container

_translation_queue_name = config.get('translation_queue_folder', 'translation_queue')
_translated_queue_name = config.get('translated_queue_folder', 'translated_queue')

TRANSLATION_QUEUE_FOLDER = os.path.join(TEMP_DIR, _translation_queue_name)
TRANSLATED_QUEUE_FOLDER = os.path.join(TEMP_DIR, _translated_queue_name)

# Dry run configuration (if True, files won't be moved/copied, etc.)
DRY_RUN = config.get('dry_run', False)

# ------------------------------------------------------------------------------
# 1) Remove the LanguageCode Enum and any hard-coded dictionaries
#    Instead, load the supported locales from config.yaml
# ------------------------------------------------------------------------------
locales_list = config.get('supported_locales', [])
LANGUAGE_CODES: Dict[str, str] = {}
NAME_TO_CODE: Dict[str, str] = {}

# 2) Build dictionaries from the "supported_locales" list in config.yaml
for locale in locales_list:
    code = locale.get('code')
    name = locale.get('name')
    if code and name:
        LANGUAGE_CODES[code] = name
        NAME_TO_CODE[name.lower()] = code

# Concurrency configuration
MAX_CONCURRENT_API_CALLS = config.get('max_concurrent_api_calls', 1)

# (Optional) Load language-specific style rules
STYLE_RULES = config.get('style_rules', {})

# Pre-compute formatted style rules text for each language to avoid redundant processing.
# This dictionary will map a language code (e.g., 'de') to a formatted string.
PRECOMPUTED_STYLE_RULES_TEXT: Dict[str, str] = {}
for code, rules in STYLE_RULES.items():
    if rules:
        language_name = LANGUAGE_CODES.get(code, code)
        rules_list = "\n".join([f"- {rule}" for rule in rules])
        PRECOMPUTED_STYLE_RULES_TEXT[code] = f"**Language-Specific Quality Checklist ({language_name})**:\n{rules_list}"
    else:
        PRECOMPUTED_STYLE_RULES_TEXT[code] = ""


# (Optional) Load brand/technical glossary
BRAND_GLOSSARY = config.get('brand_technical_glossary', ['MuSig', 'Bisq', 'Lightning', 'I2P', 'Tor'])


def lint_properties_file(file_path: str) -> List[str]:
    """
    Lints a .properties file to check for common issues.

    Args:
        file_path: The path to the .properties file.

    Returns:
        A list of error messages. An empty list means no errors were found.
    """
    errors = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('!'):
                    continue

                if '=' in line or ':' in line:
                    sep_idx = -1
                    for j, ch in enumerate(line):
                        if ch in ('=', ':') and (j == 0 or line[j - 1] != '\\'):
                            sep_idx = j
                            break
                    if sep_idx == -1:
                        continue
                    key, value = line[:sep_idx], line[sep_idx+1:]
                    key = key.strip()

                    # Check for malformed keys (e.g., double dots)
                    if '..' in key:
                        errors.append(f"Linter Error: Malformed key '{key}' with double dots found on line {i}.")

                    # Temporarily remove a trailing backslash if it's for line continuation,
                    # so it's not incorrectly flagged as an invalid escape sequence.
                    value_to_check = value.rstrip()
                    if value_to_check.endswith('\\'):
                        value_to_check = value_to_check[:-1]

                    # Allow: \t \n \f \r \\ \= \: \# \! space, \", and \uXXXX (4 hex digits)
                    # This regex is loosened to ignore \n and \" which appear in some source files.
                    if re.search(r'\\(?!u[0-g-fA-F]{4}|[tnfr\\=:#\s!"])', value_to_check):
                        errors.append(
                            f"Linter Error: Invalid escape sequence in value for key '{key}' on line {i}."
                        )

    except (IOError, OSError, UnicodeDecodeError) as e:
        errors.append(f"Linter Error: Could not read or process file {file_path}. Reason: {e}")

    return errors


def language_code_to_name(language_code: str) -> Optional[str]:
    """
    Convert a language code to a language name.

    Args:
        language_code (str): The language code (e.g., "cs").

    Returns:
        Optional[str]: The language name if found, else None.
    """
    return LANGUAGE_CODES.get(language_code, None)


def language_name_to_code(target_language: str) -> Optional[str]:
    """
    Convert a language name to a language code.

    Args:
        target_language (str): The language name (e.g., "Czech").

    Returns:
        Optional[str]: The language code if found, else None.
    """
    return NAME_TO_CODE.get(target_language.lower(), None)


def load_glossary(glossary_file_path: str) -> Dict[str, Dict[str, str]]:
    """
    Load the glossary from a JSON file.

    Args:
        glossary_file_path (str): The path to the glossary JSON file.

    Returns:
        Dict[str, Dict[str, str]]: A dictionary containing the glossary data.
    """
    if not os.path.exists(glossary_file_path):
        logging.error(f"Glossary file '{glossary_file_path}' not found.")
        return {}
    try:
        with open(glossary_file_path, 'r', encoding='utf-8') as f:
            glossary = json.load(f)
        return glossary
    except json.JSONDecodeError as json_exc:
        logging.error(f"Error decoding JSON glossary file: {json_exc}")
        return {}
    except Exception as general_exc:
        logging.error(f"An unexpected error occurred while loading the glossary: {general_exc}")
        return {}

def normalize_value(value: Optional[str]) -> str:
    """
    Normalize a value by replacing special characters and normalizing whitespace.

    Args:
        value (Optional[str]): The value to normalize.

    Returns:
        str: The normalized value.
    """
    if value is None:
        return ''
    # Replace escaped newline characters (\n) with a placeholder
    value = value.replace('\\n', '<newline>')
    # Replace actual newline characters with the same placeholder
    value = value.replace('\n', '<newline>')
    # Remove leading/trailing whitespace and normalize inner whitespace
    value = re.sub(r'\s+', ' ', value.strip())
    return value


def extract_texts_to_translate(
        parsed_lines: List[Dict],
        source_translations: Dict[str, str],
        target_translations: Dict[str, str]
) -> Tuple[List[str], List[int], List[str]]:
    """
    Identifies which texts need to be translated. A text needs translation if:
    1. The key is new (exists in source, not in target).
    2. The key exists in both, but the source and target values are identical,
       indicating an untranslated string copied from the source by a tool like Transifex.

    Args:
        parsed_lines: The parsed content of the target language file.
        source_translations: A dictionary of key-value pairs from the source (e.g., English) file.
        target_translations: A dictionary of key-value pairs from the target file being processed.

    Returns:
        A tuple containing the list of texts to translate, their corresponding indices, and their keys.
    """
    texts_to_translate = []
    indices = []
    keys_to_translate = []

    existing_keys_in_target = {line['key'] for line in parsed_lines if line['type'] == 'entry'}

    # 1. Check existing keys for required updates.
    # A key needs translation if the source value is THE SAME as the target value,
    # as this indicates a fallback to the source language.
    for i, line in enumerate(parsed_lines):
        if line['type'] == 'entry':
            key = line['key']
            target_value = line.get('value', '')
            source_value = source_translations.get(key)

            # If key exists in source and the values are identical (a direct string comparison),
            # it needs translation. This handles cases where Transifex might have copied
            # the source English text into the target file.
            if source_value is not None and source_value.strip() == target_value.strip():
                # The value to translate is the source value.
                texts_to_translate.append(source_value)
                indices.append(i)  # Use the line's actual index
                keys_to_translate.append(key)

    # 2. Find new keys that are in the source but not in the target file.
    new_keys = source_translations.keys() - existing_keys_in_target

    # Start indexing for new keys from after the last line of the parsed file
    next_new_key_index = len(parsed_lines)

    for key in sorted(list(new_keys)):  # Sort for deterministic order
        source_value = source_translations[key]
        texts_to_translate.append(source_value)
        indices.append(next_new_key_index)
        keys_to_translate.append(key)
        next_new_key_index += 1

    return texts_to_translate, indices, keys_to_translate


def count_tokens(text: str, model_name: str = 'gpt-3.5-turbo') -> int:
    """Count the number of tokens in ``text`` for ``model_name``.

    ``tiktoken.encoding_for_model`` occasionally attempts a network request to
    download model data if it is not already cached. Network access is not
    guaranteed in all environments (e.g., in CI). If obtaining the encoding for
    the requested model fails, the function falls back to ``gpt2`` which ships
    with ``tiktoken``. As a last resort, a simple whitespace split is used.
    """

    try:
        encoding = tiktoken.encoding_for_model(model_name)
    except Exception:
        try:
            encoding = tiktoken.get_encoding("gpt2")
        except Exception:
            return len(text.split())

    try:
        return len(encoding.encode(text))
    except Exception:
        return len(text.split())


def build_context(
        existing_translations: Dict[str, str],
        source_translations: Dict[str, str],
        language_glossary: Dict[str, str],
        max_tokens: int,
        model_name: str
) -> Tuple[str, str]:
    """
    Build the context and glossary text for the translation prompt.

    Args:
        existing_translations (Dict[str, str]): Existing translations in the target language.
        source_translations (Dict[str, str]): Source translations (in English).
        language_glossary (Dict[str, str]): The glossary for the language.
        max_tokens (int): Maximum allowed tokens.
        model_name (str): The model name.

    Returns:
        Tuple[str, str]: The context examples text and glossary text.
    """
    context_examples = []
    total_tokens = 0

    # Build glossary entries
    glossary_entries = [f'"{k}" should be translated as "{v}"' for k, v in language_glossary.items()]
    glossary_text = '\n'.join(glossary_entries)
    glossary_tokens = count_tokens(glossary_text, model_name)

    # Reserve tokens for the rest of the prompt and response
    reserved_tokens = 1000  # Adjust based on your needs
    available_tokens = max_tokens - glossary_tokens - reserved_tokens

    # Iterate over existing translations
    for key, translated_value in existing_translations.items():
        source_value = source_translations.get(key)
        if not source_value:
            continue  # Skip if source value is missing

        # Normalize values
        normalized_source = normalize_value(source_value)
        normalized_translation = normalize_value(translated_value)

        # Check if the translation is different from the source
        if normalized_source == normalized_translation:
            continue  # Skip untranslated entries

        # Create context example
        example = f"{key} = \"{translated_value}\""
        example_tokens = count_tokens(example, model_name)
        if total_tokens + example_tokens > available_tokens:
            break
        context_examples.append(example)
        total_tokens += example_tokens

    context_text = '\n'.join(context_examples)
    return context_text, glossary_text


def extract_placeholders(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Extract and replace placeholders in the text with unique tokens.

    Args:
        text (str): The text to process.

    Returns:
        Tuple[str, Dict[str, str]]: The processed text and placeholder mapping.
    """
    if not isinstance(text, str):
        raise ValueError("Input text must be a string.")

    # Pattern to match placeholders like `{0}` or `{name}` and HTML-like tags
    pattern = re.compile(r'(<[^<>]+>)|({[^{}]+})')
    placeholder_mapping = {}

    def replace_placeholder(match):
        full_match = match.group(0)
        placeholder_token = f"__PH_{uuid.uuid4().hex}__"
        placeholder_mapping[placeholder_token] = full_match
        return placeholder_token

    processed_text = pattern.sub(replace_placeholder, text)
    return processed_text, placeholder_mapping


def restore_placeholders(text: str, placeholder_mapping: Dict[str, str]) -> str:
    """
    Restore placeholders in the text from the placeholder mapping.

    Args:
        text (str): The text with placeholder tokens.
        placeholder_mapping (Dict[str, str]): The placeholder mapping.

    Returns:
        str: The text with placeholders restored.
    """
    for token, placeholder in placeholder_mapping.items():
        text = text.replace(token, placeholder)
    return text


def clean_translated_text(translated_text: str, original_text: str) -> str:
    """
    Cleans the translated text by removing leading/trailing quotes and ensuring
    that the text is not surrounded by unwanted characters.

    Args:
        translated_text (str): The translated text.
        original_text (str): The original text.

    Returns:
        str: The cleaned translated text.
    """
    # Remove leading/trailing quotes if they are not in the original text
    if translated_text.startswith('"') and translated_text.endswith('"') and not (
            original_text.startswith('"') and original_text.endswith('"')):
        translated_text = translated_text[1:-1]
    # Remove square brackets if they are not in the original text
    if translated_text.startswith('[') and translated_text.endswith(']') and not (
            original_text.startswith('[') and original_text.endswith(']')):
        translated_text = translated_text[1:-1]
    return translated_text


async def _handle_retry(attempt: int, max_retries: int, base_delay: float, key: str,
                        api_exc: Optional[Exception] = None) -> bool:
    """
    Handle the retry mechanism with exponential backoff and jitter.

    Args:
        attempt (int): The current attempt number.
        max_retries (int): The maximum number of retry attempts.
        base_delay (float): The base delay in seconds.
        key (str): The key being translated.
        api_exc (Optional[Exception]): The exception object from the API, if available.

    Returns:
        bool: True if the operation should retry, False otherwise.
    """
    if attempt < max_retries:
        try:
            retry_after = None
            if api_exc and isinstance(api_exc, OpenAIError):
                retry_after_header = getattr(api_exc, "headers", {}).get("Retry-After")
                if retry_after_header:
                    if retry_after_header.isdigit():
                        retry_after = float(retry_after_header)  # Handle delay in seconds
                    elif retry_after_header.endswith("ms"):
                        retry_after = float(retry_after_header[:-2]) / 1000  # Convert ms to seconds
            if retry_after is None:
                retry_after = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
            delay = retry_after
        except Exception as exc:
            logging.warning(f"Failed to parse Retry-After header: {exc}. Falling back to exponential backoff.")
            delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
        logging.info(
            f"Retrying request to /chat/completions in {delay:.2f} seconds (Attempt {attempt}/{max_retries})")
        await asyncio.sleep(delay)
        return True
    else:
        logging.error(f"Translation failed for key '{key}' after {max_retries} attempts.")
        return False


async def run_pre_translation_validation(target_file_path: str, source_file_path: str) -> List[str]:
    """
    Runs a series of validation and preparation checks on a target properties file.
    - Synchronizes keys with the source file (adds missing, removes extra).
    - Checks for encoding issues and placeholder mismatches.

    Args:
        target_file_path: The absolute path to the target language .properties file.
        source_file_path: The absolute path to the source English .properties file.

    Returns:
        A list of validation error messages. An empty list indicates success.
    """
    errors: List[str] = []
    filename = os.path.basename(target_file_path)
    logging.info(f"Running pre-translation validation for '{filename}'...")

    # 1. Synchronize keys (add missing, remove extra)
    try:
        synchronize_keys(target_file_path, source_file_path)
        logging.info(f"Key synchronization complete for '{filename}'.")
    except (IOError, OSError) as e:
        logging.exception("Failed to synchronize keys for '%s'", filename)
        errors.append(f"I/O error during key synchronization: {e}")
        return errors  # Fail hard if we can't even sync the file

    # 2. Check encoding and mojibake on the (potentially modified) file
    encoding_errors = check_encoding_and_mojibake(target_file_path)
    if encoding_errors:
        errors.extend(encoding_errors)

    # Load file content for placeholder check
    try:
        # Re-parse the files as they might have been changed by synchronize_keys
        _, target_translations = parse_properties_file(target_file_path)
        _, source_translations = parse_properties_file(source_file_path)
    except (IOError, OSError) as e:
        logging.exception("Validation failed for '%s': Could not parse properties file after key sync", filename)
        errors.append(f"Could not parse properties file after key sync: {e}")
        return errors

    # 3. Check placeholder parity
    common_keys = set(source_translations.keys()).intersection(set(target_translations.keys()))
    for key in common_keys:
        source_value = source_translations.get(key, "")
        target_value = target_translations.get(key, "")
        if not check_placeholder_parity(source_value, target_value):
            errors.append(f"Placeholder mismatch for key `{key}`.")

    if not errors:
        logging.info(f"Pre-translation validation passed for '{filename}'.")
    else:
        logging.error(f"Pre-translation validation failed for '{filename}'.")

    return errors


def run_post_translation_validation(
    final_content: str,
    source_translations: Dict[str, str],
    filename: str
) -> bool:
    """
    Runs a series of validation checks on the final translated file content.

    Args:
        final_content: The string content of the fully translated file.
        source_translations: The original source (English) translations dictionary.
        filename: The name of the file being validated.

    Returns:
        True if all checks pass, False otherwise.
    """
    is_valid = True
    logging.info(f"Running post-translation validation for '{filename}'...")

    temp_file_path = None
    try:
        # Create a temporary file with delete=False to control its lifecycle.
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.properties', encoding='utf-8') as temp_f:
            temp_file_path = temp_f.name
            temp_f.write(final_content)
            temp_f.flush()

        # Now the file is closed, but still exists. We can pass its path to validators.
        
        # 1. Check encoding and mojibake on the final content
        encoding_errors = check_encoding_and_mojibake(temp_file_path)
        if encoding_errors:
            is_valid = False
            for error in encoding_errors:
                logging.error(f"Post-translation validation failed for '{filename}': {error}")
        
        # 2. Check placeholder parity on the final content
        try:
            _, final_translations = parse_properties_file(temp_file_path)
            common_keys = set(source_translations.keys()).intersection(set(final_translations.keys()))
            for key in common_keys:
                source_value = source_translations.get(key, "")
                target_value = final_translations.get(key, "")
                if not check_placeholder_parity(source_value, target_value):
                    is_valid = False
                    logging.error(f"Post-translation validation failed for '{filename}': Placeholder mismatch for key '{key}'.")
        except (IOError, OSError):
            is_valid = False
            logging.exception("Post-translation validation failed for '%s': Could not parse final properties content", filename)

    finally:
        # Ensure the temporary file is cleaned up
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as _e:
                logging.warning("Could not delete temporary validation file '%s': %s", temp_file_path, _e)

    if is_valid:
        logging.info(f"Post-translation validation passed for '{filename}'.")
    else:
        logging.error(f"Post-translation validation failed for '{filename}'. AI-generated content is invalid and will be discarded.")

    return is_valid


async def translate_text_async(
        text: str,
        key: str,
        existing_translations: Dict[str, str],
        source_translations: Dict[str, str],
        target_language: str,
        glossary: Dict[str, Dict[str, str]],
        semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter,
        index: int
) -> Tuple[int, str]:
    """
    Asynchronously translate a single text with context.

    Args:
        text (str): The text to translate.
        key (str): The key associated with the text.
        existing_translations (Dict[str, str]): Existing translations in the target language.
        source_translations (Dict[str, str]): Source translations (in English).
        target_language (str): The target language (e.g., "German").
        glossary (Dict[str, Dict[str, str]]): The glossary.
        semaphore (asyncio.Semaphore): A semaphore to limit concurrent API calls.
        rate_limiter (AsyncLimiter): A rate limiter to control the rate of API calls.
        index (int): The index of the text in the original list.

    Returns:
        Tuple[int, str]: The index and the translated text.
    """
    async with semaphore, rate_limiter:
        # 3) Use language_name_to_code instead of an Enum
        language_code = language_name_to_code(target_language)

        # If the language isn't recognized, just return original text
        if not language_code:
            logging.warning(f"Unsupported or unrecognized language: {target_language}")
            return index, text

        # Get the glossary for the current language
        language_glossary = glossary.get(language_code, {})

        # Get pre-computed language-specific style rules
        style_rules_text = PRECOMPUTED_STYLE_RULES_TEXT.get(language_code, "")

        # Build the context and glossary text
        context_examples_text, glossary_text = build_context(
            existing_translations,
            source_translations,
            language_glossary,
            MAX_MODEL_TOKENS,
            MODEL_NAME
        )

        # Extract and protect placeholders
        processed_text, placeholder_mapping = extract_placeholders(text)

        system_prompt = f"""
You are an expert translator specializing in software localization. Translate the following text from English to {target_language}, considering the context and glossary provided.

**Instructions**:
- **Do not translate or modify placeholder tokens**: Any text enclosed within double underscores `__` (e.g., `__PH_abc123__`) should remain exactly as is.
- **Strictly follow all glossaries**:
  - **Brand/Technical Glossary**: These terms MUST NOT be translated. Preserve their original casing and form.
  - **Translation Glossary**: These terms are non-negotiable. You MUST use the provided translation, matching the source term case-insensitively.
- **Preserve formatting**: Keep special characters and formatting such as `\\n` and `\\t`.
- **Do not add** any additional characters or punctuation (e.g., no square brackets, quotation marks, etc.).
- **Provide only** the translated text corresponding to the Value.
- **Do not escape single quotes**: Treat single quotes (') as literal characters. The system will handle necessary escaping.

Use the translations specified in the glossary for the given terms. Ensure the translation reads naturally and is culturally appropriate for the target audience.

**Style and Tone Guidelines**:
- **Professional and Reassuring**: The tone should be professional, clear, and reassuring. Avoid overly casual or informal language.
- **No Mixed Languages**: Do not mix English terms with the target language in a single phrase (e.g., "Seed Words Confermati!"). The translation should be fully localized.
- **Language-Specific Conventions**: Adhere to conventions of the target language.

{style_rules_text}

The translation is for a desktop trading app called Bisq. Keep the translations brief and consistent with typical software terminology. On Bisq, you can buy and sell bitcoin for fiat (or other cryptocurrencies) privately and securely using Bisq's peer-to-peer network and open-source desktop software. "Bisq Easy" is a brand name and should not be translated.
"""

        brand_glossary_text = '\n'.join(f"- {term}" for term in dict.fromkeys(BRAND_GLOSSARY))
        prompt = """
**Brand/Technical Glossary (Do NOT translate these terms):**
{brand_glossary_text}

**Translation Glossary:**
{glossary_text}

**Context (Existing Translations):**
{context_examples_text}

**Text to Translate:**
Key: {key}
Value: {processed_text}

Provide the translation **of the Value only**, following the instructions above.
"""

        max_retries = 5
        base_delay = 1

        for attempt in range(1, max_retries + 1): # type: ignore[arg-type]
            try:
                # Use chat completion API
                response = await client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[
                        ChatCompletionSystemMessageParam(role="system", content=system_prompt),
                        ChatCompletionUserMessageParam(role="user", content=prompt.format(
                            brand_glossary_text=brand_glossary_text,
                            glossary_text=glossary_text,
                            context_examples_text=context_examples_text,
                            key=key,
                            processed_text=processed_text
                        ))
                    ],
                    temperature=0.3,
                    timeout=60.0,
                )

                translated_text = response.choices[0].message.content.strip() # type: ignore[arg-type]

                # Restore placeholders in the translated text
                translated_text = restore_placeholders(translated_text, placeholder_mapping)

                # Clean the translated text
                translated_text = clean_translated_text(translated_text, text)

                logging.debug(f"Translated key '{key}' successfully.")
                return index, translated_text

            except (RateLimitError, APITimeoutError, APIConnectionError, APIStatusError, OpenAIError) as api_exc:
                logging.error(f"API error occurred: {api_exc.__class__.__name__} - {api_exc}")
                should_retry = await _handle_retry(attempt, max_retries, base_delay, key, api_exc)
                if should_retry:
                    continue
                else:
                    return index, text
            except Exception as general_exc:
                logging.error(f"An unexpected error occurred: {general_exc}", exc_info=True)
                return index, text

        # Fallback return statement to satisfy linters and ensure explicit return
        logging.warning(
            f"Translation loop for key '{key}' completed without an explicit return within the loop. "
            f"This shouldn't happen with current logic. Returning original text."
        )
        return index, text


def _build_holistic_review_system_prompt(
    target_language: str,
    keys_to_review: List[str],
    source_content: str,
    translated_content: str,
    style_rules_text: str  # Pass pre-computed rules
) -> str:
    """Builds the system prompt for the holistic review API call."""
    keys_to_review_text = "\n".join([f"- {k}" for k in keys_to_review])

    return f"""
You are a lead editor and quality assurance specialist for software localization. Your task is to review a list of newly translated keys within a `.properties` file for {target_language}. You are given the full source and translated files for context, but you MUST only review and return the keys specified.

**Critical Instructions**:
1.  **Strictly Limited Scope**: You MUST only review and provide corrected translations for the following keys. Do NOT output any other keys in your final JSON.
    ```
    {keys_to_review_text}
    ```
2.  **Apply All Quality Rules**: Meticulously apply the language-specific quality checklist to every key in your scope.
3.  **Do Not Escape Single Quotes**: The system will handle all necessary escaping for Java `MessageFormat`. Return single quotes (') as literal characters in the JSON values.
4.  **Output JSON Only**: Your final output **must** be a single, valid JSON object that adheres to the required schema. This object should contain ONLY the keys listed in the "Strictly Limited Scope" section above, with their final, corrected translations as the values.
5.  **Do Not Add Explanations**: Do not output any text, markdown, or explanations before or after the JSON object.

{style_rules_text}

**JSON Output Example**:
```json
{{
  "key.one": "Corrected translation for key one.",
  "key.two": "Corrected translation for key two."
}}
```

**Review Request**:
Return a JSON object containing the fully corrected translations for the following files.

**Source (English) File**:
```properties
{source_content}
```

**Translated ({target_language}) File to Review**:
```properties
{translated_content}
```
"""


async def holistic_review_async(
        source_content: str,
        translated_content: str,
        target_language: str,
        keys_to_review: List[str],
        semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter,
        style_rules_text: str
) -> Optional[Dict[str, str]]:
    """
    Performs a holistic review of an entire translated file and returns corrections
    as a JSON object.

    Args:
        source_content (str): The full content of the source (English) .properties file.
        translated_content (str): The full content of the draft translated .properties file.
        target_language (str): The target language of the translation.
        keys_to_review (List[str]): The specific list of keys to review and return.
        semaphore (asyncio.Semaphore): For concurrency control.
        rate_limiter (AsyncLimiter): For rate limiting.

    Returns:
        Optional[Dict[str, str]]: A dictionary of corrected key-value pairs, or None if review fails.
    """
    async with semaphore, rate_limiter:
        review_system_prompt = _build_holistic_review_system_prompt(
            target_language=target_language,
            keys_to_review=keys_to_review,
            source_content=source_content,
            translated_content=translated_content,
            style_rules_text=style_rules_text
        )
        max_retries = 3
        base_delay = 5  # Longer delay for a potentially larger task
        for attempt in range(1, max_retries + 1):
            try:
                response = await client.chat.completions.create(
                    model=REVIEW_MODEL_NAME,
                    messages=[
                        ChatCompletionSystemMessageParam(role="system", content=review_system_prompt)
                    ],
                    temperature=0.1,
                    response_format={"type": "json_object"},
                    max_tokens=4096,  # Increase tokens to avoid truncation
                    timeout=120.0,
                )
                response_text = response.choices[0].message.content.strip()
                
                # The response should be a JSON string. Parse and validate it.
                parsed_json = json.loads(response_text)
                jsonschema.validate(instance=parsed_json, schema=LOCALIZATION_SCHEMA)
                return parsed_json

            except json.JSONDecodeError as json_exc:
                logging.error(f"Holistic review failed: AI did not return valid JSON. Error: {json_exc}")
                logging.debug(f"Invalid AI response (JSON Decode Error):\n---\n{response_text}\n---")
                # Fall through to retry logic
            except jsonschema.ValidationError as schema_exc:
                logging.error(f"Holistic review failed: AI response did not match the required JSON schema. Error: {schema_exc.message}")
                logging.debug(f"Invalid AI response (Schema Error):\n---\n{response_text}\n---")
                # Fall through to retry logic

            except (RateLimitError, APITimeoutError, APIConnectionError, APIStatusError, OpenAIError) as api_exc:
                logging.warning(f"API error during holistic review: {api_exc}")
                should_retry = await _handle_retry(attempt, max_retries, base_delay, "holistic_review", api_exc)
                if not should_retry:
                    return None
            except Exception as e:
                logging.error(f"Unexpected error during holistic review: {e}", exc_info=True)
                return None # Do not retry on unexpected errors

            # If we're here, it means a JSON or Schema error occurred. We should retry.
            should_retry = await _handle_retry(attempt, max_retries, base_delay, "holistic_review_validation")
            if not should_retry:
                return None
        
        return None  # Fallback after all retries


def _escape_messageformat_if_needed(src_text: str, value: str) -> str:
    if re.search(r'\{[^{}]+\}', src_text):
        value = value.replace("''", "'")
        value = value.replace("'", "''")
    return value


def integrate_translations(
        parsed_lines: List[Dict],
        translations: List[str],
        indices: List[int],
        keys: List[str],
        source_translations: Dict[str, str]
) -> List[Dict]:
    """
    Integrate translated texts back into the parsed lines.

    Args:
        parsed_lines (List[Dict]): The parsed lines from the target file.
        translations (List[str]): The list of translated texts.
        indices (List[int]): The indices where the translations should be inserted.
        keys (List[str]): The keys associated with the translations.
        source_translations (Dict[str, str]): The source translations for context.

    Returns:
        List[Dict]: The updated parsed lines.
    """
    for idx, (translation_idx, key) in enumerate(zip(indices, keys)):
        translated_text = translations[idx]
        original_source_text = source_translations.get(key, "")

        translated_text = _escape_messageformat_if_needed(original_source_text, translated_text)

        if translation_idx < len(parsed_lines):
            # Update existing entry
            line_info = parsed_lines[translation_idx]
            line_info['value'] = translated_text
            logging.debug(f"Integrated translation for key '{key}': '{translated_text}'")
        else:
            # This logic branch for adding completely new keys might need refinement
            # if we expect new keys to also require quote escaping. For now, we assume
            # they follow the same logic based on their source_text.
            parsed_lines.append({
                'type': 'entry',
                'key': key,
                'value': translated_text,
                'original_value': translated_text,
                'line_number': translation_idx
            })
            logging.debug(f"Appended new translation for key '{key}': '{translated_text}'")

    return parsed_lines


def extract_language_from_filename(filename: str, supported_codes: List[str]) -> Optional[str]:
    """
    Extract the language code from a filename by checking against a list of supported codes.

    Args:
        filename (str): The filename.
        supported_codes (List[str]): A list of supported language codes.

    Returns:
        Optional[str]: The language code if found, else None.
    """
    # Sort codes by length, longest first, to handle cases like 'pt_BR' before 'pt'
    # if 'pt' were ever a supported code.
    sorted_codes = sorted(supported_codes, key=len, reverse=True)
    for code in sorted_codes:
        if filename.endswith(f'_{code}.properties'):
            return code
    return None


def move_files_to_archive(input_folder_path: str, archive_folder_path: str):
    """
    Move processed files to an archive folder.

    Args:
        input_folder_path (str): The input folder path.
        archive_folder_path (str): The archive folder path.
    """
    os.makedirs(archive_folder_path, exist_ok=True)
    for filename in os.listdir(input_folder_path):
        if filename.endswith('.properties') and re.search(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', filename):
            source_path = os.path.join(input_folder_path, filename)
            dest_path = os.path.join(archive_folder_path, filename)

            if DRY_RUN:
                logging.info(f"[Dry Run] Would move file '{source_path}' to '{dest_path}'.")
            else:
                shutil.move(source_path, dest_path)
                logging.info(f"Moved file '{source_path}' to '{dest_path}'.")
    logging.info(f"All translation files in '{input_folder_path}' have been archived.")


def copy_translated_files_back(
        translated_queue_folder: str,
        input_folder_path: str
):
    """
    Copy translated translation files back to the input folder, overwriting existing ones.

    Args:
        translated_queue_folder (str): The folder containing translated files.
        input_folder_path (str): The input folder path.
    """
    for filename in os.listdir(translated_queue_folder):
        if filename.endswith('.properties') and re.search(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', filename):
            translated_file_path = os.path.join(translated_queue_folder, filename)
            dest_path = os.path.join(input_folder_path, filename)

            if DRY_RUN:
                logging.info(f"[Dry Run] Would copy translated file '{translated_file_path}' back to '{dest_path}'.")
            else:
                shutil.copy2(translated_file_path, dest_path)
                logging.info(f"Copied translated file '{translated_file_path}' back to '{dest_path}'.")


def validate_paths(input_folder: str, translation_queue: str, translated_queue: str, repo_root: str):
    """
    Validate that the input and queue folders exist and are accessible.

    Args:
        input_folder (str): Path to the input folder.
        translation_queue (str): Path to the translation queue folder.
        translated_queue (str): Path to the translated queue folder.
        repo_root (str): Path to the Git repository root.
    """
    for path, name in [(input_folder, "Input Folder"),
                       (translation_queue, "Translation Queue Folder"),
                       (translated_queue, "Translated Queue Folder"),
                       (repo_root, "Repository Root")]:
        if not os.path.exists(path):
            logging.error(f"{name} '{path}' does not exist.")
            raise FileNotFoundError(f"{name} '{path}' does not exist.")
        if not os.access(path, os.R_OK | os.W_OK):
            logging.error(f"{name} '{path}' is not accessible (read/write permissions needed).")
            raise PermissionError(f"{name} '{path}' is not accessible (read/write permissions needed).")
    logging.info("All critical paths are valid and accessible.")


def get_changed_translation_files(input_folder_path: str, repo_root: str) -> List[str]:
    """
    Use git to find changed translation files in the input folder.

    If the TRANSLATION_FILTER_GLOB environment variable is set, this function will
    only return files that match the provided glob pattern. Otherwise, it returns all
    changed .properties files.

    Args:
        input_folder_path (str): The absolute path to the input folder.
        repo_root (str): The absolute path to the Git repository root.

    Returns:
        List[str]: List of changed translation file names relative to input_folder_path.
    """
    try:
        # Calculate the relative path of input_folder from repo_root
        rel_input_folder = os.path.relpath(input_folder_path, repo_root)

        # Run 'git status --porcelain rel_input_folder' to get changed files in that folder
        result = subprocess.run(
            ['git', 'status', '--porcelain', rel_input_folder],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

        changed_files = []
        for line in result.stdout.splitlines():
            # Each line starts with two characters indicating status
            # e.g., ' M filename', '?? filename'
            status, filepath = line[:2], line[3:]
            if status.strip().startswith('R') and ' -> ' in filepath:
                filepath = filepath.split(' -> ', 1)[1]
            if status.strip() in {'M', 'A', 'AM', 'MM', 'RM', 'R'}:
                if filepath.endswith('.properties'):
                    # Check if it's a translation file (has language suffix)
                    if re.search(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', filepath):
                        # Extract the filename relative to input_folder
                        rel_path = os.path.relpath(filepath, rel_input_folder)
                        changed_files.append(rel_path)

        # If a filter glob is provided via environment variable, apply it now.
        # This allows the pipeline to selectively translate only a subset of changed files.
        filter_glob = os.environ.get('TRANSLATION_FILTER_GLOB')
        if filter_glob:
            # We need the `fnmatch` module to compare against the glob pattern.
            import fnmatch
            filtered_list = [f for f in changed_files if fnmatch.fnmatch(os.path.basename(f), filter_glob)]
            logging.info(f"Applied filter '{filter_glob}', {len(filtered_list)} out of {len(changed_files)} files will be translated.")
            return filtered_list

        return changed_files
    except subprocess.CalledProcessError as git_exc:
        logging.error(f"Error running git command: {git_exc.stderr}")
        return []
    except Exception as general_exc:
        logging.error(f"An unexpected error occurred while fetching changed files: {general_exc}")
        return []


def copy_files_to_translation_queue(
        changed_files: List[str],
        input_folder_path: str,
        translation_queue_folder: str
):
    """
    Copy changed translation files to the translation queue folder, preserving subdirectories.

    Args:
        changed_files (List[str]): List of changed translation file names.
        input_folder_path (str): The absolute path to the input folder.
        translation_queue_folder (str): The absolute path to the translation queue folder.
    """
    os.makedirs(translation_queue_folder, exist_ok=True)
    for translation_file in changed_files:
        # Define full source and destination paths
        source_file_path = os.path.join(input_folder_path, translation_file)
        dest_path = os.path.join(translation_queue_folder, translation_file)

        # Log the files being processed
        logging.info(f"Processing translation file: {translation_file}")

        # Check if source file exists
        if not os.path.exists(source_file_path):
            logging.warning(f"Translation file '{translation_file}' not found in '{input_folder_path}'. Skipping.")
            continue

        if DRY_RUN:
            logging.info(f"[Dry Run] Would copy translation file '{source_file_path}' to '{dest_path}'.")
        else:
            # Ensure the destination directory exists
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            # Copy translation file to translation_queue_folder
            shutil.copy2(source_file_path, dest_path)
            logging.info(f"Copied translation file '{source_file_path}' to '{dest_path}'.")


async def process_translation_queue(
        translation_queue_folder: str,
        translated_queue_folder: str,
        glossary_file_path: str
) -> Tuple[int, Dict[str, List[str]]]:
    """
    Process all .properties files in the translation queue folder.

    Args:
        translation_queue_folder (str): The folder containing files to translate.
        translated_queue_folder (str): The folder to save translated files.
        glossary_file_path (str): The glossary file path.

    Returns:
        A tuple containing:
        - The number of files successfully processed.
        - A dictionary of skipped files, mapping filename to a list of error strings.
    """
    properties_files = [f for f in os.listdir(translation_queue_folder) if f.endswith('.properties')]

    # Load the glossary from the JSON file
    glossary = load_glossary(glossary_file_path)

    # Set up a single semaphore for all API calls to control concurrency globally.
    # A value of 1 ensures that only one API request is active at any time.
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_API_CALLS)

    # Initialize rate limiter (e.g., 60 requests per minute)
    rate_limit = 60  # Number of allowed requests
    rate_period = 60  # Time period in seconds
    rate_limiter = AsyncLimiter(max_rate=rate_limit, time_period=rate_period)

    processed_files_count = 0
    skipped_files: Dict[str, List[str]] = {}

    for translation_file in properties_files:
        # Extract the language code from the filename
        language_code = extract_language_from_filename(translation_file, list(LANGUAGE_CODES.keys()))
        if not language_code:
            logging.warning(f"Skipping file {translation_file}: unable to extract language code.")
            continue
        # 4) Now we find the "friendly name" from the dictionary
        target_language = language_code_to_name(language_code)
        if not target_language:
            logging.warning(f"Skipping file {translation_file}: unsupported language code '{language_code}'.")
            continue
        
        # Define full paths
        translation_file_path = os.path.join(translation_queue_folder, translation_file)
        source_file_name = re.sub(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', '.properties', translation_file)
        source_file_path = os.path.join(INPUT_FOLDER, source_file_name)

        if not os.path.exists(source_file_path):
            logging.warning(f"Source file '{source_file_name}' not found in '{INPUT_FOLDER}'. Skipping.")
            continue
        
        logging.info(f"Processing file '{translation_file}' for language '{target_language}'...")

        # --- Pre-flight Validator ---
        validation_errors = await run_pre_translation_validation(translation_file_path, source_file_path)
        if validation_errors:
            logging.error(f"Skipping translation for '{translation_file}' due to pre-translation validation errors.")
            for error in validation_errors:
                logging.error(f"  - {error}")
            skipped_files[translation_file] = validation_errors
            continue
        # --- End Validator ---

        # --- Pre-flight Linter Check ---
        # Before processing, lint the file to catch basic syntax errors.
        lint_errors = lint_properties_file(translation_file_path)
        if lint_errors:
            logging.error(f"Linter found errors in '{translation_file}'. Skipping translation for this file.")
            for error in lint_errors:
                logging.error(f"  - {error}")
            skipped_files[translation_file] = lint_errors
            continue
        # --- End Linter Check ---

        # Load files
        parsed_lines, target_translations = parse_properties_file(translation_file_path)
        _, source_translations = parse_properties_file(source_file_path)

        # Extract texts to translate
        texts_to_translate, indices, keys_to_translate = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations
        )
        if not texts_to_translate:
            logging.info(f"No texts to translate in file '{translation_file}'.")
            continue

        # Gather all translation tasks
        tasks = [
            translate_text_async(
                text,
                key,
                target_translations,
                source_translations,
                target_language,
                glossary,
                semaphore,
                rate_limiter,  # Pass the rate limiter
                idx
            )
            for idx, (text, key) in enumerate(zip(texts_to_translate, keys_to_translate))
        ]

        # Run tasks concurrently with progress indication
        results = []
        for coro in tqdm.as_completed(tasks, desc=f"Translating {translation_file}", unit="translation"):
            index, result = await coro
            results.append((index, result))

        # Sort results by index to ensure correct order
        results.sort(key=lambda x: x[0])
        translations = [result for _, result in results]

        # Integrate initial translations to create a draft file for review
        draft_lines = integrate_translations(
            parsed_lines,
            translations,
            indices,
            keys_to_translate,
            source_translations
        )
        draft_content = reassemble_file(draft_lines)

        # --- Holistic Review Step ---
        # Instead of one large review, we chunk the keys to avoid token limits.
        logging.info(f"Performing holistic review for {len(keys_to_translate)} keys in '{translation_file}'...")

        # Create chunks of keys
        key_chunks = [
            keys_to_translate[i:i + HOLISTIC_REVIEW_CHUNK_SIZE]
            for i in range(0, len(keys_to_translate), HOLISTIC_REVIEW_CHUNK_SIZE)
        ]

        # We need a dictionary of the draft translations to build targeted context for each chunk.
        # This is easier than parsing the string repeatedly.
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.properties', encoding='utf-8') as temp_f:
            temp_f.write(draft_content)
            temp_draft_path = temp_f.name
        _, draft_translations = parse_properties_file(temp_draft_path)
        os.remove(temp_draft_path)

        final_corrected_translations = {}
        style_rules_text_for_review = PRECOMPUTED_STYLE_RULES_TEXT.get(language_code, "")

        for i, key_chunk in enumerate(key_chunks):
            logging.info(f"Reviewing chunk {i + 1}/{len(key_chunks)} ({len(key_chunk)} keys)...")

            # Build targeted source and translated content for this chunk only
            chunk_source_content = "\n".join(
                [f"{key}={source_translations.get(key, '')}" for key in key_chunk]
            )
            chunk_translated_content = "\n".join(
                [f"{key}={draft_translations.get(key, '')}" for key in key_chunk]
            )

            corrected_chunk = await holistic_review_async(
                source_content=chunk_source_content,
                translated_content=chunk_translated_content,
                target_language=target_language,
                keys_to_review=key_chunk,
                semaphore=semaphore,
                rate_limiter=rate_limiter,
                style_rules_text=style_rules_text_for_review
            )

            if corrected_chunk:
                final_corrected_translations.update(corrected_chunk)
            else:
                logging.warning(f"Holistic review for chunk {i + 1} failed or returned no corrections.")
                # Even if the review fails for a chunk, we should still include the initial translations
                # for those keys in the final output. We can do this by "correcting" them to their draft state.
                for key in key_chunk:
                    final_corrected_translations[key] = draft_translations.get(key, "")


        if final_corrected_translations:
            logging.info("Holistic review successful. Applying all corrected translations.")
            logging.debug(f"--- ALL CORRECTED JSON FROM REVIEW ---\n{json.dumps(final_corrected_translations, indent=2)}")

            # The corrected_translations dict is the new source of truth.
            # We iterate through our master file structure `draft_lines` and update it in-place.
            changed_keys_count = 0
            for line_info in draft_lines:
                if line_info['type'] == 'entry':
                    key = line_info['key']
                    if key in final_corrected_translations:
                        new_value = final_corrected_translations[key]
                        original_source_text = source_translations.get(key, "")

                        # Apply the same escaping logic to the corrected value
                        new_value = _escape_messageformat_if_needed(original_source_text, new_value)

                        if line_info['value'] != new_value:
                            changed_keys_count += 1
                            logging.debug(f"Review changed key '{key}': FROM '{line_info['value']}' TO '{new_value}'")
                            line_info['value'] = new_value
            if changed_keys_count > 0:
                logging.info(f"Holistic review changed {changed_keys_count} value(s) in total.")
            else:
                logging.info("Holistic review completed without making changes to the draft translation.")

            updated_lines = draft_lines
        else:
            logging.warning("Holistic review failed for all chunks. Proceeding with initial translations.")
            # If review fails, we use the original draft which was already correctly escaped.
            updated_lines = draft_lines
        new_file_content = reassemble_file(updated_lines)

        # --- Post-translation Validator ---
        is_final_content_valid = run_post_translation_validation(
            final_content=new_file_content,
            source_translations=source_translations,
            filename=translation_file
        )
        if not is_final_content_valid:
            logging.error(f"Discarding invalid translation for '{translation_file}'. The original file will be used.")
            continue # Skip to the next file
        # --- End Post-translation Validator ---

        translated_file_path = os.path.join(translated_queue_folder, translation_file)

        if DRY_RUN:
            logging.info(f"[Dry Run] Would write translated content to '{translated_file_path}'.")
        else:
            # Ensure the destination directory exists
            os.makedirs(os.path.dirname(translated_file_path), exist_ok=True)
            with open(translated_file_path, 'w', encoding='utf-8') as file:
                file.write(new_file_content)
            logging.info(f"Translated file saved to '{translated_file_path}'.\n")

        processed_files_count += 1

    return processed_files_count, skipped_files


def archive_original_files(
    changed_files: List[str],
    input_folder_path: str,
    archive_folder_path: str
):
    """
    Copies the original changed files to the archive folder.
    """
    os.makedirs(archive_folder_path, exist_ok=True)
    for filename in changed_files:
        source_path = os.path.join(input_folder_path, filename)
        dest_path = os.path.join(archive_folder_path, filename)

        if not os.path.exists(source_path):
            logging.warning(f"Original file '{filename}' not found for archiving. Skipping.")
            continue

        if DRY_RUN:
            logging.info(f"[Dry Run] Would archive '{source_path}' to '{dest_path}'.")
        else:
            shutil.copy2(source_path, dest_path)
            logging.info(f"Archived original file '{source_path}' to '{dest_path}'.")


async def main():
    """
    Main function to orchestrate the translation process.
    """
    # Clean up queue folders from any previous runs to ensure a fresh start
    if os.path.exists(TRANSLATION_QUEUE_FOLDER):
        shutil.rmtree(TRANSLATION_QUEUE_FOLDER)
    if os.path.exists(TRANSLATED_QUEUE_FOLDER):
        shutil.rmtree(TRANSLATED_QUEUE_FOLDER)

    # Ensure queue folders exist before validation (works when main() is invoked directly)
    os.makedirs(TRANSLATION_QUEUE_FOLDER, exist_ok=True)
    os.makedirs(TRANSLATED_QUEUE_FOLDER, exist_ok=True)
    # Ensure critical paths that might be derived from config are validated after config load
    # For example, if INPUT_FOLDER or REPO_ROOT uses defaults, they might be invalid.
    # The validate_paths function should be called early in main if it relies on these.
    validate_paths(INPUT_FOLDER, TRANSLATION_QUEUE_FOLDER, TRANSLATED_QUEUE_FOLDER, REPO_ROOT)

    # Step 1: Identify changed translation files
    changed_files = get_changed_translation_files(INPUT_FOLDER, REPO_ROOT)
    if not changed_files:
        logging.info("No changed translation files detected. Exiting.")
        return
    logging.info(f"Detected {len(changed_files)} changed translation file(s).")

    # Step 2: Archive the original files before any processing.
    archive_folder_path = os.path.join(INPUT_FOLDER, 'archive')
    archive_original_files(changed_files, INPUT_FOLDER, archive_folder_path)
    logging.info(f"Successfully archived original files to '{archive_folder_path}'.")

    # Step 3: Copy changed files to the translation queue for processing.
    copy_files_to_translation_queue(changed_files, INPUT_FOLDER, TRANSLATION_QUEUE_FOLDER)
    logging.info(f"Copied changed files to '{TRANSLATION_QUEUE_FOLDER}' for processing.")

    # Step 4: Process the files in the translation queue.
    processed_files_count, skipped_files = await process_translation_queue(
        translation_queue_folder=TRANSLATION_QUEUE_FOLDER,
        translated_queue_folder=TRANSLATED_QUEUE_FOLDER,
        glossary_file_path=GLOSSARY_FILE_PATH
    )
    if processed_files_count > 0:
        logging.info(f"Completed translations for {processed_files_count} file(s). Translated files are in '{TRANSLATED_QUEUE_FOLDER}'.")
    else:
        logging.info("No files were successfully translated.")

    # Step 5: Write skipped files report
    report_path = os.path.join(PROJECT_ROOT_DIR, 'logs', 'skipped_files_report.log')
    if skipped_files:
        logging.info(f"Some files were skipped. Writing report to {report_path}")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("## ⚠️ Translation Pipeline Warnings\n\n")
            f.write("The following files were skipped during the AI translation process due to validation or linter errors. These issues must be addressed manually.\n\n")
            for filename, errors in skipped_files.items():
                f.write(f"### 📄 `{filename}`\n")
                for error in errors:
                    f.write(f"- {error}\n")
                f.write("\n")
    else:
        # Ensure no old report file is left
        if os.path.exists(report_path):
            os.remove(report_path)

    # Step 6: Copy translated files back to the input folder, overwriting the originals.
    copy_translated_files_back(TRANSLATED_QUEUE_FOLDER, INPUT_FOLDER)
    if processed_files_count > 0:
        logging.info("Copied translated files back to the input folder.")

    # Optional: Clean up translation queue folders.
    if DRY_RUN:
        logging.info("Dry run enabled; skipping cleanup of translation queue folders.")
    else:
        try:
            shutil.rmtree(TRANSLATION_QUEUE_FOLDER)
            shutil.rmtree(TRANSLATED_QUEUE_FOLDER)
            logging.info("Cleaned up translation queue folders.")
        except Exception as clean_exc:
            logging.error(f"Error cleaning up translation queue folders: {clean_exc}")


if __name__ == "__main__":
    # Ensure queue folders exist, potentially using paths derived from config or defaults
    os.makedirs(TRANSLATION_QUEUE_FOLDER, exist_ok=True)
    os.makedirs(TRANSLATED_QUEUE_FOLDER, exist_ok=True)
    try:
        asyncio.run(main())
    except Exception as main_exc:
        logging.error(f"An unexpected error occurred during execution: {main_exc}")
