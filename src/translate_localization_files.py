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
from tqdm.asyncio import tqdm_asyncio

# Determine the correct path to config.yaml relative to the script's location
SCRIPT_REAL_PATH = os.path.realpath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_REAL_PATH)
CONFIG_FILE = os.path.join(SCRIPT_DIR, '..', 'config.yaml')

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

                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()

                    # Check for malformed keys (e.g., double dots)
                    if '..' in key:
                        errors.append(f"Linter Error: Malformed key '{key}' with double dots found on line {i}.")

                    # Check for invalid escape sequences in the value.
                    # A backslash not followed by a valid escape char or 'u' is an error.
                    # This is a simplified check; a full Java properties parser is complex.
                    # We are specifically looking for the '\' followed by a non-special character.
                    if '\\' in value:
                        # Find all occurrences of a backslash
                        for m in re.finditer(r'\\', value):
                            char_after = value[m.start() + 1] if len(value) > m.start() + 1 else None
                            # Common valid escapes in .properties files. This is not exhaustive.
                            valid_escapes = ['t', 'n', 'f', 'r', '\\', 'u', '=', ':', '#', '!', ' ']
                            if char_after and char_after not in valid_escapes:
                                # A more specific check for the Unicode error seen in reviews
                                if char_after.isalpha() and char_after != 'u':
                                     errors.append(f"Linter Error: Invalid escape sequence '\\{char_after}' in value for key '{key}' on line {i}.")

    except Exception as e:
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


def load_source_properties_file(source_file_path: str) -> Dict[str, str]:
    """
    Load translations from a source .properties file.

    Args:
        source_file_path (str): The path to the source .properties file.

    Returns:
        Dict[str, str]: A dictionary of translations.
    """
    with open(source_file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    source_translations = {}
    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        if line.startswith('#') or line.strip() == '':
            i += 1
        else:
            match = re.match(r'([^=]+)=(.*)', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2)
                # Handle multiline values
                while value.endswith('\\'):
                    value = value[:-1]  # Remove the backslash
                    i += 1
                    if i < len(lines):
                        next_line = lines[i].rstrip('\n')
                        value += next_line.lstrip()
                    else:
                        break
                else:
                    i += 1
                source_translations[key] = value
            else:
                i += 1
    return source_translations


def parse_properties_file(file_path: str) -> Tuple[List[Dict], Dict[str, str]]:
    """
    Parse a .properties file.

    Args:
        file_path (str): The path to the .properties file.

    Returns:
        Tuple[List[Dict], Dict[str, str]]: A list of parsed lines and a dictionary of translations.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    parsed_lines = []
    target_translations = {}
    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        if line.startswith('#') or line.strip() == '':
            parsed_lines.append({'type': 'comment_or_blank', 'content': lines[i]})
            i += 1
        else:
            match = re.match(r'([^=]+)=(.*)', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2)
                line_number = i
                original_value_lines = [value]
                # Handle multiline values
                while value.endswith('\\'):
                    value = value[:-1]  # Remove the backslash
                    i += 1
                    if i < len(lines):
                        next_line = lines[i].rstrip('\n')
                        original_value_lines.append(next_line)
                        value += next_line.lstrip()
                    else:
                        break
                else:
                    i += 1
                original_value = ''.join(original_value_lines)
                target_translations[key] = value
                parsed_lines.append({
                    'type': 'entry',
                    'key': key,
                    'value': value,
                    'original_value': original_value,
                    'line_number': line_number
                })
            else:
                parsed_lines.append({'type': 'unknown', 'content': lines[i]})
                i += 1
    return parsed_lines, target_translations


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

            # If key exists in source and the values are identical, it needs translation.
            if source_value is not None and normalize_value(source_value) == normalize_value(target_value):
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
- **Strictly follow the glossary**: The glossary provides key-value pairs for specific terms. You must use the provided translation for these terms. The matching of terms from the source text to the keys in the glossary should be case-insensitive. For example, if the source text contains "Backup Seeds" and the glossary has an entry for "backup seeds", you must use the translation from that glossary entry.
- **Maintain placeholders**: Keep placeholders like `{0}`, `{1}` unchanged.
- **Preserve formatting**: Keep special characters and formatting such as `\\n` and `\\t`.
- **Do not add** any additional characters or punctuation (e.g., no square brackets, quotation marks, etc.).
- **Provide only** the translated text corresponding to the Value.

Use the translations specified in the glossary for the given terms. Ensure the translation reads naturally and is culturally appropriate for the target audience.

For German translations, please use the formal "Sie" form of address.

**Style and Tone Guidelines**:
- **Professional and Reassuring**: The tone should be professional, clear, and reassuring. Avoid overly casual or informal language.
- **No Mixed Languages**: Do not mix English terms with the target language in a single phrase (e.g., "Seed Words Confermati!"). The translation should be fully localized.
- **Language-Specific Conventions**: Adhere to conventions of the target language. For example, in Russian, "Bitcoin" should be lowercase ("биткойн") when used as a common noun.

The translation is for a desktop trading app called Bisq. Keep the translations brief and consistent with typical software terminology. On Bisq, you can buy and sell bitcoin for fiat (or other cryptocurrencies) privately and securely using Bisq's peer-to-peer network and open-source desktop software. "Bisq Easy" is a brand name and should not be translated.
"""

        prompt = f"""
**Glossary:**
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
                        ChatCompletionUserMessageParam(role="user", content=prompt)
                    ],
                    temperature=0.3,
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

        # If the original source text contained placeholders, it's likely for MessageFormat,
        # which requires single quotes to be escaped.
        if '{' in original_source_text and '}' in original_source_text:
            # Escape single quotes that are not already escaped.
            translated_text = re.sub(r"(?<!')'", "''", translated_text)

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


def reassemble_file(parsed_lines: List[Dict]) -> str:
    """
    Reassemble the file content from parsed lines.

    Args:
        parsed_lines (List[Dict]): The parsed lines.

    Returns:
        str: The reassembled file content.
    """
    lines = []
    for item in parsed_lines:
        if item['type'] == 'entry':
            value = item['value']
            # Preserve original formatting if possible
            if '\\n' in item.get('original_value', ''):
                # Use escaped newline characters
                value = value.replace('\n', '\\n')
                line = f"{item['key']}={value}\n"
            elif '\n' in value or '\\\n' in item.get('original_value', ''):
                # Handle multiline values with line continuations
                lines_value = value.split('\n')
                formatted_value = '\\\n'.join(lines_value)
                line = (f"{item['key']}="
                        f"{formatted_value}\n")
            else:
                line = f"{item['key']}={value}\n"
            lines.append(line)
        else:
            lines.append(item['content'])
    return ''.join(lines)


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
            if status.strip() in {'M', 'A', 'AM', 'MM', 'RM', 'R'}:
                if filepath.endswith('.properties'):
                    # Check if it's a translation file (has language suffix)
                    if re.search(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', filepath):
                        # Extract the filename relative to input_folder
                        rel_path = os.path.relpath(filepath, rel_input_folder)
                        changed_files.append(rel_path)
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
    Copy changed translation files to the translation queue folder without nested directories.

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
):
    """
    Process all .properties files in the translation queue folder.

    Args:
        translation_queue_folder (str): The folder containing files to translate.
        translated_queue_folder (str): The folder to save translated files.
        glossary_file_path (str): The glossary file path.
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
        logging.info(f"Processing file '{translation_file}' for language '{target_language}'...")

        # --- Pre-flight Linter Check ---
        # Before processing, lint the file to catch basic syntax errors.
        lint_errors = lint_properties_file(os.path.join(translation_queue_folder, translation_file))
        if lint_errors:
            logging.error(f"Linter found errors in '{translation_file}'. Skipping translation for this file.")
            for error in lint_errors:
                logging.error(f"  - {error}")
            continue
        # --- End Linter Check ---

        # Define full paths
        translation_file_path = os.path.join(translation_queue_folder, translation_file)
        source_file_name = re.sub(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', '.properties', translation_file)
        source_file_path = os.path.join(INPUT_FOLDER, source_file_name)

        if not os.path.exists(source_file_path):
            logging.warning(f"Source file '{source_file_name}' not found in '{INPUT_FOLDER}'. Skipping.")
            continue

        # Load files
        parsed_lines, target_translations = parse_properties_file(translation_file_path)
        source_translations = load_source_properties_file(source_file_path)

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
        for coro in tqdm_asyncio.as_completed(tasks, desc=f"Translating {translation_file}", unit="translation"):
            index, result = await coro
            results.append((index, result))

        # Sort results by index to ensure correct order
        results.sort(key=lambda x: x[0])  # type: ignore[arg-type]
        translations = [result for _, result in results]  # type: ignore[arg-type]

        # Integrate translations into the parsed lines
        updated_lines = integrate_translations(
            parsed_lines,
            translations,
            indices,
            keys_to_translate,
            source_translations
        )
        new_file_content = reassemble_file(updated_lines)
        translated_file_path = os.path.join(translated_queue_folder, translation_file)

        if DRY_RUN:
            logging.info(f"[Dry Run] Would write translated content to '{translated_file_path}'.")
        else:
            # Ensure the destination directory exists
            os.makedirs(os.path.dirname(translated_file_path), exist_ok=True)
            with open(translated_file_path, 'w', encoding='utf-8') as file:
                file.write(new_file_content)
            logging.info(f"Translated file saved to '{translated_file_path}'.\n")


async def main():
    """
    Main function to orchestrate the translation process.
    """
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

    # Step 2: Copy changed files to translation queue
    copy_files_to_translation_queue(changed_files, INPUT_FOLDER, TRANSLATION_QUEUE_FOLDER)
    logging.info(f"Copied changed files to '{TRANSLATION_QUEUE_FOLDER}'.")

    # Step 3: Process translation queue
    await process_translation_queue(
        translation_queue_folder=TRANSLATION_QUEUE_FOLDER,
        translated_queue_folder=TRANSLATED_QUEUE_FOLDER,
        glossary_file_path=GLOSSARY_FILE_PATH
    )
    logging.info(f"Completed translations. Translated files are in '{TRANSLATED_QUEUE_FOLDER}'.")

    # Step 4: Copy translated files back to input folder
    copy_translated_files_back(TRANSLATED_QUEUE_FOLDER, INPUT_FOLDER)
    logging.info("Copied translated files back to the input folder.")

    # Step 5: Archive original changed files
    archive_folder_path = os.path.join(INPUT_FOLDER, 'archive')
    move_files_to_archive(TRANSLATION_QUEUE_FOLDER, archive_folder_path)
    logging.info(f"Archived original files to '{archive_folder_path}'.")

    # Optional: Clean up translation queue folders
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
