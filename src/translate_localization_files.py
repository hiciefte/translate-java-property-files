import asyncio
import datetime as _dt
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
from email.utils import parsedate_to_datetime
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
from aiolimiter import AsyncLimiter
from openai import (
    APIConnectionError,
    APIStatusError,
    RateLimitError,
    APITimeoutError,
    OpenAIError
)
from openai.types.chat import (
    ChatCompletionSystemMessageParam,
    ChatCompletionUserMessageParam
)
from tqdm.asyncio import tqdm

from src.app_config import load_app_config
from src.properties_parser import parse_properties_file, reassemble_file
from src.translation_validator import (
    check_placeholder_parity,
    check_encoding_and_mojibake,
    synchronize_keys
)

# --- Constants and Globals ---
# Load application configuration
config = load_app_config()

# Create a dedicated logger for this script to avoid conflicts with the root logger.
logger = logging.getLogger("translation_script")

# Define the expected JSON schema for the AI's response in the holistic review.
# This ensures that the AI returns a dictionary where every value is a string.
LOCALIZATION_SCHEMA = {
    "type": "object",
    "patternProperties": {
        "^.*$": {"type": "string"}
    },
    "additionalProperties": False
}

# Extract configuration values for convenience
PROJECT_ROOT_DIR = config.project_root
REPO_ROOT = config.target_project_root
INPUT_FOLDER = config.input_folder
GLOSSARY_FILE_PATH = config.glossary_file_path
MODEL_NAME = config.model_name
REVIEW_MODEL_NAME = config.review_model_name
MAX_MODEL_TOKENS = config.max_model_tokens
DRY_RUN = config.dry_run
HOLISTIC_REVIEW_CHUNK_SIZE = config.holistic_review_chunk_size
MAX_CONCURRENT_API_CALLS = config.max_concurrent_api_calls
LANGUAGE_CODES = config.language_codes
NAME_TO_CODE = config.name_to_code
STYLE_RULES = config.style_rules
PRECOMPUTED_STYLE_RULES_TEXT = config.precomputed_style_rules_text
BRAND_GLOSSARY = config.brand_glossary
TRANSLATION_QUEUE_FOLDER = config.translation_queue_folder
TRANSLATED_QUEUE_FOLDER = config.translated_queue_folder
PRESERVE_QUEUES_FOR_DEBUG = config.preserve_queues_for_debug
client = config.openai_client

# --- End Config and Globals ---

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
                    key, value = line[:sep_idx], line[sep_idx + 1:]
                    key = key.strip()

                    # Check for malformed keys (e.g., double dots)
                    if '..' in key:
                        errors.append(f"Linter Error: Malformed key '{key}' with double dots found on line {i}.")

                    # Temporarily remove a trailing backslash if it's for line continuation,
                    # so it's not incorrectly flagged as an invalid escape sequence.
                    value_to_check = value.rstrip('\r\n')
                    # Treat as continuation only if an odd number of trailing backslashes
                    m = re.search(r'(\\+)$', value_to_check)
                    if m and (len(m.group(1)) % 2 == 1):
                        value_to_check = value_to_check[:-1]

                    # Allow: \t \n \f \r \\ \= \: \# \! space, \", and \uXXXX (4 hex digits)
                    # This regex is loosened to ignore \n and \" which appear in some source files.
                    if re.search(r'\\(?!u[0-9a-fA-F]{4}|[tnfr\\=:#\s!"])', value_to_check):
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
        logger.error(f"Glossary file '{glossary_file_path}' not found.")
        return {}
    try:
        with open(glossary_file_path, 'r', encoding='utf-8') as f:
            glossary = json.load(f)
        return glossary
    except json.JSONDecodeError as json_exc:
        logger.error(f"Error decoding JSON glossary file: {json_exc}")
        return {}
    except Exception as general_exc:
        logger.error(f"An unexpected error occurred while loading the glossary: {general_exc}")
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
                # Try HTTP-date (RFC 7231)
                try:
                    dt = parsedate_to_datetime(retry_after_header)
                    retry_after = max(0.0, (dt - _dt.datetime.now(dt.tzinfo)).total_seconds())
                except Exception:
                    retry_after = None
            if retry_after is None:
                retry_after = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
            delay = retry_after
        except Exception as exc:
            logger.warning(f"Failed to parse Retry-After header: {exc}. Falling back to exponential backoff.")
            delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
        logger.info(
            f"Retrying request to /chat/completions in {delay:.2f} seconds (Attempt {attempt}/{max_retries})")
        await asyncio.sleep(delay)
        return True
    else:
        logger.error(f"Translation failed for key '{key}' after {max_retries} attempts.")
        return False

def run_pre_translation_validation(target_file_path: str, source_file_path: str) -> List[str]:
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
    logger.info(f"Running pre-translation validation for '{filename}'...")

    # 1. Synchronize keys (add missing, remove extra)
    try:
        synchronize_keys(target_file_path, source_file_path)
        logger.info(f"Key synchronization complete for '{filename}'.")
    except (IOError, OSError) as e:
        logger.exception("Failed to synchronize keys for '%s'", filename)
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
        logger.exception("Validation failed for '%s': Could not parse properties file after key sync", filename)
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
        logger.info(f"Pre-translation validation passed for '{filename}'.")
    else:
        logger.error(f"Pre-translation validation failed for '{filename}'.")

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
    logger.info(f"Running post-translation validation for '{filename}'...")

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
                logger.error(f"Post-translation validation failed for '{filename}': {error}")

        # 2. Check placeholder parity on the final content
        try:
            _, final_translations = parse_properties_file(temp_file_path)
            common_keys = set(source_translations.keys()).intersection(set(final_translations.keys()))
            for key in common_keys:
                source_value = source_translations.get(key, "")
                target_value = final_translations.get(key, "")
                if not check_placeholder_parity(source_value, target_value):
                    is_valid = False
                    logger.error(
                        f"Post-translation validation failed for '{filename}': Placeholder mismatch for key '{key}'.")
        except (IOError, OSError):
            is_valid = False
            logger.exception(
                "Post-translation validation failed for '%s': Could not parse final properties content", filename)

    finally:
        # Ensure the temporary file is cleaned up
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except OSError as _e:
                logger.warning("Could not delete temporary validation file '%s': %s", temp_file_path, _e)

    if is_valid:
        logger.info(f"Post-translation validation passed for '{filename}'.")
    else:
        logger.error(
            f"Post-translation validation failed for '{filename}'. AI-generated content is invalid and will be discarded.")

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
    if DRY_RUN:
        logger.info(f"[Dry Run] Skipping actual translation for key '{key}'. Returning original text.")
        return index, text

    if client is None:
        logger.error("OpenAI client is None. Cannot proceed with translation.")
        return index, text

    async with semaphore, rate_limiter:
        # 3) Use language_name_to_code instead of an Enum
        language_code = language_name_to_code(target_language)

        # If the language isn't recognized, just return original text
        if not language_code:
            logger.warning(f"Unsupported or unrecognized language: {target_language}")
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

        for attempt in range(1, max_retries + 1):  # type: ignore[arg-type]
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

                msg_content = response.choices[0].message.content
                if not msg_content:
                    logger.warning("Empty assistant content for key '%s'; keeping original text.", key)
                    return index, text
                translated_text = msg_content.strip()

                # Restore placeholders in the translated text
                translated_text = restore_placeholders(translated_text, placeholder_mapping)

                # Clean the translated text
                translated_text = clean_translated_text(translated_text, text)

                logger.debug(f"Translated key '{key}' successfully.")
                return index, translated_text

            except (RateLimitError, APITimeoutError, APIConnectionError, APIStatusError, OpenAIError) as api_exc:
                logger.error(f"API error occurred: {api_exc.__class__.__name__} - {api_exc}")
                should_retry = await _handle_retry(attempt, max_retries, base_delay, key, api_exc)
                if should_retry:
                    continue
                else:
                    return index, text
            except Exception as general_exc:
                logger.error(f"An unexpected error occurred: {general_exc}", exc_info=True)
                return index, text

        # Fallback return statement to satisfy linters and ensure explicit return
        logger.warning(
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
    if DRY_RUN:
        logger.info("[Dry Run] Skipping holistic review API call.")
        # Return an empty dictionary to simulate a successful review that made no changes.
        return {}

    if client is None:
        logger.error("OpenAI client is None. Cannot proceed with holistic review.")
        return {}

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
                msg_content = response.choices[0].message.content
                if not msg_content or not msg_content.strip():
                    logger.error("Holistic review returned empty content.")
                    raise json.JSONDecodeError("empty response", "", 0)
                response_text = msg_content.strip()

                # The response should be a JSON string. Parse and validate it.
                parsed_json = json.loads(response_text)
                jsonschema.validate(instance=parsed_json, schema=LOCALIZATION_SCHEMA)
                return parsed_json

            except json.JSONDecodeError:
                logger.exception("Holistic review failed: AI did not return valid JSON.")
                logger.debug(f"Invalid AI response (JSON Decode Error):\n---\n{response_text}\n---")
                # Fall through to retry logic
            except jsonschema.ValidationError:
                logger.exception("Holistic review failed: AI response did not match the required JSON schema.")
                logger.debug(f"Invalid AI response (Schema Error):\n---\n{response_text}\n---")
                # Fall through to retry logic

            except (RateLimitError, APITimeoutError, APIConnectionError, APIStatusError, OpenAIError) as api_exc:
                logger.warning(f"API error during holistic review: {api_exc}")
                should_retry = await _handle_retry(attempt, max_retries, base_delay, "holistic_review", api_exc)
                if not should_retry:
                    return None
            except Exception as e:
                logger.error(f"Unexpected error during holistic review: {e}", exc_info=True)
                return None  # Do not retry on unexpected errors

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
            logger.debug(f"Integrated translation for key '{key}': '{translated_text}'")
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
            logger.debug(f"Appended new translation for key '{key}': '{translated_text}'")

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
    Move processed files to an archive folder, preserving subdirectories.

    Args:
        input_folder_path (str): The input folder path.
        archive_folder_path (str): The archive folder path.
    """
    os.makedirs(archive_folder_path, exist_ok=True)
    for root, _, files in os.walk(input_folder_path):
        for filename in files:
            if filename.endswith('.properties') and re.search(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', filename):
                # Construct relative path to maintain directory structure
                relative_path = os.path.relpath(os.path.join(root, filename), input_folder_path)
                source_path = os.path.join(input_folder_path, relative_path)
                dest_path = os.path.join(archive_folder_path, relative_path)

                if DRY_RUN:
                    logger.info(f"[Dry Run] Would move file '{source_path}' to '{dest_path}'.")
                else:
                    # Ensure the destination subdirectory exists before moving.
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    shutil.move(source_path, dest_path)
                    logger.info(f"Moved file '{source_path}' to '{dest_path}'.")
    logger.info(f"All translation files in '{input_folder_path}' have been archived.")

def copy_translated_files_back(
        translated_queue_folder: str,
        input_folder_path: str
):
    """
    Copy translated translation files back to the input folder, overwriting existing ones and preserving subdirectories.

    Args:
        translated_queue_folder (str): The folder containing translated files.
        input_folder_path (str): The input folder path.
    """
    for root, _dirs, files in os.walk(translated_queue_folder):
        for name in files:
            if name.endswith('.properties') and re.search(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', name):
                rel_path = os.path.relpath(os.path.join(root, name), translated_queue_folder)
                translated_file_path = os.path.join(translated_queue_folder, rel_path)
                dest_path = os.path.join(input_folder_path, rel_path)
                if DRY_RUN:
                    logger.info(
                        f"[Dry Run] Would copy translated file '{translated_file_path}' back to '{dest_path}'.")
                else:
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    shutil.copy2(translated_file_path, dest_path)
                    logger.info(f"Copied translated file '{translated_file_path}' back to '{dest_path}'.")

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
            logger.error(f"{name} '{path}' does not exist.")
            raise FileNotFoundError(f"{name} '{path}' does not exist.")
        required = os.R_OK | os.W_OK
        if name == "Repository Root":
            required = os.R_OK
        if not os.access(path, required):
            logger.error("%s '%s' is not accessible (required perms: %s).", name, path, "R+W" if required & os.W_OK else "R")
            raise PermissionError(f"{name} '{path}' lacks required permissions.")
    logger.info("All critical paths are valid and accessible.")

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

        # Log the command being run for traceability
        logger.info(f"Running git status in '{repo_root}' for path '{rel_input_folder}'")

        # Run 'git status --porcelain rel_input_folder' to get changed files in that folder
        # We include untracked files with '--untracked-files=normal'
        result = subprocess.run(
            ['git', 'status', '--porcelain', '--untracked-files=normal', rel_input_folder],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

        changed_files = []
        for line in result.stdout.splitlines():
            if len(line) < 4:
                continue
            # Each line starts with two characters indicating status
            # e.g., ' M filename', '?? filename'
            status, filepath = line[:2], line[3:]
            if status.strip().startswith('R') and ' -> ' in filepath:
                filepath = filepath.split(' -> ', 1)[1]

            cleaned_status = status.strip()
            # We now also check for '??' (untracked files)
            if cleaned_status in {'M', 'A', 'AM', 'MM', 'RM', 'R', '??'}:
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
            # If the glob contains a path separator, match against the full relative path.
            # Otherwise, match against the basename to preserve the original behavior.
            if '/' in filter_glob:
                filtered_list = [f for f in changed_files if fnmatch.fnmatch(f, filter_glob)]
            else:
                filtered_list = [f for f in changed_files if fnmatch.fnmatch(os.path.basename(f), filter_glob)]

            logger.info(
                f"Applied filter '{filter_glob}', {len(filtered_list)} out of {len(changed_files)} files will be translated.")
            return filtered_list

        return changed_files
    except subprocess.CalledProcessError as git_exc:
        logger.error(f"Error running git command: {git_exc.stderr}")
        return []
    except Exception as general_exc:
        logger.error(f"An unexpected error occurred while fetching changed files: {general_exc}")
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
        logger.info(f"Processing translation file: {translation_file}")

        # Check if source file exists
        if not os.path.exists(source_file_path):
            logger.warning(f"Translation file '{translation_file}' not found in '{input_folder_path}'. Skipping.")
            continue

        if DRY_RUN:
            logger.info(f"[Dry Run] Would copy translation file '{source_file_path}' to '{dest_path}'.")
        else:
            # Ensure the destination directory exists
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            # Copy translation file to translation_queue_folder
            shutil.copy2(source_file_path, dest_path)
            logger.info(f"Copied translation file '{source_file_path}' to '{dest_path}'.")

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
    properties_files = []
    for root, _, files in os.walk(translation_queue_folder):
        for name in files:
            if name.endswith('.properties'):
                # Get the relative path from the queue folder to preserve subdirectories
                relative_path = os.path.relpath(os.path.join(root, name), translation_queue_folder)
                properties_files.append(relative_path)

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
            logger.warning(f"Skipping file {translation_file}: unable to extract language code.")
            continue
        # 4) Now we find the "friendly name" from the dictionary
        target_language = language_code_to_name(language_code)
        if not target_language:
            logger.warning(f"Skipping file {translation_file}: unsupported language code '{language_code}'.")
            continue

        # Define full paths
        translation_file_path = os.path.join(translation_queue_folder, translation_file)
        source_file_name = re.sub(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', '.properties', translation_file)
        source_file_path = os.path.join(INPUT_FOLDER, source_file_name)

        if not os.path.exists(source_file_path):
            logger.warning(f"Source file '{source_file_name}' not found in '{INPUT_FOLDER}'. Skipping.")
            continue

        logger.info(f"Processing file '{translation_file}' for language '{target_language}'...")

        # --- Pre-flight Validator ---
        validation_errors = run_pre_translation_validation(translation_file_path, source_file_path)
        if validation_errors:
            logger.error(f"Skipping translation for '{translation_file}' due to pre-translation validation errors.")
            for error in validation_errors:
                logger.error(f"  - {error}")
            skipped_files[translation_file] = validation_errors
            continue
        # --- End Validator ---

        # --- Pre-flight Linter Check ---
        # Before processing, lint the file to catch basic syntax errors.
        lint_errors = lint_properties_file(translation_file_path)
        if lint_errors:
            logger.error(f"Linter found errors in '{translation_file}'. Skipping translation for this file.")
            for error in lint_errors:
                logger.error(f"  - {error}")
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
            logger.info(f"No texts to translate in file '{translation_file}'.")
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
        # The tqdm output is directed to stderr by default, which is ideal.
        # It prevents progress bars from being broken by stdout prints.
        for coro in tqdm(
                asyncio.as_completed(tasks),
                desc=f"Translating {translation_file}",
                unit="translation",
                total=len(tasks)  # Provide the total number of tasks
        ):
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
        logger.info(f"Performing holistic review for {len(keys_to_translate)} keys in '{translation_file}'...")

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

        review_results = await asyncio.gather(
            *[holistic_review_async(
                source_content="\n".join([f"{key}={source_translations.get(key, '')}" for key in key_chunk]),
                translated_content="\n".join([f"{key}={draft_translations.get(key, '')}" for key in key_chunk]),
                target_language=target_language,
                keys_to_review=key_chunk,
                semaphore=semaphore,
                rate_limiter=rate_limiter,
                style_rules_text=style_rules_text_for_review
            ) for key_chunk in key_chunks]
        )

        try:
            for i, (corrected_chunk, key_chunk) in enumerate(zip(review_results, key_chunks)):
                if corrected_chunk is not None:
                    if corrected_chunk:
                        final_corrected_translations.update(corrected_chunk)
                    else:
                        logger.info("Holistic review returned no corrections for this chunk; keeping draft values.")
                        for key in key_chunk:
                            final_corrected_translations[key] = draft_translations.get(key, "")
                else:
                    logger.warning(f"Holistic review for chunk {i + 1} failed; keeping draft values for this chunk.")
                    for key in key_chunk:
                        final_corrected_translations[key] = draft_translations.get(key, "")
        except Exception:
            logger.exception("An error occurred during asyncio.gather for holistic review of %s", translation_file)

        # Always apply the results from the review stage, which includes fallbacks to draft for failed chunks.
        logger.info("Applying corrected translations (including any draft fallbacks).")
        logger.debug(f"--- ALL CORRECTED JSON FROM REVIEW ---\n{json.dumps(final_corrected_translations, indent=2)}")
        for line in draft_lines:
            if line['type'] == 'entry':
                key = line.get('key')
                if key in final_corrected_translations:
                    new_value = final_corrected_translations[key]
                    logger.debug(f"Review changed key '{key}': FROM '{line['value']}' TO '{new_value}'")
                    line['value'] = new_value

        # Reassemble the final file content
        updated_lines = draft_lines
        new_file_content = reassemble_file(updated_lines)

        # --- Post-translation Validator ---
        is_final_content_valid = run_post_translation_validation(
            final_content=new_file_content,
            source_translations=source_translations,
            filename=translation_file
        )
        if not is_final_content_valid:
            logger.error(
                f"Discarding invalid translation for '{translation_file}'. The original file will be used.")
            continue  # Skip to the next file
        # --- End Post-translation Validator ---

        translated_file_path = os.path.join(translated_queue_folder, translation_file)

        if DRY_RUN:
            logger.info(f"[Dry Run] Would write translated content to '{translated_file_path}'.")
        else:
            # Ensure the destination directory exists
            os.makedirs(os.path.dirname(translated_file_path), exist_ok=True)
            with open(translated_file_path, 'w', encoding='utf-8') as file:
                file.write(new_file_content)
            logger.info(f"Translated file saved to '{translated_file_path}'.\n")

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
            logger.warning(f"Original file '{filename}' not found for archiving. Skipping.")
            continue

        if DRY_RUN:
            logger.info(f"[Dry Run] Would archive '{source_path}' to '{dest_path}'.")
        else:
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy2(source_path, dest_path)
            logger.info(f"Archived original file '{source_path}' to '{dest_path}'.")

async def main():
    """
    Main function to orchestrate the translation process.
    """
    # Configuration is loaded and globals are set at the module level.
    # The logger is also configured there.

    # --- Validation and Setup ---
    validate_paths(INPUT_FOLDER, TRANSLATION_QUEUE_FOLDER, TRANSLATED_QUEUE_FOLDER, REPO_ROOT)

    # Step 1: Identify changed translation files
    changed_files = get_changed_translation_files(INPUT_FOLDER, REPO_ROOT)
    if not changed_files:
        logger.info("No changed translation files detected. Exiting.")
        return
    logger.info(f"Detected {len(changed_files)} changed translation file(s).")

    # Step 2: Archive the original files before any processing.
    archive_folder_path = os.path.join(INPUT_FOLDER, 'archive')
    archive_original_files(changed_files, INPUT_FOLDER, archive_folder_path)
    logger.info(f"Successfully archived original files to '{archive_folder_path}'.")

    # Step 3: Copy changed files to the translation queue for processing.
    copy_files_to_translation_queue(changed_files, INPUT_FOLDER, TRANSLATION_QUEUE_FOLDER)
    logger.info(f"Copied changed files to '{TRANSLATION_QUEUE_FOLDER}' for processing.")

    # Step 4: Process the files in the translation queue.
    processed_files_count, skipped_files = await process_translation_queue(
        translation_queue_folder=TRANSLATION_QUEUE_FOLDER,
        translated_queue_folder=TRANSLATED_QUEUE_FOLDER,
        glossary_file_path=GLOSSARY_FILE_PATH
    )
    if processed_files_count > 0:
        logger.info(
            f"Completed translations for {processed_files_count} file(s). Translated files are in '{TRANSLATED_QUEUE_FOLDER}'.")
    else:
        logger.info("No files were successfully translated.")

    # Step 5: Write skipped files report
    report_path = os.path.join(PROJECT_ROOT_DIR, 'logs', 'skipped_files_report.log')
    if skipped_files:
        logger.info(f"Some files were skipped. Writing report to {report_path}")
        # Ensure the directory exists before trying to write the file.
        report_dir = os.path.dirname(report_path)
        os.makedirs(report_dir, exist_ok=True)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("## ⚠️ Translation Pipeline Warnings\n\n")
            f.write(
                "The following files were skipped during the AI translation process due to validation or linter errors. These issues must be addressed manually.\n\n")
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
        logger.info("Copied translated files back to the input folder.")

    # Optional: Clean up translation queue folders.
    if DRY_RUN or PRESERVE_QUEUES_FOR_DEBUG:
        logger.info("Skipping cleanup of translation queue folders (dry-run or preserve-for-debug enabled).")
    else:
        try:
            shutil.rmtree(TRANSLATION_QUEUE_FOLDER)
            shutil.rmtree(TRANSLATED_QUEUE_FOLDER)
            logger.info("Cleaned up translation queue folders.")
        except Exception:
            logger.exception("Error cleaning up translation queue folders")

if __name__ == "__main__":
    # Ensure queue folders exist, potentially using paths derived from config or defaults
    os.makedirs(TRANSLATION_QUEUE_FOLDER, exist_ok=True)
    os.makedirs(TRANSLATED_QUEUE_FOLDER, exist_ok=True)
    try:
        asyncio.run(main())
    except Exception:
        logger.exception("An unexpected error occurred during execution")
