import asyncio
import json
import logging
import os
import random
import re
import shutil
import subprocess
import uuid
from enum import Enum
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
from tqdm.asyncio import tqdm_asyncio

# Set up logging with timestamps and log levels, logging to both console and file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("translation_log.log")
    ]
)

# Load environment variables from a .env file (make sure to create one with your API key)
load_dotenv()

# Initialize the OpenAI client with your API key
client = AsyncOpenAI(api_key=os.environ.get('OPENAI_API_KEY'))

# Load configuration from a YAML file
CONFIG_FILE = 'config.yaml'

with open(CONFIG_FILE, 'r') as config_file:
    config = yaml.safe_load(config_file)

# Configuration Parameters
REPO_ROOT = config.get('target_project_root', '/path/to/repo/root')
INPUT_FOLDER = config.get('input_folder', '/path/to/default/input_folder')  # Absolute path to resources
GLOSSARY_FILE_PATH = config.get('glossary_file_path', 'glossary.json')
MODEL_NAME = config.get('model_name', 'gpt-4')

# Decide maximum tokens based on model name
# This logic can be adjusted to reflect your custom model token limits
MAX_MODEL_TOKENS = 128000 if MODEL_NAME == 'gpt-4o-mini' else 4000

# Define the translation queue folders
TRANSLATION_QUEUE_FOLDER = config.get('translation_queue_folder', 'translation_queue')
TRANSLATED_QUEUE_FOLDER = config.get('translated_queue_folder', 'translated_queue')

# Dry run configuration (if True, files won't be moved/copied, etc.)
DRY_RUN = config.get('dry_run', False)


class LanguageCode(Enum):
    """
    Enumeration of supported language codes.
    """
    CS = 'cs'
    DE = 'de'
    ES = 'es'
    IT = 'it'
    PT_BR = 'pt_BR'
    PCM = 'pcm'
    RU = 'ru'
    AF_ZA = 'af_ZA'
    # Add more as needed


# Mapping from language codes to language names
LANGUAGE_CODES = {
    LanguageCode.CS.value: 'Czech',
    LanguageCode.DE.value: 'German',
    LanguageCode.ES.value: 'Spanish',
    LanguageCode.IT.value: 'Italian',
    LanguageCode.PT_BR.value: 'Brazilian Portuguese',
    LanguageCode.PCM.value: 'Nigerian Pidgin',
    LanguageCode.RU.value: 'Russian',
    LanguageCode.AF_ZA.value: 'Afrikaans'
    # Add more as needed
}

# Reverse mapping from language names to codes
NAME_TO_CODE = {name.lower(): code for code, name in LANGUAGE_CODES.items()}


def language_code_to_name(language_code: str) -> Optional[str]:
    """
    Convert a language code to a language name.

    Args:
        language_code (str): The language code (e.g., 'cs').

    Returns:
        Optional[str]: The language name if found, else None.
    """
    return LANGUAGE_CODES.get(language_code, None)


def language_name_to_code(target_language: str) -> Optional[str]:
    """
    Convert a language name to a language code.

    Args:
        target_language (str): The full language name (e.g., 'Czech').

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
        Dict[str, Dict[str, str]]: A dictionary containing the glossary data,
                                   keyed by language code, with subdicts of term: translation.
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
        Dict[str, str]: A dictionary of translations {key: value}.
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
                # Handle multiline values if they end with a backslash
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
    Parse a .properties file into a list of entries, comments, or unknown lines,
    as well as produce a dictionary of target translations.

    Args:
        file_path (str): The path to the .properties file.

    Returns:
        Tuple[List[Dict], Dict[str, str]]:
            - A list of parsed lines, each item includes 'type' (entry/comment/unknown),
              'key', 'value', 'original_value', 'line_number'.
            - A dictionary of translations {key: value}.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    parsed_lines = []
    target_translations = {}
    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        if line.startswith('#') or line.strip() == '':
            # Capture comments or blank lines
            parsed_lines.append({'type': 'comment_or_blank', 'content': lines[i]})
            i += 1
        else:
            match = re.match(r'([^=]+)=(.*)', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2)
                line_number = i
                original_value_lines = [value]

                # Handle multiline values if they end with a backslash
                while value.endswith('\\'):
                    value = value[:-1]
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
                # Unknown line format
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
    # Remove leading/trailing whitespace and normalize internal whitespace
    value = re.sub(r'\s+', ' ', value.strip())
    return value


def extract_texts_to_translate(
        parsed_lines: List[Dict],
        source_translations: Dict[str, str],
        target_translations: Dict[str, str]
) -> Tuple[List[str], List[int], List[str]]:
    """
    Figure out which texts need translation by comparing source vs. target.

    Args:
        parsed_lines (List[Dict]): Parsed lines from the target file.
        source_translations (Dict[str, str]): Translations from the source file.
        target_translations (Dict[str, str]): Translations from the target file.

    Returns:
        Tuple[List[str], List[int], List[str]]:
            - List of source texts that need translation,
            - List of indices in parsed_lines where each translation should go,
            - List of keys associated with those texts.
    """
    texts_to_translate = []
    indices = []
    keys = []

    # Create a lookup to find the index in parsed_lines by key
    key_to_index = {item['key']: idx for idx, item in enumerate(parsed_lines) if item['type'] == 'entry'}
    next_index = len(parsed_lines)  # Start index for new entries if needed

    for key, source_value in source_translations.items():
        target_value = target_translations.get(key)
        normalized_source = normalize_value(source_value)
        normalized_target = normalize_value(target_value)

        # If target is None or if it matches the source (implying no translation yet), we need a translation
        if target_value is None or normalized_target == normalized_source:
            texts_to_translate.append(source_value)
            if key in key_to_index:
                indices.append(key_to_index[key])
            else:
                # Key is missing in target, it will be appended
                indices.append(next_index)
                next_index += 1
            keys.append(key)

    return texts_to_translate, indices, keys


def apply_glossary(translated_text: str, language_glossary: Dict[str, str]) -> str:
    """
    Apply glossary terms to the translated text, excluding text within angle brackets (tags).

    Args:
        translated_text (str): The text to adjust with glossary terms.
        language_glossary (Dict[str, str]): The glossary dictionary for the given language.

    Returns:
        str: The text with glossary terms applied (outside of tags).
    """
    # Split text into parts inside and outside of angle brackets
    parts = re.split(r'(<[^<>]+>)', translated_text)
    # parts will be: [outside_text, <tag>, outside_text, <tag>, ...]

    for i in range(0, len(parts), 2):  # Only process outside parts
        for source_term, target_term in language_glossary.items():
            # Use regex to replace whole words only, case-insensitive
            parts[i] = re.sub(
                rf'\b{re.escape(source_term)}\b',
                target_term,
                parts[i],
                flags=re.IGNORECASE
            )

    return ''.join(parts)


def count_tokens(text: str, model_name: str = 'gpt-3.5-turbo') -> int:
    """
    Count the number of tokens in a text for a specific model.

    Args:
        text (str): The text to count tokens in.
        model_name (str): The model name.

    Returns:
        int: The number of tokens used by the provided text.
    """
    encoding = tiktoken.encoding_for_model(model_name)
    return len(encoding.encode(text))


def build_context(
        existing_translations: Dict[str, str],
        source_translations: Dict[str, str],
        language_glossary: Dict[str, str],
        max_tokens: int,
        model_name: str
) -> Tuple[str, str]:
    """
    Build the context prompt (existing translations) and a glossary snippet text
    for use in the translation prompt.

    Args:
        existing_translations (Dict[str, str]): Existing translations in the target language.
        source_translations (Dict[str, str]): Source translations (English).
        language_glossary (Dict[str, str]): The glossary for the given language.
        max_tokens (int): Maximum allowed tokens for the model.
        model_name (str): The model name.

    Returns:
        Tuple[str, str]: (context_text, glossary_text).
    """
    context_examples = []
    total_tokens = 0

    # Build the glossary text
    glossary_entries = [f'"{k}" should be translated as "{v}"' for k, v in language_glossary.items()]
    glossary_text = '\n'.join(glossary_entries)
    glossary_tokens = count_tokens(glossary_text, model_name)

    # Reserve tokens for the rest of the prompt and response
    reserved_tokens = 1000  # Adjust based on your needs
    available_tokens = max_tokens - glossary_tokens - reserved_tokens

    # Iterate over existing translations to provide context examples
    for key, translated_value in existing_translations.items():
        source_value = source_translations.get(key)
        if not source_value:
            continue  # Skip if source key is missing in the source translations

        # Normalize values
        normalized_source = normalize_value(source_value)
        normalized_translation = normalize_value(translated_value)

        # Only use lines that are actually translated (i.e., different from the source)
        if normalized_source == normalized_translation:
            continue

        example = f"{key} = \"{translated_value}\""
        example_tokens = count_tokens(example, model_name)
        if total_tokens + example_tokens > available_tokens:
            # Stop if adding this example would exceed available tokens
            break
        context_examples.append(example)
        total_tokens += example_tokens

    context_text = '\n'.join(context_examples)
    return context_text, glossary_text


def extract_placeholders(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Extract placeholders or tags in angle brackets / curly braces
    and replace them with UUID tokens to prevent accidental translation.

    Args:
        text (str): The text to process.

    Returns:
        Tuple[str, Dict[str, str]]:
            - The processed text with placeholders replaced by tokens,
            - A mapping of tokens to the original placeholders.
    """
    if not isinstance(text, str):
        raise ValueError("Input text must be a string.")

    pattern = re.compile(r'(<[^<>]+>)|(\{[^{}]+\})')
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
    Restore placeholders in the text based on the token -> original mapping.

    Args:
        text (str): The text with placeholder tokens.
        placeholder_mapping (Dict[str, str]): The dictionary of token -> original placeholder.

    Returns:
        str: The text with all placeholders restored.
    """
    for token, placeholder in placeholder_mapping.items():
        text = text.replace(token, placeholder)
    return text


def clean_translated_text(translated_text: str, original_text: str) -> str:
    """
    Clean the translated text by removing any extra quotation marks or brackets
    not present in the original.

    Args:
        translated_text (str): The translated text.
        original_text (str): The original source text.

    Returns:
        str: The cleaned translated text.
    """
    # If the translation got wrapped in quotes but the original wasn't, remove them
    if translated_text.startswith('"') and translated_text.endswith('"') and not (
            original_text.startswith('"') and original_text.endswith('"')):
        translated_text = translated_text[1:-1]

    # If the translation got wrapped in brackets but the original wasn't, remove them
    if translated_text.startswith('[') and translated_text.endswith(']') and not (
            original_text.startswith('[') and original_text.endswith(']')):
        translated_text = translated_text[1:-1]

    return translated_text


async def _handle_retry(attempt: int, max_retries: int, base_delay: float, key: str,
                        api_exc: Optional[Exception] = None) -> bool:
    """
    Handle the retry mechanism with exponential backoff and optional jitter.

    Args:
        attempt (int): The current attempt number.
        max_retries (int): The maximum number of retry attempts.
        base_delay (float): The base delay in seconds for backoff.
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
                        # If header is in seconds
                        retry_after = float(retry_after_header)
                    elif retry_after_header.endswith("ms"):
                        # If header is in milliseconds
                        retry_after = float(retry_after_header[:-2]) / 1000

            # If no Retry-After header, use exponential backoff + random jitter
            if retry_after is None:
                retry_after = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)

            delay = retry_after
        except Exception as exc:
            logging.warning(f"Failed to parse Retry-After header: {exc}. Falling back to exponential backoff.")
            delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)

        logging.info(
            f"Retrying request to /chat/completions in {delay:.2f} seconds (Attempt {attempt}/{max_retries})"
        )
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
    Asynchronously translate a single text with context and glossary applied.

    Args:
        text (str): The text to translate.
        key (str): The key in the .properties file associated with the text.
        existing_translations (Dict[str, str]): Existing translations in target language.
        source_translations (Dict[str, str]): Source translations (English).
        target_language (str): The target language (e.g., 'German').
        glossary (Dict[str, Dict[str, str]]): The loaded glossary data by language code.
        semaphore (asyncio.Semaphore): Semaphore to limit concurrent API calls.
        rate_limiter (AsyncLimiter): Rate limiter to control request rate.
        index (int): The index of this text in the original list being processed.

    Returns:
        Tuple[int, str]:
            - The original index,
            - The translated text (or fallback to the original text on failure).
    """
    async with semaphore, rate_limiter:
        # Get the language code from the target language name
        language_code = language_name_to_code(target_language)

        # Get the glossary for the current language
        language_glossary = glossary.get(language_code, {})

        # Build context and glossary text
        context_examples_text, glossary_text = build_context(
            existing_translations,
            source_translations,
            language_glossary,
            MAX_MODEL_TOKENS,
            MODEL_NAME
        )

        # Extract and protect placeholders
        processed_text, placeholder_mapping = extract_placeholders(text)

        # The system prompt for chat completion
        system_prompt = f"""
You are an expert translator specializing in software localization. Translate the following text from English to {target_language}, considering the context and glossary provided.

**Instructions**:
- **Do not translate or modify placeholder tokens**: Any text enclosed within double underscores `__` (e.g., `__PH_abc123__`) should remain exactly as is.
- **Maintain placeholders**: Keep placeholders like `{{0}}`, `{{1}}` unchanged.
- **Preserve formatting**: Keep special characters and formatting such as `\\n` and `\\t`.
- **Do not add** any additional characters or punctuation (e.g., no square brackets, quotation marks, etc.).
- **Provide only** the translated text corresponding to the Value.

Use the translations specified in the glossary for the given terms. Ensure the translation reads naturally and is culturally appropriate for the target audience.

The translation is for a desktop trading app called Bisq. Keep the translations brief and consistent with typical software terminology. On Bisq, you can buy and sell bitcoin for fiat (or other cryptocurrencies) privately and securely using Bisq's peer-to-peer network and open-source desktop software. "Bisq Easy" is a brand name and should not be translated.
"""

        # The user prompt, containing the glossary and context examples
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

        for attempt in range(1, max_retries + 1):
            try:
                # Use the ChatCompletion API
                response = await client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[
                        {
                            "role": "system",
                            "content": system_prompt
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    temperature=0.3,
                )

                translated_text = response.choices[0].message.content.strip()

                # Restore placeholders in the translated text
                translated_text = restore_placeholders(translated_text, placeholder_mapping)

                # Clean the translated text (remove quotes/brackets if they weren't in the original)
                translated_text = clean_translated_text(translated_text, text)

                # Apply glossary post-processing
                translated_text = apply_glossary(translated_text, language_glossary)

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
                logging.error(f"An unexpected error occurred: {general_exc}")
                return index, text


def integrate_translations(
        parsed_lines: List[Dict],
        translations: List[str],
        indices: List[int],
        keys: List[str]
) -> List[Dict]:
    """
    Integrate newly translated texts back into parsed_lines.

    Args:
        parsed_lines (List[Dict]): Original parsed lines.
        translations (List[str]): The list of translated texts corresponding to the keys.
        indices (List[int]): The positions in parsed_lines to place each translation.
        keys (List[str]): The .properties keys for each translation.

    Returns:
        List[Dict]: The updated parsed_lines list with translations applied.
    """
    for idx, translation_idx in enumerate(indices):
        key = keys[idx]
        value = translations[idx]
        if translation_idx < len(parsed_lines):
            # Update existing entry
            parsed_lines[translation_idx]['value'] = value
        else:
            # Key was missing in target, create a new entry at the end
            parsed_lines.append({
                'type': 'entry',
                'key': key,
                'value': value,
                'original_value': value,  # For new entries, original_value matches the new translation
                'line_number': translation_idx
            })
    return parsed_lines


def reassemble_file(parsed_lines: List[Dict]) -> str:
    """
    Reassemble the file content from the updated parsed lines.

    Args:
        parsed_lines (List[Dict]): The parsed lines.

    Returns:
        str: The reassembled file content as a single string.
    """
    lines = []
    for item in parsed_lines:
        if item['type'] == 'entry':
            value = item['value']

            # Preserve multiline formatting if it existed originally
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
            # Comments, blank, unknown lines
            lines.append(item['content'])
    return ''.join(lines)


def extract_language_from_filename(filename: str) -> Optional[str]:
    """
    Extract the language code from a properties filename.

    Args:
        filename (str): The filename (e.g., 'messages_cs.properties').

    Returns:
        Optional[str]: The language code (e.g., 'cs') if found, else None.
    """
    match = re.search(r'_(\w{2,3}(?:_\w{2})?)\.properties$', filename)
    if match:
        lang_code = match.group(1)  # e.g., 'cs' from '_cs.properties'
        return lang_code
    else:
        return None


def move_files_to_archive(input_folder_path: str, archive_folder_path: str):
    """
    Move processed .properties files to an archive folder.

    Args:
        input_folder_path (str): The path to the original folder containing .properties files.
        archive_folder_path (str): The path to the archive folder.
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
    Copy translated .properties files from the translated queue back to the input folder.

    Args:
        translated_queue_folder (str): The folder containing translated files.
        input_folder_path (str): The input folder path where files should be placed.
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
    Validate that the necessary folders exist and have appropriate read/write permissions.

    Args:
        input_folder (str): Path to the input folder.
        translation_queue (str): Path to the translation queue folder.
        translated_queue (str): Path to the translated queue folder.
        repo_root (str): Path to the Git repository root.

    Raises:
        FileNotFoundError: If any path does not exist.
        PermissionError: If any path is not accessible (lacking read/write permissions).
    """
    for path, name in [
        (input_folder, "Input Folder"),
        (translation_queue, "Translation Queue Folder"),
        (translated_queue, "Translated Queue Folder"),
        (repo_root, "Repository Root")
    ]:
        if not os.path.exists(path):
            logging.error(f"{name} '{path}' does not exist.")
            raise FileNotFoundError(f"{name} '{path}' does not exist.")
        if not os.access(path, os.R_OK | os.W_OK):
            logging.error(f"{name} '{path}' is not accessible (read/write permissions needed).")
            raise PermissionError(f"{name} '{path}' is not accessible (read/write permissions needed).")
    logging.info("All critical paths are valid and accessible.")


def get_changed_translation_files(input_folder_path: str, repo_root: str) -> List[str]:
    """
    Use Git to find changed translation files in the input folder.

    Args:
        input_folder_path (str): The absolute path to the input folder.
        repo_root (str): The absolute path to the Git repository root.

    Returns:
        List[str]: List of changed translation file names relative to input_folder_path.
    """
    try:
        # Relative path of input_folder from repo_root
        rel_input_folder = os.path.relpath(input_folder_path, repo_root)

        # Run 'git status --porcelain rel_input_folder' to get changed files
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
            # Each line starts with two characters indicating status, e.g.:
            # ' M filename', '?? filename', 'A  filename'
            status, filepath = line[:2], line[3:]
            # We check for certain statuses: M (modified), A (added), etc.
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
    Copy changed translation files from the input folder to the translation queue,
    flattening any folder structure (no nested directories).

    Args:
        changed_files (List[str]): List of changed translation file names.
        input_folder_path (str): The absolute path to the input folder.
        translation_queue_folder (str): The absolute path to the translation queue folder.
    """
    os.makedirs(translation_queue_folder, exist_ok=True)
    for translation_file in changed_files:
        source_file_path = os.path.join(input_folder_path, translation_file)
        dest_translation_path = os.path.join(translation_queue_folder, translation_file)

        logging.info(f"Processing translation file: {translation_file}")

        # Check if source file exists
        if not os.path.exists(source_file_path):
            logging.warning(f"Translation file '{translation_file}' not found in '{input_folder_path}'. Skipping.")
            continue

        if DRY_RUN:
            logging.info(f"[Dry Run] Would copy translation file '{source_file_path}' to '{dest_translation_path}'.")
        else:
            # Ensure the destination directory exists
            dest_dir = os.path.dirname(dest_translation_path)
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copy2(source_file_path, dest_translation_path)
            logging.info(f"Copied translation file '{source_file_path}' to '{dest_translation_path}'.")


async def process_translation_queue(
        translation_queue_folder: str,
        translated_queue_folder: str,
        glossary_file_path: str
):
    """
    Process all .properties files in the translation queue folder, applying AI translations
    for needed keys.

    Args:
        translation_queue_folder (str): The folder containing files to translate.
        translated_queue_folder (str): The folder to save translated files.
        glossary_file_path (str): The glossary file path.
    """
    properties_files = [f for f in os.listdir(translation_queue_folder) if f.endswith('.properties')]

    # Load the glossary from the JSON file
    glossary = load_glossary(glossary_file_path)

    # Initialize rate limiter (example: 60 requests per minute)
    rate_limit = 60  # Number of allowed requests
    rate_period = 60  # Time period in seconds
    rate_limiter = AsyncLimiter(max_rate=rate_limit, time_period=rate_period)

    for translation_file in properties_files:
        language_code = extract_language_from_filename(translation_file)
        if not language_code:
            logging.warning(f"Skipping file {translation_file}: unable to extract language code.")
            continue

        target_language = language_code_to_name(language_code)
        if not target_language:
            logging.warning(f"Skipping file {translation_file}: unsupported language code '{language_code}'.")
            continue

        logging.info(f"Processing file '{translation_file}' for language '{target_language}'...")

        # Construct full paths
        translation_file_path = os.path.join(translation_queue_folder, translation_file)
        source_file_name = re.sub(r'_[a-z]{2,3}(?:_[A-Z]{2})?\.properties$', '.properties', translation_file)
        source_file_path = os.path.join(INPUT_FOLDER, source_file_name)

        if not os.path.exists(source_file_path):
            logging.warning(f"Source file '{source_file_name}' not found in '{INPUT_FOLDER}'. Skipping.")
            continue

        # Parse target and source files
        parsed_lines, target_translations = parse_properties_file(translation_file_path)
        source_translations = load_source_properties_file(source_file_path)

        # Determine which texts need translating
        texts_to_translate, indices, keys_to_translate = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations
        )
        if not texts_to_translate:
            logging.info(f"No texts to translate in file '{translation_file}'.")
            continue

        # Limit concurrency
        semaphore = asyncio.Semaphore(2)

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
                rate_limiter,
                idx
            )
            for idx, (text, key) in enumerate(zip(texts_to_translate, keys_to_translate))
        ]

        # Run tasks concurrently with a progress bar
        results = []
        for coro in tqdm_asyncio.as_completed(tasks, desc=f"Translating {translation_file}", unit="translation"):
            index, result = await coro
            results.append((index, result))

        # Sort results by their original index to maintain correct order
        results.sort(key=lambda x: x[0])
        translations = [result for _, result in results]

        # Integrate the new translations back into the parsed lines
        updated_lines = integrate_translations(parsed_lines, translations, indices, keys_to_translate)
        new_file_content = reassemble_file(updated_lines)
        translated_file_path = os.path.join(translated_queue_folder, translation_file)

        if DRY_RUN:
            logging.info(f"[Dry Run] Would write translated content to '{translated_file_path}'.")
        else:
            os.makedirs(os.path.dirname(translated_file_path), exist_ok=True)
            with open(translated_file_path, 'w', encoding='utf-8') as file:
                file.write(new_file_content)
            logging.info(f"Translated file saved to '{translated_file_path}'.\n")


async def main():
    """
    Main function orchestrating the end-to-end translation process:
    1) Validate paths.
    2) Identify changed translation files via Git.
    3) Copy changed files to the translation queue.
    4) Process the translation queue (AI translations).
    5) Copy translated files back.
    6) Archive original queue files.
    7) Clean up if not a dry run.
    """
    # Validate required paths and permissions
    validate_paths(INPUT_FOLDER, TRANSLATION_QUEUE_FOLDER, TRANSLATED_QUEUE_FOLDER, REPO_ROOT)

    # Step 1: Identify changed translation files
    changed_files = get_changed_translation_files(INPUT_FOLDER, REPO_ROOT)
    if not changed_files:
        logging.info("No changed translation files detected. Exiting.")
        return
    logging.info(f"Detected {len(changed_files)} changed translation file(s).")

    # Step 2: Copy changed files to the translation queue
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

    # Optional: Clean up translation queue folders if not a dry run
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
    # Ensure queue folders exist before running
    os.makedirs(TRANSLATION_QUEUE_FOLDER, exist_ok=True)
    os.makedirs(TRANSLATED_QUEUE_FOLDER, exist_ok=True)
    try:
        asyncio.run(main())
    except Exception as main_exc:
        logging.error(f"An unexpected error occurred during execution: {main_exc}")
