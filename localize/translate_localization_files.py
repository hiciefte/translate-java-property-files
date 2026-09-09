import asyncio
import datetime as _dt
import hashlib
import html
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Dict, List, Mapping, Optional, Pattern, Set, Tuple

# --- Python Version Check ---
# This script requires Python 3.11 or newer for features like modern asyncio.
if sys.version_info < (3, 11):
    sys.stderr.write("Error: This script requires Python 3.11 or newer.\n")
    sys.stderr.write(f"You are running Python {sys.version.split()[0]}.\n")
    sys.exit(1)
# --- End Version Check ---

import jsonschema
from aiolimiter import AsyncLimiter
from openai.types.chat import (
    ChatCompletionSystemMessageParam,
    ChatCompletionUserMessageParam
)
from tqdm.asyncio import tqdm

from localize.app_config import load_app_config
from localize.atomic_io import write_json_atomic, write_text_atomic
from localize.ignore_keys import is_ignored_key
from localize.json_response import (
    chat_json_mode_kwargs,
    chat_reasoning_effort_kwargs,
    loads_json_object,
)
from localize.localization_adapters import (
    get_localization_adapter,
    lint_properties_file as lint_properties_file,
)
from localize.localization_formats import LocalizationFormat
from localize.localization_layouts import LocalizationLayout
from localize.localization_profiles import LocalizationProfile
from localize.model_provider import OpenAICompatibleProvider
from localize.placeholder_rules import (
    extract_placeholder_tokens,
    protect_placeholders,
    restore_placeholders as restore_protected_placeholders,
    set_placeholder_profile,
)
from localize.pipeline_core import (
    RUN_METRIC_KEYS,
    TranslationPipelineOptions,
    TranslationPipelinePaths,
    TranslationPipelineSteps,
    run_translation_pipeline,
)
from localize.translation_prompts import build_translation_system_prompt
from localize.translation_memory import (
    TranslationMemory,
    load_translation_memory,
    save_translation_memory,
)
from localize.translation_validator import (
    check_placeholder_parity,
    check_encoding_and_mojibake,
    find_glossary_mismatches,
    find_disallowed_control_characters,
)
# --- Constants and Globals ---
# Load application configuration
# TODO: Move configuration loading behind the runtime entry point so importing
# this module no longer reads files or environment variables as a side effect.
config = load_app_config()
set_placeholder_profile(config.placeholder_profile)

# Create a dedicated logger for this script to avoid conflicts with the root logger.
logger = logging.getLogger("translation_script")

# Define the expected JSON schema for the AI's response in the holistic review.
# This ensures that the AI returns a dictionary where every value is a string.
LOCALIZATION_SCHEMA = {
    "type": "object",
    "additionalProperties": {"type": "string"},
}
HOLISTIC_REVIEW_CONTEXT_MAX_KEYS = 24
HOLISTIC_REVIEW_CONTEXT_MAX_UTF8_BYTES = 16 * 1024

# Extract configuration values for convenience
PROJECT_ROOT_DIR = config.project_root
REPO_ROOT = config.target_project_root
INPUT_FOLDER = config.input_folder
GLOSSARY_FILE_PATH = config.glossary_file_path
MODEL_NAME = config.model_name
REVIEW_MODEL_NAME = config.review_model_name
REVIEW_REASONING_EFFORT = config.review_reasoning_effort
SEMANTIC_REVIEW_ENABLED = config.semantic_review_enabled
SEMANTIC_REVIEW_MODEL_NAME = config.semantic_review_model_name
MAX_MODEL_TOKENS = config.max_model_tokens
DRY_RUN = config.dry_run
PROCESS_ALL_FILES = config.process_all_files
HOLISTIC_REVIEW_CHUNK_SIZE = config.holistic_review_chunk_size
MAX_CONCURRENT_API_CALLS = config.max_concurrent_api_calls
RATE_LIMIT_PER_MINUTE = config.rate_limit_per_minute
LANGUAGE_CODES = config.language_codes
NAME_TO_CODE = config.name_to_code
RETRANSLATE_IDENTICAL_SOURCE_STRINGS = config.retranslate_identical_source_strings
STYLE_RULES = config.style_rules
PRECOMPUTED_STYLE_RULES_TEXT = config.precomputed_style_rules_text
BRAND_GLOSSARY = config.brand_glossary
IGNORE_KEY_PATTERNS = config.ignore_key_patterns
PROJECT_CONTEXT = config.project_context
LOCALIZATION_FORMAT = config.localization_format
LOCALIZATION_LAYOUT = config.localization_layout
LOCALIZATION_PROFILES = config.localization_profiles
TRANSLATION_QUEUE_FOLDER = config.translation_queue_folder
TRANSLATED_QUEUE_FOLDER = config.translated_queue_folder
TRANSLATION_KEY_LEDGER_FILE_PATH = config.translation_key_ledger_file_path
TRANSLATION_MEMORY_FILE_PATH = config.translation_memory_file_path
TRANSLATION_MEMORY_ENABLED = config.translation_memory_enabled
PRESERVE_QUEUES_FOR_DEBUG = config.preserve_queues_for_debug
TRANSLATION_GLOSSARY_ENFORCEMENT = config.translation_glossary_enforcement
MODEL_PROVIDER = config.model_provider
client = config.openai_client
_FALLBACK_PROVIDER = OpenAICompatibleProvider(client=None)

# --- End Config and Globals ---

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
            payload = json.load(f)
        if not isinstance(payload, dict):
            logger.error("Glossary file '%s' must contain a JSON object.", glossary_file_path)
            return {}
        glossary: Dict[str, Dict[str, str]] = {}
        for locale, mappings in payload.items():
            if str(locale).startswith('_'):
                continue
            if not isinstance(mappings, dict) or not all(
                isinstance(source, str) and isinstance(target, str)
                for source, target in mappings.items()
            ):
                logger.warning("Ignoring invalid glossary locale namespace '%s'.", locale)
                continue
            glossary[str(locale)] = dict(mappings)
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


def compute_ledger_hash(value: Optional[str]) -> str:
    """Compute a stable hash for ledger comparisons."""
    normalized = normalize_value(value)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def _ledger_verified_existing_translation(
        key: str,
        source_translations: Mapping[str, str],
        existing_translations: Mapping[str, str],
        file_ledger_entries: Mapping[str, Mapping[str, str]],
) -> Optional[str]:
    source_value = source_translations.get(key)
    existing_value = existing_translations.get(key)
    ledger_entry = file_ledger_entries.get(key)
    if (
            isinstance(source_value, str)
            and isinstance(existing_value, str)
            and existing_value.strip()
            and normalize_value(existing_value) != normalize_value(source_value)
            and isinstance(ledger_entry, Mapping)
            and ledger_entry.get("source_hash") == compute_ledger_hash(source_value)
            and ledger_entry.get("target_hash") == compute_ledger_hash(existing_value)
    ):
        return existing_value
    return None


def prefer_existing_translation_on_failure(
        results: List[Tuple[int, str, bool]],
        keys_to_translate: List[str],
        source_translations: Mapping[str, str],
        existing_translations: Mapping[str, str],
        file_ledger_entries: Mapping[str, Mapping[str, str]],
) -> List[Tuple[int, str, bool]]:
    """Keep a verified current-source translation when a model call fails.

    A prior target is safe to reuse only when the ledger binds both its source
    and target hashes to the values still on disk.  This avoids restoring a
    stale translation after the source changed or after an unrecorded target
    edit.  The failure flag remains false so the key is retried and never seeds
    translation memory.
    """
    repaired: List[Tuple[int, str, bool]] = []
    for position, value, succeeded in results:
        if not succeeded and 0 <= position < len(keys_to_translate):
            existing_value = _ledger_verified_existing_translation(
                keys_to_translate[position],
                source_translations,
                existing_translations,
                file_ledger_entries,
            )
            if existing_value is not None:
                value = existing_value
        repaired.append((position, value, succeeded))
    return repaired


def translation_memory_context_fingerprint(
        *,
        locale: str,
        glossary: Mapping[str, Dict[str, str]],
        brand_glossary: List[str],
        style_rules_text: str = "",
        translation_glossary_enforcement: str = "exact",
) -> str:
    """Hash context that can materially change the correct target string."""
    payload = {
        "locale": locale,
        "glossary": glossary.get(locale, {}),
        "brand_glossary": sorted(set(brand_glossary)),
        "style_rules_text": style_rules_text,
        "translation_glossary_enforcement": translation_glossary_enforcement,
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def load_translation_key_ledger(ledger_file_path: str) -> Dict[str, Dict[str, Dict[str, str]]]:
    """
    Load the persistent translation key ledger from disk.

    Returns:
        Mapping of translation_file -> key -> {source_hash, target_hash}
    """
    if not os.path.exists(ledger_file_path):
        return {}
    allow_reset = os.environ.get("LOCALIZE_ALLOW_RESET_LEDGER", "").lower() in {"1", "true", "yes"}

    def _backup_and_handle_failure(reason: str) -> Dict[str, Dict[str, Dict[str, str]]]:
        timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d%H%M%S")
        backup_path = f"{ledger_file_path}.corrupt-{timestamp}"
        backed_up = False
        try:
            os.replace(ledger_file_path, backup_path)
            backed_up = True
        except OSError:
            logger.exception("Failed to back up invalid translation key ledger '%s'.", ledger_file_path)
            if not allow_reset:
                raise RuntimeError(f"Failed to load translation key ledger '{ledger_file_path}': {reason}")
        if backed_up:
            message = (
                f"Translation key ledger '{ledger_file_path}' is invalid and was backed up to "
                f"'{backup_path}': {reason}"
            )
        else:
            message = (
                f"Translation key ledger '{ledger_file_path}' is invalid and could not be backed up: {reason}"
            )
        if allow_reset:
            logger.warning("%s. LOCALIZE_ALLOW_RESET_LEDGER is set; continuing with an empty ledger.", message)
            return {}
        raise RuntimeError(f"{message}. Set LOCALIZE_ALLOW_RESET_LEDGER=true to reset deliberately.")

    try:
        with open(ledger_file_path, 'r', encoding='utf-8') as f:
            payload = json.load(f)
        if not isinstance(payload, dict):
            return _backup_and_handle_failure("root JSON value is not an object")
        files_obj = payload.get("files", {})
        if not isinstance(files_obj, dict):
            return _backup_and_handle_failure("missing or invalid 'files' map")
        return files_obj
    except Exception as exc:
        if isinstance(exc, RuntimeError):
            raise
        return _backup_and_handle_failure(str(exc))


def save_translation_key_ledger(
        ledger_file_path: str,
        key_ledger: Dict[str, Dict[str, Dict[str, str]]]
) -> None:
    """Persist translation key ledger to disk."""
    if DRY_RUN:
        logger.info("[Dry Run] Skipping write of translation key ledger.")
        return
    try:
        payload = {
            "version": 1,
            "updated_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
            "files": key_ledger
        }
        write_json_atomic(ledger_file_path, payload, sort_keys=True)
    except Exception as exc:
        logger.exception("Failed to save translation key ledger to '%s'.", ledger_file_path)
        raise RuntimeError(f"Failed to save translation key ledger '{ledger_file_path}'.") from exc


def build_file_key_ledger(
        source_translations: Dict[str, str],
        final_translations: Dict[str, str],
        failed_keys: Optional[Set[str]] = None
) -> Dict[str, Dict[str, str]]:
    """Build per-file ledger entries from source/target key-value maps."""
    file_ledger: Dict[str, Dict[str, str]] = {}
    failed_keys = failed_keys or set()
    for key, target_value in final_translations.items():
        source_value = source_translations.get(key, "")
        entry = {
            "source_hash": compute_ledger_hash(source_value),
            "target_hash": compute_ledger_hash(target_value)
        }
        if key in failed_keys:
            entry["status"] = "failed"
        file_ledger[key] = entry
    return file_ledger


@dataclass(frozen=True)
class TranslationMemoryPlan:
    """Split of cached translation-memory results and pending model work."""

    cached_results: List[Tuple[int, str]]
    pending_texts: List[str]
    pending_line_indices: List[int]
    pending_keys: List[str]
    pending_positions: List[int]


def new_run_metrics() -> Dict[str, int]:
    """Create a run-metrics map with stable keys for reporting."""
    return {key: 0 for key in RUN_METRIC_KEYS}


def increment_run_metric(metrics: Dict[str, int], key: str, amount: int = 1) -> None:
    """Increment a named run metric in-place."""
    metrics[key] = int(metrics.get(key, 0)) + amount


def count_changed_translation_values(
        before: Mapping[str, str],
        after: Mapping[str, str],
) -> int:
    """Count target values that changed during this pipeline run."""
    changed = 0
    for key, value in after.items():
        if before.get(key) != value:
            changed += 1
    return changed


class ProcessTranslationQueueResult(tuple):
    """Four-value process result with attached run metrics.

    Existing direct callers can still unpack the legacy four fields, while the
    generic pipeline core can read ``run_metrics`` for richer reporting.
    """

    run_metrics: Dict[str, int]

    def __new__(
            cls,
            processed_files_count: int,
            processed_filenames: List[str],
            skipped_files: Dict[str, List[str]],
            total_keys_translated: int,
            run_metrics: Optional[Dict[str, int]] = None,
    ):
        obj = super().__new__(
            cls,
            (processed_files_count, processed_filenames, skipped_files, total_keys_translated),
        )
        obj.run_metrics = run_metrics or new_run_metrics()
        return obj


def apply_translation_memory(
        *,
        texts_to_translate: List[str],
        indices: List[int],
        keys_to_translate: List[str],
        memory: Optional[TranslationMemory],
        locale: str,
        format_id: str,
        context_fingerprint: Optional[str] = None,
) -> TranslationMemoryPlan:
    """Reuse exact approved translations and keep unresolved keys for the model."""
    if memory is None:
        return TranslationMemoryPlan(
            cached_results=[],
            pending_texts=list(texts_to_translate),
            pending_line_indices=list(indices),
            pending_keys=list(keys_to_translate),
            pending_positions=list(range(len(texts_to_translate))),
        )

    cached_results: List[Tuple[int, str]] = []
    pending_texts: List[str] = []
    pending_line_indices: List[int] = []
    pending_keys: List[str] = []
    pending_positions: List[int] = []
    for position, (text, line_index, key) in enumerate(zip(texts_to_translate, indices, keys_to_translate)):
        cached = memory.lookup(
            text,
            locale=locale,
            format_id=format_id,
            context_fingerprint=context_fingerprint,
        )
        if cached is not None:
            if normalize_value(cached) == normalize_value(text):
                logger.warning("Ignoring source-identical translation memory entry for key '%s'.", key)
            else:
                cached_results.append((position, cached))
                logger.info("Reused translation memory for key '%s'.", key)
                continue
        pending_texts.append(text)
        pending_line_indices.append(line_index)
        pending_keys.append(key)
        pending_positions.append(position)
    return TranslationMemoryPlan(
        cached_results=cached_results,
        pending_texts=pending_texts,
        pending_line_indices=pending_line_indices,
        pending_keys=pending_keys,
        pending_positions=pending_positions,
    )


def update_translation_memory(
        memory: TranslationMemory,
        source_translations: Dict[str, str],
        final_translations: Dict[str, str],
        keys: List[str],
        *,
        locale: str,
        format_id: str,
        failed_keys: Set[str],
        context_fingerprint: Optional[str] = None,
) -> None:
    """Record successful translations for future exact-match reuse."""
    for key in keys:
        if key in failed_keys:
            continue
        source_value = source_translations.get(key)
        target_value = final_translations.get(key)
        if source_value is None or target_value is None:
            continue
        if not target_value.strip() or normalize_value(source_value) == normalize_value(target_value):
            continue
        memory.record(
            source_value,
            target_value,
            locale=locale,
            format_id=format_id,
            context_fingerprint=context_fingerprint,
        )


def extract_texts_to_translate(
        parsed_lines: List[Dict],
        source_translations: Dict[str, str],
        target_translations: Dict[str, str],
        newly_added_keys: Optional[Set[str]] = None,
        file_ledger_entries: Optional[Dict[str, Dict[str, str]]] = None,
        retranslate_identical_existing: bool = False,
        ignore_key_patterns: Optional[List[Pattern[str]]] = None,
        selection_metrics: Optional[Dict[str, int]] = None,
) -> Tuple[List[str], List[int], List[str]]:
    """
    Identifies which texts need to be translated. A text needs translation if:
    1. The key is new (exists in source, not in target).
    2. The key was newly synchronized in this run and currently equals the source.
       This includes keys added by file key synchronization and keys changed in
       the current git working tree (e.g., inserted by ``tx pull -t -f``).
    3. The source is non-empty but the existing target value is empty.
    4. (Optional legacy mode) Existing keys with source-identical values are also
       translated when ``retranslate_identical_existing`` is enabled.

    Args:
        parsed_lines: The parsed content of the target language file.
        source_translations: A dictionary of key-value pairs from the source (e.g., English) file.
        target_translations: A dictionary of key-value pairs from the target file being processed.
        newly_added_keys: Keys that were added by key synchronization in this run.
        file_ledger_entries: Persisted hash data for keys in this translation file.
        retranslate_identical_existing: Whether to retranslate pre-existing source-identical keys.
        ignore_key_patterns: Compiled key regexes that are never model-translated.
        selection_metrics: Optional metrics map updated with selection decisions.

    Returns:
        A tuple containing the list of texts to translate, their corresponding indices, and their keys.
    """
    texts_to_translate = []
    indices = []
    keys_to_translate = []
    newly_added_keys = newly_added_keys or set()
    file_ledger_entries = file_ledger_entries or {}
    ignore_key_patterns = ignore_key_patterns or []

    existing_keys_in_target = {line['key'] for line in parsed_lines if line['type'] == 'entry'}

    # 1. Check existing keys for required updates.
    for i, line in enumerate(parsed_lines):
        if line['type'] == 'entry':
            key = line['key']
            if is_ignored_key(key, ignore_key_patterns):
                continue
            target_value = line.get('value', '')
            source_value = source_translations.get(key)

            if source_value is None:
                continue

            is_source_identical = normalize_value(source_value) == normalize_value(target_value)
            ledger_entry = file_ledger_entries.get(key, {})
            previous_status = ledger_entry.get("status")
            previous_source_hash = ledger_entry.get("source_hash")
            previous_target_hash = ledger_entry.get("target_hash")
            current_source_hash = compute_ledger_hash(source_value)
            current_target_hash = compute_ledger_hash(target_value)
            should_translate_newly_added = key in newly_added_keys
            should_translate_empty_target = bool(source_value.strip()) and not target_value.strip()
            should_translate_legacy_mode = is_source_identical and retranslate_identical_existing
            should_translate_changed_source = (
                previous_source_hash is not None and previous_source_hash != current_source_hash
            )
            should_translate_regressed_to_source = (
                previous_target_hash is not None
                and current_target_hash == current_source_hash
                and previous_target_hash != current_source_hash
            )
            should_translate_failed_status = previous_status == "failed"
            should_translate_existing = (
                # New keys synchronized in this run should always be translated.
                should_translate_newly_added
                # Explicitly empty locale values are part of the translation backlog.
                or should_translate_empty_target
                # Legacy behavior: also retranslate any source-identical existing key.
                or should_translate_legacy_mode
                # Source text changed since the last run for this key.
                or should_translate_changed_source
                # Previously translated key fell back to source-identical content.
                or should_translate_regressed_to_source
                # Keys previously reverted by validation should be retried.
                or should_translate_failed_status
            )

            # Only newly synchronized source-identical keys are translated by default.
            if should_translate_existing:
                # The value to translate is the source value.
                texts_to_translate.append(source_value)
                indices.append(i)  # Use the line's actual index
                keys_to_translate.append(key)
                continue

            # Migration visibility: without a baseline, existing source-identical keys are skipped by default.
            if (
                    is_source_identical
                    and previous_source_hash is None
                    and not retranslate_identical_existing
                    and not should_translate_newly_added
            ):
                logger.info(
                    "Skipping key '%s' (source==target) because no ledger baseline exists yet. "
                    "Enable 'retranslate_identical_source_strings' or seed the translation key ledger.",
                    key
                )
                if selection_metrics is not None:
                    increment_run_metric(selection_metrics, "source_identical_skipped_count")

    # 2. Find new keys that are in the source but not in the target file.
    new_keys = source_translations.keys() - existing_keys_in_target

    # Start indexing for new keys from after the last line of the parsed file
    next_new_key_index = len(parsed_lines)

    for key in sorted(list(new_keys)):  # Sort for deterministic order
        if is_ignored_key(key, ignore_key_patterns):
            continue
        source_value = source_translations[key]
        texts_to_translate.append(source_value)
        indices.append(next_new_key_index)
        keys_to_translate.append(key)
        next_new_key_index += 1

    return texts_to_translate, indices, keys_to_translate


def apply_ignored_source_values(
        parsed_lines: List[Dict],
        target_translations: Dict[str, str],
        source_translations: Dict[str, str],
        ignore_key_patterns: List[Pattern[str]],
) -> Set[str]:
    """Force ignored keys in the target draft to the source value verbatim."""
    if not ignore_key_patterns:
        return set()

    updated_keys: Set[str] = set()
    for line in parsed_lines:
        if line.get('type') != 'entry':
            continue
        key = line.get('key')
        if not key or not is_ignored_key(key, ignore_key_patterns):
            continue
        if key not in source_translations:
            continue
        source_value = source_translations[key]
        if line.get('value', '') != source_value:
            updated_keys.add(key)
        line['value'] = source_value
        target_translations[key] = source_value
    return updated_keys


def filter_git_changed_keys_by_source(
        git_changed_keys: Set[str],
        source_translations: Dict[str, str],
        ledger_entries: Dict[str, Dict[str, str]],
        target_translations: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """Filter git-changed keys to only those whose source English value changed.

    When ``tx pull -f`` downloads community translations from Transifex,
    keys appear in ``git diff`` even though the English source didn't change.
    Re-translating those keys creates an infinite cycle: our AI overwrites
    the community version, Transifex serves the community version again next
    run, and the key reappears in the diff.

    This function breaks the cycle by keeping only keys where:
    - The key has no ledger entry (truly new)
    - The ledger entry has no source_hash (legacy/incomplete)
    - The source value is missing (orphaned key, handled downstream)
    - The current source hash differs from the ledger's source hash
    - The current target value regressed to the English source value
    """
    if not git_changed_keys:
        return set()

    filtered: Set[str] = set()
    for key in git_changed_keys:
        ledger_entry = ledger_entries.get(key)
        previous_source_hash = ledger_entry.get("source_hash") if ledger_entry else None
        source_value = source_translations.get(key)
        target_value = target_translations.get(key) if target_translations else None

        # If Transifex returns English/source text for a locale, do not let the
        # unchanged-source filter silently preserve that regression.
        if (
                source_value is not None
                and target_value is not None
                and normalize_value(source_value) == normalize_value(target_value)
        ):
            filtered.add(key)
            continue

        # Include key unless ledger proves the source is unchanged.
        if (previous_source_hash is None
                or source_value is None
                or compute_ledger_hash(source_value) != previous_source_hash):
            filtered.add(key)

    return filtered


def get_working_tree_changed_keys(
        target_file_path: str,
        repo_root: str,
        localization_format: Optional[LocalizationFormat] = None,
) -> Set[str]:
    """
    Return keys that were added/updated for ``target_file_path`` in git working tree.

    This is used to capture keys that appear in locale files through ``tx pull``
    before AI translation runs, so they can be treated as newly synchronized.
    """
    try:
        relative_target_path = os.path.relpath(target_file_path, repo_root)
        result = subprocess.run(
            ['git', 'diff', '--unified=0', '--', relative_target_path],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        if result.returncode != 0:
            logger.debug(
                "Unable to inspect git diff for '%s' (exit=%s): %s",
                relative_target_path,
                result.returncode,
                result.stderr.strip()
            )
            return set()

        adapter = get_localization_adapter(localization_format or LOCALIZATION_FORMAT)
        changed_keys: Set[str] = set()
        for line in result.stdout.splitlines():
            if not line.startswith('+') or line.startswith('+++'):
                continue
            key = adapter.extract_changed_key_from_diff_line(line[1:])
            if key:
                changed_keys.add(key)
        return changed_keys
    except Exception:
        logger.debug("Failed to compute git-diff changed keys for '%s'.", target_file_path, exc_info=True)
        return set()

def count_tokens(text: str, model_name: Optional[str] = None) -> int:
    """Count the number of tokens in ``text`` for ``model_name``.

    ``tiktoken.encoding_for_model`` occasionally attempts a network request to
    download model data if it is not already cached. Network access is not
    guaranteed in all environments (e.g., in CI). If obtaining the encoding for
    the requested model fails, the function falls back to ``gpt2`` which ships
    with ``tiktoken``. As a last resort, a simple whitespace split is used.
    """

    provider = MODEL_PROVIDER or _FALLBACK_PROVIDER
    return provider.count_tokens(text, model_name or MODEL_NAME)

def _shared_key_prefix_length(key_a: str, key_b: str) -> int:
    """Return the number of leading dot-separated segments two keys share.

    Used to rank existing translations by how closely related they are to the
    key currently being translated, so that sibling keys establishing a
    concept's terminology are preferred when the context window is
    size-limited.
    """
    shared = 0
    for segment_a, segment_b in zip(key_a.split("."), key_b.split(".")):
        if segment_a != segment_b:
            break
        shared += 1
    return shared


def _select_holistic_review_context_keys(
        source_translations: Mapping[str, str],
        translated_translations: Mapping[str, str],
        keys_to_review: List[str],
        localization_format: LocalizationFormat,
        *,
        excluded_context_keys: Optional[Set[str]] = None,
        max_context_keys: int = HOLISTIC_REVIEW_CONTEXT_MAX_KEYS,
        max_context_utf8_bytes: int = HOLISTIC_REVIEW_CONTEXT_MAX_UTF8_BYTES,
) -> List[str]:
    """Select bounded, read-only sibling terminology context for review.

    Only established localized values are useful as terminology evidence;
    callers exclude every key newly translated in the current run so an
    unreviewed draft from another chunk cannot become terminology authority.
    Candidates are ordered by their strongest shared dotted-key prefix with a
    reviewed key, with target-file order breaking ties. The byte limit covers
    the serialized source and target context excerpts together.
    """
    reviewed_keys = list(dict.fromkeys(keys_to_review))
    excluded_key_set = set(excluded_context_keys or ())
    excluded_key_set.update(reviewed_keys)
    if not reviewed_keys or max_context_keys <= 0 or max_context_utf8_bytes <= 0:
        return []

    ranked_candidates: List[Tuple[int, int, str]] = []
    for file_order, (key, target_value) in enumerate(translated_translations.items()):
        if key in excluded_key_set:
            continue
        source_value = source_translations.get(key)
        if (
                not isinstance(source_value, str)
                or not source_value.strip()
                or not isinstance(target_value, str)
                or not target_value.strip()
                or normalize_value(source_value) == normalize_value(target_value)
        ):
            continue
        strongest_prefix = max(
            _shared_key_prefix_length(key, reviewed_key)
            for reviewed_key in reviewed_keys
        )
        if strongest_prefix < 1:
            continue
        ranked_candidates.append((strongest_prefix, file_order, key))

    ranked_candidates.sort(key=lambda item: (-item[0], item[1]))
    adapter = get_localization_adapter(localization_format)
    selected: List[str] = []
    for _prefix_length, _file_order, key in ranked_candidates:
        if len(selected) >= max_context_keys:
            break
        candidate_keys = [*selected, key]
        source_context = adapter.build_review_content(
            source_translations,
            candidate_keys,
        )
        target_context = adapter.build_review_content(
            translated_translations,
            candidate_keys,
        )
        context_size = len(source_context.encode("utf-8")) + len(
            target_context.encode("utf-8")
        )
        if context_size > max_context_utf8_bytes:
            continue
        selected.append(key)
    return selected


def build_context(
        existing_translations: Dict[str, str],
        source_translations: Dict[str, str],
        language_glossary: Dict[str, str],
        max_tokens: int,
        model_name: str,
        system_prompt_text: str = "",
        current_key: Optional[str] = None,
        translation_glossary_enforcement: str = "exact",
) -> Tuple[str, str]:
    """
    Build the context and glossary text for the translation prompt.

    Args:
        existing_translations (Dict[str, str]): Existing translations in the target language.
        source_translations (Dict[str, str]): Source translations (in English).
        language_glossary (Dict[str, str]): The glossary for the language.
        max_tokens (int): Maximum allowed tokens.
        model_name (str): The model name.
        current_key (Optional[str]): The key being translated. When provided,
            sibling keys sharing a dotted prefix with it are surfaced first so
            established terminology survives the context-window truncation.

    Returns:
        Tuple[str, str]: The context examples text and glossary text.
    """
    context_examples = []
    total_tokens = 0

    # Build glossary entries
    if translation_glossary_enforcement == "prompt-only":
        glossary_entries = [
            f'"{k}" preferred base term: "{v}" (inflect or adapt for grammar)'
            for k, v in language_glossary.items()
        ]
    else:
        glossary_entries = [
            f'"{k}" should be translated as "{v}"'
            for k, v in language_glossary.items()
        ]
    glossary_text = '\n'.join(glossary_entries)
    glossary_tokens = count_tokens(glossary_text, model_name)

    # Reserve tokens for the fixed prompt content, response budget, and the
    # actual system prompt instead of assuming all models/prompts cost the same.
    reserved_tokens = 1000 + count_tokens(system_prompt_text, model_name)
    available_tokens = max_tokens - glossary_tokens - reserved_tokens

    # Order existing translations so keys most closely related to the key being
    # translated come first. The context window is bounded by available_tokens
    # and is frequently too small to hold every existing translation, so without
    # prioritisation the sibling keys that establish a concept's terminology
    # (for example ...pairingCode.textField / ...pairingCode.invalid relative to
    # ...pairingCode.unsupportedVersion) get truncated away, and the model then
    # retranslates the shared term independently and drifts from the established
    # wording. A stable sort by shared dotted-prefix length keeps siblings near
    # the top while preserving the original order among unrelated keys.
    ordered_translations = list(existing_translations.items())
    if current_key:
        ordered_translations.sort(
            key=lambda item: _shared_key_prefix_length(item[0], current_key),
            reverse=True,
        )

    # Iterate over existing translations
    for key, translated_value in ordered_translations:
        if current_key is not None and key == current_key:
            continue  # Never feed the key its own prior translation back as context
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
            # A long sibling can exceed the remaining budget while a later,
            # shorter sibling still fits. Keep searching instead of hiding all
            # remaining terminology context behind the first oversized entry.
            continue
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
    return protect_placeholders(text)

def restore_placeholders(text: str, placeholder_mapping: Dict[str, str]) -> str:
    """
    Restore placeholders in the text from the placeholder mapping.

    Args:
        text (str): The text with placeholder tokens.
        placeholder_mapping (Dict[str, str]): The placeholder mapping.

    Returns:
        str: The text with placeholders restored.
    """
    return restore_protected_placeholders(text, placeholder_mapping)

def protect_placeholders_in_properties(content: str) -> Tuple[str, Dict[str, str]]:
    """
    Protect all placeholders in properties file content by replacing them with unique tokens.

    This function is designed for protecting entire properties file content (multiple keys)
    before sending to holistic review. It uses the same protection mechanism as
    extract_placeholders() but works on full file content.

    Args:
        content: Full properties file content with multiple key=value pairs

    Returns:
        Tuple containing:
        - protected_content: Content with placeholders replaced by __PH_xxx__ tokens
        - placeholder_mapping: Dict mapping tokens back to original placeholders
    """
    return protect_placeholders(content)

def restore_placeholders_in_properties(content: str, placeholder_mapping: Dict[str, str]) -> str:
    """
    Restore all placeholders in properties file content from protection tokens.

    This is the reverse operation of protect_placeholders_in_properties().
    It replaces all __PH_xxx__ tokens back with their original placeholder values.

    Args:
        content: Properties file content with __PH_xxx__ protection tokens
        placeholder_mapping: Dict mapping tokens to original placeholders

    Returns:
        Content with all placeholders restored to original {0}, {1}, etc.
    """
    return restore_protected_placeholders(content, placeholder_mapping)

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
        retry_after_header = None
        try:
            retry_after = None
            if api_exc:
                headers = getattr(api_exc, "headers", None)
                if headers is None:
                    response = getattr(api_exc, "response", None)
                    headers = getattr(response, "headers", None)
                retry_after_header = (headers or {}).get("Retry-After")
                if retry_after_header:
                    try:
                        retry_after = float(retry_after_header)  # Handle delay in seconds
                    except ValueError:
                        if retry_after_header.endswith("ms"):
                            retry_after = float(retry_after_header[:-2]) / 1000  # Convert ms to seconds
            if retry_after is None:
                # Try HTTP-date (RFC 7231)
                try:
                    if retry_after_header:
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

def run_pre_translation_validation(
        target_file_path: str,
        source_file_path: str,
        localization_format: Optional[LocalizationFormat] = None,
        git_changed_keys: Optional[Set[str]] = None,
        file_ledger_entries: Optional[Dict[str, Dict[str, str]]] = None,
        ignore_key_patterns: Optional[List[Pattern[str]]] = None,
) -> Tuple[List[str], Set[str]]:
    """
    Runs validation and preparation checks on a target localization file.
    - Synchronizes keys with the source file (adds missing, removes extra).
    - Checks for encoding issues and placeholder mismatches.

    Args:
        target_file_path: The absolute path to the target language localization file.
        source_file_path: The absolute path to the source English localization file.

    Returns:
        A tuple containing:
        - A list of validation error messages. An empty list indicates success.
        - A set of keys newly added to the target file during key synchronization.
    """
    errors: List[str] = []
    newly_added_keys: Set[str] = set()
    filename = os.path.basename(target_file_path)
    adapter = get_localization_adapter(localization_format or LOCALIZATION_FORMAT)
    ignore_key_patterns = ignore_key_patterns or []
    logger.info(f"Running pre-translation validation for '{filename}'...")

    # 1. Synchronize keys (add missing, remove extra)
    try:
        missing_keys, _extra_keys = adapter.synchronize_keys(target_file_path, source_file_path)
        newly_added_keys = missing_keys
        logger.info(f"Key synchronization complete for '{filename}'.")
    except Exception as e:
        logger.exception("Failed to synchronize keys for '%s'", filename)
        errors.append(f"Error during key synchronization: {e}")
        return errors, newly_added_keys  # Fail hard if we can't even sync the file

    # 2. Check encoding and mojibake on the (potentially modified) file
    encoding_errors = check_encoding_and_mojibake(target_file_path)
    if encoding_errors:
        errors.extend(encoding_errors)

    # Load file content for placeholder check
    try:
        # Re-parse the files as they might have been changed by synchronize_keys
        _, target_translations = adapter.parse_file(target_file_path)
        _, source_translations = adapter.parse_file(source_file_path)
    except Exception as e:
        logger.exception("Validation failed for '%s': Could not parse localization file after key sync", filename)
        errors.append(f"Could not parse localization file after key sync: {e}")
        return errors, newly_added_keys

    changed_keys_for_run: Optional[Set[str]] = None
    if git_changed_keys is not None:
        changed_keys_for_run = newly_added_keys.union(
            filter_git_changed_keys_by_source(
                git_changed_keys,
                source_translations,
                file_ledger_entries or {},
                target_translations=target_translations,
            )
        )

    # 3. Check placeholder parity
    common_keys = set(source_translations.keys()).intersection(set(target_translations.keys()))
    for key in common_keys:
        if is_ignored_key(key, ignore_key_patterns):
            continue
        source_value = source_translations.get(key, "")
        target_value = target_translations.get(key, "")
        if not check_placeholder_parity(source_value, target_value):
            message = f"Placeholder mismatch for key `{key}`."
            if changed_keys_for_run is None or key in changed_keys_for_run:
                errors.append(message)
            else:
                logger.warning("Pre-existing validation issue ignored for unchanged key in '%s': %s", filename, message)

    if not errors:
        logger.info(f"Pre-translation validation passed for '{filename}'.")
    else:
        logger.error(f"Pre-translation validation failed for '{filename}'.")

    return errors, newly_added_keys

def run_post_translation_validation(
        final_content: str,
        source_translations: Dict[str, str],
        filename: str,
        localization_format: Optional[LocalizationFormat] = None,
        ignore_key_patterns: Optional[List[Pattern[str]]] = None,
        changed_keys_for_run: Optional[Set[str]] = None,
        translation_glossary: Optional[Mapping[str, str]] = None,
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
    effective_format = localization_format or LOCALIZATION_FORMAT
    adapter = get_localization_adapter(effective_format)
    ignore_key_patterns = ignore_key_patterns or []
    translation_glossary = translation_glossary or {}
    try:
        # Create a temporary file with delete=False to control its lifecycle.
        with tempfile.NamedTemporaryFile(
                mode='w',
                delete=False,
                suffix=effective_format.file_extension,
                encoding='utf-8'
        ) as temp_f:
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
            _, final_translations = adapter.parse_file(temp_file_path)
            common_keys = set(source_translations.keys()).intersection(set(final_translations.keys()))
            for key in common_keys:
                if is_ignored_key(key, ignore_key_patterns):
                    continue
                source_value = source_translations.get(key, "")
                target_value = final_translations.get(key, "")
                if not check_placeholder_parity(source_value, target_value):
                    source_placeholders = list(extract_placeholder_tokens(source_value).elements())
                    target_placeholders = list(extract_placeholder_tokens(target_value).elements())
                    message = (
                        f"Post-translation validation failed for '{filename}': Placeholder mismatch for key '{key}'.\n"
                        f"  Source value: {source_value}\n"
                        f"  Target value: {target_value}\n"
                        f"  Source placeholders: {source_placeholders}\n"
                        f"  Target placeholders: {target_placeholders}"
                    )
                    if changed_keys_for_run is None or key in changed_keys_for_run:
                        is_valid = False
                        logger.error(message)
                    else:
                        logger.warning("Pre-existing post-validation issue ignored for unchanged key: %s", message)
                    continue

                if normalize_value(source_value) == normalize_value(target_value):
                    # A failed generated value may have been deliberately
                    # reverted to its source fallback by per-key validation.
                    # It is already reported as failed; it is not a generated
                    # translation that claims glossary compliance.
                    continue
                glossary_mismatches = find_glossary_mismatches(
                    source_value,
                    target_value,
                    translation_glossary,
                )
                if glossary_mismatches:
                    required = ", ".join(
                        f"{source_term!r}→{target_term!r}"
                        for source_term, target_term in glossary_mismatches
                    )
                    message = (
                        f"Post-translation validation failed for '{filename}': "
                        f"Glossary mismatch for key '{key}'; required {required}."
                    )
                    if changed_keys_for_run is None or key in changed_keys_for_run:
                        is_valid = False
                        logger.error(message)
                    else:
                        logger.warning("Pre-existing post-validation issue ignored for unchanged key: %s", message)
        except Exception:
            is_valid = False
            logger.exception(
                "Post-translation validation failed for '%s': Could not parse final localization content", filename)

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


def split_lint_findings(findings: List[str]) -> Tuple[List[str], List[str]]:
    """Separate blocking linter errors from warning-only findings."""
    warnings = [finding for finding in findings if finding.startswith("Linter Warning:")]
    errors = [finding for finding in findings if not finding.startswith("Linter Warning:")]
    return errors, warnings


def run_per_key_validation_with_summary(
        final_translations: Dict[str, str],
        source_translations: Dict[str, str],
        filename: str,
        ignore_key_patterns: Optional[List[Pattern[str]]] = None,
        translation_glossary: Optional[Mapping[str, str]] = None,
        existing_translations: Optional[Mapping[str, str]] = None,
        file_ledger_entries: Optional[Mapping[str, Mapping[str, str]]] = None,
        selected_keys: Optional[Set[str]] = None,
) -> Tuple[Dict[str, str], Dict[str, object]]:
    """
    Validates each translation key individually and selectively reverts failed keys.

    Instead of discarding all translations when validation fails, this function:
    1. Validates each key's placeholder parity individually
    2. Keeps valid translations
    3. Reverts only failed keys to their source values

    Args:
        final_translations: Dictionary of translated key-value pairs to validate
        source_translations: Dictionary of source (English) key-value pairs
        filename: Name of the file being validated (for logging)
        existing_translations: Original target values, used to preserve a
            localized value when generated output falls back to the source.
        file_ledger_entries: Baseline hashes proving that both the source and
            previous target are unchanged.
        selected_keys: Keys translated in this run. Source echoes for these
            keys stay failed even if the original target was also the source.

    Returns:
        Tuple containing:
        - valid_translations: Dictionary with valid translations + reverted source for failed keys
        - failed_keys: List of keys that failed validation
    """
    valid_translations = {}
    failed_keys = []
    control_character_keys = []
    placeholder_mismatch_keys = []
    empty_target_keys = []
    glossary_mismatch_keys = []
    source_identical_keys = []
    ignore_key_patterns = ignore_key_patterns or []
    translation_glossary = translation_glossary or {}
    existing_translations = existing_translations or {}
    selected_keys = selected_keys or set()

    for key, target_value in final_translations.items():
        source_value = source_translations.get(key, "")
        if is_ignored_key(key, ignore_key_patterns):
            valid_translations[key] = source_value
            continue
        if source_value.strip() and not target_value.strip():
            failed_keys.append(key)
            empty_target_keys.append(key)
            logger.warning(
                f"Key '{key}' failed validation in '{filename}' - reverting to source because "
                f"the translated value is empty.\n"
                f"  Source: {source_value}"
            )
            valid_translations[key] = source_value
            continue
        existing_value = _ledger_verified_existing_translation(
            key, source_translations, existing_translations, file_ledger_entries or {}
        )
        original_value = existing_translations.get(key)
        if (
                source_value.strip()
                and normalize_value(source_value) == normalize_value(target_value)
                and (
                    key in selected_keys
                    or (
                        isinstance(original_value, str)
                        and original_value.strip()
                        and normalize_value(original_value) != normalize_value(source_value)
                    )
                )
        ):
            failed_keys.append(key)
            source_identical_keys.append(key)
            logger.warning(
                "Key '%s' failed validation in '%s' - generated value matches the "
                "source; only a ledger-verified target may be reused after validation.",
                key,
                filename,
            )
            if existing_value is not None:
                target_value = existing_value
        control_character_findings = find_disallowed_control_characters(target_value)

        if control_character_findings:
            failed_keys.append(key)
            control_character_keys.append(key)
            logger.warning(
                f"Key '{key}' failed validation in '{filename}' - reverting to source due to "
                f"disallowed control character artifact(s): {', '.join(control_character_findings[:3])}"
                f"{' ...' if len(control_character_findings) > 3 else ''}.\n"
                f"  Source: {source_value}\n"
                f"  Translation: {target_value}"
            )
            valid_translations[key] = source_value
            continue

        glossary_mismatches = find_glossary_mismatches(
            source_value,
            target_value,
            translation_glossary,
        )
        if glossary_mismatches:
            failed_keys.append(key)
            glossary_mismatch_keys.append(key)
            required = ", ".join(
                f"{source_term!r}→{target_term!r}"
                for source_term, target_term in glossary_mismatches
            )
            logger.warning(
                "Key '%s' failed glossary validation in '%s' - reverting to source; required %s.",
                key,
                filename,
                required,
            )
            valid_translations[key] = source_value
            continue

        # Validate placeholder parity for this key
        if check_placeholder_parity(source_value, target_value):
            # Validation passed - keep the translation
            valid_translations[key] = target_value
        else:
            # Validation failed - revert to source and track the failure
            failed_keys.append(key)
            placeholder_mismatch_keys.append(key)

            source_placeholders = list(extract_placeholder_tokens(source_value).elements())
            target_placeholders = list(extract_placeholder_tokens(target_value).elements())

            logger.warning(
                f"Key '{key}' failed validation in '{filename}' - reverting to source.\n"
                f"  Source: {source_value}\n"
                f"  Translation: {target_value}\n"
                f"  Expected placeholders: {source_placeholders}\n"
                f"  Found placeholders: {target_placeholders}"
            )

            # Use source value for this failed key
            valid_translations[key] = source_value

    # A rejected source echo and an invalid fallback can flag the same key.
    failed_keys = list(dict.fromkeys(failed_keys))
    # Log summary if any keys failed
    if failed_keys:
        logger.warning(
            f"Validation failed for {len(failed_keys)} out of {len(final_translations)} keys in '{filename}'. "
            f"Failed keys retained a validated baseline or reverted to source: {', '.join(failed_keys[:5])}"
            f"{' ...' if len(failed_keys) > 5 else ''}"
        )
        logger.info(
            f"Successfully validated {len(final_translations) - len(failed_keys)} keys in '{filename}'."
        )
    else:
        logger.info(f"All {len(final_translations)} keys passed validation in '{filename}'.")

    summary = {
        "failed_keys": failed_keys,
        "control_character_keys": control_character_keys,
        "placeholder_mismatch_keys": placeholder_mismatch_keys,
        "empty_target_keys": empty_target_keys,
        "glossary_mismatch_keys": glossary_mismatch_keys,
        "source_identical_keys": source_identical_keys,
        "reverted_keys_count": len(failed_keys),
        "control_character_findings_count": len(control_character_keys),
        "placeholder_failures_count": len(placeholder_mismatch_keys),
        "empty_target_failures_count": len(empty_target_keys),
        "glossary_failures_count": len(glossary_mismatch_keys),
        "source_identical_failures_count": len(source_identical_keys),
    }
    return valid_translations, summary


def run_per_key_validation(
        final_translations: Dict[str, str],
        source_translations: Dict[str, str],
        filename: str,
        ignore_key_patterns: Optional[List[Pattern[str]]] = None,
        translation_glossary: Optional[Mapping[str, str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """
    Backward-compatible wrapper returning only the failed key list.
    """
    valid_translations, summary = run_per_key_validation_with_summary(
        final_translations,
        source_translations,
        filename,
        ignore_key_patterns=ignore_key_patterns,
        translation_glossary=translation_glossary,
    )
    return valid_translations, list(summary["failed_keys"])


async def translate_text_async(
        text: str,
        key: str,
        existing_translations: Dict[str, str],
        source_translations: Dict[str, str],
        target_language: str,
        glossary: Dict[str, Dict[str, str]],
        semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter,
        index: int,
        localization_format: Optional[LocalizationFormat] = None,
) -> Tuple[int, str, bool]:
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
        Tuple[int, str, bool]: The index, translated text, and whether model translation succeeded.
    """
    if DRY_RUN:
        logger.info(f"[Dry Run] Skipping actual translation for key '{key}'. Returning original text.")
        return index, text, True

    if MODEL_PROVIDER is None:
        logger.error("Model provider is not configured. Cannot proceed with translation.")
        return index, text, False

    async with semaphore:
        # 3) Use language_name_to_code instead of an Enum
        language_code = language_name_to_code(target_language)

        # If the language isn't recognized, just return original text
        if not language_code:
            logger.warning(f"Unsupported or unrecognized language: {target_language}")
            return index, text, False

        # Get the glossary for the current language
        language_glossary = glossary.get(language_code, {})

        # Get pre-computed language-specific style rules
        style_rules_text = PRECOMPUTED_STYLE_RULES_TEXT.get(language_code, "")

        system_prompt = build_translation_system_prompt(
            target_language=target_language,
            style_rules_text=style_rules_text,
            project_context=PROJECT_CONTEXT,
            localization_format=localization_format or LOCALIZATION_FORMAT,
            translation_glossary_enforcement=TRANSLATION_GLOSSARY_ENFORCEMENT,
        )

        # Build the context and glossary text
        context_examples_text, glossary_text = build_context(
            existing_translations,
            source_translations,
            language_glossary,
            MAX_MODEL_TOKENS,
            MODEL_NAME,
            system_prompt_text=system_prompt,
            current_key=key,
            translation_glossary_enforcement=TRANSLATION_GLOSSARY_ENFORCEMENT,
        )

        # Extract and protect placeholders
        processed_text, placeholder_mapping = extract_placeholders(text)

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
                async with rate_limiter:
                    response = await MODEL_PROVIDER.create_chat_completion(
                        model=MODEL_NAME,
                        messages=[
                            ChatCompletionSystemMessageParam(role="system", content=system_prompt),
                            ChatCompletionUserMessageParam(role="user", content=prompt.format(
                                brand_glossary_text=brand_glossary_text,
                                glossary_text=glossary_text,
                                context_examples_text=context_examples_text,
                                key=_display_translation_key(key),
                                processed_text=processed_text
                            ))
                        ],
                        temperature=0.3,
                        timeout=60.0,
                    )

                msg_content = response.choices[0].message.content
                if not msg_content:
                    logger.warning("Empty assistant content for key '%s'; keeping original text.", key)
                    return index, text, False
                translated_text = msg_content.strip()

                # Restore placeholders in the translated text
                translated_text = restore_placeholders(translated_text, placeholder_mapping)

                # Clean the translated text
                translated_text = clean_translated_text(translated_text, text)

                logger.debug(f"Translated key '{key}' successfully.")
                return index, translated_text, True

            except Exception as general_exc:
                if MODEL_PROVIDER.is_retryable_error(general_exc):
                    logger.error(f"API error occurred: {general_exc.__class__.__name__} - {general_exc}")
                    should_retry = await _handle_retry(attempt, max_retries, base_delay, key, general_exc)
                    if should_retry:
                        continue
                    return index, text, False
                logger.error(f"An unexpected error occurred: {general_exc}", exc_info=True)
                return index, text, False

        # Fallback return statement to satisfy linters and ensure explicit return
        logger.warning(
            f"Translation loop for key '{key}' completed without an explicit return within the loop. "
            f"This shouldn't happen with current logic. Returning original text."
        )
        return index, text, False

def _build_holistic_review_system_prompt(
        target_language: str,
        keys_to_review: List[str],
        source_content: str,
        translated_content: str,
        style_rules_text: str,  # Pass pre-computed rules
        localization_format: LocalizationFormat = LOCALIZATION_FORMAT,
        translation_glossary: Optional[Mapping[str, str]] = None,
        translation_glossary_enforcement: str = "exact",
) -> str:
    """Builds the system prompt for the holistic review API call."""
    review_items = _holistic_review_items(keys_to_review)
    keys_to_review_text = "\n".join(
        f'- "{item_id}" identifies source key "{_display_translation_key(key)}"'
        for item_id, key in review_items.items()
    )
    if translation_glossary_enforcement == "prompt-only":
        glossary_rules = "\n".join(
            f'- When the English source contains "{source_term}", use "{target_term}" '
            "as the preferred base term; inflect or adapt it when grammar requires."
            for source_term, target_term in (translation_glossary or {}).items()
        )
        glossary_heading = "**Preferred Translation Glossary**:\n"
    else:
        glossary_rules = "\n".join(
            f'- When the English source contains "{source_term}", the translation must contain "{target_term}".'
            for source_term, target_term in (translation_glossary or {}).items()
        )
        glossary_heading = "**Mandatory Translation Glossary**:\n"
    glossary_section = glossary_heading + glossary_rules + "\n\n" if glossary_rules else ""

    return f"""
You are a lead editor and quality assurance specialist for software localization. Your task is to review a list of newly translated keys within a {localization_format.display_name} file for {target_language}. You are given source and translated excerpts containing every requested key and, when available, related read-only context keys. You MUST only review and return the keys specified.

**Critical Instructions**:
1.  **Strictly Limited Scope**: Review every item below. The left side is an opaque item ID; the right side is the source localization key used to find its values in the supplied files.
    ```
    {keys_to_review_text}
    ```
2.  **CRITICAL - Placeholder Protection**: You will see placeholder tokens in the format `__PH_abc123__`. These represent dynamic values like {{0}}, {{1}}, HTML tags, etc.
    - DO NOT translate, modify, remove, or duplicate these tokens
    - DO NOT add new placeholder tokens
    - Maintain EXACT 1:1 correspondence with source placeholders
    - These tokens are automatically managed by the system
3.  **CRITICAL - Translate ALL Other Text**: You MUST ensure that ALL regular text (text that is NOT a placeholder token) is properly translated, even if it appears between, before, or after placeholder tokens. Do not leave any translatable text untranslated just because it is near placeholders.
4.  **Apply All Quality Rules**: Meticulously apply the language-specific quality checklist to every key in your scope.
5.  **Consistent UI Terminology**: Use the provided translated context. Related keys that refer to the same concept or control, including keys with a shared dotted prefix, MUST use the same established term. Context keys outside the requested scope are read-only: never edit or return them.
6.  **Preserve Format Semantics**: Return plain translated string values. The system will serialize and escape values according to the target localization format. For Java `MessageFormat` strings, return single quotes (') as literal characters; the system handles required escaping.
7.  **Output JSON Only**: Your final output **must** be a single, valid JSON object that adheres to the required schema. Return every opaque item ID listed in the "Strictly Limited Scope" section exactly once, with its final corrected translation as the value. JSON property names MUST be the opaque item IDs, never the source localization keys.
8.  **Do Not Add Explanations**: Do not output any text, markdown, or explanations before or after the JSON object.

{glossary_section}{style_rules_text}

**JSON Output Example**:
```json
{{
  "review_item_0001": "Corrected translation for the first item.",
  "review_item_0002": "Corrected translation for the second item."
}}
```
"""


def _display_translation_key(key: str) -> str:
    """Render control characters visibly without changing ordinary prompt keys."""
    if any(character in key for character in ("\t", "\n", "\r", "\f")):
        return json.dumps(key, ensure_ascii=False)[1:-1]
    return key


def _prefer_glossary_compliant_draft(
    source_value: str,
    draft_value: str,
    reviewed_value: str,
    translation_glossary: Mapping[str, str],
) -> str:
    """Keep a compliant draft when holistic review breaks a required mapping."""
    if (
        find_glossary_mismatches(source_value, reviewed_value, translation_glossary)
        and not find_glossary_mismatches(source_value, draft_value, translation_glossary)
    ):
        return draft_value
    return reviewed_value


def _glossary_for_deterministic_enforcement(
    translation_glossary: Mapping[str, str],
    enforcement: str,
) -> Mapping[str, str]:
    """Return exact mappings only when the configured policy requires them."""
    return translation_glossary if enforcement == "exact" else {}


def _build_holistic_review_user_prompt(
        target_language: str,
        source_content: str,
        translated_content: str,
        localization_format: LocalizationFormat,
) -> str:
    """Build the user prompt for the holistic review API call."""
    return f"""

**Review Request**:
Return a JSON object containing the fully corrected translations for the requested items in the following excerpts.

**Source (English) Context**:
```{localization_format.code_fence}
{source_content}
```

**Translated ({target_language}) Context**:
```{localization_format.code_fence}
{translated_content}
```
"""


def _holistic_review_completion_token_limit(keys_to_review: List[str]) -> int:
    """Return a completion budget that scales with the reviewed key count."""
    return max(8192, min(16384, len(keys_to_review) * 512))


def _holistic_review_items(keys_to_review: List[str]) -> Dict[str, str]:
    """Assign stable opaque response IDs so models never have to reproduce keys."""
    return {
        f"review_item_{index:04d}": key
        for index, key in enumerate(keys_to_review, start=1)
    }


def _validate_holistic_review_response_keys(
        parsed_json: Mapping[str, str],
        keys_to_review: List[str],
) -> None:
    """Reject partial reviews and model-renamed or out-of-scope keys.

    An empty object remains the established explicit "no corrections" response.
    """
    if not parsed_json:
        return
    expected_keys = set(keys_to_review)
    actual_keys = set(parsed_json)
    missing_keys = expected_keys - actual_keys
    unexpected_keys = actual_keys - expected_keys
    if missing_keys or unexpected_keys:
        details = []
        if missing_keys:
            details.append(f"missing {len(missing_keys)} requested key(s)")
        if unexpected_keys:
            details.append(f"returned {len(unexpected_keys)} out-of-scope key(s)")
        raise jsonschema.ValidationError(
            "Holistic review key set mismatch: " + "; ".join(details),
        )


async def holistic_review_async(
        source_content: str,
        translated_content: str,
        target_language: str,
        keys_to_review: List[str],
        semaphore: asyncio.Semaphore,
        rate_limiter: AsyncLimiter,
        style_rules_text: str,
        localization_format: Optional[LocalizationFormat] = None,
        translation_glossary: Optional[Mapping[str, str]] = None,
        translation_glossary_enforcement: str = "exact",
) -> Optional[Dict[str, str]]:
    """Review a bounded localization excerpt and return scoped corrections.

    Args:
        source_content (str): Source content for requested and context keys.
        translated_content (str): Draft content for requested and context keys.
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

    if MODEL_PROVIDER is None:
        logger.error("Model provider is not configured. Cannot proceed with holistic review.")
        return {}

    # Protect placeholders in both source and translated content before sending to AI
    protected_source, source_placeholder_map = protect_placeholders_in_properties(source_content)
    protected_translated, translated_placeholder_map = protect_placeholders_in_properties(translated_content)
    review_items = _holistic_review_items(keys_to_review)

    logger.debug(f"Protected {len(source_placeholder_map)} placeholders in source content")
    logger.debug(f"Protected {len(translated_placeholder_map)} placeholders in translated content")

    async with semaphore:
        review_system_prompt = _build_holistic_review_system_prompt(
            target_language=target_language,
            keys_to_review=keys_to_review,
            source_content=protected_source,
            translated_content=protected_translated,
            style_rules_text=style_rules_text,
            localization_format=localization_format or LOCALIZATION_FORMAT,
            translation_glossary=translation_glossary,
            translation_glossary_enforcement=translation_glossary_enforcement,
        )
        review_user_prompt = _build_holistic_review_user_prompt(
            target_language=target_language,
            source_content=protected_source,
            translated_content=protected_translated,
            localization_format=localization_format or LOCALIZATION_FORMAT,
        )
        max_retries = 3
        base_delay = 5  # Longer delay for a potentially larger task
        response_text = ""
        validation_failures = 0
        for attempt in range(1, max_retries + 1):
            try:
                async with rate_limiter:
                    review_json_kwargs = chat_json_mode_kwargs(MODEL_PROVIDER, REVIEW_MODEL_NAME)
                    review_reasoning_kwargs = chat_reasoning_effort_kwargs(
                        MODEL_PROVIDER,
                        REVIEW_MODEL_NAME,
                        REVIEW_REASONING_EFFORT,
                    )
                    response = await MODEL_PROVIDER.create_chat_completion(
                        model=REVIEW_MODEL_NAME,
                        messages=[
                            ChatCompletionSystemMessageParam(role="system", content=review_system_prompt),
                            ChatCompletionUserMessageParam(role="user", content=review_user_prompt),
                        ],
                        temperature=0.1,
                        **review_json_kwargs,
                        **review_reasoning_kwargs,
                        completion_token_limit=_holistic_review_completion_token_limit(keys_to_review),
                        timeout=120.0,
                    )
                msg_content = response.choices[0].message.content
                if not msg_content or not msg_content.strip():
                    logger.error("Holistic review returned empty content.")
                    response_text = ""
                    raise json.JSONDecodeError("empty response", "", 0)
                response_text = msg_content.strip()

                # The response should be a JSON string. Parse and validate it.
                parsed_json = loads_json_object(response_text)
                jsonschema.validate(instance=parsed_json, schema=LOCALIZATION_SCHEMA)
                _validate_holistic_review_response_keys(parsed_json, list(review_items))

                # Debug: Check what AI returned before restoration
                sample_ai_keys = list(parsed_json.keys())[:2]
                for sample_key in sample_ai_keys:
                    ai_value = parsed_json.get(sample_key, "")
                    has_tokens = "__PH_" in ai_value
                    logger.debug(f"AI returned for '{sample_key}': '{ai_value}' (has_tokens={has_tokens})")

                # The reviewer may use tokens from either protected input. Restore
                # against one combined map so the unresolved-token assertion runs
                # only after both namespaces have been considered.
                review_placeholder_map = {
                    **source_placeholder_map,
                    **translated_placeholder_map,
                }
                restored_json = {}
                for item_id, value in parsed_json.items():
                    restored_json[review_items[item_id]] = restore_placeholders_in_properties(
                        value,
                        review_placeholder_map,
                    )

                # Debug: Check restoration results
                for sample_item_id in sample_ai_keys:
                    sample_key = review_items[sample_item_id]
                    if sample_key in restored_json:
                        restored_value = restored_json[sample_key]
                        has_tokens = "__PH_" in restored_value
                        has_placeholders = "{0}" in restored_value or "{1}" in restored_value
                        logger.debug(f"After restoration '{sample_key}': '{restored_value}' "
                                   f"(has_tokens={has_tokens}, has_placeholders={has_placeholders})")

                logger.debug(f"Restored placeholders in {len(restored_json)} reviewed translations")
                return restored_json

            except json.JSONDecodeError:
                validation_failures += 1
                logger.exception("Holistic review failed: AI did not return valid JSON.")
                logger.debug(f"Invalid AI response (JSON Decode Error):\n---\n{response_text}\n---")
                # Fall through to retry logic
            except jsonschema.ValidationError:
                validation_failures += 1
                logger.exception("Holistic review failed: AI response did not match the required JSON schema.")
                logger.debug(f"Invalid AI response (Schema Error):\n---\n{response_text}\n---")
                # Fall through to retry logic

            except Exception as e:
                if MODEL_PROVIDER.is_retryable_error(e):
                    logger.warning(f"API error during holistic review: {e}")
                    should_retry = await _handle_retry(attempt, max_retries, base_delay, "holistic_review", e)
                    if not should_retry:
                        return None
                    continue
                logger.error(f"Unexpected error during holistic review: {e}", exc_info=True)
                return None  # Do not retry on unexpected errors

            # If we're here, it means a JSON or Schema error occurred. We should retry.
            if validation_failures > 1:
                logger.warning(
                    "Holistic review returned invalid JSON/schema %d time(s); the response may be truncated.",
                    validation_failures,
                )
            should_retry = await _handle_retry(attempt, max_retries, base_delay, "holistic_review_validation")
            if not should_retry:
                return None

        return None  # Fallback after all retries


def _escape_output_value(
        adapter,
        source_translations: Dict[str, str],
        key: str,
        value: str,
) -> str:
    return adapter.escape_translation(source_translations.get(key, ""), value)


def integrate_translations(
        parsed_lines: List[Dict],
        translations: List[str],
        indices: List[int],
        keys: List[str],
        source_translations: Dict[str, str],
        localization_format: LocalizationFormat = LOCALIZATION_FORMAT,
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
    adapter = get_localization_adapter(localization_format)
    for idx, (translation_idx, key) in enumerate(zip(indices, keys)):
        translated_text = _escape_output_value(adapter, source_translations, key, translations[idx])

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


def _default_localization_profile() -> LocalizationProfile:
    return LocalizationProfile(LOCALIZATION_FORMAT, LOCALIZATION_LAYOUT)


def _iter_localization_profiles(
        localization_profiles: Optional[Tuple[LocalizationProfile, ...]] = None,
) -> Tuple[LocalizationProfile, ...]:
    profiles = tuple(localization_profiles or LOCALIZATION_PROFILES or ())
    default_profile = _default_localization_profile()
    if not profiles:
        return (default_profile,)
    if default_profile not in profiles:
        return (*profiles, default_profile)
    return profiles


def find_target_localization_profile(
        relative_path: str,
        supported_codes: Optional[List[str]] = None,
        localization_profiles: Optional[Tuple[LocalizationProfile, ...]] = None,
) -> Optional[LocalizationProfile]:
    """Return the configured profile that treats ``relative_path`` as a target file."""
    codes = supported_codes or list(LANGUAGE_CODES.keys())
    for profile in _iter_localization_profiles(localization_profiles):
        if profile.localization_layout.is_target_file(
                relative_path,
                codes,
                profile.localization_format,
        ):
            return profile
    return None


def find_source_localization_profile(
        relative_path: str,
        supported_codes: Optional[List[str]] = None,
        localization_profiles: Optional[Tuple[LocalizationProfile, ...]] = None,
) -> Optional[LocalizationProfile]:
    """Return the configured profile that treats ``relative_path`` as a source file."""
    codes = supported_codes or list(LANGUAGE_CODES.keys())
    for profile in _iter_localization_profiles(localization_profiles):
        if profile.localization_layout.is_source_file(
                relative_path,
                codes,
                profile.localization_format,
        ):
            return profile
    return None


def _profile_for_target_or_default(
        relative_path: str,
        supported_codes: Optional[List[str]] = None,
) -> LocalizationProfile:
    return find_target_localization_profile(relative_path, supported_codes) or _default_localization_profile()


def extract_language_from_filename(filename: str, supported_codes: List[str]) -> Optional[str]:
    """
    Extract the language code from a filename by checking against a list of supported codes.

    Args:
        filename (str): The filename.
        supported_codes (List[str]): A list of supported language codes.

    Returns:
        Optional[str]: The language code if found, else None.
    """
    profile = _profile_for_target_or_default(filename, supported_codes)
    return profile.localization_layout.extract_locale(
        filename,
        supported_codes,
        profile.localization_format,
    )

def get_source_filename(translation_file: str, supported_codes: List[str]) -> str:
    """
    Extract the source filename by removing the language code suffix.

    This function correctly handles base filenames containing underscores
    (e.g., 'mu_sig') by checking against actual supported language codes
    instead of using regex patterns that could incorrectly match parts
    of the base filename.

    Args:
        translation_file: Filename with language code, e.g., 'mu_sig_pt_PT.properties'
        supported_codes: List of valid language codes, e.g., ['es', 'pt_PT', 'pt_BR']

    Returns:
        Source filename with language suffix removed, e.g., 'mu_sig.properties'
        If no language code is found, returns the original filename unchanged.

    Examples:
        >>> get_source_filename('mu_sig_es.properties', ['es', 'de'])
        'mu_sig.properties'
        >>> get_source_filename('mu_sig_pt_PT.properties', ['pt_PT', 'es'])
        'mu_sig.properties'
        >>> get_source_filename('app.properties', ['es', 'de'])
        'app.properties'
    """
    profile = _profile_for_target_or_default(translation_file, supported_codes)
    return profile.localization_layout.source_path_for_target(
        translation_file,
        supported_codes,
        profile.localization_format,
    )


def is_target_localization_file(
        relative_path: str,
        supported_codes: Optional[List[str]] = None,
        localization_format: Optional[LocalizationFormat] = None,
        localization_layout: Optional[LocalizationLayout] = None,
) -> bool:
    """Return true when ``relative_path`` is a configured target locale file."""
    if localization_format is None and localization_layout is None:
        return find_target_localization_profile(relative_path, supported_codes) is not None
    return (localization_layout or LOCALIZATION_LAYOUT).is_target_file(
        relative_path,
        supported_codes or list(LANGUAGE_CODES.keys()),
        localization_format or LOCALIZATION_FORMAT,
    )


def is_source_localization_file(
        relative_path: str,
        supported_codes: Optional[List[str]] = None,
        localization_format: Optional[LocalizationFormat] = None,
        localization_layout: Optional[LocalizationLayout] = None,
) -> bool:
    """Return true when ``relative_path`` is a configured source locale file."""
    if localization_format is None and localization_layout is None:
        return find_source_localization_profile(relative_path, supported_codes) is not None
    return (localization_layout or LOCALIZATION_LAYOUT).is_source_file(
        relative_path,
        supported_codes or list(LANGUAGE_CODES.keys()),
        localization_format or LOCALIZATION_FORMAT,
    )

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
            rel_path = os.path.relpath(os.path.join(root, name), translated_queue_folder)
            if is_target_localization_file(rel_path):
                translated_file_path = os.path.join(translated_queue_folder, rel_path)
                dest_path = os.path.join(input_folder_path, rel_path)
                if DRY_RUN:
                    logger.info(
                        f"[Dry Run] Would copy translated file '{translated_file_path}' back to '{dest_path}'.")
                else:
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    shutil.copy2(translated_file_path, dest_path)
                    logger.info(f"Copied translated file '{translated_file_path}' back to '{dest_path}'.")

def _real_path(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


def _paths_overlap(first_path: str, second_path: str) -> bool:
    try:
        common_path = os.path.commonpath([first_path, second_path])
    except ValueError:
        return False
    return common_path in {first_path, second_path}


def validate_paths(input_folder: str, translation_queue: str, translated_queue: str, repo_root: str):
    """
    Validate that the input and queue folders are usable.

    Args:
        input_folder (str): Path to the input folder.
        translation_queue (str): Path to the translation queue folder.
        translated_queue (str): Path to the translated queue folder.
        repo_root (str): Path to the Git repository root.
    """
    protected_paths = {
        "Input Folder": _real_path(input_folder),
        "Repository Root": _real_path(repo_root),
    }
    queue_paths = {
        _real_path(translation_queue): "Translation Queue Folder",
        _real_path(translated_queue): "Translated Queue Folder",
    }
    if len(queue_paths) != 2:
        raise ValueError("translation_queue and translated_queue must be different folders.")
    for queue_path in queue_paths:
        for protected_path in protected_paths.values():
            if _paths_overlap(queue_path, protected_path):
                raise ValueError("Queue folders must be separate from repo_root and input_folder.")

    for path, name in [(input_folder, "Input Folder"), (repo_root, "Repository Root")]:
        if not os.path.exists(path):
            logger.error(f"{name} '{path}' does not exist.")
            raise FileNotFoundError(f"{name} '{path}' does not exist.")
        required = os.R_OK | os.W_OK
        if name == "Repository Root":
            required = os.R_OK
        if not os.access(path, required):
            logger.error("%s '%s' is not accessible (required perms: %s).", name, path, "R+W" if required & os.W_OK else "R")
            raise PermissionError(f"{name} '{path}' lacks required permissions.")
    for path, name in queue_paths.items():
        if os.path.exists(path) and not os.path.isdir(path):
            logger.error("%s '%s' is not a directory.", name, path)
            raise NotADirectoryError(f"{name} '{path}' is not a directory.")
        os.makedirs(path, exist_ok=True)
        if not os.access(path, os.R_OK | os.W_OK):
            logger.error("%s '%s' is not accessible (required perms: R+W).", name, path)
            raise PermissionError(f"{name} '{path}' lacks required permissions.")
    logger.info("All critical paths are valid and accessible.")

def get_changed_translation_files(
        input_folder_path: str,
        repo_root: str,
        process_all_files: bool = False
) -> List[str]:
    """
    Use git to find changed translation files in the input folder.

    If the TRANSLATION_FILTER_GLOB environment variable is set, this function will
    only return files that match the provided glob pattern. Otherwise, it returns
    changed files for the configured localization format.

    Args:
        input_folder_path (str): The absolute path to the input folder.
        repo_root (str): The absolute path to the Git repository root.
        process_all_files (bool): If true, scan all translation files under input_folder_path
            instead of only changed files from git status.

    Returns:
        List[str]: List of translation file names relative to input_folder_path.
    """
    def is_archive_path(relative_path: str) -> bool:
        """Return True when a relative file path is inside an archive directory."""
        normalized_path = relative_path.replace('\\', '/')
        return normalized_path.startswith('archive/') or '/archive/' in normalized_path

    def is_discoverable_target_file(relative_path: str) -> bool:
        """Return true for target files that should be queued for locale extraction."""
        return find_discoverable_target_profile(relative_path) is not None

    def find_discoverable_target_profile(relative_path: str) -> Optional[LocalizationProfile]:
        """Return the profile for a target file, including unsupported suffix locales."""
        target_profile = find_target_localization_profile(relative_path)
        if target_profile:
            return target_profile
        for profile in _iter_localization_profiles():
            if profile.localization_layout.id != "suffix":
                continue
            if (
                    profile.localization_format.is_supported_file(relative_path)
                    and profile.localization_format.is_locale_file(os.path.basename(relative_path))
            ):
                return profile
        return None

    def supports_configured_format(relative_path: str) -> bool:
        """Return true if any configured profile owns this file extension."""
        return any(
            profile.localization_format.is_supported_file(relative_path)
            for profile in _iter_localization_profiles()
        )

    def apply_filter_glob(files: List[str]) -> List[str]:
        """Apply optional TRANSLATION_FILTER_GLOB filtering to discovered files."""
        filter_glob = os.environ.get('TRANSLATION_FILTER_GLOB')
        if not filter_glob:
            return files

        import fnmatch
        # If the glob contains a path separator, match against the full relative path.
        # Otherwise, match against the basename to preserve the original behavior.
        if '/' in filter_glob:
            filtered_list = [f for f in files if fnmatch.fnmatch(f, filter_glob)]
        else:
            filtered_list = [f for f in files if fnmatch.fnmatch(os.path.basename(f), filter_glob)]

        logger.info(
            "Applied filter '%s', %d out of %d files will be translated.",
            filter_glob,
            len(filtered_list),
            len(files)
        )
        return filtered_list

    def discover_translation_files() -> List[str]:
        """Discover all translation files (excluding source files and archive paths)."""
        discovered_files: List[str] = []
        for root, _, files in os.walk(input_folder_path):
            for filename in files:
                absolute_path = os.path.join(root, filename)
                relative_path = os.path.relpath(absolute_path, input_folder_path)
                if not is_discoverable_target_file(relative_path):
                    continue
                if is_archive_path(relative_path):
                    continue
                discovered_files.append(relative_path)
        return sorted(discovered_files)

    try:
        if process_all_files:
            logger.info("process_all_files=true, scanning all translation files under '%s'.", input_folder_path)
            return apply_filter_glob(discover_translation_files())

        # Calculate the relative path of input_folder from repo_root
        rel_input_folder = os.path.relpath(input_folder_path, repo_root)

        def _entries_from_status_output(stdout: str):
            """Yield (status, path) pairs from `git status --porcelain` output."""
            for line in stdout.splitlines():
                if len(line) < 4:
                    continue
                # Each line starts with two characters indicating status, e.g. ' M file', '?? file'.
                status, filepath = line[:2], line[3:]
                # Renames (R) and copies (C) both use the 'old -> new' path format.
                if status.strip()[:1] in ('R', 'C') and ' -> ' in filepath:
                    filepath = filepath.split(' -> ', 1)[1]
                yield status.strip(), filepath

        def _entries_from_diff_output(stdout: str):
            """Yield (status, path) pairs from `git diff --name-status` output."""
            for line in stdout.splitlines():
                if not line.strip():
                    continue
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                # parts[0] is the status code (M, A, D, R100, …); for renames/copies the
                # destination path is the last field.
                yield parts[0][:1], parts[-1]

        # In CI a fresh checkout has no working-tree changes, so detection can instead
        # diff against a base ref (TRANSLATION_DIFF_BASE, e.g. the PR/push base). When
        # unset we keep the working-tree behaviour used by the Transifex/server flow.
        diff_base = (os.environ.get('TRANSLATION_DIFF_BASE') or '').strip()
        if diff_base:
            logger.info("Detecting changed files via 'git diff' against base '%s' for path '%s'",
                        diff_base, rel_input_folder)
            subprocess.run(
                ['git', 'cat-file', '-e', f'{diff_base}^{{commit}}'],
                cwd=repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
            result = subprocess.run(
                ['git', 'diff', '--name-status', f'{diff_base}...HEAD', '--', rel_input_folder],
                cwd=repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
            entries = _entries_from_diff_output(result.stdout)
        else:
            logger.info(f"Running git status in '{repo_root}' for path '{rel_input_folder}'")
            result = subprocess.run(
                ['git', 'status', '--porcelain', '--untracked-files=normal', rel_input_folder],
                cwd=repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
            entries = _entries_from_status_output(result.stdout)

        changed_translation_files: Set[str] = set()
        changed_source_files: Set[Tuple[LocalizationProfile, str]] = set()
        # Accepted change statuses for both formats; deletions (D) are intentionally excluded.
        accepted_status = {'M', 'A', 'AM', 'MM', 'RM', 'R', 'C', 'T', '??'}
        for cleaned_status, filepath in entries:
            if cleaned_status not in accepted_status:
                continue
            if not supports_configured_format(filepath):
                continue
            # Extract the filename relative to input_folder
            rel_path = os.path.relpath(filepath, rel_input_folder)
            rel_path = rel_path.replace('\\', '/')
            if is_archive_path(rel_path):
                continue
            # Check if it's a translation file (has language suffix). Supports
            # hyphenated locale codes like zh-Hans, zh-Hant.
            if is_discoverable_target_file(rel_path):
                changed_translation_files.add(rel_path)
            else:
                source_profile = find_source_localization_profile(rel_path)
                if source_profile:
                    changed_source_files.add((source_profile, rel_path))

        # Resilience to delayed Transifex propagation:
        # if source files changed, also enqueue all related locale files even if unchanged in git status.
        if changed_source_files:
            for translation_rel_path in discover_translation_files():
                target_profile = find_target_localization_profile(translation_rel_path)
                if not target_profile:
                    continue
                source_rel_path = target_profile.localization_layout.source_path_for_target(
                    translation_rel_path,
                    list(LANGUAGE_CODES.keys()),
                    target_profile.localization_format,
                )
                if (target_profile, source_rel_path.replace('\\', '/')) in changed_source_files:
                    changed_translation_files.add(translation_rel_path)

        return apply_filter_glob(sorted(changed_translation_files))
    except subprocess.CalledProcessError as git_exc:
        diff_base = (os.environ.get('TRANSLATION_DIFF_BASE') or '').strip()
        if diff_base:
            stderr = (git_exc.stderr or "").strip()
            detail = f": {stderr}" if stderr else ""
            raise RuntimeError(
                f"TRANSLATION_DIFF_BASE '{diff_base}' is not reachable or could not be diffed{detail}. "
                "Fetch the base ref, use fetch-depth: 0, or pass a reachable diff base."
            ) from git_exc
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
        glossary_file_path: str,
        validation_summary: Optional[Dict[str, Dict[str, object]]] = None
) -> ProcessTranslationQueueResult:
    """
    Process all localization files in the translation queue folder.

    Args:
        translation_queue_folder (str): The folder containing files to translate.
        translated_queue_folder (str): The folder to save translated files.
        glossary_file_path (str): The glossary file path.

    Returns:
        A tuple containing:
        - The number of files successfully processed.
        - List of successfully processed filenames.
        - A dictionary of skipped files, mapping filename to a list of error strings.
        - Total number of keys translated across all files.
        Run metrics are attached to the result as ``result.run_metrics``.
    """
    localization_files: List[Tuple[str, LocalizationProfile]] = []
    for root, dirs, files in os.walk(translation_queue_folder):
        dirs.sort()
        for name in files:
            if name.startswith("."):
                continue
            relative_path = os.path.relpath(os.path.join(root, name), translation_queue_folder)
            relative_path = relative_path.replace('\\', '/')
            profile = find_target_localization_profile(relative_path)
            if profile:
                localization_files.append((relative_path, profile))
    localization_files.sort(key=lambda item: item[0])

    # Load the glossary from the JSON file
    glossary = load_glossary(glossary_file_path)
    key_ledger = load_translation_key_ledger(TRANSLATION_KEY_LEDGER_FILE_PATH)
    translation_memory = (
        load_translation_memory(TRANSLATION_MEMORY_FILE_PATH)
        if TRANSLATION_MEMORY_ENABLED
        else None
    )

    # Set up a single semaphore for all API calls to control concurrency globally.
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_API_CALLS)

    # Initialize configurable request-rate limiting.
    rate_limiter = AsyncLimiter(max_rate=RATE_LIMIT_PER_MINUTE, time_period=60)

    processed_files_count = 0
    processed_filenames: List[str] = []
    total_keys_translated = 0
    run_metrics = new_run_metrics()
    skipped_files: Dict[str, List[str]] = {}

    for translation_file, localization_profile in localization_files:
        try:
            localization_format = localization_profile.localization_format
            localization_layout = localization_profile.localization_layout
            adapter = get_localization_adapter(localization_format)
            # Extract the language code from the filename
            language_code = localization_layout.extract_locale(
                translation_file,
                list(LANGUAGE_CODES.keys()),
                localization_format,
            )
            if not language_code:
                logger.warning(f"Skipping file {translation_file}: unable to extract language code.")
                continue
            # 4) Now we find the "friendly name" from the dictionary
            target_language = language_code_to_name(language_code)
            if not target_language:
                logger.warning(f"Skipping file {translation_file}: unsupported language code '{language_code}'.")
                continue
            style_rules_text_for_review = PRECOMPUTED_STYLE_RULES_TEXT.get(language_code, "")
            raw_language_glossary = glossary.get(language_code, {})
            language_glossary = (
                raw_language_glossary
                if isinstance(raw_language_glossary, Mapping)
                else {}
            )
            enforced_language_glossary = _glossary_for_deterministic_enforcement(
                language_glossary,
                TRANSLATION_GLOSSARY_ENFORCEMENT,
            )
            memory_context_fingerprint = translation_memory_context_fingerprint(
                locale=language_code,
                glossary=glossary,
                brand_glossary=BRAND_GLOSSARY,
                style_rules_text=style_rules_text_for_review,
                translation_glossary_enforcement=TRANSLATION_GLOSSARY_ENFORCEMENT,
            )

            # Define full paths
            translation_file_path = os.path.join(translation_queue_folder, translation_file)
            source_file_name = localization_layout.source_path_for_target(
                translation_file,
                list(LANGUAGE_CODES.keys()),
                localization_format,
            )
            source_file_path = os.path.join(INPUT_FOLDER, source_file_name)

            if not os.path.exists(source_file_path):
                logger.warning(f"Source file '{source_file_name}' not found in '{INPUT_FOLDER}'. Skipping.")
                continue

            logger.info(f"Processing file '{translation_file}' for language '{target_language}'...")

            # --- Pre-flight Validator ---
            file_ledger_entries = key_ledger.get(translation_file, {})
            original_input_file_path = os.path.join(INPUT_FOLDER, translation_file)
            raw_git_changed_keys = get_working_tree_changed_keys(
                original_input_file_path,
                REPO_ROOT,
                localization_format,
            )
            validation_errors, newly_added_keys = run_pre_translation_validation(
                translation_file_path,
                source_file_path,
                localization_format,
                git_changed_keys=raw_git_changed_keys,
                file_ledger_entries=file_ledger_entries,
                ignore_key_patterns=IGNORE_KEY_PATTERNS,
            )
            if validation_errors:
                logger.error(f"Skipping translation for '{translation_file}' due to pre-translation validation errors.")
                for error in validation_errors:
                    logger.error(f"  - {error}")
                skipped_files[translation_file] = validation_errors
                continue
            # --- End Validator ---

            # --- Pre-flight Linter Check ---
            # Before processing, lint the file to catch basic syntax errors.
            lint_errors, lint_warnings = split_lint_findings(adapter.lint_file(translation_file_path))
            for warning in lint_warnings:
                logger.warning("Non-blocking linter warning in '%s': %s", translation_file, warning)
            if lint_errors:
                logger.error(f"Linter found errors in '{translation_file}'. Skipping translation for this file.")
                for error in lint_errors:
                    logger.error(f"  - {error}")
                skipped_files[translation_file] = lint_errors
                continue
            # --- End Linter Check ---

            # Load files
            parsed_lines, target_translations = adapter.parse_file(translation_file_path)
            _, source_translations = adapter.parse_file(source_file_path)
            original_target_translations = dict(target_translations)
            ignored_keys_updated = apply_ignored_source_values(
                parsed_lines,
                target_translations,
                source_translations,
                IGNORE_KEY_PATTERNS,
            )
            ignored_keys_requiring_output = ignored_keys_updated.union(
                key for key in newly_added_keys if is_ignored_key(key, IGNORE_KEY_PATTERNS)
            )

            # Extract texts to translate
            git_changed_keys = raw_git_changed_keys
            # Only re-translate git-dirty keys if their English source actually changed.
            # This prevents an infinite cycle where Transifex community translations
            # are overwritten by AI, then Transifex re-serves the community version.
            git_changed_keys = filter_git_changed_keys_by_source(
                git_changed_keys,
                source_translations,
                file_ledger_entries,
                target_translations=target_translations
            )
            newly_synchronized_keys = newly_added_keys.union(git_changed_keys)
            if git_changed_keys:
                logger.info(
                    "Detected %d git-diff key updates in '%s' with changed source; treating them as newly synchronized.",
                    len(git_changed_keys),
                    translation_file
                )
            texts_to_translate, indices, keys_to_translate = extract_texts_to_translate(
                parsed_lines,
                source_translations,
                target_translations,
                newly_added_keys=newly_synchronized_keys,
                file_ledger_entries=file_ledger_entries,
                retranslate_identical_existing=RETRANSLATE_IDENTICAL_SOURCE_STRINGS,
                ignore_key_patterns=IGNORE_KEY_PATTERNS,
                selection_metrics=run_metrics,
            )
            if not texts_to_translate:
                # Refresh ledger baseline even when no translation was required.
                key_ledger[translation_file] = build_file_key_ledger(source_translations, target_translations)
                save_translation_key_ledger(TRANSLATION_KEY_LEDGER_FILE_PATH, key_ledger)
                if ignored_keys_requiring_output:
                    increment_run_metric(
                        run_metrics,
                        "changed_values_count",
                        count_changed_translation_values(original_target_translations, target_translations),
                    )
                    translated_file_path = os.path.join(translated_queue_folder, translation_file)
                    new_file_content = adapter.reassemble_file(parsed_lines)
                    if not run_post_translation_validation(
                            new_file_content,
                            source_translations,
                            translation_file,
                            localization_format,
                            ignore_key_patterns=IGNORE_KEY_PATTERNS,
                            changed_keys_for_run=set(ignored_keys_requiring_output),
                            translation_glossary=enforced_language_glossary,
                    ):
                        logger.error(
                            "Skipping write for '%s' because post-translation validation failed.",
                            translation_file,
                        )
                        skipped_files[translation_file] = ["Post-translation validation failed."]
                        continue
                    if DRY_RUN:
                        logger.info(f"[Dry Run] Would write ignored-key passthrough content to '{translated_file_path}'.")
                    else:
                        os.makedirs(os.path.dirname(translated_file_path), exist_ok=True)
                        with open(translated_file_path, 'w', encoding='utf-8') as file:
                            file.write(new_file_content)
                    processed_files_count += 1
                    processed_filenames.append(translation_file)
                    logger.info(
                        "Updated %d ignored key(s) from source in '%s'.",
                        len(ignored_keys_requiring_output),
                        translation_file,
                    )
                    continue
                logger.info(f"No texts to translate in file '{translation_file}'.")
                continue

            increment_run_metric(run_metrics, "candidate_keys_count", len(keys_to_translate))

            memory_plan = apply_translation_memory(
                texts_to_translate=texts_to_translate,
                indices=indices,
                keys_to_translate=keys_to_translate,
                memory=translation_memory,
                locale=language_code,
                format_id=localization_format.id,
                context_fingerprint=memory_context_fingerprint,
            )
            increment_run_metric(run_metrics, "translation_memory_reused_count", len(memory_plan.cached_results))
            increment_run_metric(run_metrics, "model_translation_keys_count", len(memory_plan.pending_keys))

            # Pre-run scope/cost preview for this file (ballpark — actuals logged at the end).
            provider = MODEL_PROVIDER or _FALLBACK_PROVIDER
            file_estimate = provider.estimate_run_cost(
                num_keys=len(memory_plan.pending_keys),
                locale_codes=[language_code],
                translate_model=MODEL_NAME,
                review_model=REVIEW_MODEL_NAME,
                review_num_keys=len(keys_to_translate),
                semantic_review_model=(
                    SEMANTIC_REVIEW_MODEL_NAME if SEMANTIC_REVIEW_ENABLED else None
                ),
                semantic_review_num_keys=(
                    len(keys_to_translate) if SEMANTIC_REVIEW_ENABLED else None
                ),
            )
            logger.info("Pre-run estimate for '%s':", translation_file)
            for line in provider.format_estimate(file_estimate).splitlines():
                logger.info(line)

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
                    position,
                    localization_format,
                )
                for text, key, position in zip(
                    memory_plan.pending_texts,
                    memory_plan.pending_keys,
                    memory_plan.pending_positions,
                )
            ]

            # Run tasks concurrently with progress indication
            results: List[Tuple[int, str, bool]] = [
                (position, value, True)
                for position, value in memory_plan.cached_results
            ]
            # The tqdm output is directed to stderr by default, which is ideal.
            # It prevents progress bars from being broken by stdout prints.
            if tasks:
                for coro in tqdm(
                        asyncio.as_completed(tasks),
                        desc=f"Translating {translation_file}",
                        unit="translation",
                        total=len(tasks)  # Provide the total number of tasks
                ):
                    try:
                        index, result, succeeded = await coro
                    except Exception:
                        logger.exception("Translation task failed unexpectedly for '%s'; continuing.", translation_file)
                        continue
                    results.append((index, result, succeeded))

            # Sort results by index to ensure correct order
            seen_positions = {position for position, _result, _succeeded in results}
            for position, key in enumerate(keys_to_translate):
                if position in seen_positions:
                    continue
                fallback_text = source_translations.get(
                    key,
                    texts_to_translate[position] if position < len(texts_to_translate) else "",
                )
                results.append((position, fallback_text, False))
            results = prefer_existing_translation_on_failure(
                results,
                keys_to_translate,
                source_translations,
                original_target_translations,
                file_ledger_entries,
            )
            results.sort(key=lambda x: x[0])
            translations = [result for _, result, _ in results]
            model_failed_keys = {
                keys_to_translate[position]
                for position, _result, succeeded in results
                if not succeeded and position < len(keys_to_translate)
            }
            if model_failed_keys:
                preserved_existing_keys = {
                    keys_to_translate[position]
                    for position, _result, succeeded in results
                    if (
                        not succeeded
                        and position < len(keys_to_translate)
                        and _ledger_verified_existing_translation(
                            keys_to_translate[position],
                            source_translations,
                            original_target_translations,
                            file_ledger_entries,
                        )
                        is not None
                    )
                }
                logger.warning(
                    "Model translation failed for %d key(s) in '%s'; preserved %d ledger-verified existing translation(s), used the current source fallback for %d, and marked all failed for retry.",
                    len(model_failed_keys),
                    translation_file,
                    len(preserved_existing_keys),
                    len(model_failed_keys) - len(preserved_existing_keys),
                )

            # Integrate initial translations to create a draft file for review
            draft_lines = integrate_translations(
                parsed_lines,
                translations,
                indices,
                keys_to_translate,
                source_translations,
                localization_format,
            )
            draft_content = adapter.reassemble_file(draft_lines)

            # We need a dictionary of the draft translations to build targeted context for each chunk.
            # This is easier than parsing the string repeatedly.
            temp_draft_path = ""
            try:
                with tempfile.NamedTemporaryFile(
                        mode='w',
                        delete=False,
                        suffix=localization_format.file_extension,
                        encoding='utf-8'
                ) as temp_f:
                    temp_f.write(draft_content)
                    temp_draft_path = temp_f.name
                _, draft_translations = adapter.parse_file(temp_draft_path)
            finally:
                if temp_draft_path and os.path.exists(temp_draft_path):
                    os.remove(temp_draft_path)

            final_corrected_translations = {}
            # --- Holistic Review Step ---
            # Instead of one large review, we chunk the keys to avoid token limits.
            logger.info(f"Performing holistic review for {len(keys_to_translate)} keys in '{translation_file}'...")

            # Create chunks of keys. Translation-memory hits stay in scope so they
            # receive the same review/glossary scrutiny as fresh model output.
            key_chunks = [
                keys_to_translate[i:i + HOLISTIC_REVIEW_CHUNK_SIZE]
                for i in range(0, len(keys_to_translate), HOLISTIC_REVIEW_CHUNK_SIZE)
            ]

            review_inputs = []
            newly_translated_keys = set(keys_to_translate)
            for key_chunk in key_chunks:
                context_keys = _select_holistic_review_context_keys(
                    source_translations,
                    draft_translations,
                    key_chunk,
                    localization_format,
                    excluded_context_keys=newly_translated_keys,
                )
                review_content_keys = [*key_chunk, *context_keys]
                review_inputs.append((key_chunk, review_content_keys))

            review_results = await asyncio.gather(
                *[holistic_review_async(
                    source_content=adapter.build_review_content(
                        source_translations,
                        review_content_keys,
                    ),
                    translated_content=adapter.build_review_content(
                        draft_translations,
                        review_content_keys,
                    ),
                    target_language=target_language,
                    keys_to_review=key_chunk,
                    semaphore=semaphore,
                    rate_limiter=rate_limiter,
                    style_rules_text=style_rules_text_for_review,
                    localization_format=localization_format,
                    translation_glossary=language_glossary,
                    translation_glossary_enforcement=TRANSLATION_GLOSSARY_ENFORCEMENT,
                ) for key_chunk, review_content_keys in review_inputs],
                return_exceptions=True,
            )

            review_failed_keys = set()
            for i, (corrected_chunk, key_chunk) in enumerate(zip(review_results, key_chunks)):
                if isinstance(corrected_chunk, Exception):
                    logger.error(
                        "Holistic review task failed for chunk %d in '%s'.",
                        i + 1,
                        translation_file,
                        exc_info=(type(corrected_chunk), corrected_chunk, corrected_chunk.__traceback__),
                    )
                    review_failed_keys.update(key_chunk)
                    for key in key_chunk:
                        final_corrected_translations[key] = draft_translations.get(key, "")
                elif corrected_chunk is not None:
                    if not isinstance(corrected_chunk, Mapping):
                        logger.warning(
                            "Holistic review returned unexpected %s for chunk %d; keeping draft values.",
                            type(corrected_chunk).__name__,
                            i + 1,
                        )
                        review_failed_keys.update(key_chunk)
                        for key in key_chunk:
                            final_corrected_translations[key] = draft_translations.get(key, "")
                        continue
                    if corrected_chunk:
                        key_chunk_set = set(key_chunk)
                        scoped = {}
                        for key, value in corrected_chunk.items():
                            if key not in key_chunk_set:
                                continue
                            selected_value = _prefer_glossary_compliant_draft(
                                source_translations.get(key, ""),
                                draft_translations.get(key, ""),
                                value,
                                enforced_language_glossary,
                            )
                            if selected_value != value:
                                logger.warning(
                                    "Holistic review broke a required glossary mapping for key '%s'; "
                                    "keeping the compliant draft.",
                                    key,
                                )
                            scoped[key] = selected_value
                        dropped = set(corrected_chunk) - key_chunk_set
                        if dropped:
                            logger.warning(
                                "Holistic review returned %d out-of-scope key(s); ignored.",
                                len(dropped),
                            )
                        final_corrected_translations.update(scoped)
                        missing = key_chunk_set - set(scoped)
                        if missing:
                            logger.warning(
                                "Holistic review omitted %d key(s) from chunk %d; keeping draft values.",
                                len(missing),
                                i + 1,
                            )
                            review_failed_keys.update(missing)
                            for key in missing:
                                final_corrected_translations[key] = draft_translations.get(key, "")
                    else:
                        logger.info("Holistic review returned no corrections for this chunk; keeping draft values.")
                        for key in key_chunk:
                            final_corrected_translations[key] = draft_translations.get(key, "")
                else:
                    logger.warning(f"Holistic review for chunk {i + 1} failed; keeping draft values for this chunk.")
                    review_failed_keys.update(key_chunk)
                    for key in key_chunk:
                        final_corrected_translations[key] = draft_translations.get(key, "")

            model_failed_keys.update(review_failed_keys)

            # Always apply the results from the review stage, which includes fallbacks to draft for failed chunks.
            logger.info("Applying corrected translations (including any draft fallbacks).")

            # Debug: Check if restored translations have real placeholders or protection tokens
            sample_keys = list(final_corrected_translations.keys())[:3]
            for sample_key in sample_keys:
                sample_value = final_corrected_translations.get(sample_key, "")
                has_protection_tokens = "__PH_" in sample_value
                has_real_placeholders = "{0}" in sample_value or "{1}" in sample_value or "{2}" in sample_value
                logger.debug(f"Sample restored translation for '{sample_key}': '{sample_value}' "
                            f"(has_tokens={has_protection_tokens}, has_placeholders={has_real_placeholders})")

            logger.debug("--- ALL CORRECTED JSON FROM REVIEW (first 3 keys) ---")
            for key in sample_keys:
                logger.debug(f"  {key}={final_corrected_translations.get(key, '')}")

            # Track changes made by holistic review for INFO-level logging
            review_changes = 0
            for line in draft_lines:
                if line['type'] == 'entry':
                    key = line.get('key')
                    if key in final_corrected_translations:
                        new_value = _escape_output_value(
                            adapter,
                            source_translations,
                            key,
                            final_corrected_translations[key],
                        )
                        old_value = line['value']
                        if old_value != new_value:
                            review_changes += 1
                            logger.debug(f"Review changed key '{key}': FROM '{old_value}' TO '{new_value}'")
                        line['value'] = new_value

            if review_changes > 0:
                logger.info(f"Holistic review modified {review_changes} translations out of {len(final_corrected_translations)} reviewed keys.")

            # --- Per-Key Validation ---
            # Extract final translations from updated lines
            final_translations = {}
            for line in draft_lines:
                if line['type'] == 'entry':
                    key = line.get('key')
                    if key:
                        final_translations[key] = line['value']

            # Debug: Check what's in final_translations before validation
            validation_sample_keys = list(final_translations.keys())[:3]
            logger.debug("--- FINAL TRANSLATIONS BEFORE VALIDATION (first 3 keys) ---")
            for sample_key in validation_sample_keys:
                sample_value = final_translations.get(sample_key, "")
                has_protection_tokens = "__PH_" in sample_value
                has_real_placeholders = "{0}" in sample_value or "{1}" in sample_value or "{2}" in sample_value
                logger.debug(f"  {sample_key}={sample_value} "
                            f"(has_tokens={has_protection_tokens}, has_placeholders={has_real_placeholders})")

            # Validate each key individually and selectively revert failures
            changed_final_translations = {
                key: final_translations[key]
                for key in keys_to_translate
                if key in final_translations
            }
            valid_translations, per_key_summary = run_per_key_validation_with_summary(
                changed_final_translations,
                source_translations,
                translation_file,
                ignore_key_patterns=IGNORE_KEY_PATTERNS,
                translation_glossary=enforced_language_glossary,
                existing_translations=original_target_translations,
                file_ledger_entries=file_ledger_entries,
                selected_keys=set(keys_to_translate),
            )
            failed_keys = set(per_key_summary["failed_keys"]).union(model_failed_keys)
            increment_run_metric(run_metrics, "model_translation_failed_count", len(failed_keys))
            per_key_summary["model_translation_failed_count"] = len(model_failed_keys)
            per_key_summary["model_translation_failed_keys"] = sorted(model_failed_keys)
            if validation_summary is not None:
                validation_summary[translation_file] = per_key_summary

            # Apply validated translations (valid translations + reverted source for failed keys)
            for line in draft_lines:
                if line['type'] == 'entry':
                    key = line.get('key')
                    if key and key in valid_translations:
                        line['value'] = valid_translations[key]

            # Reassemble the final file content with validated translations
            updated_lines = draft_lines
            new_file_content = adapter.reassemble_file(updated_lines)
            final_output_translations = {
                line['key']: line.get('value', '')
                for line in updated_lines
                if line.get('type') == 'entry' and line.get('key')
            }
            increment_run_metric(
                run_metrics,
                "changed_values_count",
                count_changed_translation_values(original_target_translations, final_output_translations),
            )
            # --- End Per-Key Validation ---

            translated_file_path = os.path.join(translated_queue_folder, translation_file)

            if not run_post_translation_validation(
                    new_file_content,
                    source_translations,
                    translation_file,
                    localization_format,
                    ignore_key_patterns=IGNORE_KEY_PATTERNS,
                    changed_keys_for_run=set(keys_to_translate),
                    translation_glossary=enforced_language_glossary,
            ):
                logger.error("Skipping write for '%s' because post-translation validation failed.", translation_file)
                skipped_files[translation_file] = ["Post-translation validation failed."]
                continue

            if DRY_RUN:
                logger.info(f"[Dry Run] Would write translated content to '{translated_file_path}'.")
            else:
                # Ensure the destination directory exists
                os.makedirs(os.path.dirname(translated_file_path), exist_ok=True)
                with open(translated_file_path, 'w', encoding='utf-8') as file:
                    file.write(new_file_content)
                logger.info(f"Translated file saved to '{translated_file_path}'.\n")

            # Update and persist per-file key ledger after successful file processing.
            key_ledger[translation_file] = build_file_key_ledger(
                source_translations,
                final_output_translations,
                failed_keys=failed_keys
            )
            save_translation_key_ledger(TRANSLATION_KEY_LEDGER_FILE_PATH, key_ledger)
            if translation_memory is not None and not DRY_RUN:
                update_translation_memory(
                    translation_memory,
                    source_translations,
                    valid_translations,
                    keys_to_translate,
                    locale=language_code,
                    format_id=localization_format.id,
                    failed_keys=failed_keys,
                    context_fingerprint=memory_context_fingerprint,
                )
                save_translation_memory(TRANSLATION_MEMORY_FILE_PATH, translation_memory)

            processed_files_count += 1
            processed_filenames.append(translation_file)
            total_keys_translated += len(keys_to_translate)

        except Exception as exc:
            logger.exception("Unexpected error while processing translation file %s.", translation_file)
            skipped_files[translation_file] = [f"Unexpected processing error: {exc}"]
            continue
    return ProcessTranslationQueueResult(
        processed_files_count,
        processed_filenames,
        skipped_files,
        total_keys_translated,
        run_metrics,
    )
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

def generate_translation_summary(
    summary_path: str,
    processed_files: List[str],
    new_keys_count: int,
    updated_keys_count: int,
    supported_codes: Optional[List[str]] = None,
    run_metrics: Optional[Mapping[str, int]] = None,
) -> None:
    """Write a JSON summary consumed by the shell script for PR title/body.

    Args:
        summary_path: Where to write the JSON file.
        processed_files: List of translated file paths (e.g. ``bisq_easy_de.properties``).
        new_keys_count: Total number of newly added translation keys.
        updated_keys_count: Total number of updated translation keys.
        supported_codes: Language codes for locale extraction. Defaults to
            ``LANGUAGE_CODES`` keys.
        run_metrics: Optional explicit run counters for PR reporting.
    """
    if supported_codes is None:
        supported_codes = list(LANGUAGE_CODES.keys())
    # Pre-sort once; extract_language_from_filename sorts on every call otherwise.
    sorted_codes = sorted(supported_codes, key=len, reverse=True)
    modules: set[str] = set()
    locales: set[str] = set()

    for filename in processed_files:
        profile = find_target_localization_profile(filename, sorted_codes)
        if not profile:
            continue
        code = profile.localization_layout.extract_locale(
            filename,
            sorted_codes,
            profile.localization_format,
        )
        if code:
            locales.add(code)
            source_filename = profile.localization_layout.source_path_for_target(
                filename,
                sorted_codes,
                profile.localization_format,
            )
            source_basename = os.path.basename(source_filename)
            if source_basename.endswith(profile.localization_format.file_extension):
                module = source_basename[:-len(profile.localization_format.file_extension)]
            else:
                module = os.path.splitext(source_basename)[0]
            if module and module != os.path.basename(filename):
                modules.add(module)

    sorted_modules = sorted(modules)
    sorted_locales = sorted(locales)

    metrics = {key: int(value) for key, value in (run_metrics or {}).items()}
    changed_values_count = metrics.get("changed_values_count")
    title = _build_pr_title(
        sorted_modules,
        new_keys_count,
        updated_keys_count,
        len(sorted_locales),
        changed_values=changed_values_count,
    )

    summary = {
        "title": title,
        "files_count": len(processed_files),
        "modules": sorted_modules,
        "locales": sorted_locales,
        "new_keys_count": new_keys_count,
        "updated_keys_count": updated_keys_count,
    }
    for key in RUN_METRIC_KEYS:
        summary[key] = metrics.get(key, 0)

    write_json_atomic(summary_path, summary)


def write_translation_validation_summary(
    summary_path: str,
    validation_files: Dict[str, Dict[str, object]],
    skipped_files: Dict[str, List[str]],
) -> None:
    """Write structured validation data consumed by the PR quality gate."""
    summary = {
        "files": validation_files,
        "pipeline_warnings": [
            {"file": filename, "errors": errors}
            for filename, errors in sorted(skipped_files.items())
        ],
    }
    write_json_atomic(summary_path, summary)


def _escape_markdown_report_text(value: object) -> str:
    """Escape user-controlled text before writing markdown reports."""
    escaped = html.escape(str(value), quote=False)
    return escaped.replace("`", "\\`")


def write_skipped_files_report(report_path: str, skipped_files: Dict[str, List[str]]) -> None:
    """Write a markdown report for files skipped by validation or linting."""
    lines = [
        "## ⚠️ Translation Pipeline Warnings\n\n",
        "The following files were skipped during the AI translation process due to "
        "validation or linter errors. These issues must be addressed manually.\n\n",
    ]
    for filename, errors in skipped_files.items():
        lines.append(f"### 📄 `{_escape_markdown_report_text(filename)}`\n")
        for error in errors:
            lines.append(f"- {_escape_markdown_report_text(error)}\n")
        lines.append("\n")
    write_text_atomic(report_path, "".join(lines))


def remove_file_if_exists(path: str) -> None:
    """Remove a file when present."""
    if os.path.exists(path):
        os.remove(path)


def write_token_usage_summary(summary_path: str) -> None:
    """Persist and log token usage for the current run."""
    try:
        provider = MODEL_PROVIDER or _FALLBACK_PROVIDER
        provider.write_usage_summary(
            summary_path,
            stage_name="translation_and_holistic_review",
        )
        for line in provider.format_usage_summary().splitlines():
            logger.info(line)
        logger.info(f"Wrote token usage summary to {summary_path}")
    except Exception:
        logger.exception("Failed to write token usage summary")


def cleanup_translation_queue_folders(
        translation_queue_folder: str,
        translated_queue_folder: str
) -> None:
    """Remove queue folders after a successful non-debug run."""
    try:
        shutil.rmtree(translation_queue_folder)
        shutil.rmtree(translated_queue_folder)
        logger.info("Cleaned up translation queue folders.")
    except Exception:
        logger.exception("Error cleaning up translation queue folders")


def _build_pr_title(
    modules: List[str],
    new_keys: int,
    updated_keys: int,
    locale_count: int,
    changed_values: Optional[int] = None,
) -> str:
    """Build a concise, descriptive PR title (max 72 chars)."""
    if changed_values is not None:
        if not modules and changed_values == 0:
            return "Update translations"
        key_segment = f" ({changed_values} changed values)" if changed_values > 0 else ""
    elif not modules and not new_keys and not updated_keys:
        return "Update translations"
    else:
        parts: list[str] = []
        if new_keys:
            parts.append(f"{new_keys} new")
        if updated_keys:
            parts.append(f"{updated_keys} updated")
        key_desc = ", ".join(parts)
        key_segment = f" ({key_desc} keys)" if key_desc else ""

    if len(modules) == 1:
        mod_segment = f" in {modules[0]}"
    elif len(modules) <= 3:
        mod_segment = f" in {', '.join(modules)}"
    else:
        mod_segment = f" across {len(modules)} modules"

    locale_segment = f" for {locale_count} locales" if locale_count else ""

    # Try progressively shorter variants until under 72 chars.
    candidates = [
        f"Update translations{key_segment}{mod_segment}{locale_segment}",
        f"Update translations{key_segment}{mod_segment}",
        f"Update translations{key_segment}",
    ]
    for title in candidates:
        if len(title) <= 72:
            return title

    return candidates[-1][:69] + "..."


async def main():
    """
    Main function to orchestrate the translation process.
    """
    paths = TranslationPipelinePaths(
        project_root_dir=PROJECT_ROOT_DIR,
        repo_root=REPO_ROOT,
        input_folder=INPUT_FOLDER,
        translation_queue_folder=TRANSLATION_QUEUE_FOLDER,
        translated_queue_folder=TRANSLATED_QUEUE_FOLDER,
        glossary_file_path=GLOSSARY_FILE_PATH,
    )
    options = TranslationPipelineOptions(
        process_all_files=PROCESS_ALL_FILES,
        dry_run=DRY_RUN,
        preserve_queues_for_debug=PRESERVE_QUEUES_FOR_DEBUG,
    )
    steps = TranslationPipelineSteps(
        validate_paths=validate_paths,
        get_changed_translation_files=get_changed_translation_files,
        archive_original_files=archive_original_files,
        copy_files_to_translation_queue=copy_files_to_translation_queue,
        process_translation_queue=process_translation_queue,
        write_skipped_files_report=write_skipped_files_report,
        remove_file_if_exists=remove_file_if_exists,
        generate_translation_summary=generate_translation_summary,
        write_translation_validation_summary=write_translation_validation_summary,
        write_token_usage_summary=write_token_usage_summary,
        copy_translated_files_back=copy_translated_files_back,
        cleanup_queue_folders=cleanup_translation_queue_folders,
    )
    return await run_translation_pipeline(
        paths=paths,
        options=options,
        steps=steps,
        logger=logger,
    )

if __name__ == "__main__":
    # Ensure queue folders exist, potentially using paths derived from config or defaults
    os.makedirs(TRANSLATION_QUEUE_FOLDER, exist_ok=True)
    os.makedirs(TRANSLATED_QUEUE_FOLDER, exist_ok=True)
    try:
        run_result = asyncio.run(main())
        if (
            getattr(run_result, "changed_files", None)
            and getattr(run_result, "processed_files_count", 0) == 0
            and getattr(run_result, "skipped_files", None)
        ):
            sys.exit(1)
    except Exception:
        logger.exception("An unexpected error occurred during execution")
        sys.exit(1)
