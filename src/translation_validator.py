from typing import Dict, Set, Tuple, List
import re
from collections import Counter
from src.properties_parser import parse_properties_file, reassemble_file

def check_key_coverage(base_keys: Set[str], target_keys: Set[str]) -> Tuple[Set[str], Set[str]]:
    """
    Compares the keys in a target locale file against a base English file.

    Args:
        base_keys: A set of keys from the base English .properties file.
        target_keys: A set of keys from the target locale .properties file.

    Returns:
        A tuple containing two sets:
        - missing_keys: Keys present in the base file but missing from the target file.
        - extra_keys: Keys present in the target file but absent from the base file.
    """
    missing_keys = base_keys - target_keys
    extra_keys = target_keys - base_keys
    return missing_keys, extra_keys

def check_placeholder_parity(base_string: str, target_string: str) -> bool:
    """
    Checks if the set of placeholders is identical between a base and a target string.
    Placeholders are expected to be in the format {<index>}, e.g., {0}, {1}.
    This function allows for reordering of placeholders.

    Args:
        base_string: The base English string.
        target_string: The translated string.

    Returns:
        True if the set of placeholders in both strings is identical, False otherwise.
    """
    # Regex to find placeholders like {0}, {1}, {name}, etc.
    placeholder_regex = re.compile(r'\{([^{}]+)\}')

    base_placeholders = Counter(placeholder_regex.findall(base_string))
    target_placeholders = Counter(placeholder_regex.findall(target_string))

    return base_placeholders == target_placeholders

def _find_insertion_index_for_missing_key(
        key: str,
        source_key_order: List[str],
        source_parsed_lines: List[Dict],
        source_line_index_by_key: Dict[str, int],
        final_parsed_lines: List[Dict]
) -> int:
    """
    Find insertion index for a missing key so key order follows source order.

    The key is inserted before the next existing source key when possible, or
    directly after the previous existing source key as fallback.
    """
    source_index_map = {source_key: idx for idx, source_key in enumerate(source_key_order)}
    target_entry_index_map = {
        line['key']: idx
        for idx, line in enumerate(final_parsed_lines)
        if line.get('type') == 'entry'
    }
    source_idx = source_index_map[key]

    # Insert before the next source key that already exists in target.
    for next_key in source_key_order[source_idx + 1:]:
        if next_key in target_entry_index_map:
            insertion_index = target_entry_index_map[next_key]
            key_line_idx = source_line_index_by_key[key]
            next_key_line_idx = source_line_index_by_key[next_key]
            has_non_entry_between = any(
                line.get('type') != 'entry'
                for line in source_parsed_lines[key_line_idx + 1:next_key_line_idx]
            )
            if has_non_entry_between:
                while insertion_index > 0 and final_parsed_lines[insertion_index - 1].get('type') != 'entry':
                    insertion_index -= 1
            return insertion_index

    # Otherwise insert after the previous source key that exists in target.
    for prev_key in reversed(source_key_order[:source_idx]):
        if prev_key in target_entry_index_map:
            insertion_index = target_entry_index_map[prev_key] + 1
            prev_key_line_idx = source_line_index_by_key[prev_key]
            key_line_idx = source_line_index_by_key[key]
            has_non_entry_between = any(
                line.get('type') != 'entry'
                for line in source_parsed_lines[prev_key_line_idx + 1:key_line_idx]
            )
            if has_non_entry_between:
                while insertion_index < len(final_parsed_lines) and final_parsed_lines[insertion_index].get('type') != 'entry':
                    insertion_index += 1
            return insertion_index

    # No anchor keys exist; append at end.
    return len(final_parsed_lines)

def synchronize_keys(target_file_path: str, source_file_path: str) -> Tuple[Set[str], Set[str]]:
    """
    Synchronizes the keys in a target .properties file with a source file.
    - Removes keys from the target that are not in the source.
    - Adds keys to the target that are in the source but not the target,
      using the value from the source file.

    Args:
        target_file_path: The path to the target locale file to be modified.
        source_file_path: The path to the source (e.g., English) file.

    Returns:
        A tuple of (missing_keys, extra_keys) that were applied to the target.
    """
    # Parse both files to get their structure and key-value pairs
    target_parsed_lines, target_translations = parse_properties_file(target_file_path)
    source_parsed_lines, source_translations = parse_properties_file(source_file_path)

    # Find the differences in keys
    missing_keys, extra_keys = check_key_coverage(set(source_translations.keys()), set(target_translations.keys()))

    if not missing_keys and not extra_keys:
        return missing_keys, extra_keys  # No changes needed

    # Filter out lines with extra keys from the target file
    final_parsed_lines = [
        line for line in target_parsed_lines
        if line.get('key') not in extra_keys
    ]

    source_key_order = [line['key'] for line in source_parsed_lines if line.get('type') == 'entry']
    source_line_index_by_key = {
        line['key']: idx
        for idx, line in enumerate(source_parsed_lines)
        if line.get('type') == 'entry'
    }
    source_entry_map = {
        line['key']: line for line in source_parsed_lines if line.get('type') == 'entry'
    }

    # Add missing keys in source order and at source-relative positions.
    for key in source_key_order:
        if key not in missing_keys:
            continue

        source_entry = source_entry_map.get(key, {})
        insertion_index = _find_insertion_index_for_missing_key(
            key,
            source_key_order,
            source_parsed_lines,
            source_line_index_by_key,
            final_parsed_lines
        )
        final_parsed_lines.insert(insertion_index, {
            'type': 'entry',
            'key': key,
            'value': source_translations[key],
            'original_value': source_translations[key],
            'line_number': source_entry.get('line_number', insertion_index),
            'was_multiline': source_entry.get('was_multiline', False),
            'separator_group': source_entry.get('separator_group', '=')
        })

    # Reassemble the file content and write it back
    new_content = reassemble_file(final_parsed_lines)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    return missing_keys, extra_keys

def check_encoding_and_mojibake(file_path: str) -> List[str]:
    """
    Checks a file for UTF-8 encoding and common mojibake patterns.

    Args:
        file_path: The path to the file to check.

    Returns:
        A list of string error messages. An empty list means the file is valid.
    """
    errors = []
    
    # 1. Check for valid UTF-8 encoding
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        errors.append(f"File '{file_path}' is not a valid UTF-8 file.")
        return errors  # Stop further checks if the file can't be read
    except OSError as e:
        errors.append(f"Could not read file '{file_path}'. Reason: {e}")
        return errors

    # 2. Check for common mojibake patterns
    # This regex looks for the character 'Ã' followed by another character
    # in the range 0x80-0xFF, which is a strong indicator of UTF-8 text being
    # incorrectly decoded as a single-byte encoding like latin-1 or cp1252.
    mojibake_pattern = re.compile(r'Ã[\x80-\xff]')
    if mojibake_pattern.search(content):
        errors.append(f"Potential mojibake detected in '{file_path}'. Found patterns like 'Ã¼', 'Ã¤', etc.")

    # 3. Check for the Unicode replacement character
    if '\uFFFD' in content:
        errors.append(f"File '{file_path}' contains the official Unicode replacement character (\uFFFD), indicating a previous encoding/decoding error.")
        
    return errors
