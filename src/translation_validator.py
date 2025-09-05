from typing import Set, Tuple, List
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

def synchronize_keys(target_file_path: str, source_file_path: str):
    """
    Synchronizes the keys in a target .properties file with a source file.
    - Removes keys from the target that are not in the source.
    - Adds keys to the target that are in the source but not the target,
      using the value from the source file.

    Args:
        target_file_path: The path to the target locale file to be modified.
        source_file_path: The path to the source (e.g., English) file.
    """
    # Parse both files to get their structure and key-value pairs
    target_parsed_lines, target_translations = parse_properties_file(target_file_path)
    _, source_translations = parse_properties_file(source_file_path)

    # Find the differences in keys
    missing_keys, extra_keys = check_key_coverage(set(source_translations.keys()), set(target_translations.keys()))

    if not missing_keys and not extra_keys:
        return # No changes needed

    # Filter out lines with extra keys from the target file
    final_parsed_lines = [
        line for line in target_parsed_lines
        if line.get('key') not in extra_keys
    ]

    # Add missing keys to the end of the file structure
    for key in sorted(list(missing_keys)): # Sort for deterministic order
        final_parsed_lines.append({
            'type': 'entry',
            'key': key,
            'value': source_translations[key],
            'original_value': source_translations[key],
            'line_number': len(final_parsed_lines) # Assign a new line number
        })

    # Reassemble the file content and write it back
    new_content = reassemble_file(final_parsed_lines)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

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
