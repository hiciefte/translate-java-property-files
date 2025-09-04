import re
from typing import Dict, List, Tuple


def _has_unescaped_trailing_backslash(s: str) -> bool:
    """Check if a string ends with an odd number of backslashes."""
    if not s.endswith('\\'):
        return False
    # Count trailing backslashes
    count = 0
    i = len(s) - 1
    while i >= 0 and s[i] == '\\':
        count += 1
        i -= 1
    # An odd number of trailing backslashes indicates an unescaped one
    return count % 2 == 1


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
        stripped_line = line.lstrip()

        if not stripped_line or stripped_line.startswith(('#', '!')):
            parsed_lines.append({'type': 'comment_or_blank', 'content': lines[i]})
            i += 1
        else:
            match = re.match(r'([^=:]+?)\s*[:=]\s*(.*)', line)
            if match:
                key = match.group(1).strip()
                value = match.group(2)
                line_number = i
                original_value_lines = [value]
                was_multiline = False

                # Handle multiline values
                while _has_unescaped_trailing_backslash(value):
                    was_multiline = True
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
                    'line_number': line_number,
                    'was_multiline': was_multiline
                })
            else:
                # Handle lines without a separator (e.g., a key with no value)
                key = line.strip()
                if key:  # only if it is not a blank line
                    target_translations[key] = ''
                    parsed_lines.append({
                        'type': 'entry',
                        'key': key,
                        'value': '',
                        'original_value': '',
                        'line_number': i,
                        'was_multiline': False
                    })
                else:  # if it is a blank line after all
                    parsed_lines.append(
                        {'type': 'comment_or_blank', 'content': lines[i]})
                i += 1
    return parsed_lines, target_translations


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
            elif '\n' in value or item.get('was_multiline', False):
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
