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
            sep_index = -1
            # Find the first unescaped separator
            for j, char in enumerate(line):
                if char in (':', '=') :
                    backslash_count = 0
                    k = j - 1
                    while k >= 0 and line[k] == '\\':
                        backslash_count += 1
                        k -= 1
                    if backslash_count % 2 == 0:
                        sep_index = j
                        break

            if sep_index != -1:
                # Find whitespace around separator
                start_sep_group = sep_index
                while start_sep_group > 0 and line[start_sep_group - 1].isspace():
                    start_sep_group -= 1

                end_sep_group = sep_index
                while end_sep_group < len(line) - 1 and line[end_sep_group + 1].isspace():
                    end_sep_group += 1
                
                key_raw = line[:start_sep_group]
                separator_group = line[start_sep_group : end_sep_group + 1]
                value = line[end_sep_group + 1:]
                
                # Unescape common escapes used in .properties keys
                key = re.sub(r'\\([:=\s])', r'\1', key_raw.strip())
                
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
                    'was_multiline': was_multiline,
                    'separator_group': separator_group
                })
            else:
                # Handle lines without a separator (e.g., a key with no value)
                key = line.strip().replace(r'\=', '=').replace(r'\:', ':').replace(r'\\', '\\')
                if key:  # only if it is not a blank line
                    target_translations[key] = ''
                    parsed_lines.append({
                        'type': 'entry',
                        'key': key,
                        'value': '',
                        'original_value': '',
                        'line_number': i,
                        'was_multiline': False,
                        'separator_group': '='
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
            key = item['key']
            separator_group = item.get('separator_group', '=')

            # Preserve original formatting if possible
            if '\\n' in item.get('original_value', ''):
                # Use escaped newline characters
                value = value.replace('\n', '\\n')
                line = f"{key}{separator_group}{value}\n"
            elif '\n' in value or item.get('was_multiline', False):
                # Handle multiline values with line continuations
                lines_value = value.split('\n')
                formatted_value = '\\\n'.join(lines_value)
                line = (f"{key}{separator_group}"
                        f"{formatted_value}\n")
            else:
                line = f"{key}{separator_group}{value}\n"
            lines.append(line)
        else:
            lines.append(item['content'])
    return ''.join(lines)
