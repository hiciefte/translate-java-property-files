import re
from typing import Dict, List, Tuple

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
