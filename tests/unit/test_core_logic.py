import os
import unittest
from unittest.mock import patch
import tempfile
import textwrap

# Set a dummy API key before importing the main script.
# This prevents the OpenAI client from failing in a test environment
# where the key might not be set.
os.environ['OPENAI_API_KEY'] = 'DUMMY_KEY_FOR_TESTING'

# It's good practice to be able to import the functions to be tested.
# This might require adjusting the Python path if the test runner doesn't handle it.
from src.translate_localization_files import (
    parse_properties_file,
    integrate_translations,
    reassemble_file,
    build_context,
    # Imported to assist in build_context testing
    normalize_value,
    extract_texts_to_translate,
    extract_language_from_filename
)


class TestCoreLogic(unittest.TestCase):

    def test_parse_properties_file_with_multiline_values(self):
        """
        Tests that parse_properties_file correctly handles various .properties file features,
        especially multi-line values.
        """
        # Use textwrap.dedent to avoid issues with leading whitespace.
        content = textwrap.dedent("""
            # This is a comment

            key.one=Simple value
            key.two=This is a multi-line value that \\
                     continues on the next line.
            # Another comment
            key.three=Another simple value
        """)

        # Use a temporary directory to ensure cleanup and avoid conflicts.
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_file_path = os.path.join(temp_dir, 'test.properties')
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                f.write(content.lstrip())

            parsed_lines, translations = parse_properties_file(temp_file_path)

            # 1. Test the translations dictionary
            expected_translations = {
                'key.one': 'Simple value',
                'key.two': 'This is a multi-line value that continues on the next line.',
                'key.three': 'Another simple value'
            }
            self.assertEqual(translations, expected_translations)

            # 2. Test the parsed_lines structure
            self.assertEqual(len(parsed_lines), 6)
            self.assertEqual(parsed_lines[0]['type'], 'comment_or_blank')
            self.assertEqual(parsed_lines[1]['type'], 'comment_or_blank')
            self.assertEqual(parsed_lines[2]['type'], 'entry')
            self.assertEqual(parsed_lines[2]['key'], 'key.one')
            self.assertEqual(parsed_lines[3]['type'], 'entry')
            self.assertEqual(parsed_lines[3]['key'], 'key.two')
            self.assertEqual(parsed_lines[3]['value'], 'This is a multi-line value that continues on the next line.')
            self.assertEqual(parsed_lines[4]['type'], 'comment_or_blank')
            self.assertEqual(parsed_lines[5]['type'], 'entry')

    def test_integrate_and_reassemble(self):
        """
        Tests that `integrate_translations` and `reassemble_file` work together
        to correctly update and format the file content.
        """
        # 1. Define an initial file structure
        initial_parsed_lines = [
            {'type': 'entry', 'key': 'key.one', 'value': 'old value', 'original_value': 'old value', 'line_number': 0},
            {'type': 'comment_or_blank', 'content': '# A comment\\n'},
        ]

        # 2. Define a list of new translations to apply
        # One to update an existing key, one to add a new key
        translations = ["new translated value", "a brand new key's value"]
        indices = [0, 2]  # Update line 0, add new entry at index 2
        keys = ["key.one", "key.new"]

        # 3. Integrate the translations
        updated_lines = integrate_translations(initial_parsed_lines, translations, indices, keys)

        # 4. Reassemble the file content from the updated structure
        final_content = reassemble_file(updated_lines)

        # 5. Assert the final content is exactly as expected
        expected_content = (
            "key.one=new translated value\n"
            "# A comment\\n"
            "key.new=a brand new key's value\n"
        )

        # The reassemble function uses '\\n' literally, so we compare directly.
        self.assertEqual(final_content, expected_content)

    def test_build_context_respects_token_limit(self):
        """
        Tests that build_context correctly limits the number of examples
        based on the max_tokens parameter.
        """

        # Mocking `count_tokens` to have predictable token counts
        def mock_count_tokens(text: str, model_name: str) -> int:
            # Simple mock: token count is the length of the text.
            # This makes it easy to control the test.
            return len(text)

        with patch('src.translate_localization_files.count_tokens', side_effect=mock_count_tokens):
            existing_translations = {
                "key1": "translation1",
                "key2": "translation2",
                "key3": "translation3"
            }
            source_translations = {
                "key1": "source1",
                "key2": "source2",
                "key3": "source3"
            }
            language_glossary = {"term": "gloss"}
            model_name = "test-model"

            # Dynamically calculate token counts based on the mock function
            # to make the test self-verifying.
            glossary_len = mock_count_tokens(f'"term" should be translated as "gloss"', model_name)
            example1_len = mock_count_tokens(f'key1 = "translation1"', model_name)
            # Function reserves 1000 tokens for the response.
            reserved_len = 1000

            # Set max_tokens so only the glossary and one example can fit.
            max_tokens = glossary_len + example1_len + reserved_len + 1

            context_text, glossary_text = build_context(
                existing_translations,
                source_translations,
                language_glossary,
                max_tokens,
                model_name
            )

            # Assert that the glossary text is present
            self.assertIn("term", glossary_text)

            # Assert that only one of the possible examples was included in the context
            self.assertEqual(context_text.count("="), 1, "Should only include one example to fit token limit.")
            self.assertIn("key1", context_text, "The first example should have been included.")
            self.assertNotIn("key2", context_text, "The second example should not have been included.")

    def test_normalize_value_logic(self):
        """
        Tests the `normalize_value` helper function.
        """
        # Test case for a real, literal newline character in the string.
        self.assertEqual(normalize_value("hello\nworld"), "hello<newline>world", "Literal newline should be replaced.")
        self.assertEqual(normalize_value("  hello   world  "), "hello world", "Spaces should be normalized.")
        # Test case for an escaped newline sequence in the string.
        self.assertEqual(normalize_value("hello\\nworld"), "hello<newline>world", "Escaped newline should be replaced.")
        self.assertEqual(normalize_value(None), "", "None input should return empty string.")

    def test_extract_texts_to_translate_logic(self):
        """
        Tests the logic of `extract_texts_to_translate`.
        It should identify texts that need translation based on two conditions:
        1. The key is present in the source but not in the target file (a new key).
        2. The key is present in both, but its value is identical in both (an untranslated key).
        """
        # Case where a key has a real, existing translation. Should be ignored.
        # `key0` has a different value in target vs source.
        parsed_lines = [
            {'type': 'entry', 'key': 'key0_translated', 'value': 'Zielwert 0', 'line_number': 0},
            {'type': 'entry', 'key': 'key1_needs_translation', 'value': 'Source Value 1', 'line_number': 1},
            {'type': 'comment_or_blank', 'content': '# comment', 'line_number': 2},
        ]

        target_translations = {
            'key0_translated': 'Zielwert 0',
            'key1_needs_translation': 'Source Value 1',
        }

        # `key1` has same value as target, needs translation.
        # `key2` is new, needs translation.
        source_translations = {
            'key0_translated': 'Source Value 0',
            'key1_needs_translation': 'Source Value 1',
            'key2_new': 'Source Value 2',
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines, source_translations, target_translations
        )

        # It should pick up key1 (identical value) and key2 (new key).
        # The text to be translated is always from the source.
        expected_texts = sorted(['Source Value 1', 'Source Value 2'])
        expected_keys = sorted(['key1_needs_translation', 'key2_new'])
        # key1 is at index 1 in parsed_lines. key2 is new, so its index is len(parsed_lines) = 3.
        expected_indices = [1, 3]

        self.assertEqual(sorted(texts), expected_texts, "Should identify untranslated and new keys.")
        self.assertEqual(sorted(keys), expected_keys, "Should identify the correct keys for translation.")
        self.assertEqual(indices, expected_indices, "Should return the correct original and new indices.")

    def test_extract_language_from_filename(self):
        """
        Tests that `extract_language_from_filename` correctly identifies language codes.
        """
        supported_codes = ["de", "pt_BR", "af_ZA", "en"]

        # Test case for the bug: filename with underscore in the name part
        self.assertEqual(extract_language_from_filename("mu_sig_de.properties", supported_codes), "de")

        # Standard cases
        self.assertEqual(extract_language_from_filename("app_de.properties", supported_codes), "de")
        self.assertEqual(extract_language_from_filename("app_pt_BR.properties", supported_codes), "pt_BR")
        self.assertEqual(extract_language_from_filename("app_af_ZA.properties", supported_codes), "af_ZA")

        # Cases that should not match
        self.assertIsNone(extract_language_from_filename("app.properties", supported_codes))
        self.assertIsNone(extract_language_from_filename("app_fr.properties", supported_codes)) # fr is not supported
        self.assertIsNone(extract_language_from_filename("app_de.txt", supported_codes)) # wrong extension


if __name__ == '__main__':
    unittest.main()
