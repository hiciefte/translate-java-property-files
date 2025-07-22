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
        translations = ["new translated value", "a brand new key's value"]
        indices = [0, 2]
        keys = ["key.one", "key.new"]
        source_translations = {"key.one": "source value", "key.new": "new source value"}

        # 3. Integrate the translations
        updated_lines = integrate_translations(initial_parsed_lines, translations, indices, keys, source_translations)

        # 4. Reassemble the file content from the updated structure
        final_content = reassemble_file(updated_lines)

        # 5. Assert the final content is exactly as expected
        expected_content = (
            "key.one=new translated value\n"
            "# A comment\\n"
            "key.new=a brand new key's value\n"
        )
        self.assertEqual(final_content, expected_content)

    def test_translation_overwrites_original_value_with_newlines(self):
        """
        Ensure that an entry whose original_value contained an escaped newline
        does not retain that escape after being updated with a single-line
        translation.
        """
        initial_parsed_lines = [
            {'type': 'entry', 'key': 'key.one', 'value': 'old\\nvalue', 'original_value': 'old\\nvalue', 'line_number': 0}
        ]
        translations = ['new value']
        indices = [0]
        keys = ['key.one']
        source_translations = {'key.one': 'old\\nvalue'}

        updated_lines = integrate_translations(initial_parsed_lines, translations, indices, keys, source_translations)
        final_content = reassemble_file(updated_lines)
        self.assertEqual(final_content, 'key.one=new value\n')

    def test_integrate_translations_updates_original_value(self):
        """Ensure original_value is updated when integrating translations."""
        initial_lines = [
            {'type': 'entry', 'key': 'multi.key', 'value': 'old line1\\nold line2', 'original_value': 'old line1\\nold line2', 'line_number': 0}
        ]
        translations = ['new line1\nnew line2']
        indices = [0]
        keys = ['multi.key']
        source_translations = {'multi.key': 'old line1\\nold line2'}

        updated = integrate_translations(initial_lines, translations, indices, keys, source_translations)
        self.assertEqual(updated[0]['value'], translations[0])
        # This assertion needs to be smarter if reassemble logic changes original_value
        reassembled = reassemble_file(updated)
        self.assertIn('new line1', reassembled)
        self.assertIn('new line2', reassembled)

    def test_build_context_respects_token_limit(self):
        """
        Tests that build_context correctly limits the number of examples
        based on the max_tokens parameter.
        """
        def mock_count_tokens(text: str, model_name: str) -> int:
            return len(text)

        with patch('src.translate_localization_files.count_tokens', side_effect=mock_count_tokens):
            existing_translations = {"key1": "translation1", "key2": "translation2", "key3": "translation3"}
            source_translations = {"key1": "source1", "key2": "source2", "key3": "source3"}
            language_glossary = {"term": "gloss"}
            model_name = "test-model"
            glossary_len = mock_count_tokens('"term" should be translated as "gloss"', model_name)
            example1_len = mock_count_tokens('key1 = "translation1"', model_name)
            reserved_len = 1000
            max_tokens = glossary_len + example1_len + reserved_len + 1

            context_text, glossary_text = build_context(
                existing_translations, source_translations, language_glossary, max_tokens, model_name
            )
            self.assertIn("term", glossary_text)
            self.assertEqual(context_text.count("="), 1)
            self.assertIn("key1", context_text)
            self.assertNotIn("key2", context_text)

    def test_normalize_value_logic(self):
        """Tests the `normalize_value` helper function."""
        self.assertEqual(normalize_value("hello\nworld"), "hello<newline>world")
        self.assertEqual(normalize_value("  hello   world  "), "hello world")
        self.assertEqual(normalize_value("hello\\nworld"), "hello<newline>world")
        self.assertEqual(normalize_value(None), "")

    def test_extract_texts_to_translate_logic(self):
        """Tests the logic of `extract_texts_to_translate`."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key0_translated', 'value': 'Zielwert 0', 'line_number': 0},
            {'type': 'entry', 'key': 'key1_needs_translation', 'value': 'Source Value 1', 'line_number': 1},
            {'type': 'comment_or_blank', 'content': '# comment', 'line_number': 2},
        ]
        target_translations = {'key0_translated': 'Zielwert 0', 'key1_needs_translation': 'Source Value 1'}
        source_translations = {'key0_translated': 'Source Value 0', 'key1_needs_translation': 'Source Value 1', 'key2_new': 'Source Value 2'}

        texts, indices, keys = extract_texts_to_translate(parsed_lines, source_translations, target_translations)
        expected_texts = sorted(['Source Value 1', 'Source Value 2'])
        expected_keys = sorted(['key1_needs_translation', 'key2_new'])
        expected_indices = [1, 3]

        self.assertEqual(sorted(texts), expected_texts)
        self.assertEqual(sorted(keys), expected_keys)
        self.assertEqual(indices, expected_indices)

    def test_should_not_retranslate_existing_translations(self):
        """Tests that keys with existing, valid translations are not re-translated."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key1', 'value': 'Zielwert 1', 'line_number': 0},
            {'type': 'entry', 'key': 'key2', 'value': 'Zielwert 2', 'line_number': 1},
        ]
        target_translations = {'key1': 'Zielwert 1', 'key2': 'Zielwert 2'}
        source_translations = {'key1': 'Source Value 1', 'key2': 'Source Value 2'}
        texts, _, _ = extract_texts_to_translate(parsed_lines, source_translations, target_translations)
        self.assertEqual(len(texts), 0)

    def test_extract_language_from_filename(self):
        """Tests that `extract_language_from_filename` correctly identifies language codes."""
        supported_codes = ["de", "pt_BR", "af_ZA", "en"]
        self.assertEqual(extract_language_from_filename("mu_sig_de.properties", supported_codes), "de")
        self.assertEqual(extract_language_from_filename("app_de.properties", supported_codes), "de")
        self.assertEqual(extract_language_from_filename("app_pt_BR.properties", supported_codes), "pt_BR")
        self.assertEqual(extract_language_from_filename("app_af_ZA.properties", supported_codes), "af_ZA")
        self.assertIsNone(extract_language_from_filename("app.properties", supported_codes))
        self.assertIsNone(extract_language_from_filename("app_fr.properties", supported_codes))
        self.assertIsNone(extract_language_from_filename("app_de.txt", supported_codes))

if __name__ == '__main__':
    unittest.main()
