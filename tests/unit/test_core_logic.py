import os
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import textwrap

# Set a dummy API key before importing the main script.
# This prevents the OpenAI client from failing in a test environment
# where the key might not be set.
os.environ['OPENAI_API_KEY'] = 'DUMMY_KEY_FOR_TESTING'

# It's good practice to be able to import the functions to be tested.
# This might require adjusting the Python path if the test runner doesn't handle it.
from src.translate_localization_files import (
    build_context,
    normalize_value,
    extract_texts_to_translate,
    extract_language_from_filename,
    run_post_translation_validation
)
from src.properties_parser import parse_properties_file, reassemble_file


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
        from src.translate_localization_files import integrate_translations
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

        from src.translate_localization_files import integrate_translations
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

        from src.translate_localization_files import integrate_translations
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

    def test_extract_language_from_filename_with_hyphens(self):
        """Tests that `extract_language_from_filename` correctly identifies hyphenated locale codes like zh-Hans and zh-Hant."""
        supported_codes = ["zh-Hans", "zh-Hant", "pt_BR", "de"]

        # Test hyphenated Chinese locale codes
        self.assertEqual(extract_language_from_filename("app_zh-Hans.properties", supported_codes), "zh-Hans")
        self.assertEqual(extract_language_from_filename("application_zh-Hans.properties", supported_codes), "zh-Hans")
        self.assertEqual(extract_language_from_filename("app_zh-Hant.properties", supported_codes), "zh-Hant")
        self.assertEqual(extract_language_from_filename("application_zh-Hant.properties", supported_codes), "zh-Hant")

        # Ensure underscore-based codes still work
        self.assertEqual(extract_language_from_filename("app_pt_BR.properties", supported_codes), "pt_BR")
        self.assertEqual(extract_language_from_filename("app_de.properties", supported_codes), "de")

        # Test that longer hyphenated codes are matched before shorter ones
        supported_codes_with_overlap = ["zh-Hans", "zh", "de"]
        self.assertEqual(extract_language_from_filename("app_zh-Hans.properties", supported_codes_with_overlap), "zh-Hans")

        # Test non-matching cases
        self.assertIsNone(extract_language_from_filename("app.properties", supported_codes))
        self.assertIsNone(extract_language_from_filename("app_fr.properties", supported_codes))

    def test_post_translation_validation_success(self):
        """Tests that valid content passes the post-translation validation."""
        final_content = "key.one=Valid value {0}"
        source_translations = {"key.one": "Source value {0}"}
        filename = "valid_file.properties"
        self.assertTrue(run_post_translation_validation(final_content, source_translations, filename))

    def test_post_translation_validation_fails_on_placeholder_mismatch(self):
        """Tests that a placeholder mismatch is caught by post-translation validation."""
        final_content = "key.one=Invalid value {1}" # Mismatched placeholder
        source_translations = {"key.one": "Source value {0}"}
        filename = "bad_placeholders.properties"
        self.assertFalse(run_post_translation_validation(final_content, source_translations, filename))

    def test_post_translation_validation_fails_on_mojibake(self):
        """Tests that mojibake is caught by post-translation validation."""
        final_content = "key.one=This is verfÃ¼gbar" # Mojibake
        source_translations = {"key.one": "This is available"}
        filename = "mojibake_file.properties"
        self.assertFalse(run_post_translation_validation(final_content, source_translations, filename))


class TestSourceFilenameExtraction(unittest.TestCase):
    """Tests for extracting source filename from translated filename."""

    def test_get_source_filename_simple_language_code(self):
        """Test extraction with simple 2-letter language codes."""
        from src.translate_localization_files import get_source_filename

        supported_codes = ['es', 'de', 'fr', 'pt_PT', 'pt_BR']

        # Simple case: app_es.properties -> app.properties
        result = get_source_filename('app_es.properties', supported_codes)
        self.assertEqual(result, 'app.properties')

        # Simple case: bisq_easy_de.properties -> bisq_easy.properties
        result = get_source_filename('bisq_easy_de.properties', supported_codes)
        self.assertEqual(result, 'bisq_easy.properties')

    def test_get_source_filename_with_underscores_in_base_name(self):
        """Test extraction when base filename contains underscores (mu_sig bug)."""
        from src.translate_localization_files import get_source_filename

        supported_codes = ['es', 'de', 'fr', 'pt_PT', 'pt_BR']

        # BUG CASE: mu_sig_es.properties should -> mu_sig.properties (not mu.properties)
        result = get_source_filename('mu_sig_es.properties', supported_codes)
        self.assertEqual(result, 'mu_sig.properties',
                        "Should preserve 'mu_sig' base name, not strip 'sig' as language code")

        # Similar case with different language
        result = get_source_filename('mu_sig_de.properties', supported_codes)
        self.assertEqual(result, 'mu_sig.properties')

        # Another multi-underscore base name
        result = get_source_filename('user_auth_flow_fr.properties', supported_codes)
        self.assertEqual(result, 'user_auth_flow.properties')

    def test_get_source_filename_with_complex_language_codes(self):
        """Test extraction with complex language codes like pt_PT."""
        from src.translate_localization_files import get_source_filename

        supported_codes = ['es', 'pt_PT', 'pt_BR', 'zh-Hans', 'zh-Hant']

        # Complex language code: mu_sig_pt_PT.properties -> mu_sig.properties
        result = get_source_filename('mu_sig_pt_PT.properties', supported_codes)
        self.assertEqual(result, 'mu_sig.properties')

        # Ensure pt_PT is matched before pt (if pt were in the list)
        result = get_source_filename('app_pt_PT.properties', supported_codes)
        self.assertEqual(result, 'app.properties')

        # Hyphenated locale
        result = get_source_filename('app_zh-Hans.properties', supported_codes)
        self.assertEqual(result, 'app.properties')

    def test_get_source_filename_no_language_code_match(self):
        """Test when filename doesn't match any supported language code."""
        from src.translate_localization_files import get_source_filename

        supported_codes = ['es', 'de', 'fr']

        # No language code in filename
        result = get_source_filename('app.properties', supported_codes)
        self.assertEqual(result, 'app.properties', "Should return unchanged if no language code")

        # Unsupported language code
        result = get_source_filename('app_ja.properties', supported_codes)
        self.assertEqual(result, 'app_ja.properties', "Should return unchanged if language code not supported")

    def test_get_source_filename_edge_cases(self):
        """Test edge cases and unusual filenames."""
        from src.translate_localization_files import get_source_filename

        supported_codes = ['es', 'de', 'pt_PT']

        # Single character base name
        result = get_source_filename('a_es.properties', supported_codes)
        self.assertEqual(result, 'a.properties')

        # Multiple dots in filename (shouldn't happen, but defensive)
        result = get_source_filename('app.config_es.properties', supported_codes)
        self.assertEqual(result, 'app.config.properties')

        # Base name ending with underscore (shouldn't happen, but defensive)
        result = get_source_filename('app__es.properties', supported_codes)
        self.assertEqual(result, 'app_.properties')


class TestValidationLogic(unittest.TestCase):
    def test_linting_finds_common_errors(self):
        """
        Tests the linter on a .properties file with various correct and incorrect syntax.
        """
        # Import inside the test to avoid circular dependency issues at the module level
        # if other tests also need to patch or modify its behavior.
        from src.translate_localization_files import lint_properties_file

        content = textwrap.dedent("""
            # Correct line
            key.one=A normal value.

            # Correctly escaped characters
            key.two=This value has a tab \\t and a newline \\n.

            # Invalid escape sequence
            key.three.bad.escape=This contains a bad escape \\U.

            # Line with double dots in key (should be flagged)
            key..four=Some value.

            # Multi-line value with valid continuation
            key.five=This is a multi-line value that \\
                     continues here.
            """)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.properties') as temp_f:
            temp_f.write(content)
            temp_file_path = temp_f.name

        try:
            errors = lint_properties_file(temp_file_path)
            self.assertEqual(len(errors), 2)
            self.assertIn("Invalid escape sequence", errors[0])
            self.assertIn("key.three.bad.escape", errors[0])
            self.assertIn("Malformed key", errors[1])
            self.assertIn("key..four", errors[1])
        finally:
            os.remove(temp_file_path)

    def test_linting_handles_common_edge_cases(self):
        """
        Tests that the linter correctly ignores common but tricky escape sequences
        that were previously flagged as errors.
        """
        from src.translate_localization_files import lint_properties_file
        content = textwrap.dedent(r'''
            # Permitted escaped quote
            key.one=This is a value with an escaped quote \"here\".

            # Permitted newline before a line continuation character
            key.two=This is a multi-line value with a newline.\n\
                     And it continues here.

            # A genuinely invalid escape sequence for control
            key.three=This has an invalid escape \z.
            ''')
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.properties') as temp_f:
            temp_f.write(content)
            temp_file_path = temp_f.name

        try:
            errors = lint_properties_file(temp_file_path)
            # It should only flag the genuinely invalid escape sequence
            self.assertEqual(len(errors), 1)
            self.assertIn("Invalid escape sequence in value for key 'key.three'", errors[0])
        finally:
            os.remove(temp_file_path)


class TestFileDetectionLogic(unittest.TestCase):

    @patch('subprocess.run')
    def test_get_changed_files_returns_all_without_filter(self, mock_subprocess_run):
        """
        Tests that get_changed_translation_files returns all changed files
        when no environment variable filter is set.
        """
        from src.translate_localization_files import get_changed_translation_files

        # Simulate git status output
        git_output = textwrap.dedent("""
             M i18n/resources/mobile_de.properties
             M i18n/resources/desktop_de.properties
             M i18n/resources/mobile_es.properties
        """).strip()
        mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

        repo_root = "/fake/repo"
        input_folder = "/fake/repo/i18n/resources"

        changed_files = get_changed_translation_files(input_folder, repo_root)

        # In a test environment with mocked paths, os.path.relpath can be unpredictable.
        # It's more robust to check the basenames of the files to ensure the correct set was returned.
        changed_basenames = [os.path.basename(f) for f in changed_files]
        self.assertEqual(len(changed_basenames), 3)
        self.assertIn("mobile_de.properties", changed_basenames)
        self.assertIn("desktop_de.properties", changed_basenames)
        self.assertIn("mobile_es.properties", changed_basenames)

    @patch('subprocess.run')
    def test_get_changed_files_applies_glob_filter(self, mock_subprocess_run):
        """
        Tests that get_changed_translation_files correctly filters files
        based on the TRANSLATION_FILTER_GLOB environment variable.
        """
        from src.translate_localization_files import get_changed_translation_files

        # Simulate git status output
        git_output = textwrap.dedent("""
             M i18n/resources/mobile_de.properties
             M i18n/resources/desktop_de.properties
             M i18n/resources/mobile_es.properties
        """).strip()
        mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

        repo_root = "/fake/repo"
        input_folder = "/fake/repo/i18n/resources"

        # Use patch.dict to temporarily set the environment variable for this test
        with patch.dict('os.environ', {'TRANSLATION_FILTER_GLOB': 'mobile_*.properties'}):
            changed_files = get_changed_translation_files(input_folder, repo_root)

            changed_basenames = [os.path.basename(f) for f in changed_files]
            self.assertEqual(len(changed_basenames), 2)
            self.assertIn("mobile_de.properties", changed_basenames)
            self.assertIn("mobile_es.properties", changed_basenames)
            self.assertNotIn("desktop_de.properties", changed_basenames)

    @patch('subprocess.run')
    def test_get_changed_files_detects_hyphenated_locales(self, mock_subprocess_run):
        """
        Tests that get_changed_translation_files correctly detects files with
        hyphenated locale codes like zh-Hans and zh-Hant, as well as untracked files.
        """
        from src.translate_localization_files import get_changed_translation_files

        # Simulate git status output with both modified and untracked files
        # Including hyphenated locale codes (zh-Hans, zh-Hant) and standard ones (pl, pt_BR)
        git_output = textwrap.dedent("""
             M i18n/resources/academy_pl.properties
             M i18n/resources/application_pt_BR.properties
            ?? i18n/resources/academy_zh-Hans.properties
            ?? i18n/resources/academy_zh-Hant.properties
            ?? i18n/resources/application_zh-Hans.properties
            ?? i18n/resources/application_zh-Hant.properties
        """).strip()
        mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

        repo_root = "/fake/repo"
        input_folder = "/fake/repo/i18n/resources"

        changed_files = get_changed_translation_files(input_folder, repo_root)

        # Verify all files are detected including hyphenated locale codes
        changed_basenames = [os.path.basename(f) for f in changed_files]
        self.assertEqual(len(changed_basenames), 6)

        # Standard locale codes should be detected
        self.assertIn("academy_pl.properties", changed_basenames)
        self.assertIn("application_pt_BR.properties", changed_basenames)

        # Hyphenated locale codes should be detected
        self.assertIn("academy_zh-Hans.properties", changed_basenames)
        self.assertIn("academy_zh-Hant.properties", changed_basenames)
        self.assertIn("application_zh-Hans.properties", changed_basenames)
        self.assertIn("application_zh-Hant.properties", changed_basenames)


if __name__ == '__main__':
    unittest.main()
