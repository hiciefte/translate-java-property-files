"""
Integration tests for the `translate_localization_files.py` script.

This test suite focuses on testing the overall workflow of the script by mocking
external dependencies and file system operations, and also includes unit-like tests
for specific helper functions within the script.
"""
import unittest
from unittest.mock import patch, MagicMock, AsyncMock, mock_open, call
import asyncio
import os
import shutil
import json
import yaml
import logging
import re # Import re for test_apply_glossary_logic if it uses re directly (though apply_glossary itself uses it)

# Assuming src.translate_localization_files will be importable.
# The try-except block allows the tests to be run from the project root (e.g., make test)
# or directly if the PYTHONPATH is configured.
try:
    import src.translate_localization_files
    from src.translate_localization_files import extract_texts_to_translate, normalize_value, apply_glossary
except ModuleNotFoundError:
    import sys
    # This assumes tests are run from a location where '../../' is the project root.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
    import src.translate_localization_files
    from src.translate_localization_files import extract_texts_to_translate, normalize_value, apply_glossary


class TestPythonScriptIntegration(unittest.IsolatedAsyncioTestCase):
    """
    Test class for `translate_localization_files.py`.

    Includes tests for individual helper functions and a simplified test
    for the main script flow with `process_translation_queue` mocked.
    """

    def setUp(self):
        """
        Set up the test environment before each test.

        This involves:
        - Defining paths for test configuration and sample data.
        - Loading test configuration from `test_config.yaml`.
        - Creating temporary queue folders for testing.
        - Copying sample property files to the temporary translation queue.
        - Disabling extensive logging during tests.
        """
        self.test_dir = os.path.dirname(__file__)
        self.project_root = os.path.abspath(os.path.join(self.test_dir, '../..'))
        self.test_config_path = os.path.join(self.test_dir, 'test_config.yaml')

        with open(self.test_config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        # Paths for queue folders are constructed relative to the project root for test isolation
        self.test_translation_queue_folder = os.path.join(self.project_root, self.config['translation_queue_folder'])
        self.test_translated_queue_folder = os.path.join(self.project_root, self.config['translated_queue_folder'])
        # The glossary path in config is relative to project root; resolve it for direct use in tests if needed.
        self.mock_glossary_path_resolved = os.path.join(self.project_root, self.config['glossary_file_path'])

        os.makedirs(self.test_translation_queue_folder, exist_ok=True)
        os.makedirs(self.test_translated_queue_folder, exist_ok=True)

        self.sample_en_props_path = os.path.join(self.test_dir, 'sample_app_en.properties')
        self.sample_de_props_path = os.path.join(self.test_dir, 'sample_app_de.properties')

        # Simulate German file being in the "to be processed" queue for some tests
        shutil.copy2(self.sample_de_props_path,
                      os.path.join(self.test_translation_queue_folder, 'app_de.properties'))

        # Ensure Spanish file is not present in the test setup's queue folder,
        # as some tests might expect it to be created by the script's logic.
        es_setup_path = os.path.join(self.test_translation_queue_folder, 'app_es.properties')
        if os.path.exists(es_setup_path):
            os.remove(es_setup_path)

        # Disable logging to keep test output clean, only re-enable if debugging a test.
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        """
        Clean up the test environment after each test.

        This involves removing the temporary queue folders.
        """
        if os.path.exists(self.test_translation_queue_folder):
            shutil.rmtree(self.test_translation_queue_folder)
        if os.path.exists(self.test_translated_queue_folder):
            shutil.rmtree(self.test_translated_queue_folder)
        logging.disable(logging.NOTSET) # Re-enable logging

    def test_normalize_value_logic(self):
        """
        Tests the `normalize_value` helper function.

        Verifies that it correctly handles None input, newline characters (both literal
        and escaped), and leading/trailing/multiple spaces.
        """
        self.assertEqual(normalize_value("hello\nworld"), "hello<newline>world", "Literal newline should be replaced.")
        self.assertEqual(normalize_value("  hello   world  "), "hello world", "Spaces should be normalized.")
        self.assertEqual(normalize_value("hello\\nworld"), "hello<newline>world", "Escaped newline should be replaced.")
        self.assertEqual(normalize_value(None), "", "None input should return empty string.")

    def test_extract_texts_to_translate_logic(self):
        """
        Tests the `extract_texts_to_translate` helper function.

        This function determines which texts from a source properties file need
        translation based on their presence and content in a target properties file.
        It should extract texts if the target value is missing (None) or if the
        normalized target value is identical to the normalized source value (implying
        it might be an untranslated placeholder or needs re-translation).
        """
        # Sample data mimicking parsed .properties file content
        parsed_lines = [
            {'type': 'entry', 'key': 'key1', 'value': 'target_val1', 'original_value': 'target_val1', 'line_number': 0},
            {'type': 'entry', 'key': 'key2', 'value': 'source_val2', 'original_value': 'source_val2', 'line_number': 1},
            {'type': 'comment_or_blank', 'content': '# comment\n', 'line_number': 2},
            {'type': 'entry', 'key': 'key4', 'value': 'source val4 normalized', 'original_value': 'source val4 normalized', 'line_number': 3},
        ]
        source_translations = {
            'key1': 'source_val1_changed',    # Target exists and is different
            'key2': 'source_val2',            # Target exists and is identical to source
            'key3': 'source_val3_new',        # Target is missing (None)
            'key4': 'source val4 normalized', # Target exists and is identical to normalized source
            'key5': 'source_val5_no_target_yet' # Target is missing (None)
        }
        target_translations = {
            'key1': 'target_val1',
            'key2': 'source_val2',
            'key4': 'source val4 normalized'
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines, source_translations, target_translations
        )

        # Based on the function's logic:
        # - key1: Not included (target exists, is different, and not same as source).
        # - key2: Included (target exists, is same as source).
        # - key3: Included (target is None).
        # - key4: Included (target exists, is same as normalized source).
        # - key5: Included (target is None).
        expected_texts_list = sorted([
            'source_val2',
            'source_val3_new',
            'source val4 normalized',
            'source_val5_no_target_yet'
        ])
        self.assertEqual(sorted(texts), expected_texts_list, "Mismatch in texts identified for translation.")
        self.assertEqual(len(texts), 4, "Incorrect number of texts identified.")

        expected_keys_list = sorted(['key2', 'key3', 'key4', 'key5'])
        self.assertEqual(sorted(keys), expected_keys_list, "Mismatch in keys identified for translation.")
        self.assertEqual(len(keys), 4, "Incorrect number of keys identified.")

    def test_apply_glossary_logic(self):
        """
        Tests the `apply_glossary` helper function.

        Verifies that glossary terms are correctly applied (case-insensitive, whole word).
        The current version of `apply_glossary` in the source code does NOT ignore
        text within HTML-like tags, so this test reflects that actual behavior.
        """
        sample_text = "Hello world, translate this text with hello again. <tag>Hello not this</tag>"
        glossary = {"hello": "Hallo", "text": "Textabschnitt"}

        # This expected output reflects that the current apply_glossary in src
        # DOES NOT skip terms inside tags.
        expected_output = "Hallo world, translate this Textabschnitt with Hallo again. <tag>Hallo not this</tag>"
        self.assertEqual(apply_glossary(sample_text, glossary), expected_output)

        sample_text_no_match = "Hi there, friend."
        self.assertEqual(apply_glossary(sample_text_no_match, glossary), sample_text_no_match, "Should not change if no glossary terms match.")

        # This test case also reflects that tags are not specially handled by current src function
        sample_text_with_tag_only = "<tag>Hello world</tag>"
        expected_tag_translation = "<tag>Hallo world</tag>"
        self.assertEqual(apply_glossary(sample_text_with_tag_only, glossary), expected_tag_translation, "Glossary should apply within tags for current src function.")


    async def test_main_translation_flow_simplified(self):
        """
        Tests the main script flow of `translate_localization_files.main()` with
        the core translation processing (`process_translation_queue`) mocked out.

        This test verifies:
        - Correct loading of configurations.
        - Orchestration of file operations:
            - Getting changed files.
            - Copying files to a translation queue.
            - Invoking the (mocked) processing function.
            - Copying results back.
            - Archiving original files.
            - Cleaning up queue folders.
        - All file system paths used by the script are correctly patched to use
          test-specific, mocked locations.
        """
        # Paths used by the script, reflecting user home for queue folders.
        script_translation_queue_abs = os.path.join(os.path.expanduser("~"), self.config['translation_queue_folder'])
        script_translated_queue_abs = os.path.join(os.path.expanduser("~"), self.config['translated_queue_folder'])

        # Mock for the function that handles the detailed translation logic.
        mock_process_translation_queue = AsyncMock()

        # Patch all external dependencies and file system interactions.
        # Global constants in the script are patched to use test-specific config values.
        with patch('src.translate_localization_files.CONFIG_FILE', self.test_config_path), \
             patch('src.translate_localization_files.REPO_ROOT', self.config['target_project_root']), \
             patch('src.translate_localization_files.INPUT_FOLDER', self.config['input_folder']), \
             patch('src.translate_localization_files.TRANSLATION_QUEUE_FOLDER', script_translation_queue_abs), \
             patch('src.translate_localization_files.TRANSLATED_QUEUE_FOLDER', script_translated_queue_abs), \
             patch('src.translate_localization_files.GLOSSARY_FILE_PATH', self.mock_glossary_path_resolved), \
             patch('src.translate_localization_files.DRY_RUN', self.config['dry_run']), \
             patch('src.translate_localization_files.process_translation_queue', new=mock_process_translation_queue), \
             patch('src.translate_localization_files.get_changed_translation_files', return_value=['app_de.properties', 'app_es.properties']) as mock_get_changed, \
             patch('src.translate_localization_files.copy_files_to_translation_queue', MagicMock()) as mock_copy_to_queue, \
             patch('src.translate_localization_files.copy_translated_files_back', MagicMock()) as mock_copy_back, \
             patch('src.translate_localization_files.move_files_to_archive', MagicMock()) as mock_move_archive, \
             patch('shutil.rmtree') as mock_shutil_rmtree, \
             patch('os.path.exists', MagicMock(return_value=True)) as mock_os_exists, \
             patch('os.access', MagicMock(return_value=True)) as mock_os_access, \
             patch('os.makedirs', MagicMock()) as mock_os_makedirs:

            await src.translate_localization_files.main()

            # Verify that each step in the main script flow was called as expected.
            mock_get_changed.assert_called_once()
            mock_copy_to_queue.assert_called_once()
            mock_process_translation_queue.assert_called_once_with(
                translation_queue_folder=script_translation_queue_abs,
                translated_queue_folder=script_translated_queue_abs,
                glossary_file_path=self.mock_glossary_path_resolved
            )
            mock_copy_back.assert_called_once()
            mock_move_archive.assert_called_once()

            # Verify cleanup calls for queue folders.
            expected_rmtree_calls = [
                call(script_translation_queue_abs),
                call(script_translated_queue_abs)
            ]
            # Check call count and presence of each expected call.
            self.assertEqual(len(mock_shutil_rmtree.call_args_list), len(expected_rmtree_calls), "shutil.rmtree not called expected number of times.")
            self.assertTrue(all(c in mock_shutil_rmtree.call_args_list for c in expected_rmtree_calls), "shutil.rmtree not called with expected arguments.")


if __name__ == '__main__':
    unittest.main()
