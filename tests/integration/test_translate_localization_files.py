"""
Integration tests for the `translate_localization_files.py` script.

This test suite focuses on testing the overall workflow of the script by mocking
external dependencies and file system operations, and also includes unit-like tests
for specific helper functions within the script.
"""
import logging
import os
import shutil
import unittest
from unittest.mock import patch, MagicMock, AsyncMock, call
import re

import yaml

# Set a dummy API key before importing the main script to prevent SystemExit.
os.environ['OPENAI_API_KEY'] = 'DUMMY_KEY_FOR_TESTING'

# Assuming src.translate_localization_files will be importable.
# The try-except block allows the tests to be run from the project root (e.g., make test)
# or directly if the PYTHONPATH is configured.
try:
    import src.translate_localization_files
    from src.translate_localization_files import extract_texts_to_translate, normalize_value
except ModuleNotFoundError:
    import sys
    # This assumes tests are run from a location where '../../' is the project root.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
    import src.translate_localization_files
    from src.translate_localization_files import extract_texts_to_translate, normalize_value


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

        with open(self.test_config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)

        # Create a temporary input folder for the source files
        self.test_input_folder = os.path.join(self.test_dir, 'temp_input')
        os.makedirs(self.test_input_folder, exist_ok=True)

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

        # Create a sample source file for end-to-end test
        self.source_file_path = os.path.join(self.test_dir, 'sample_app_en.properties')
        if not os.path.exists(self.source_file_path):
            with open(self.source_file_path, 'w', encoding='utf-8') as f:
                f.write("app.name=My App\n")
                f.write("dialog.title=Hello World\n")
                f.write("error.message=An error has occurred.\n")

        # logging.disable(logging.CRITICAL)

    def tearDown(self):
        """
        Clean up the test environment after each test.
        """
        if os.path.exists(self.test_translation_queue_folder):
            shutil.rmtree(self.test_translation_queue_folder)
        if os.path.exists(self.test_translated_queue_folder):
            shutil.rmtree(self.test_translated_queue_folder)
        if os.path.exists(self.test_input_folder):
            shutil.rmtree(self.test_input_folder)
        if os.path.exists(self.source_file_path):
            os.remove(self.source_file_path)
        logging.disable(logging.NOTSET)

    async def test_process_translation_queue_end_to_end(self):
        """
        Tests the end-to-end processing of a single file through process_translation_queue.
        This test mocks the OpenAI API call but executes all other file IO and processing logic.
        """
        # 1. Setup the source 'en' file (e.g., app.properties) that the script needs for comparison.
        #    The script derives the source filename by removing the language code from the target file.
        source_file_content = (
            "app.name=My App\n"
            "dialog.title=Hello World\n"
            "error.message=An <b>error</b> has occurred.\\nOn a new line."
        )
        source_file_path = os.path.join(self.test_input_folder, 'app.properties')
        with open(source_file_path, 'w', encoding='utf-8') as f:
            f.write(source_file_content)

        # 2. Setup the target 'de' file in the queue with outdated or different values
        test_file_content = (
            "# This is a comment\n"
            "app.name=My App\n"
            "dialog.title=Hello World\n"
        )
        test_file_path = os.path.join(self.test_translation_queue_folder, 'app_de.properties')
        with open(test_file_path, 'w', encoding='utf-8') as f:
            f.write(test_file_content)

        # 3. Mock the AI's response
        async def mock_create(*args, **kwargs):
            user_content = kwargs['messages'][1]['content']
    
            # Use a robust, non-greedy regex to extract the value between 'Value:' and the next instruction.
            # This is more reliable than capturing everything and then splitting.
            match = re.search(r"Value:\s*(.*?)\s*Provide the translation", user_content, re.DOTALL)
            key_for_lookup_raw = ""
            if match:
                key_for_lookup_raw = match.group(1).strip()

            # The value from the prompt has had placeholders (__PH_...) applied by the script.
            # We must simulate the key generation that the test expects for the lookup table.
            key_for_lookup = re.sub(r'__PH_.*?__', 'PLACEHOLDER', key_for_lookup_raw)
    
            mock_lookup = {
                "My App": "Meine App",
                "Hello World": "Hallo Welt",
                "An PLACEHOLDERerrorPLACEHOLDER has occurred.\\nOn a new line.": "Ein <b>error</b> ist aufgetreten.\\nAuf einer neuen Zeile."
            }
            
            response_text = mock_lookup.get(key_for_lookup, "Untranslated")

            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content=response_text))]
            return mock_response

        # Define mock language codes to be patched into the script,
        # ensuring the script can identify the language from the filename.
        mock_language_codes = {
            "de": "German",
            "es": "Spanish",
            "pt_BR": "Brazilian Portuguese"
        }

        # 4. Run the function under test, ensuring DRY_RUN is False
        with patch('src.translate_localization_files.client.chat.completions.create', new=mock_create), \
             patch('src.translate_localization_files.INPUT_FOLDER', self.test_input_folder), \
             patch('src.translate_localization_files.LANGUAGE_CODES', mock_language_codes), \
             patch('src.translate_localization_files.DRY_RUN', False):
            await src.translate_localization_files.process_translation_queue(
                translation_queue_folder=self.test_translation_queue_folder,
                translated_queue_folder=self.test_translated_queue_folder,
                glossary_file_path=self.mock_glossary_path_resolved
            )

        # 5. Assert the results
        output_file_path = os.path.join(self.test_translated_queue_folder, 'app_de.properties')
        self.assertTrue(os.path.exists(output_file_path), "Translated file was not created.")

        with open(output_file_path, 'r', encoding='utf-8') as f:
            output_content = f.read()

        expected_output_content = (
            "# This is a comment\n"
            "app.name=Meine App\n"
            "dialog.title=Hallo Welt\n"
            "error.message=Ein <b>error</b> ist aufgetreten.\\nAuf einer neuen Zeile.\n"
        )
        self.assertEqual(output_content, expected_output_content)

    async def test_main_translation_flow_simplified(self):
        """
        Tests the main script flow of `translate_localization_files.main()` with
        the core translation processing (`process_translation_queue`) mocked out.
        """
        script_translation_queue_abs = os.path.join(os.path.expanduser("~"), self.config['translation_queue_folder'])
        script_translated_queue_abs = os.path.join(os.path.expanduser("~"), self.config['translated_queue_folder'])
        mock_process_translation_queue = AsyncMock()

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
             patch('os.path.exists', MagicMock(return_value=True)), \
             patch('os.access', MagicMock(return_value=True)), \
             patch('os.makedirs', MagicMock()):

            await src.translate_localization_files.main()

            mock_get_changed.assert_called_once()
            mock_copy_to_queue.assert_called_once()
            mock_process_translation_queue.assert_called_once_with(
                translation_queue_folder=script_translation_queue_abs,
                translated_queue_folder=script_translated_queue_abs,
                glossary_file_path=self.mock_glossary_path_resolved
            )
            mock_copy_back.assert_called_once()
            mock_move_archive.assert_called_once()

            expected_rmtree_calls = [
                call(script_translation_queue_abs),
                call(script_translated_queue_abs)
            ]
            self.assertEqual(len(mock_shutil_rmtree.call_args_list), len(expected_rmtree_calls), "shutil.rmtree not called expected number of times.")
            self.assertTrue(all(c in mock_shutil_rmtree.call_args_list for c in expected_rmtree_calls), "shutil.rmtree not called with expected arguments.")


if __name__ == '__main__':
    unittest.main()
