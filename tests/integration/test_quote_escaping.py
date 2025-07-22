import os
import shutil
import unittest
from unittest.mock import patch, MagicMock

# Set a dummy API key before importing the main script to prevent SystemExit.
os.environ['OPENAI_API_KEY'] = 'DUMMY_KEY_FOR_TESTING'

from src.translate_localization_files import process_translation_queue


class TestQuoteEscaping(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.test_dir = os.path.dirname(__file__)
        self.project_root = os.path.abspath(os.path.join(self.test_dir, '../..'))
        self.test_input_folder = os.path.join(self.test_dir, 'temp_input_quotes')
        self.test_translation_queue_folder = os.path.join(self.project_root, 'translation_queue_quotes_test')
        self.test_translated_queue_folder = os.path.join(self.project_root, 'translated_queue_quotes_test')
        self.mock_glossary_path = os.path.join(self.test_dir, 'mock_glossary.json')

        os.makedirs(self.test_input_folder, exist_ok=True)
        os.makedirs(self.test_translation_queue_folder, exist_ok=True)
        os.makedirs(self.test_translated_queue_folder, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_input_folder)
        shutil.rmtree(self.test_translation_queue_folder)
        shutil.rmtree(self.test_translated_queue_folder)

    async def test_single_quotes_are_escaped_in_values_with_placeholders(self):
        """
        Validates that if a translated value contains a single quote and its
        corresponding key's original value had a placeholder (e.g., {0}),
        the single quote is properly escaped to a double quote ('').
        """
        # 1. Setup source file with a placeholder
        source_content = "test.key=This is a value with a {0} placeholder."
        source_file_path = os.path.join(self.test_input_folder, 'app.properties')
        with open(source_file_path, 'w', encoding='utf-8') as f:
            f.write(source_content)

        # 2. Setup target file in the queue
        target_content = "test.key=This is a value with a {0} placeholder."
        target_file_path = os.path.join(self.test_translation_queue_folder, 'app_de.properties')
        with open(target_file_path, 'w', encoding='utf-8') as f:
            f.write(target_content)

        # 3. Mock the AI response to return a translation with a single quote
        async def mock_create(*args, **kwargs):
            # This mock simulates the AI returning a German translation that *incorrectly* uses a single quote.
            response_text = "Dies ist ein Wert mit einem 'Beispiel' Platzhalter."
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content=response_text))]
            return mock_response

        mock_language_codes = {"de": "German"}
        mock_name_to_code = {"german": "de"}

        # 4. Run the process
        with patch('src.translate_localization_files.client.chat.completions.create', new=mock_create), \
                patch('src.translate_localization_files.INPUT_FOLDER', self.test_input_folder), \
                patch('src.translate_localization_files.LANGUAGE_CODES', mock_language_codes), \
                patch('src.translate_localization_files.NAME_TO_CODE', mock_name_to_code), \
                patch('src.translate_localization_files.DRY_RUN', False):
            await process_translation_queue(
                translation_queue_folder=self.test_translation_queue_folder,
                translated_queue_folder=self.test_translated_queue_folder,
                glossary_file_path=self.mock_glossary_path
            )

        # 5. Assert the output
        output_file_path = os.path.join(self.test_translated_queue_folder, 'app_de.properties')
        self.assertTrue(os.path.exists(output_file_path))

        with open(output_file_path, 'r', encoding='utf-8') as f:
            output_content = f.read().strip()

        # The test asserts that the single quote has been correctly doubled.
        # This test will FAIL with the current code because we are mocking the AI
        # to NOT do the escaping.
        expected_content = "test.key=Dies ist ein Wert mit einem ''Beispiel'' Platzhalter."
        self.assertEqual(output_content, expected_content)
