import os
import shutil
import unittest
from unittest.mock import patch, MagicMock, AsyncMock, mock_open

# Set a dummy API key before importing the main script to prevent SystemExit.
os.environ['OPENAI_API_KEY'] = 'DUMMY_KEY_FOR_TESTING'

from src.properties_parser import reassemble_file


class TestQuoteEscaping(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.test_dir = "temp_test_quote_escaping"
        self.queue_dir = os.path.join(self.test_dir, "queue")
        self.translated_dir = os.path.join(self.test_dir, "translated")
        os.makedirs(self.queue_dir, exist_ok=True)
        os.makedirs(self.translated_dir, exist_ok=True)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @patch('os.path.exists', return_value=True)
    @patch('src.translate_localization_files.holistic_review_async')
    @patch('src.translate_localization_files.run_pre_translation_validation', new_callable=AsyncMock)
    @patch('src.translate_localization_files.load_source_properties_file')
    @patch('src.translate_localization_files.parse_properties_file')
    @patch('src.translate_localization_files.client.chat.completions.create')
    async def test_single_quotes_are_escaped(self, mock_create, mock_parse_properties, mock_load_source, mock_validator, mock_holistic_review, mock_exists):
        from src.translate_localization_files import process_translation_queue, LANGUAGE_CODES, NAME_TO_CODE, INPUT_FOLDER
        
        # Configure the async mocks
        mock_validator.return_value = True
        mock_holistic_review.return_value = None

        # 1. Mock the file system interactions
        mock_load_source.return_value = {"test.key": "This has a {0} placeholder."}
        mock_parse_properties.return_value = (
            [{'type': 'entry', 'key': 'test.key', 'value': 'This has a {0} placeholder.', 'original_value': '...'}],
            {"test.key": "This has a {0} placeholder."}
        )

        # 2. Mock the AI response for the initial translation
        async def mock_ai_response(*args, **kwargs):
            response_text = "Dies ist ein 'Beispiel'."
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content=response_text))]
            return mock_response
        mock_create.side_effect = mock_ai_response

        # 3. Create the dummy files the function needs to find
        source_file_path = os.path.join(self.test_dir, 'app.properties')
        with open(source_file_path, 'w', encoding='utf-8') as f:
            f.write("test.key=This has a {0} placeholder.")
            
        target_file_path = os.path.join(self.queue_dir, 'app_de.properties')
        with open(target_file_path, 'w', encoding='utf-8') as f:
            f.write("test.key=This has a {0} placeholder.")

        # 4. Run the process, patching globals that are still read directly
        with patch.dict(LANGUAGE_CODES, {"de": "German"}), \
             patch.dict(NAME_TO_CODE, {"german": "de"}), \
             patch('src.translate_localization_files.INPUT_FOLDER', self.test_dir):
             await process_translation_queue(
                translation_queue_folder=self.queue_dir,
                translated_queue_folder=self.translated_dir,
                glossary_file_path="" # Not needed for this test
            )

        # 5. Assert the output
        output_file_path = os.path.join(self.translated_dir, 'app_de.properties')
        self.assertTrue(os.path.exists(output_file_path))

        with open(output_file_path, 'r', encoding='utf-8') as f:
            output_content = f.read().strip()
        
        self.assertEqual(output_content, "test.key=Dies ist ein ''Beispiel''.")

    def test_reassemble_with_single_quotes(self):
        # This test only needs reassemble_file, no circular import.
        parsed_lines = [
            {'type': 'entry', 'key': 'key.one', 'value': "This is a value with 'quotes'", 'original_value': "This is a value with 'quotes'", 'line_number': 0}
        ]
        content = reassemble_file(parsed_lines)
        self.assertEqual(content, "key.one=This is a value with 'quotes'\n")
