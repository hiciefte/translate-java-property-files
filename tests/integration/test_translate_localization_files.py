"""
Integration tests for the `translate_localization_files.py` script.

This test suite focuses on testing the overall workflow of the script by mocking
external dependencies and file system operations, and also includes unit-like tests
for specific helper functions within the script.
"""
import os
from unittest.mock import patch, MagicMock
import pytest
import src.translate_localization_files

# All fixtures are now defined in conftest.py and are auto-discovered by pytest.

@pytest.mark.asyncio
@patch('src.translate_localization_files.get_changed_translation_files')
@patch('src.translate_localization_files.copy_files_to_translation_queue')
@patch('src.translate_localization_files.process_translation_queue')
@patch('src.translate_localization_files.copy_translated_files_back')
@patch('src.translate_localization_files.move_files_to_archive')
async def test_main_flow_no_changes(mock_move, mock_copy_back, mock_process, mock_copy_to_queue, mock_get_changed, integration_test_environment):
    mock_get_changed.return_value = []
    await src.translate_localization_files.main()
    mock_get_changed.assert_called_once_with(
        src.translate_localization_files.INPUT_FOLDER,
        src.translate_localization_files.REPO_ROOT,
        process_all_files=src.translate_localization_files.PROCESS_ALL_FILES
    )
    mock_copy_to_queue.assert_not_called()
    mock_process.assert_not_called()
    mock_copy_back.assert_not_called()
    mock_move.assert_not_called()

@pytest.mark.asyncio
async def test_process_translation_queue_end_to_end(integration_test_environment):
    env = integration_test_environment
    source_content = "key.one=value one\nkey.two=value two"
    target_content = "key.one=Wert eins"  # This key is already translated
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write(source_content)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write(target_content)

    async def mock_create(*args, **kwargs):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Wert zwei"))]
        return mock_response

    with patch('src.translate_localization_files.client.chat.completions.create', new=mock_create):
        await src.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'app_de.properties')
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_content = f.read()
        assert "key.two=Wert zwei" in final_content
        assert "key.one=Wert eins" in final_content
        assert len(final_content.strip().split('\n')) == 2

@pytest.mark.asyncio
async def test_handles_already_escaped_quotes_correctly(integration_test_environment):
    env = integration_test_environment
    source_content = "key.name=URL is ''{0}''"
    target_content = ""

    source_en_path = os.path.join(env['input_folder'], 'app.properties')
    target_de_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')

    with open(source_en_path, 'w', encoding='utf-8') as f:
        f.write(source_content)
    with open(target_de_path, 'w', encoding='utf-8') as f:
        f.write(target_content)

    async def mock_create(*args, **kwargs):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="URL ist '{0}'"))]
        return mock_response

    with patch('src.translate_localization_files.lint_properties_file', return_value=[]), \
         patch('src.translate_localization_files.client.chat.completions.create', new=mock_create):
        await src.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'app_de.properties')
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_content = f.read().strip()
        expected_content = "key.name=URL ist ''{0}''"
        assert final_content == expected_content
        assert "''''" not in final_content
