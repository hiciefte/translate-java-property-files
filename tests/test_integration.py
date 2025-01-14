# tests/test_integration.py

import asyncio
import os
import shutil
# Import the main module from the src directory
import sys
from unittest import mock
from unittest.mock import AsyncMock, patch

import pytest
from aiolimiter import AsyncLimiter

from src import translate_localization_files as translate_main

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def setup_test_environment(tmp_path):
    # Prepare test directories
    input_folder = tmp_path / "input"
    translation_queue_folder = tmp_path / "translation_queue"
    translated_queue_folder = tmp_path / "translated_queue"
    repo_root = tmp_path / "repo"
    os.makedirs(input_folder)
    os.makedirs(translation_queue_folder)
    os.makedirs(translated_queue_folder)
    os.makedirs(repo_root)

    # Copy test input files
    test_files_dir = os.path.join(os.path.dirname(__file__), 'fixtures', 'input_files')
    for filename in os.listdir(test_files_dir):
        shutil.copy(os.path.join(test_files_dir, filename), input_folder / filename)

    # Copy test glossaries
    test_glossaries_dir = os.path.join(os.path.dirname(__file__), 'fixtures', 'glossaries')
    for filename in os.listdir(test_glossaries_dir):
        shutil.copy(os.path.join(test_glossaries_dir, filename), translate_main.GLOSSARY_FILE_PATH)

    # Return paths
    return {
        "input_folder": str(input_folder),
        "translation_queue_folder": str(translation_queue_folder),
        "translated_queue_folder": str(translated_queue_folder),
        "repo_root": str(repo_root),
    }

@pytest.mark.asyncio
async def test_placeholder_handling(setup_test_environment):
    # Prepare a sample text with placeholders
    text = "This is a sample text with placeholders {0} and {1}."
    key = "sample.key"
    existing_translations = {}
    source_translations = {key: text}
    target_language = "German"
    glossary = {}
    index = 0

    # Mock the OpenAI API response
    with patch('translate_localization_files.client.chat.completions.create', new_callable=AsyncMock) as mock_create:
        mock_response = AsyncMock()
        mock_response.choices = [
            mock.Mock(message=mock.Mock(content="Dies ist ein Beispieltext mit Platzhaltern __PH_1__ und __PH_2__."))]
        mock_create.return_value = mock_response

        # Call the translate_text_async function
        result_index, translated_text = await translate_main.translate_text_async(
            text,
            key,
            existing_translations,
            source_translations,
            target_language,
            glossary,
            asyncio.Semaphore(1),
            AsyncLimiter(1, 1),
            index
        )

        # Restore placeholders
        placeholder_mapping = {
            "__PH_1__": "{0}",
            "__PH_2__": "{1}"
        }
        translated_text = translate_main.restore_placeholders(translated_text, placeholder_mapping)

        # Check that placeholders are correctly restored
        assert "{0}" in translated_text
        assert "{1}" in translated_text
        assert "__PH_" not in translated_text


@pytest.mark.asyncio
async def test_glossary_application(setup_test_environment):
    # Prepare a sample text and glossary
    text = "Trade Bitcoin easily."
    key = "trade.key"
    existing_translations = {}
    source_translations = {key: text}
    target_language = "Spanish"
    glossary = {
        "es": {
            "Bitcoin": "Bitcoin",
            "Trade": "Comerciar"
        }
    }
    index = 0

    # Mock the OpenAI API response
    with patch('translate_localization_files.client.chat.completions.create', new_callable=AsyncMock) as mock_create:
        mock_response = AsyncMock()
        mock_response.choices = [mock.Mock(message=mock.Mock(content="Intercambia __PH_bitcoin__ fácilmente."))]
        mock_create.return_value = mock_response

        # Call the translate_text_async function
        result_index, translated_text = await translate_main.translate_text_async(
            text,
            key,
            existing_translations,
            source_translations,
            target_language,
            glossary,
            asyncio.Semaphore(1),
            AsyncLimiter(1, 1),
            index
        )

        # Restore placeholders
        placeholder_mapping = {
            "__PH_bitcoin__": "Bitcoin"
        }
        translated_text = translate_main.restore_placeholders(translated_text, placeholder_mapping)

        # Apply glossary
        translated_text = translate_main.apply_glossary(translated_text, glossary.get("es", {}))

        # Check that glossary terms are applied
        assert "Comerciar Bitcoin fácilmente." == translated_text


@pytest.mark.asyncio
async def test_api_error_handling(setup_test_environment):
    # Prepare a sample text
    text = "Sample text."
    key = "sample.key"
    existing_translations = {}
    source_translations = {key: text}
    target_language = "French"
    glossary = {}
    index = 0

    # Mock the OpenAI API to raise an error on the first call
    with patch('translate_localization_files.client.chat.completions.create', new_callable=AsyncMock) as mock_create:
        mock_create.side_effect = [
            Exception("API Error"),
            AsyncMock(choices=[mock.Mock(message=mock.Mock(content="Texte d'exemple."))])
        ]

        # Call the translate_text_async function
        result_index, translated_text = await translate_main.translate_text_async(
            text,
            key,
            existing_translations,
            source_translations,
            target_language,
            glossary,
            asyncio.Semaphore(1),
            AsyncLimiter(1, 1),
            index
        )

        # Check that the translation was eventually successful
        assert translated_text == "Texte d'exemple."
