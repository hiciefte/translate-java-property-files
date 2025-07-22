import json
import logging
import os
import shutil
from unittest.mock import patch

import pytest


@pytest.fixture(scope="session")
def integration_test_paths():
    """Session-scoped fixture to define the absolute paths for test directories."""
    tests_root = os.path.dirname(os.path.abspath(__file__))
    # Place temp dirs in the root of the tests folder for simplicity
    input_dir = os.path.join(tests_root, 'temp_integration_input')
    translation_queue_dir = os.path.join(tests_root, 'temp_integration_translation_queue')
    translated_queue_dir = os.path.join(tests_root, 'temp_integration_translated_queue')
    mock_glossary_path = os.path.join(tests_root, 'temp_mock_glossary.json')

    return {
        "input_folder": input_dir,
        "translation_queue_folder": translation_queue_dir,
        "translated_queue_folder": translated_queue_dir,
        "mock_glossary_path": mock_glossary_path
    }


@pytest.fixture(scope="session", autouse=True)
def setup_global_test_environment(integration_test_paths):
    """
    Session-scoped, autouse fixture to create directories and patch globals.
    This runs once for the entire test session.
    """
    paths = integration_test_paths

    # Create directories once
    for folder in [paths['input_folder'], paths['translation_queue_folder'], paths['translated_queue_folder']]:
        os.makedirs(folder, exist_ok=True)

    patches = [
        patch('src.translate_localization_files.INPUT_FOLDER', paths['input_folder']),
        patch('src.translate_localization_files.TRANSLATION_QUEUE_FOLDER', paths['translation_queue_folder']),
        patch('src.translate_localization_files.TRANSLATED_QUEUE_FOLDER', paths['translated_queue_folder']),
        patch('src.translate_localization_files.DRY_RUN', False)
    ]
    started_patches = []
    try:
        for p in patches:
            try:
                p.start()
                started_patches.append(p)
            except Exception as e:
                logging.error(f"Failed to start patch: {e}")
                raise

        yield  # Run all tests

    finally:
        for p in reversed(started_patches):
            try:
                p.stop()
            except Exception as e:
                logging.error(f"Failed to stop patch: {e}")

    # Clean up directories once after all tests are done
    for folder in [paths['input_folder'], paths['translation_queue_folder'], paths['translated_queue_folder']]:
        if os.path.exists(folder):
            try:
                shutil.rmtree(folder)
            except Exception as e:
                logging.error(f"Failed to delete directory {folder}. Reason: {e}")


@pytest.fixture
def integration_test_environment(integration_test_paths):
    """
    Function-scoped fixture to clean directories and create mock files for each test.
    """
    paths = integration_test_paths

    # Clean directories before each test
    for folder in [paths['input_folder'], paths['translation_queue_folder'], paths['translated_queue_folder']]:
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}. Reason: {e}")

    # Create mock glossary for each test
    glossary_content = {"de": {"Hello": "Hallo"}}
    with open(paths['mock_glossary_path'], 'w', encoding='utf-8') as f:
        json.dump(glossary_content, f, ensure_ascii=False, indent=2)

    yield {
        "input_folder": paths['input_folder'],
        "translation_queue_folder": paths['translation_queue_folder'],
        "translated_queue_folder": paths['translated_queue_folder'],
        "mock_glossary_path_resolved": paths['mock_glossary_path']
    }

    # Teardown after each test
    if os.path.exists(paths['mock_glossary_path']):
        os.remove(paths['mock_glossary_path'])
