"""
Integration tests for the `translate_localization_files.py` script.

This test suite focuses on testing the overall workflow of the script by mocking
external dependencies and file system operations, and also includes unit-like tests
for specific helper functions within the script.
"""
import os
import json
from unittest.mock import AsyncMock, patch, MagicMock
from types import SimpleNamespace
import pytest
import localize.translate_localization_files
from localize.ignore_keys import compile_ignore_key_patterns
from localize.localization_formats import JSON_FORMAT, JAVA_PROPERTIES_FORMAT
from localize.localization_layouts import LocalizationLayout
from localize.localization_profiles import LocalizationProfile
from localize.properties_parser import parse_properties_file
from localize.translation_memory import (
    TranslationMemory,
    load_translation_memory,
    save_translation_memory,
)

# All fixtures are now defined in conftest.py and are auto-discovered by pytest.

@pytest.mark.asyncio
@patch('localize.translate_localization_files.get_changed_translation_files')
@patch('localize.translate_localization_files.copy_files_to_translation_queue')
@patch('localize.translate_localization_files.process_translation_queue')
@patch('localize.translate_localization_files.copy_translated_files_back')
async def test_main_flow_no_changes(mock_copy_back, mock_process, mock_copy_to_queue, mock_get_changed, integration_test_environment):
    mock_get_changed.return_value = []
    await localize.translate_localization_files.main()
    mock_get_changed.assert_called_once_with(
        localize.translate_localization_files.INPUT_FOLDER,
        localize.translate_localization_files.REPO_ROOT,
        process_all_files=localize.translate_localization_files.PROCESS_ALL_FILES
    )
    mock_copy_to_queue.assert_not_called()
    mock_process.assert_not_called()
    mock_copy_back.assert_not_called()


@pytest.mark.asyncio
async def test_main_translates_json_from_detection_to_copyback(integration_test_environment):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.json')
    target_file_path = os.path.join(env['input_folder'], 'app_de.json')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        json.dump({"hello": "Hello", "nested": {"title": "Title {0}"}}, f, ensure_ascii=False, indent=2)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        json.dump({"hello": "Hallo"}, f, ensure_ascii=False, indent=2)

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(side_effect=[
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="Titel {0}"))]),
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content=json.dumps({"/nested/title": "Titel {0}"})
        ))]),
    ])
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    profiles = (
        LocalizationProfile(JSON_FORMAT, LocalizationLayout(id="suffix", source_locale="en")),
    )
    with patch('localize.translate_localization_files.get_changed_translation_files',
               return_value=['app_de.json']), \
         patch('localize.translate_localization_files.LOCALIZATION_FORMAT', JSON_FORMAT), \
         patch('localize.translate_localization_files.LOCALIZATION_PROFILES', profiles), \
         patch('localize.translate_localization_files.LANGUAGE_CODES', {'de': 'German'}), \
         patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.PRESERVE_QUEUES_FOR_DEBUG', True), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()):
        await localize.translate_localization_files.main()

    with open(target_file_path, 'r', encoding='utf-8') as f:
        final_payload = json.load(f)

    assert final_payload == {
        "hello": "Hallo",
        "nested": {"title": "Titel {0}"},
    }


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

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Wert zwei"))]
    ))
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider):
        await localize.translate_localization_files.process_translation_queue(
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
async def test_process_translation_queue_reuses_translation_memory_without_model_calls(integration_test_environment):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    memory_path = os.path.join(env['input_folder'], 'translation_memory.json')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write("key.one=value one\nkey.two=value two\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write("key.one=Wert eins\n")

    memory = TranslationMemory()
    memory.record("value two", "Wert zwei", locale="de", format_id="java_properties")
    save_translation_memory(memory_path, memory)

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock()
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_MEMORY_ENABLED', True), \
         patch('localize.translate_localization_files.TRANSLATION_MEMORY_FILE_PATH', memory_path), \
         patch('localize.translate_localization_files.SEMANTIC_REVIEW_ENABLED', True), \
         patch(
             'localize.translate_localization_files.SEMANTIC_REVIEW_MODEL_NAME',
             'gpt-5.4-mini',
         ), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review:
        review.return_value = {}
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'app_de.properties')
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_content = f.read()

    assert "key.one=Wert eins" in final_content
    assert "key.two=Wert zwei" in final_content
    provider.create_chat_completion.assert_not_called()
    review.assert_awaited_once()
    provider.estimate_run_cost.assert_called_once_with(
        num_keys=0,
        locale_codes=["de"],
        translate_model=localize.translate_localization_files.MODEL_NAME,
        review_model=localize.translate_localization_files.REVIEW_MODEL_NAME,
        review_num_keys=1,
        semantic_review_model="gpt-5.4-mini",
        semantic_review_num_keys=1,
    )


@pytest.mark.asyncio
async def test_process_translation_queue_does_not_seed_memory_for_noop_file(integration_test_environment):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    memory_path = os.path.join(env['input_folder'], 'translation_memory.json')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write("key.one=value one\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write("key.one=Wert eins\n")

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock()
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_MEMORY_ENABLED', True), \
         patch('localize.translate_localization_files.TRANSLATION_MEMORY_FILE_PATH', memory_path), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()):
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    assert not os.path.exists(memory_path)
    provider.create_chat_completion.assert_not_called()


@pytest.mark.asyncio
async def test_process_translation_queue_ignores_out_of_scope_review_keys(integration_test_environment):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write("key.keep=Keep\nkey.new=New\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write("key.keep=Alt\n")

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Neu draft"))]
    ))
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review:
        review.return_value = {"key.new": "Neu", "key.keep": "Nicht anwenden"}
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'app_de.properties')
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_content = f.read()

    assert "key.keep=Alt" in final_content
    assert "key.keep=Nicht anwenden" not in final_content
    assert "key.new=Neu" in final_content


@pytest.mark.asyncio
async def test_holistic_review_receives_read_only_out_of_chunk_sibling_context(
    integration_test_environment,
):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write(
            "account.security.title=Security\n"
            "account.security.reset=Reset password\n"
            "account.security.rotate=Rotate password\n"
            "unrelated.title=Unrelated\n"
        )
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write(
            "account.security.title=Sicherheit\n"
            "unrelated.title=Nicht verwandt\n"
        )

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(side_effect=[
        SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content="Passwort zuruecksetzen")
        )]),
        SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content="Passwort rotieren")
        )]),
    ])
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.HOLISTIC_REVIEW_CHUNK_SIZE', 1), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review:
        review.return_value = {}
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved'],
        )

    assert review.await_count == 2
    review_calls = {
        call.kwargs["keys_to_review"][0]: call.kwargs
        for call in review.await_args_list
    }
    assert set(review_calls) == {
        "account.security.reset",
        "account.security.rotate",
    }
    for reviewed_key, review_call in review_calls.items():
        other_fresh_key = (
            "account.security.rotate"
            if reviewed_key == "account.security.reset"
            else "account.security.reset"
        )
        assert f"{reviewed_key}=" in review_call["source_content"]
        assert f"{other_fresh_key}=" not in review_call["source_content"]
        assert f"{other_fresh_key}=" not in review_call["translated_content"]
        assert "account.security.title=Security" in review_call["source_content"]
        assert "account.security.title=Sicherheit" in review_call["translated_content"]
        assert "unrelated.title" not in review_call["source_content"]
        assert "unrelated.title" not in review_call["translated_content"]


@pytest.mark.asyncio
async def test_failed_model_translation_marks_ledger_and_skips_memory(integration_test_environment):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    ledger_path = os.path.join(env['input_folder'], 'ledger.json')
    memory_path = os.path.join(env['input_folder'], 'translation_memory.json')
    validation_summary = {}

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write("key.fail=Needs translation\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write("")

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(side_effect=RuntimeError("rate limited"))
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = True

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_MEMORY_ENABLED', True), \
         patch('localize.translate_localization_files.TRANSLATION_MEMORY_FILE_PATH', memory_path), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH', ledger_path), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files._handle_retry', new_callable=AsyncMock) as retry, \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review:
        retry.return_value = False
        review.return_value = None
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved'],
            validation_summary=validation_summary,
        )

    ledger = localize.translate_localization_files.load_translation_key_ledger(ledger_path)
    assert ledger["app_de.properties"]["key.fail"]["status"] == "failed"
    assert validation_summary["app_de.properties"]["model_translation_failed_count"] == 1
    assert validation_summary["app_de.properties"]["model_translation_failed_keys"] == ["key.fail"]

    memory = load_translation_memory(memory_path)
    assert memory.lookup(
        "Needs translation",
        locale="de",
        format_id=JAVA_PROPERTIES_FORMAT.id,
    ) is None

    output_file_path = os.path.join(env['translated_queue_folder'], 'app_de.properties')
    parsed_lines, target_translations = parse_properties_file(output_file_path)
    texts, _indices, keys = localize.translate_localization_files.extract_texts_to_translate(
        parsed_lines,
        {"key.fail": "Needs translation"},
        target_translations,
        file_ledger_entries=ledger["app_de.properties"],
    )
    assert keys == ["key.fail"]
    assert texts == ["Needs translation"]


@pytest.mark.asyncio
async def test_failed_model_translation_preserves_ledger_verified_target(
    integration_test_environment,
):
    env = integration_test_environment
    source_value = "Open trade chat"
    existing_value = "Чат сделки"
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    ledger_path = os.path.join(env['input_folder'], 'ledger.json')
    validation_summary = {}

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write(f"key.chat={source_value}\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write(f"key.chat={existing_value}\n")
    with open(ledger_path, 'w', encoding='utf-8') as f:
        json.dump(
            {
                "version": 1,
                "files": {
                    "app_de.properties": {
                        "key.chat": {
                            "source_hash": (
                                localize.translate_localization_files.compute_ledger_hash(
                                    source_value
                                )
                            ),
                            "target_hash": (
                                localize.translate_localization_files.compute_ledger_hash(
                                    existing_value
                                )
                            ),
                            "status": "failed",
                        }
                    }
                },
            },
            f,
        )

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(
        side_effect=RuntimeError("rate limited")
    )
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = True

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH', ledger_path), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files._handle_retry', new_callable=AsyncMock) as retry, \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review:
        retry.return_value = False
        review.return_value = None
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved'],
            validation_summary=validation_summary,
        )

    output_file_path = os.path.join(
        env['translated_queue_folder'], 'app_de.properties'
    )
    parsed_lines, target_translations = parse_properties_file(output_file_path)
    assert target_translations["key.chat"] == existing_value
    assert validation_summary["app_de.properties"][
        "model_translation_failed_keys"
    ] == ["key.chat"]
    ledger = localize.translate_localization_files.load_translation_key_ledger(
        ledger_path
    )
    assert ledger["app_de.properties"]["key.chat"]["status"] == "failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "previous_source,existing_value,expected_value",
    [
        ("Open {0}", "Öffnen {0}", "Öffnen {0}"),
        ("Close {0}", "Schließen {0}", "Open {0}"),
        ("Open {0}", "Öffnen {1}", "Open {0}"),
    ],
)
async def test_source_echo_preserves_only_valid_current_source_baseline(
    integration_test_environment, previous_source, existing_value, expected_value,
):
    """Echoes stay failed; only fresh, placeholder-safe old text reaches output."""
    env = integration_test_environment
    pipeline = localize.translate_localization_files
    source_value = "Open {0}"
    source_path = os.path.join(env['input_folder'], 'app.properties')
    target_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    ledger_path = os.path.join(env['input_folder'], 'echo-ledger.json')
    memory_path = os.path.join(env['input_folder'], 'echo-memory.json')
    with open(source_path, 'w', encoding='utf-8') as stream:
        stream.write(f"key.open={source_value}\n")
    with open(target_path, 'w', encoding='utf-8') as stream:
        stream.write(f"key.open={existing_value}\n")
    pipeline.save_translation_key_ledger(ledger_path, {
        "app_de.properties": pipeline.build_file_key_ledger(
            {"key.open": previous_source}, {"key.open": existing_value},
            failed_keys={"key.open"},
        ),
    })
    summary = {}
    with patch.object(pipeline, 'TRANSLATION_KEY_LEDGER_FILE_PATH', ledger_path), \
         patch.object(pipeline, 'TRANSLATION_MEMORY_ENABLED', True), \
         patch.object(pipeline, 'TRANSLATION_MEMORY_FILE_PATH', memory_path), \
         patch.object(pipeline, 'get_working_tree_changed_keys', return_value=set()), \
         patch.object(pipeline, 'translate_text_async', new_callable=AsyncMock) as translate, \
         patch.object(pipeline, 'holistic_review_async', new_callable=AsyncMock) as review:
        translate.return_value = (0, source_value, True)
        review.return_value = {"key.open": source_value}
        await pipeline.process_translation_queue(
            env['translation_queue_folder'], env['translated_queue_folder'],
            env['mock_glossary_path_resolved'], validation_summary=summary,
        )
    _, output = parse_properties_file(os.path.join(
        env['translated_queue_folder'], 'app_de.properties'
    ))
    assert output["key.open"] == expected_value
    assert summary["app_de.properties"]["source_identical_keys"] == ["key.open"]
    assert summary["app_de.properties"]["reverted_keys_count"] == 1
    ledger = pipeline.load_translation_key_ledger(ledger_path)
    assert ledger["app_de.properties"]["key.open"]["status"] == "failed"
    memory = load_translation_memory(memory_path)
    assert memory.lookup(
        source_value, locale="de", format_id=JAVA_PROPERTIES_FORMAT.id,
    ) is None


@pytest.mark.asyncio
async def test_failed_holistic_review_marks_keys_failed(integration_test_environment):
    """A draft is not a successful two-pass translation when review failed."""
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    ledger_path = os.path.join(env['input_folder'], 'ledger.json')
    validation_summary = {}

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write("key.review=Needs review\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write("")

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Braucht Prüfung"))]
    ))
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH', ledger_path), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review:
        review.return_value = None
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved'],
            validation_summary=validation_summary,
        )

    ledger = localize.translate_localization_files.load_translation_key_ledger(ledger_path)
    assert ledger["app_de.properties"]["key.review"]["status"] == "failed"
    assert validation_summary["app_de.properties"]["model_translation_failed_count"] == 1
    assert validation_summary["app_de.properties"]["model_translation_failed_keys"] == ["key.review"]


@pytest.mark.asyncio
async def test_key_ledger_preserves_full_file_baseline_after_partial_translation(integration_test_environment):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    ledger_path = os.path.join(env['input_folder'], 'ledger.json')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write("key.one=One\nkey.two=Two\nkey.three=Three\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write("key.one=Eins\nkey.three=Drei\n")

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Zwei"))]
    ))
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH', ledger_path), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review:
        review.return_value = None
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    ledger = localize.translate_localization_files.load_translation_key_ledger(ledger_path)
    assert set(ledger["app_de.properties"]) == {"key.one", "key.two", "key.three"}


@pytest.mark.asyncio
async def test_process_translation_queue_skips_file_when_post_validation_fails(integration_test_environment):
    env = integration_test_environment
    source_file_path = os.path.join(env['input_folder'], 'app.properties')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        f.write("key.one=One\n")
    with open(target_file_path, 'w', encoding='utf-8') as f:
        f.write("")

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Eins"))]
    ))
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()), \
         patch('localize.translate_localization_files.holistic_review_async', new_callable=AsyncMock) as review, \
         patch('localize.translate_localization_files.run_post_translation_validation') as post_validation:
        review.return_value = None
        post_validation.return_value = False
        processed_count, processed_files, skipped_files, total_keys = (
            await localize.translate_localization_files.process_translation_queue(
                translation_queue_folder=env['translation_queue_folder'],
                translated_queue_folder=env['translated_queue_folder'],
                glossary_file_path=env['mock_glossary_path_resolved']
            )
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'app_de.properties')
    assert processed_count == 0
    assert processed_files == []
    assert total_keys == 0
    assert "app_de.properties" in skipped_files
    assert not os.path.exists(output_file_path)
    post_validation.assert_called_once()


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

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="URL ist '{0}'"))]
    ))
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.lint_properties_file', return_value=[]), \
         patch('localize.translate_localization_files.MODEL_PROVIDER', provider):
        await localize.translate_localization_files.process_translation_queue(
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


@pytest.mark.asyncio
async def test_process_translation_queue_translates_json_locale_file(integration_test_environment):
    env = integration_test_environment
    source_content = {
        "hello": "Hello",
        "nested": {
            "title": "Title {0}",
        },
        "count": 3,
    }
    target_content = {
        "hello": "Hallo",
    }
    source_file_path = os.path.join(env['input_folder'], 'app.json')
    target_file_path = os.path.join(env['translation_queue_folder'], 'app_de.json')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        json.dump(source_content, f, ensure_ascii=False, indent=2)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        json.dump(target_content, f, ensure_ascii=False, indent=2)

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(side_effect=[
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="Titel {0}"))]),
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content=json.dumps({"/nested/title": "Titel {0}"})
        ))]),
    ])
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.LOCALIZATION_FORMAT', JSON_FORMAT), \
         patch('localize.translate_localization_files.LANGUAGE_CODES', {'de': 'German'}), \
         patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()):
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'app_de.json')
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_payload = json.load(f)

    assert final_payload == {
        "hello": "Hallo",
        "nested": {
            "title": "Titel {0}",
        },
        "count": 3,
    }


@pytest.mark.asyncio
async def test_process_translation_queue_translates_json_locale_directory_layout(integration_test_environment):
    env = integration_test_environment
    layout = LocalizationLayout(id="locale_directory", source_locale="en")
    source_content = {
        "hello": "Hello",
        "steps": [
            {"title": "Review details"},
        ],
    }
    target_content = {
        "hello": "Hallo",
    }
    source_file_path = os.path.join(env['input_folder'], 'en', 'app.json')
    target_file_path = os.path.join(env['translation_queue_folder'], 'de', 'app.json')
    os.makedirs(os.path.dirname(source_file_path), exist_ok=True)
    os.makedirs(os.path.dirname(target_file_path), exist_ok=True)

    with open(source_file_path, 'w', encoding='utf-8') as f:
        json.dump(source_content, f, ensure_ascii=False, indent=2)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        json.dump(target_content, f, ensure_ascii=False, indent=2)

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(side_effect=[
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="Details prüfen"))]),
        SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content=json.dumps({"/steps/0/title": "Details prüfen"})
        ))]),
    ])
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    with patch('localize.translate_localization_files.LOCALIZATION_FORMAT', JSON_FORMAT), \
         patch('localize.translate_localization_files.LOCALIZATION_LAYOUT', layout), \
         patch('localize.translate_localization_files.LANGUAGE_CODES', {'de': 'German'}), \
         patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()):
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'de', 'app.json')
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_payload = json.load(f)

    assert final_payload == {
        "hello": "Hallo",
        "steps": [
            {"title": "Details prüfen"},
        ],
    }


@pytest.mark.asyncio
async def test_process_translation_queue_preserves_ignored_json_comment_keys(integration_test_environment):
    env = integration_test_environment
    layout = LocalizationLayout(id="locale_filename", source_locale="en")
    source_content = {
        "#1": "Phrases in app/Main.tsx",
        "#2": "Phrases in app/SettingsPage/index.tsx",
        "welcome": "Welcome to Acme",
        "amount": "Amount {{amount}} sats",
    }
    target_content = {}
    source_file_path = os.path.join(env['input_folder'], 'en.json')
    target_file_path = os.path.join(env['translation_queue_folder'], 'de.json')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        json.dump(source_content, f, ensure_ascii=False, indent=2)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        json.dump(target_content, f, ensure_ascii=False, indent=2)

    seen_prompt_texts = []

    async def fake_completion(**kwargs):
        prompt_text = "\n".join(message["content"] for message in kwargs["messages"])
        seen_prompt_texts.append(prompt_text)
        if kwargs.get("response_format"):
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
                content=json.dumps({
                    "/amount": "Betrag {{amount}} sats",
                    "/welcome": "Willkommen bei Acme",
                })
            ))])
        if "Key: /amount" in prompt_text:
            content = "Betrag {{amount}} sats"
        elif "Key: /welcome" in prompt_text:
            content = "Willkommen bei Acme"
        else:
            raise AssertionError(f"Unexpected model prompt: {prompt_text}")
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(side_effect=fake_completion)
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    profiles = (
        LocalizationProfile(JSON_FORMAT, layout),
    )
    with patch('localize.translate_localization_files.LOCALIZATION_FORMAT', JSON_FORMAT), \
         patch('localize.translate_localization_files.LOCALIZATION_LAYOUT', layout), \
         patch('localize.translate_localization_files.LOCALIZATION_PROFILES', profiles), \
         patch('localize.translate_localization_files.LANGUAGE_CODES', {'de': 'German'}), \
         patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.IGNORE_KEY_PATTERNS',
               compile_ignore_key_patterns([r"^/#\d+$"])), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()):
        processed_count, processed_files, skipped_files, total_keys = (
            await localize.translate_localization_files.process_translation_queue(
                translation_queue_folder=env['translation_queue_folder'],
                translated_queue_folder=env['translated_queue_folder'],
                glossary_file_path=env['mock_glossary_path_resolved']
            )
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'de.json')
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_payload = json.load(f)

    assert processed_count == 1
    assert processed_files == ['de.json']
    assert skipped_files == {}
    assert total_keys == 2
    assert final_payload == {
        "#1": "Phrases in app/Main.tsx",
        "#2": "Phrases in app/SettingsPage/index.tsx",
        "welcome": "Willkommen bei Acme",
        "amount": "Betrag {{amount}} sats",
    }
    assert provider.estimate_run_cost.call_args.kwargs["num_keys"] == 2
    assert all('"#1"' not in prompt for prompt in seen_prompt_texts)
    assert all('"#2"' not in prompt for prompt in seen_prompt_texts)
    assert all("Phrases in app" not in prompt for prompt in seen_prompt_texts)


@pytest.mark.asyncio
async def test_process_translation_queue_writes_only_ignored_json_keys(integration_test_environment):
    env = integration_test_environment
    layout = LocalizationLayout(id="locale_filename", source_locale="en")
    source_content = {
        "#1": "Phrases in app/Main.tsx",
        "#2": "Phrases in app/SettingsPage/index.tsx",
    }
    source_file_path = os.path.join(env['input_folder'], 'en.json')
    target_file_path = os.path.join(env['translation_queue_folder'], 'de.json')

    with open(source_file_path, 'w', encoding='utf-8') as f:
        json.dump(source_content, f, ensure_ascii=False, indent=2)
    with open(target_file_path, 'w', encoding='utf-8') as f:
        json.dump({}, f, ensure_ascii=False, indent=2)

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(
        side_effect=AssertionError("Ignored keys must not call the model")
    )
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"

    profiles = (
        LocalizationProfile(JSON_FORMAT, layout),
    )
    with patch('localize.translate_localization_files.LOCALIZATION_FORMAT', JSON_FORMAT), \
         patch('localize.translate_localization_files.LOCALIZATION_LAYOUT', layout), \
         patch('localize.translate_localization_files.LOCALIZATION_PROFILES', profiles), \
         patch('localize.translate_localization_files.LANGUAGE_CODES', {'de': 'German'}), \
         patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.IGNORE_KEY_PATTERNS',
               compile_ignore_key_patterns([r"^/#\d+$"])), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()):
        processed_count, processed_files, skipped_files, total_keys = (
            await localize.translate_localization_files.process_translation_queue(
                translation_queue_folder=env['translation_queue_folder'],
                translated_queue_folder=env['translated_queue_folder'],
                glossary_file_path=env['mock_glossary_path_resolved']
            )
        )

    output_file_path = os.path.join(env['translated_queue_folder'], 'de.json')
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r', encoding='utf-8') as f:
        final_payload = json.load(f)

    assert processed_count == 1
    assert processed_files == ['de.json']
    assert skipped_files == {}
    assert total_keys == 0
    assert final_payload == source_content
    provider.create_chat_completion.assert_not_awaited()
    provider.estimate_run_cost.assert_not_called()


@pytest.mark.asyncio
async def test_process_translation_queue_routes_mixed_format_profiles(integration_test_environment):
    env = integration_test_environment
    properties_source_path = os.path.join(env['input_folder'], 'app.properties')
    properties_target_path = os.path.join(env['translation_queue_folder'], 'app_de.properties')
    json_source_path = os.path.join(env['input_folder'], 'locales', 'en', 'common.json')
    json_target_path = os.path.join(env['translation_queue_folder'], 'locales', 'de', 'common.json')
    os.makedirs(os.path.dirname(json_source_path), exist_ok=True)
    os.makedirs(os.path.dirname(json_target_path), exist_ok=True)

    with open(properties_source_path, 'w', encoding='utf-8') as f:
        f.write('headline=Headline\ncta=Continue with {0}\n')
    with open(properties_target_path, 'w', encoding='utf-8') as f:
        f.write('headline=Ueberschrift\n')
    with open(json_source_path, 'w', encoding='utf-8') as f:
        json.dump({
            "nested": {"title": "JSON title {0}"},
            "metadata": {"version": 1},
        }, f, ensure_ascii=False, indent=2)
    with open(json_target_path, 'w', encoding='utf-8') as f:
        json.dump({"metadata": {"version": 1}}, f, ensure_ascii=False, indent=2)

    async def fake_completion(**kwargs):
        if kwargs.get("response_format"):
            system_content = kwargs["messages"][0]["content"]
            if "/nested/title" in system_content:
                return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
                    content=json.dumps({"/nested/title": "JSON-Titel {0}"})
                ))])
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
                content=json.dumps({"cta": "Weiter mit {0}"})
            ))])

        user_content = kwargs["messages"][1]["content"]
        if "Key: /nested/title" in user_content:
            content = "JSON-Titel {0}"
        else:
            content = "Weiter mit {0}"
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    provider = MagicMock()
    provider.create_chat_completion = AsyncMock(side_effect=fake_completion)
    provider.count_tokens.side_effect = lambda text, model: len(text.split())
    provider.estimate_run_cost.return_value = MagicMock()
    provider.format_estimate.return_value = "estimate"
    provider.is_retryable_error.return_value = False

    profiles = (
        LocalizationProfile(
            JAVA_PROPERTIES_FORMAT,
            LocalizationLayout(id="suffix", source_locale="en"),
        ),
        LocalizationProfile(
            JSON_FORMAT,
            LocalizationLayout(id="locale_directory", source_locale="en"),
        ),
    )
    with patch('localize.translate_localization_files.LOCALIZATION_PROFILES', profiles), \
         patch('localize.translate_localization_files.LANGUAGE_CODES', {'de': 'German'}), \
         patch('localize.translate_localization_files.MODEL_PROVIDER', provider), \
         patch('localize.translate_localization_files.TRANSLATION_KEY_LEDGER_FILE_PATH',
               os.path.join(env['input_folder'], 'ledger.json')), \
         patch('localize.translate_localization_files.get_working_tree_changed_keys', return_value=set()):
        await localize.translate_localization_files.process_translation_queue(
            translation_queue_folder=env['translation_queue_folder'],
            translated_queue_folder=env['translated_queue_folder'],
            glossary_file_path=env['mock_glossary_path_resolved']
        )

    with open(os.path.join(env['translated_queue_folder'], 'app_de.properties'), 'r', encoding='utf-8') as f:
        properties_content = f.read()
    with open(os.path.join(env['translated_queue_folder'], 'locales', 'de', 'common.json'), 'r', encoding='utf-8') as f:
        json_payload = json.load(f)

    assert "headline=Ueberschrift" in properties_content
    assert "cta=Weiter mit {0}" in properties_content
    assert json_payload == {
        "nested": {"title": "JSON-Titel {0}"},
        "metadata": {"version": 1},
    }
