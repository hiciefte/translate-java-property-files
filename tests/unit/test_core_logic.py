import os
import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import tempfile
import textwrap

import pytest
from openai import OpenAIError

# Set a dummy API key before importing the main script.
# This prevents the OpenAI client from failing in a test environment
# where the key might not be set.
os.environ['OPENAI_API_KEY'] = 'DUMMY_KEY_FOR_TESTING'

# It's good practice to be able to import the functions to be tested.
# This might require adjusting the Python path if the test runner doesn't handle it.
from localize.translate_localization_files import (
    build_context,
    apply_ignored_source_values,
    normalize_value,
    prefer_existing_translation_on_failure,
    compute_ledger_hash,
    build_file_key_ledger,
    extract_texts_to_translate,
    filter_git_changed_keys_by_source,
    get_working_tree_changed_keys,
    extract_language_from_filename,
    run_post_translation_validation,
    run_per_key_validation_with_summary,
    run_pre_translation_validation,
    split_lint_findings,
    validate_paths,
    write_skipped_files_report,
    _handle_retry,
)
from localize.ignore_keys import compile_ignore_key_patterns
from localize.properties_parser import parse_properties_file, reassemble_file


class TestCoreLogic(unittest.TestCase):

    def test_validate_paths_creates_missing_queue_folders(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = os.path.join(temp_dir, 'repo')
            input_folder = os.path.join(repo_root, 'i18n')
            queue_folder = os.path.join(temp_dir, 'translation_queue')
            translated_folder = os.path.join(temp_dir, 'translated_queue')
            os.makedirs(input_folder)

            validate_paths(input_folder, queue_folder, translated_folder, repo_root)

            self.assertTrue(os.path.isdir(queue_folder))
            self.assertTrue(os.path.isdir(translated_folder))

    def test_validate_paths_rejects_queue_path_collisions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = os.path.join(temp_dir, 'repo')
            input_folder = os.path.join(repo_root, 'i18n')
            safe_queue = os.path.join(temp_dir, 'translation_queue')
            safe_translated = os.path.join(temp_dir, 'translated_queue')
            os.makedirs(input_folder)

            unsafe_cases = [
                (input_folder, safe_translated),
                (os.path.join(repo_root, '.translation_queue'), safe_translated),
                (temp_dir, safe_translated),
                (safe_queue, os.path.join(input_folder, 'translated_queue')),
            ]

            for queue_folder, translated_folder in unsafe_cases:
                with self.subTest(queue_folder=queue_folder, translated_folder=translated_folder):
                    with self.assertRaisesRegex(ValueError, 'separate from repo_root and input_folder'):
                        validate_paths(input_folder, queue_folder, translated_folder, repo_root)

    def test_validate_paths_rejects_existing_queue_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = os.path.join(temp_dir, 'repo')
            input_folder = os.path.join(repo_root, 'i18n')
            queue_file = os.path.join(temp_dir, 'translation_queue')
            translated_folder = os.path.join(temp_dir, 'translated_queue')
            os.makedirs(input_folder)
            with open(queue_file, 'w', encoding='utf-8') as file:
                file.write('not a directory')

            with self.assertRaises(NotADirectoryError):
                validate_paths(input_folder, queue_file, translated_folder, repo_root)

    def test_pre_validation_ignores_unchanged_placeholder_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = os.path.join(temp_dir, 'mobile.properties')
            target_path = os.path.join(temp_dir, 'mobile_de.properties')
            with open(source_path, 'w', encoding='utf-8') as file:
                file.write('old.key=Old {0}\nnew.key=New {0}\n')
            with open(target_path, 'w', encoding='utf-8') as file:
                file.write('old.key=Alt\nnew.key=New {0}\n')

            errors, _newly_added_keys = run_pre_translation_validation(
                target_path,
                source_path,
                git_changed_keys={'new.key'},
                file_ledger_entries={},
            )

            self.assertEqual(errors, [])

    def test_pre_validation_blocks_changed_placeholder_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = os.path.join(temp_dir, 'mobile.properties')
            target_path = os.path.join(temp_dir, 'mobile_de.properties')
            with open(source_path, 'w', encoding='utf-8') as file:
                file.write('old.key=Old {0}\nnew.key=New {0}\n')
            with open(target_path, 'w', encoding='utf-8') as file:
                file.write('old.key=Alt\nnew.key=Neu\n')

            errors, _newly_added_keys = run_pre_translation_validation(
                target_path,
                source_path,
                git_changed_keys={'new.key'},
                file_ledger_entries={},
            )

            self.assertEqual(errors, ['Placeholder mismatch for key `new.key`.'])

    def test_pre_validation_ignores_placeholder_mismatch_for_ignored_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = os.path.join(temp_dir, 'mobile.properties')
            target_path = os.path.join(temp_dir, 'mobile_de.properties')
            with open(source_path, 'w', encoding='utf-8') as file:
                file.write('comment.key=Path {0}\nnew.key=New {0}\n')
            with open(target_path, 'w', encoding='utf-8') as file:
                file.write('comment.key=Path\nnew.key=Neu\n')

            errors, _newly_added_keys = run_pre_translation_validation(
                target_path,
                source_path,
                git_changed_keys={'comment.key', 'new.key'},
                file_ledger_entries={},
                ignore_key_patterns=compile_ignore_key_patterns([r'^comment\.']),
            )

            self.assertEqual(errors, ['Placeholder mismatch for key `new.key`.'])

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
        from localize.translate_localization_files import integrate_translations
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

        from localize.translate_localization_files import integrate_translations
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

        from localize.translate_localization_files import integrate_translations
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

        with patch('localize.translate_localization_files.count_tokens', side_effect=mock_count_tokens):
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

    def test_build_context_marks_prompt_only_terms_as_inflectable(self):
        _, glossary_text = build_context(
            {},
            {},
            {"entry": "запись"},
            4000,
            "gpt-4o-mini",
            translation_glossary_enforcement="prompt-only",
        )

        self.assertIn("preferred base term", glossary_text)
        self.assertIn("inflect or adapt", glossary_text)
        self.assertNotIn("should be translated as", glossary_text)

    def test_build_context_prioritizes_sibling_keys(self):
        """
        Tests that build_context surfaces sibling keys (sharing a dotted prefix
        with the key being translated) even when the token budget only fits one
        example, and never feeds the key its own prior translation back.
        """
        def mock_count_tokens(text: str, model_name: str) -> int:
            return len(text)

        with patch('localize.translate_localization_files.count_tokens', side_effect=mock_count_tokens):
            # The sibling terminology key is deliberately last in insertion order.
            existing_translations = {
                "app.unrelated.first": "translationA",
                "app.unrelated.second": "translationB",
                "trusted.pairingCode.unsupportedVersion": "old value",
                "trusted.pairingCode.textField": "Kode pasangan",
            }
            source_translations = {
                "app.unrelated.first": "sourceA",
                "app.unrelated.second": "sourceB",
                "trusted.pairingCode.unsupportedVersion": "Old value source",
                "trusted.pairingCode.textField": "Pairing code",
            }
            language_glossary = {}
            model_name = "test-model"
            sibling_example = 'trusted.pairingCode.textField = "Kode pasangan"'
            reserved_len = 1000
            # Budget for exactly one example beyond the reserved block.
            max_tokens = reserved_len + mock_count_tokens(sibling_example, model_name) + 1

            context_text, _ = build_context(
                existing_translations,
                source_translations,
                language_glossary,
                max_tokens,
                model_name,
                current_key="trusted.pairingCode.unsupportedVersion",
            )

            self.assertEqual(context_text.count("="), 1)
            self.assertIn("trusted.pairingCode.textField", context_text)
            self.assertNotIn("app.unrelated.first", context_text)
            # The key being translated is never fed back as its own context.
            self.assertNotIn("trusted.pairingCode.unsupportedVersion", context_text)

    def test_build_context_skips_oversized_sibling_and_keeps_searching(self):
        """An oversized high-priority sibling must not hide later siblings."""
        def mock_count_tokens(text: str, model_name: str) -> int:
            return len(text)

        with patch('localize.translate_localization_files.count_tokens', side_effect=mock_count_tokens):
            existing_translations = {
                "trusted.pairingCode.longExplanation": "x" * 200,
                "trusted.pairingCode.textField": "Kode pasangan",
            }
            source_translations = {
                "trusted.pairingCode.longExplanation": "Long explanation",
                "trusted.pairingCode.textField": "Pairing code",
            }
            short_example = 'trusted.pairingCode.textField = "Kode pasangan"'
            max_tokens = 1000 + mock_count_tokens(short_example, "test-model") + 1

            context_text, _ = build_context(
                existing_translations,
                source_translations,
                {},
                max_tokens,
                "test-model",
                current_key="trusted.pairingCode.unsupportedVersion",
            )

            self.assertEqual(context_text, short_example)

    def test_normalize_value_logic(self):
        """Tests the `normalize_value` helper function."""
        self.assertEqual(normalize_value("hello\nworld"), "hello<newline>world")
        self.assertEqual(normalize_value("  hello   world  "), "hello world")
        self.assertEqual(normalize_value("hello\\nworld"), "hello<newline>world")
        self.assertEqual(normalize_value(None), "")

    def test_write_skipped_files_report_escapes_markdown_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(temp_dir, "skipped.md")
            write_skipped_files_report(
                report_path,
                {
                    "bad`file<script>.properties": [
                        "placeholder <script>alert(1)</script> `code`"
                    ]
                },
            )

            with open(report_path, "r", encoding="utf-8") as report_file:
                content = report_file.read()

        self.assertIn("bad\\`file&lt;script&gt;.properties", content)
        self.assertIn("placeholder &lt;script&gt;alert(1)&lt;/script&gt; \\`code\\`", content)
        self.assertNotIn("<script>", content)


class TestRetryHandling(unittest.IsolatedAsyncioTestCase):

    async def test_handle_retry_accepts_float_retry_after_seconds(self):
        exc = OpenAIError("rate limited")
        exc.headers = {"Retry-After": "1.5"}

        with patch("localize.translate_localization_files.asyncio.sleep", new_callable=AsyncMock) as sleep:
            should_retry = await _handle_retry(
                attempt=1,
                max_retries=2,
                base_delay=1,
                key="key.one",
                api_exc=exc,
            )

        self.assertTrue(should_retry)
        sleep.assert_awaited_once_with(1.5)

    async def test_handle_retry_reads_retry_after_from_response_headers(self):
        exc = OpenAIError("rate limited")
        exc.response = type("Response", (), {"headers": {"Retry-After": "2.5"}})()

        with patch("localize.translate_localization_files.asyncio.sleep", new_callable=AsyncMock) as sleep:
            should_retry = await _handle_retry(
                attempt=1,
                max_retries=2,
                base_delay=1,
                key="key.one",
                api_exc=exc,
            )

        self.assertTrue(should_retry)
        sleep.assert_awaited_once_with(2.5)

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
        expected_texts = ['Source Value 2']
        expected_keys = ['key2_new']
        expected_indices = [3]

        self.assertEqual(texts, expected_texts)
        self.assertEqual(keys, expected_keys)
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

    def test_extract_texts_to_translate_includes_newly_added_identical_keys(self):
        """Newly synchronized keys with source-identical values should be translated."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key_existing', 'value': 'Source Existing', 'line_number': 0},
            {'type': 'entry', 'key': 'key_newly_added', 'value': 'Source New', 'line_number': 1},
        ]
        target_translations = {
            'key_existing': 'Source Existing',
            'key_newly_added': 'Source New'
        }
        source_translations = {
            'key_existing': 'Source Existing',
            'key_newly_added': 'Source New'
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            newly_added_keys={'key_newly_added'}
        )

        self.assertEqual(texts, ['Source New'])
        self.assertEqual(indices, [1])
        self.assertEqual(keys, ['key_newly_added'])

    def test_extract_texts_to_translate_skips_ignored_keys(self):
        """Ignored keys should never be selected for model translation."""
        parsed_lines = [
            {'type': 'entry', 'key': '/#1', 'value': 'Phrases in app/Main.tsx', 'line_number': 0},
            {'type': 'entry', 'key': '/welcome', 'value': 'Welcome', 'line_number': 1},
        ]
        target_translations = {
            '/#1': 'Phrases in app/Main.tsx',
            '/welcome': 'Welcome',
        }
        source_translations = {
            '/#1': 'Phrases in app/Main.tsx',
            '/welcome': 'Welcome',
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            newly_added_keys={'/#1', '/welcome'},
            ignore_key_patterns=compile_ignore_key_patterns([r'^/#\d+$']),
        )

        self.assertEqual(texts, ['Welcome'])
        self.assertEqual(indices, [1])
        self.assertEqual(keys, ['/welcome'])

    def test_extract_texts_to_translate_is_unchanged_without_ignore_patterns(self):
        """Unset ignore_key_patterns should preserve existing selection behavior."""
        parsed_lines = [
            {'type': 'entry', 'key': '/#1', 'value': 'Phrases in app/Main.tsx', 'line_number': 0},
            {'type': 'entry', 'key': '/welcome', 'value': 'Welcome', 'line_number': 1},
        ]
        target_translations = {
            '/#1': 'Phrases in app/Main.tsx',
            '/welcome': 'Welcome',
        }
        source_translations = {
            '/#1': 'Phrases in app/Main.tsx',
            '/welcome': 'Welcome',
        }

        baseline = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            newly_added_keys={'/#1', '/welcome'},
        )
        explicit_empty = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            newly_added_keys={'/#1', '/welcome'},
            ignore_key_patterns=[],
        )

        self.assertEqual(baseline, explicit_empty)
        self.assertEqual(baseline[2], ['/#1', '/welcome'])

    def test_empty_ignore_patterns_do_not_rewrite_content(self):
        """Empty ignore_key_patterns should be byte-for-byte inert."""
        content = textwrap.dedent("""\
            # Existing target file
            comment.1=Phrases in app/Main.tsx
            welcome=Willkommen
        """)
        with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            parsed_lines, target_translations = parse_properties_file(temp_file_path)
            before = reassemble_file(parsed_lines)

            updated_keys = apply_ignored_source_values(
                parsed_lines,
                target_translations,
                {
                    'comment.1': 'Phrases in app/Main.tsx',
                    'welcome': 'Welcome',
                },
                [],
            )

            self.assertEqual(updated_keys, set())
            self.assertEqual(reassemble_file(parsed_lines), before)
        finally:
            os.unlink(temp_file_path)

    def test_per_key_validation_excludes_ignored_keys_from_failures(self):
        valid_translations, summary = run_per_key_validation_with_summary(
            {
                '/#1': 'Phrases in app/Main.tsx',
                '/welcome': 'Willkommen',
                '/broken': 'Hallo',
            },
            {
                '/#1': 'Phrases in app/Main.tsx {{name}}',
                '/welcome': 'Welcome',
                '/broken': 'Hello {{name}}',
            },
            'de.json',
            ignore_key_patterns=compile_ignore_key_patterns([r'^/#\d+$']),
        )

        self.assertEqual(valid_translations['/#1'], 'Phrases in app/Main.tsx {{name}}')
        self.assertEqual(valid_translations['/welcome'], 'Willkommen')
        self.assertEqual(valid_translations['/broken'], 'Hello {{name}}')
        self.assertEqual(summary['failed_keys'], ['/broken'])
        self.assertEqual(summary['placeholder_failures_count'], 1)

    def test_extract_texts_to_translate_can_opt_in_retranslate_identical_existing(self):
        """Legacy behavior can be enabled explicitly for source-identical existing keys."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key_existing', 'value': 'Source Existing', 'line_number': 0},
        ]
        target_translations = {'key_existing': 'Source Existing'}
        source_translations = {'key_existing': 'Source Existing'}

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            retranslate_identical_existing=True
        )

        self.assertEqual(texts, ['Source Existing'])
        self.assertEqual(indices, [0])
        self.assertEqual(keys, ['key_existing'])

    def test_extract_texts_to_translate_includes_nonempty_source_with_empty_target(self):
        parsed_lines = [
            {'type': 'entry', 'key': 'needs.translation', 'value': '', 'line_number': 0},
            {'type': 'entry', 'key': 'intentionally.empty', 'value': '', 'line_number': 1},
        ]
        target_translations = {'needs.translation': '', 'intentionally.empty': ''}
        source_translations = {
            'needs.translation': 'Copy citation key',
            'intentionally.empty': '',
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
        )

        self.assertEqual(texts, ['Copy citation key'])
        self.assertEqual(indices, [0])
        self.assertEqual(keys, ['needs.translation'])

    def test_extract_texts_to_translate_includes_existing_key_when_source_hash_changed(self):
        """Existing keys should be translated when source text changed since last run."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key_existing', 'value': 'Old Target Translation', 'line_number': 0},
        ]
        target_translations = {'key_existing': 'Old Target Translation'}
        source_translations = {'key_existing': 'New Source Value'}
        file_ledger_entries = {
            'key_existing': {
                'source_hash': compute_ledger_hash('Old Source Value'),
                'target_hash': compute_ledger_hash('Old Target Translation')
            }
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            file_ledger_entries=file_ledger_entries
        )

        self.assertEqual(texts, ['New Source Value'])
        self.assertEqual(indices, [0])
        self.assertEqual(keys, ['key_existing'])

    def test_extract_texts_to_translate_retries_failed_ledger_keys(self):
        """Keys marked failed in the ledger should be eligible for retranslation."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key_existing', 'value': 'Source Existing', 'line_number': 0},
        ]
        target_translations = {'key_existing': 'Source Existing'}
        source_translations = {'key_existing': 'Source Existing'}
        file_ledger_entries = {
            'key_existing': {
                'source_hash': compute_ledger_hash('Source Existing'),
                'target_hash': compute_ledger_hash('Source Existing'),
                'status': 'failed'
            }
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            file_ledger_entries=file_ledger_entries
        )

        self.assertEqual(texts, ['Source Existing'])
        self.assertEqual(indices, [0])
        self.assertEqual(keys, ['key_existing'])

    def test_extract_texts_to_translate_retries_when_target_regresses_to_source(self):
        """Previously translated keys should be retried if target falls back to source text."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key_existing', 'value': 'Source Existing', 'line_number': 0},
        ]
        target_translations = {'key_existing': 'Source Existing'}
        source_translations = {'key_existing': 'Source Existing'}
        file_ledger_entries = {
            'key_existing': {
                'source_hash': compute_ledger_hash('Source Existing'),
                'target_hash': compute_ledger_hash('Old Real Translation')
            }
        }

        texts, indices, keys = extract_texts_to_translate(
            parsed_lines,
            source_translations,
            target_translations,
            file_ledger_entries=file_ledger_entries
        )

        self.assertEqual(texts, ['Source Existing'])
        self.assertEqual(indices, [0])
        self.assertEqual(keys, ['key_existing'])

    def test_extract_texts_to_translate_logs_missing_ledger_baseline_skip(self):
        """Existing source-identical keys should log migration hint when no baseline hash exists."""
        parsed_lines = [
            {'type': 'entry', 'key': 'key_existing', 'value': 'Source Existing', 'line_number': 0},
        ]
        target_translations = {'key_existing': 'Source Existing'}
        source_translations = {'key_existing': 'Source Existing'}
        selection_metrics = {}

        with self.assertLogs('translation_script', level='INFO') as captured_logs:
            texts, indices, keys = extract_texts_to_translate(
                parsed_lines,
                source_translations,
                target_translations,
                newly_added_keys=set(),
                file_ledger_entries={},
                retranslate_identical_existing=False,
                selection_metrics=selection_metrics,
            )

        self.assertEqual(texts, [])
        self.assertEqual(indices, [])
        self.assertEqual(keys, [])
        self.assertEqual(selection_metrics["source_identical_skipped_count"], 1)
        joined_logs = "\n".join(captured_logs.output)
        self.assertIn("Skipping key 'key_existing' (source==target)", joined_logs)
        self.assertIn("retranslate_identical_source_strings", joined_logs)

    def test_get_working_tree_changed_keys_parses_added_entries(self):
        """git diff added key/value lines should be parsed as newly synchronized keys."""
        git_diff_output = (
            "diff --git a/mobile_pt_BR.properties b/mobile_pt_BR.properties\n"
            "@@ -1 +1,5 @@\n"
            "+mobile.bisqEasy.tradeWizard.amount.seller.limitInfo=Your maximum selling amount is {0} out of {1}.\n"
            "+mobile.bisqEasy.colonKey:Value from colon separator\n"
            "+   # translated comment\n"
            "+! linter directive\n"
            "+mobile.bisqEasy.someOtherKey = Value\n"
            "+this is not a properties assignment\n"
        )
        mocked_result = MagicMock(returncode=0, stdout=git_diff_output, stderr="")
        with patch("localize.translate_localization_files.subprocess.run", return_value=mocked_result):
            keys = get_working_tree_changed_keys(
                "/repo/mobile/mobile_pt_BR.properties",
                "/repo"
            )

        self.assertSetEqual(
            {
                "mobile.bisqEasy.tradeWizard.amount.seller.limitInfo",
                "mobile.bisqEasy.colonKey",
                "mobile.bisqEasy.someOtherKey",
            },
            keys
        )

    def test_get_working_tree_changed_keys_returns_empty_on_command_failure(self):
        """git diff inspection failures should fail open and return no changed keys."""
        with patch("localize.translate_localization_files.subprocess.run", side_effect=OSError("git missing")):
            keys = get_working_tree_changed_keys(
                "/repo/mobile/mobile_pt_BR.properties",
                "/repo"
            )
        self.assertEqual(set(), keys)

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

    def test_post_translation_validation_ignores_unchanged_placeholder_mismatch(self):
        final_content = "legacy=Legacy text\nnew.key=Neuer Wert"
        source_translations = {
            "legacy": "Legacy text {0}",
            "new.key": "New value",
        }
        filename = "legacy_bad_placeholders.properties"

        self.assertTrue(
            run_post_translation_validation(
                final_content,
                source_translations,
                filename,
                changed_keys_for_run={"new.key"},
            )
        )
        self.assertFalse(
            run_post_translation_validation(
                final_content,
                source_translations,
                filename,
                changed_keys_for_run={"legacy"},
            )
        )

    def test_post_translation_validation_fails_on_mojibake(self):
        """Tests that mojibake is caught by post-translation validation."""
        final_content = "key.one=This is verfÃ¼gbar" # Mojibake
        source_translations = {"key.one": "This is available"}
        filename = "mojibake_file.properties"
        self.assertFalse(run_post_translation_validation(final_content, source_translations, filename))

    def test_split_lint_findings_keeps_warnings_non_blocking(self):
        errors, warnings = split_lint_findings(
            [
                "Linter Warning: Unknown escape sequence in value for key 'x'.",
                "Linter Error: Disallowed control character artifact.",
            ]
        )

        self.assertEqual(errors, ["Linter Error: Disallowed control character artifact."])
        self.assertEqual(warnings, ["Linter Warning: Unknown escape sequence in value for key 'x'."])

    def test_per_key_validation_reverts_empty_translation(self):
        valid, summary = run_per_key_validation_with_summary(
            {"key.one": ""},
            {"key.one": "Source text"},
            "empty.properties",
        )

        self.assertEqual(valid["key.one"], "Source text")
        self.assertEqual(summary["empty_target_keys"], ["key.one"])

    def test_per_key_validation_preserves_existing_target_when_generated_value_matches_source(self):
        """A matching baseline can retain validated localized text."""
        valid, summary = run_per_key_validation_with_summary(
            {"key.one": "Open trade chat"},
            {"key.one": "Open trade chat"},
            "de.properties",
            existing_translations={"key.one": "Handels-Chat öffnen"},
            file_ledger_entries=build_file_key_ledger(
                {"key.one": "Open trade chat"},
                {"key.one": "Handels-Chat öffnen"},
            ),
        )

        self.assertEqual(valid["key.one"], "Handels-Chat öffnen")
        self.assertEqual(summary["source_identical_keys"], ["key.one"])
        self.assertEqual(summary["source_identical_failures_count"], 1)

    def test_source_echo_does_not_restore_unverified_old_meaning(self):
        """An old number must not override the current English source."""
        valid, summary = run_per_key_validation_with_summary(
            {"key": "Wait 14 days"}, {"key": "Wait 14 days"}, "de.properties",
            existing_translations={"key": "Warten Sie 7 Tage"},
        )
        self.assertEqual(valid["key"], "Wait 14 days")
        self.assertEqual(summary["failed_keys"], ["key"])

    def test_source_echo_requires_matching_source_and_target_baseline(self):
        """Changed sources and edited targets cannot reuse an old baseline."""
        source = {"key": "Wait 14 days"}
        existing = {"key": "Warten Sie 7 Tage"}
        for ledger in (
            build_file_key_ledger({"key": "Wait 7 days"}, existing),
            build_file_key_ledger(source, {"key": "Anderer Text"}),
        ):
            with self.subTest(ledger=ledger):
                valid, _ = run_per_key_validation_with_summary(
                    source, source, "de.properties", existing_translations=existing,
                    file_ledger_entries=ledger,
                )
                self.assertEqual(valid, source)

    def test_source_echo_fallback_still_checks_placeholders_controls_and_glossary(self):
        """A matching baseline does not exempt old text from current validation."""
        cases = (
            ("Open {0}", "Öffnen {1}", {}, "placeholder_mismatch_keys"),
            ("Open chat", "Chat\x00 öffnen", {}, "control_character_keys"),
            ("Open account", "Konto öffnen", {"account": "Account"}, "glossary_mismatch_keys"),
        )
        for source_text, old_text, glossary, failure_category in cases:
            with self.subTest(category=failure_category):
                source, existing = {"key": source_text}, {"key": old_text}
                valid, summary = run_per_key_validation_with_summary(
                    source, source, "de.properties", existing_translations=existing,
                    file_ledger_entries=build_file_key_ledger(source, existing),
                    translation_glossary=glossary,
                )
                self.assertEqual(valid, source)
                self.assertEqual(summary[failure_category], ["key"])
                self.assertEqual(summary["failed_keys"], ["key"])
                self.assertEqual(summary["reverted_keys_count"], 1)


class TestSourceFilenameExtraction(unittest.TestCase):
    """Tests for extracting source filename from translated filename."""

    def test_get_source_filename_simple_language_code(self):
        """Test extraction with simple 2-letter language codes."""
        from localize.translate_localization_files import get_source_filename

        supported_codes = ['es', 'de', 'fr', 'pt_PT', 'pt_BR']

        # Simple case: app_es.properties -> app.properties
        result = get_source_filename('app_es.properties', supported_codes)
        self.assertEqual(result, 'app.properties')

        # Simple case: bisq_easy_de.properties -> bisq_easy.properties
        result = get_source_filename('bisq_easy_de.properties', supported_codes)
        self.assertEqual(result, 'bisq_easy.properties')

    def test_get_source_filename_with_underscores_in_base_name(self):
        """Test extraction when base filename contains underscores (mu_sig bug)."""
        from localize.translate_localization_files import get_source_filename

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
        from localize.translate_localization_files import get_source_filename

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
        from localize.translate_localization_files import get_source_filename

        supported_codes = ['es', 'de', 'fr']

        # No language code in filename
        result = get_source_filename('app.properties', supported_codes)
        self.assertEqual(result, 'app.properties', "Should return unchanged if no language code")

        # Unsupported language code
        result = get_source_filename('app_ja.properties', supported_codes)
        self.assertEqual(result, 'app_ja.properties', "Should return unchanged if language code not supported")

    def test_get_source_filename_edge_cases(self):
        """Test edge cases and unusual filenames."""
        from localize.translate_localization_files import get_source_filename

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
        from localize.translate_localization_files import lint_properties_file

        content = textwrap.dedent("""
            # Correct line
            key.one=A normal value.

            # Correctly escaped characters
            key.two=This value has a tab \\t and a newline \\n.

            # Unknown Java escape sequence
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
            self.assertIn("Unknown escape sequence", errors[0])
            self.assertIn("key.three.bad.escape", errors[0])
            self.assertTrue(errors[0].startswith("Linter Warning:"))
            self.assertIn("Malformed key", errors[1])
            self.assertIn("key..four", errors[1])
        finally:
            os.remove(temp_file_path)

    def test_linting_handles_common_edge_cases(self):
        """
        Tests that the linter correctly ignores common but tricky escape sequences
        that were previously flagged as errors.
        """
        from localize.translate_localization_files import lint_properties_file
        content = textwrap.dedent(r'''
            # Permitted escaped quote
            key.one=This is a value with an escaped quote \"here\".

            # Permitted newline before a line continuation character
            key.two=This is a multi-line value with a newline.\n\
                     And it continues here.

            # A tolerated Java escape sequence that should warn, not block.
            key.three=This has an invalid escape \z.
            ''')
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.properties') as temp_f:
            temp_f.write(content)
            temp_file_path = temp_f.name

        try:
            errors = lint_properties_file(temp_file_path)
            # It should only flag the unknown escape sequence as a warning.
            self.assertEqual(len(errors), 1)
            self.assertIn("Unknown escape sequence in value for key 'key.three'", errors[0])
            self.assertTrue(errors[0].startswith("Linter Warning:"))
        finally:
            os.remove(temp_file_path)

    def test_linting_treats_even_backslash_runs_as_literal_backslashes(self):
        """A valid ``\\\\`` pair must not expose its second slash as an escape."""
        from localize.translate_localization_files import lint_properties_file

        content = (
            r"regex=Use \\(deep|machine\\) learning" "\n"
            r"literal=Unknown-looking \\z remains literal" "\n"
            r"invalid=An odd run \\\z still contains an invalid escape" "\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            suffix=".properties",
            encoding="utf-8",
        ) as temp_f:
            temp_f.write(content)
            temp_file_path = temp_f.name

        try:
            errors = lint_properties_file(temp_file_path)
            self.assertEqual(len(errors), 1)
            self.assertIn(
                "Unknown escape sequence in value for key 'invalid'",
                errors[0],
            )
        finally:
            os.remove(temp_file_path)


class TestFileDetectionLogic(unittest.TestCase):

    @patch('subprocess.run')
    def test_get_changed_files_returns_all_without_filter(self, mock_subprocess_run):
        """
        Tests that get_changed_translation_files returns all changed files
        when no environment variable filter is set.
        """
        from localize.translate_localization_files import get_changed_translation_files

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
        from localize.translate_localization_files import get_changed_translation_files

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
    def test_get_changed_files_handles_copy_entries(self, mock_subprocess_run):
        """Copy entries (C) use the same 'old -> new' format as renames; use the new path."""
        from localize.translate_localization_files import get_changed_translation_files

        git_output = "C  i18n/resources/mobile_en.properties -> i18n/resources/mobile_fr.properties\n"
        mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

        changed_files = get_changed_translation_files("/fake/repo/i18n/resources", "/fake/repo")

        changed_basenames = [os.path.basename(f) for f in changed_files]
        self.assertIn("mobile_fr.properties", changed_basenames)
        # The combined "old -> new" string must not survive as a path.
        assert not any("->" in f for f in changed_files)

    @patch('subprocess.run')
    def test_get_changed_files_uses_diff_base_when_env_set(self, mock_subprocess_run):
        """With TRANSLATION_DIFF_BASE set, detection uses `git diff --name-status` against the base."""
        from localize.translate_localization_files import get_changed_translation_files

        # git diff --name-status output (tab-separated status<TAB>path)
        diff_output = "M\ti18n/resources/mobile_de.properties\nA\ti18n/resources/mobile_es.properties\n"
        mock_subprocess_run.return_value = MagicMock(stdout=diff_output, stderr="", check_returncode=MagicMock())

        with patch.dict('os.environ', {'TRANSLATION_DIFF_BASE': 'origin/main'}):
            changed_files = get_changed_translation_files("/fake/repo/i18n/resources", "/fake/repo")

        # The subprocess must have been a `git diff` against the base, not `git status`.
        args = mock_subprocess_run.call_args[0][0]
        assert args[:3] == ['git', 'diff', '--name-status']
        assert any('origin/main' in a for a in args)
        changed_basenames = [os.path.basename(f) for f in changed_files]
        self.assertIn("mobile_de.properties", changed_basenames)
        self.assertIn("mobile_es.properties", changed_basenames)

    @patch('subprocess.run')
    def test_get_changed_files_diff_base_ignores_deletions(self, mock_subprocess_run):
        """Deleted files (status D) in the base diff are not enqueued for translation."""
        from localize.translate_localization_files import get_changed_translation_files

        diff_output = "D\ti18n/resources/mobile_de.properties\nM\ti18n/resources/mobile_es.properties\n"
        mock_subprocess_run.return_value = MagicMock(stdout=diff_output, stderr="", check_returncode=MagicMock())

        with patch.dict('os.environ', {'TRANSLATION_DIFF_BASE': 'origin/main'}):
            changed_files = get_changed_translation_files("/fake/repo/i18n/resources", "/fake/repo")

        changed_basenames = [os.path.basename(f) for f in changed_files]
        self.assertNotIn("mobile_de.properties", changed_basenames)
        self.assertIn("mobile_es.properties", changed_basenames)

    @patch('subprocess.run')
    def test_get_changed_files_diff_base_accepts_typechanges(self, mock_subprocess_run):
        """Typechange entries should be processed like modified locale files."""
        from localize.translate_localization_files import get_changed_translation_files

        diff_output = "T\ti18n/resources/mobile_de.properties\n"
        mock_subprocess_run.return_value = MagicMock(stdout=diff_output, stderr="", check_returncode=MagicMock())

        with patch.dict('os.environ', {'TRANSLATION_DIFF_BASE': 'origin/main'}):
            changed_files = get_changed_translation_files("/fake/repo/i18n/resources", "/fake/repo")

        changed_basenames = [os.path.basename(f) for f in changed_files]
        self.assertIn("mobile_de.properties", changed_basenames)

    @patch('subprocess.run')
    def test_get_changed_files_diff_base_fails_closed_when_unreachable(self, mock_subprocess_run):
        """An unreachable configured diff base should fail the run instead of returning no changes."""
        import subprocess

        from localize.translate_localization_files import get_changed_translation_files

        mock_subprocess_run.side_effect = subprocess.CalledProcessError(
            returncode=128,
            cmd=["git", "cat-file", "-e", "origin/main^{commit}"],
            stderr="fatal: Not a valid object name origin/main",
        )

        with patch.dict('os.environ', {'TRANSLATION_DIFF_BASE': 'origin/main'}):
            with pytest.raises(RuntimeError, match="TRANSLATION_DIFF_BASE"):
                get_changed_translation_files("/fake/repo/i18n/resources", "/fake/repo")

    @patch('subprocess.run')
    def test_get_changed_files_detects_hyphenated_locales(self, mock_subprocess_run):
        """
        Tests that get_changed_translation_files correctly detects files with
        hyphenated locale codes like zh-Hans and zh-Hant, as well as untracked files.
        """
        from localize.translate_localization_files import get_changed_translation_files

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

    @patch('subprocess.run')
    def test_get_changed_files_process_all_files_mode(self, mock_subprocess_run):
        """Tests process_all_files mode scans input folder directly without git."""
        from localize.translate_localization_files import get_changed_translation_files

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = temp_dir
            input_folder = os.path.join(temp_dir, "i18n", "resources")
            nested_folder = os.path.join(input_folder, "nested")
            os.makedirs(nested_folder, exist_ok=True)

            included_paths = [
                os.path.join(input_folder, "mobile_de.properties"),
                os.path.join(nested_folder, "payment_method_pt_BR.properties"),
                os.path.join(nested_folder, "academy_zh-Hans.properties"),
            ]
            excluded_paths = [
                os.path.join(input_folder, "mobile.properties"),  # source file
                os.path.join(input_folder, "notes.txt"),  # not properties
            ]

            for file_path in included_paths + excluded_paths:
                with open(file_path, "w", encoding="utf-8") as temp_file:
                    temp_file.write("k=v\n")

            files = get_changed_translation_files(input_folder, repo_root, process_all_files=True)

        mock_subprocess_run.assert_not_called()
        self.assertEqual(
            files,
            [
                "mobile_de.properties",
                "nested/academy_zh-Hans.properties",
                "nested/payment_method_pt_BR.properties",
            ]
        )

    @patch('subprocess.run')
    def test_get_changed_files_process_all_files_mode_with_glob_filter(self, mock_subprocess_run):
        """Tests process_all_files mode also honors TRANSLATION_FILTER_GLOB."""
        from localize.translate_localization_files import get_changed_translation_files

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = temp_dir
            input_folder = os.path.join(temp_dir, "i18n", "resources")
            os.makedirs(input_folder, exist_ok=True)

            for file_name in [
                "mobile_de.properties",
                "desktop_de.properties",
                "mobile_es.properties",
            ]:
                with open(os.path.join(input_folder, file_name), "w", encoding="utf-8") as temp_file:
                    temp_file.write("k=v\n")

            with patch.dict('os.environ', {'TRANSLATION_FILTER_GLOB': 'mobile_*.properties'}):
                files = get_changed_translation_files(input_folder, repo_root, process_all_files=True)

        mock_subprocess_run.assert_not_called()
        self.assertEqual(files, ["mobile_de.properties", "mobile_es.properties"])

    @patch('subprocess.run')
    def test_get_changed_files_excludes_archive_paths(self, mock_subprocess_run):
        """Tests file detection excludes archive directories in both discovery modes."""
        from localize.translate_localization_files import get_changed_translation_files

        git_output = textwrap.dedent("""
             M i18n/resources/archive/mobile_de.properties
             M i18n/resources/mobile_es.properties
        """).strip()
        mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

        repo_root = "/fake/repo"
        input_folder = "/fake/repo/i18n/resources"
        changed_files = get_changed_translation_files(input_folder, repo_root)
        changed_basenames = [os.path.basename(f) for f in changed_files]
        self.assertEqual(changed_basenames, ["mobile_es.properties"])

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = temp_dir
            input_folder = os.path.join(temp_dir, "i18n", "resources")
            archive_folder = os.path.join(input_folder, "archive")
            os.makedirs(archive_folder, exist_ok=True)

            with open(os.path.join(archive_folder, "mobile_de.properties"), "w", encoding="utf-8") as temp_file:
                temp_file.write("k=v\n")
            with open(os.path.join(input_folder, "mobile_es.properties"), "w", encoding="utf-8") as temp_file:
                temp_file.write("k=v\n")

            files = get_changed_translation_files(input_folder, repo_root, process_all_files=True)
            self.assertEqual(files, ["mobile_es.properties"])

    @patch('subprocess.run')
    def test_get_changed_files_includes_locale_files_when_source_file_changed(self, mock_subprocess_run):
        """When a source file changes, all related locale files should be queued."""
        from localize.translate_localization_files import get_changed_translation_files

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = temp_dir
            input_folder = os.path.join(temp_dir, "i18n", "resources")
            os.makedirs(input_folder, exist_ok=True)

            for file_name in [
                "mobile.properties",
                "mobile_de.properties",
                "mobile_es.properties",
                "desktop.properties",
                "desktop_de.properties",
            ]:
                with open(os.path.join(input_folder, file_name), "w", encoding="utf-8") as temp_file:
                    temp_file.write("k=v\n")

            git_output = " M i18n/resources/mobile.properties"
            mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

            files = get_changed_translation_files(input_folder, repo_root)

        self.assertEqual(sorted(files), ["mobile_de.properties", "mobile_es.properties"])

    @patch('subprocess.run')
    def test_get_changed_files_supports_json_locale_directory_layout(self, mock_subprocess_run):
        """Directory-based locale projects should not need locale suffix filenames."""
        from localize.localization_formats import JSON_FORMAT
        from localize.localization_layouts import LocalizationLayout
        from localize.translate_localization_files import get_changed_translation_files

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = temp_dir
            input_folder = os.path.join(temp_dir, "locales")
            for rel_path in [
                "en/common.json",
                "de/common.json",
                "fr/common.json",
            ]:
                path = os.path.join(input_folder, rel_path)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as temp_file:
                    temp_file.write('{"k":"v"}\n')

            git_output = " M locales/en/common.json\n"
            mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

            with patch("localize.translate_localization_files.LOCALIZATION_FORMAT", JSON_FORMAT), \
                 patch(
                     "localize.translate_localization_files.LOCALIZATION_LAYOUT",
                     LocalizationLayout(id="locale_directory", source_locale="en"),
                 ):
                files = get_changed_translation_files(input_folder, repo_root)

        self.assertEqual(files, ["de/common.json", "fr/common.json"])

    @patch('subprocess.run')
    def test_get_changed_files_supports_mixed_format_profiles(self, mock_subprocess_run):
        """Projects can discover changed locale files across configured format profiles."""
        from localize.localization_formats import JSON_FORMAT, JAVA_PROPERTIES_FORMAT
        from localize.localization_layouts import LocalizationLayout
        from localize.localization_profiles import LocalizationProfile
        from localize.translate_localization_files import get_changed_translation_files

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = temp_dir
            input_folder = os.path.join(temp_dir, "i18n")
            for rel_path in [
                "messages.properties",
                "messages_de.properties",
                "locales/en/common.json",
                "locales/de/common.json",
                "notes.txt",
            ]:
                path = os.path.join(input_folder, rel_path)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as temp_file:
                    temp_file.write("k=v\n")

            git_output = (
                " M i18n/messages_de.properties\n"
                " M i18n/locales/de/common.json\n"
                " M i18n/notes.txt\n"
            )
            mock_subprocess_run.return_value = MagicMock(stdout=git_output, stderr="", check_returncode=MagicMock())

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
            with patch("localize.translate_localization_files.LOCALIZATION_PROFILES", profiles):
                files = get_changed_translation_files(input_folder, repo_root)

        self.assertEqual(files, ["locales/de/common.json", "messages_de.properties"])

    @patch('subprocess.run')
    def test_process_all_files_supports_mixed_format_profiles(self, mock_subprocess_run):
        """Full scans should include target files from every configured format profile."""
        from localize.localization_formats import JSON_FORMAT, JAVA_PROPERTIES_FORMAT
        from localize.localization_layouts import LocalizationLayout
        from localize.localization_profiles import LocalizationProfile
        from localize.translate_localization_files import get_changed_translation_files

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = temp_dir
            input_folder = os.path.join(temp_dir, "i18n")
            for rel_path in [
                "messages.properties",
                "messages_de.properties",
                "locales/en/common.json",
                "locales/de/common.json",
                "locales/fr/common.json",
                "archive/messages_es.properties",
            ]:
                path = os.path.join(input_folder, rel_path)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as temp_file:
                    temp_file.write("k=v\n")

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
            with patch("localize.translate_localization_files.LOCALIZATION_PROFILES", profiles):
                files = get_changed_translation_files(input_folder, repo_root, process_all_files=True)

        mock_subprocess_run.assert_not_called()
        self.assertEqual(files, [
            "locales/de/common.json",
            "locales/fr/common.json",
            "messages_de.properties",
        ])

    def test_explicit_profiles_take_precedence_over_implicit_default(self):
        """Compatibility default must not shadow explicitly configured profiles."""
        from localize.localization_formats import JSON_FORMAT
        from localize.localization_layouts import LocalizationLayout
        from localize.localization_profiles import LocalizationProfile
        from localize.translate_localization_files import get_source_filename

        explicit_profiles = (
            LocalizationProfile(
                JSON_FORMAT,
                LocalizationLayout(id="locale_directory", source_locale="en"),
            ),
        )
        with patch(
                "localize.translate_localization_files.LOCALIZATION_PROFILES",
                explicit_profiles,
        ), patch(
                "localize.translate_localization_files.LOCALIZATION_FORMAT",
                JSON_FORMAT,
        ), patch(
                "localize.translate_localization_files.LOCALIZATION_LAYOUT",
                LocalizationLayout(id="suffix", source_locale="en"),
        ):
            source_path = get_source_filename("locales/de/messages_fr.json", ["de", "fr"])

        self.assertEqual(source_path, "locales/en/messages_fr.json")


class TestFilterGitChangedKeys(unittest.TestCase):
    """Tests for filter_git_changed_keys_by_source, which prevents the
    Transifex ↔ AI translation cycle by only re-translating keys whose
    English source actually changed."""

    def test_filters_out_keys_with_unchanged_source(self):
        """Keys changed by Transifex community translators (source unchanged)
        should NOT be treated as newly synchronized."""
        source_translations = {
            "key.stable": "Hello world",
            "key.changed": "Updated greeting",
        }
        ledger_entries = {
            "key.stable": {"source_hash": compute_ledger_hash("Hello world")},
            "key.changed": {"source_hash": compute_ledger_hash("Old greeting")},
        }
        git_changed_keys = {"key.stable", "key.changed"}

        result = filter_git_changed_keys_by_source(
            git_changed_keys, source_translations, ledger_entries
        )

        self.assertIn("key.changed", result)
        self.assertNotIn("key.stable", result)

    def test_includes_git_changed_keys_that_regressed_to_source_when_source_unchanged(self):
        """Git-dirty locale keys that equal English/source need translation even if source is unchanged."""
        source_translations = {
            "key.regressed": "Open trades",
            "key.localized": "Trade history",
        }
        target_translations = {
            "key.regressed": "Open trades",
            "key.localized": "Historial de comercio",
        }
        ledger_entries = {
            "key.regressed": {"source_hash": compute_ledger_hash("Open trades")},
            "key.localized": {"source_hash": compute_ledger_hash("Trade history")},
        }
        git_changed_keys = {"key.regressed", "key.localized"}

        result = filter_git_changed_keys_by_source(
            git_changed_keys,
            source_translations,
            ledger_entries,
            target_translations=target_translations
        )

        self.assertIn("key.regressed", result)
        self.assertNotIn("key.localized", result)

    def test_includes_keys_with_no_ledger_entry(self):
        """Keys not in the ledger are new — always include them."""
        source_translations = {"key.new": "Brand new key"}
        ledger_entries = {}
        git_changed_keys = {"key.new"}

        result = filter_git_changed_keys_by_source(
            git_changed_keys, source_translations, ledger_entries
        )

        self.assertIn("key.new", result)

    def test_includes_keys_with_no_source_hash_in_ledger(self):
        """Ledger entries without source_hash (legacy) should be included."""
        source_translations = {"key.legacy": "Some value"}
        ledger_entries = {"key.legacy": {"target_hash": "abc123"}}
        git_changed_keys = {"key.legacy"}

        result = filter_git_changed_keys_by_source(
            git_changed_keys, source_translations, ledger_entries
        )

        self.assertIn("key.legacy", result)

    def test_empty_git_changed_keys(self):
        """No git changes means no keys to filter."""
        result = filter_git_changed_keys_by_source(set(), {}, {})
        self.assertEqual(result, set())

    def test_preserves_keys_not_in_source(self):
        """Keys in git diff but not in source translations should be included
        (they'll be handled/skipped by downstream logic)."""
        source_translations = {}
        ledger_entries = {"key.orphan": {"source_hash": compute_ledger_hash("old")}}
        git_changed_keys = {"key.orphan"}

        result = filter_git_changed_keys_by_source(
            git_changed_keys, source_translations, ledger_entries
        )

        self.assertIn("key.orphan", result)


class TestPreferExistingTranslationOnFailure(unittest.TestCase):
    """Model failures may reuse only a ledger-attested current translation."""

    def test_preserves_existing_translation_when_both_hashes_match(self):
        source_value = "Open trade chat"
        existing_value = "Открыть чат сделки"
        repaired = prefer_existing_translation_on_failure(
            [(0, source_value, False)],
            ["key.chat"],
            {"key.chat": source_value},
            {"key.chat": existing_value},
            {
                "key.chat": {
                    "source_hash": compute_ledger_hash(source_value),
                    "target_hash": compute_ledger_hash(existing_value),
                    "status": "failed",
                }
            },
        )

        self.assertEqual(repaired, [(0, existing_value, False)])

    def test_does_not_restore_translation_after_source_changed(self):
        current_source = "Open the new trade chat"
        old_source = "Open trade chat"
        existing_value = "Открыть чат сделки"

        repaired = prefer_existing_translation_on_failure(
            [(0, current_source, False)],
            ["key.chat"],
            {"key.chat": current_source},
            {"key.chat": existing_value},
            {
                "key.chat": {
                    "source_hash": compute_ledger_hash(old_source),
                    "target_hash": compute_ledger_hash(existing_value),
                }
            },
        )

        self.assertEqual(repaired, [(0, current_source, False)])

    def test_does_not_restore_target_changed_outside_ledger(self):
        source_value = "Open trade chat"
        recorded_target = "Открыть торговый чат"
        current_target = "Открыть чат сделки"

        repaired = prefer_existing_translation_on_failure(
            [(0, source_value, False)],
            ["key.chat"],
            {"key.chat": source_value},
            {"key.chat": current_target},
            {
                "key.chat": {
                    "source_hash": compute_ledger_hash(source_value),
                    "target_hash": compute_ledger_hash(recorded_target),
                }
            },
        )

        self.assertEqual(repaired, [(0, source_value, False)])

    def test_requires_a_usable_non_source_existing_value(self):
        source_value = "Open trade chat"
        source_hash = compute_ledger_hash(source_value)
        for existing_value in (None, "", "   ", source_value):
            with self.subTest(existing_value=existing_value):
                existing = (
                    {}
                    if existing_value is None
                    else {"key.chat": existing_value}
                )
                repaired = prefer_existing_translation_on_failure(
                    [(0, source_value, False)],
                    ["key.chat"],
                    {"key.chat": source_value},
                    existing,
                    {
                        "key.chat": {
                            "source_hash": source_hash,
                            "target_hash": compute_ledger_hash(existing_value),
                        }
                    },
                )
                self.assertEqual(repaired, [(0, source_value, False)])

    def test_leaves_success_and_unknown_positions_untouched(self):
        results = [
            (0, "Otevřít obchodní chat", True),
            (2, "outside scope", False),
        ]

        repaired = prefer_existing_translation_on_failure(
            results,
            ["key.chat"],
            {"key.chat": "Open trade chat"},
            {"key.chat": "stale"},
            {},
        )

        self.assertEqual(repaired, results)


if __name__ == '__main__':
    unittest.main()
