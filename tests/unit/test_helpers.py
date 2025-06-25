import unittest
from unittest.mock import patch, MagicMock

from src.translate_localization_files import (
    extract_placeholders,
    restore_placeholders,
    clean_translated_text,
    count_tokens
)


class TestHelperFunctions(unittest.TestCase):
    def test_extract_and_restore_placeholders(self):
        original = "Hello <b>{name}</b>!"
        processed, mapping = extract_placeholders(original)
        # Ensure placeholders replaced with tokens
        self.assertNotIn('<b>', processed)
        self.assertEqual(len(mapping), 2)
        restored = restore_placeholders(processed, mapping)
        self.assertEqual(restored, original)

    def test_clean_translated_text_quotes_and_brackets(self):
        self.assertEqual(
            clean_translated_text('"Hallo"', 'Hallo'),
            'Hallo'
        )
        self.assertEqual(
            clean_translated_text('[Hallo]', 'Hallo'),
            'Hallo'
        )
        # If original had quotes they should be preserved
        self.assertEqual(
            clean_translated_text('"Hallo"', '"Hallo"'),
            '"Hallo"'
        )

    def test_count_tokens_fallback(self):
        # Force encoding_for_model to raise to trigger fallback
        with patch('src.translate_localization_files.tiktoken.encoding_for_model', side_effect=Exception()):
            # Also patch get_encoding to provide predictable encode
            fake_enc = MagicMock()
            fake_enc.encode.side_effect = lambda s: list(s.split())
            with patch('src.translate_localization_files.tiktoken.get_encoding', return_value=fake_enc):
                count = count_tokens('one two three')
        self.assertEqual(count, 3)


if __name__ == '__main__':
    unittest.main()
