import unittest
import os
import tempfile
from src.translation_validator import (
    check_key_coverage,
    check_placeholder_parity,
    check_encoding_and_mojibake,
    synchronize_keys
)
from src.properties_parser import parse_properties_file

class TestTranslationValidator(unittest.TestCase):
    def test_check_key_coverage(self):
        base_keys = {'key.one', 'key.two', 'key.three'}
        target_keys = {'key.one', 'key.three', 'key.four'}

        missing, extra = check_key_coverage(base_keys, target_keys)

        self.assertEqual(missing, {'key.two'})
        self.assertEqual(extra, {'key.four'})

    def test_check_key_coverage_no_diff(self):
        base_keys = {'key.one', 'key.two'}
        target_keys = {'key.one', 'key.two'}

        missing, extra = check_key_coverage(base_keys, target_keys)

        self.assertEqual(missing, set())
        self.assertEqual(extra, set())

    def test_placeholder_parity_success(self):
        base_string = "Hello {0}, welcome to {1}."
        target_string = "Hallo {0}, willkommen bei {1}."
        self.assertTrue(check_placeholder_parity(base_string, target_string))

    def test_placeholder_parity_missing_placeholder(self):
        base_string = "Hello {0}, welcome to {1}."
        target_string = "Hallo, willkommen bei {1}."
        self.assertFalse(check_placeholder_parity(base_string, target_string))

    def test_placeholder_parity_extra_placeholder(self):
        base_string = "Hello {0}."
        target_string = "Hallo {0}, willkommen bei {1}."
        self.assertFalse(check_placeholder_parity(base_string, target_string))

    def test_placeholder_parity_reordered_placeholders(self):
        # This test is important. The *set* of placeholders might be the same,
        # but the order matters for many localization frameworks.
        base_string = "First {0}, then {1}."
        target_string = "Zuerst {1}, dann {0}."
        # For now, we allow reordering as it's common in translation.
        # The function will just check for set equality.
        # A future, stricter version could check for order if needed.
        self.assertTrue(check_placeholder_parity(base_string, target_string))

    def test_placeholder_parity_different_placeholders(self):
        base_string = "Hello {0}."
        target_string = "Hallo {name}."
        self.assertFalse(check_placeholder_parity(base_string, target_string))

    def test_placeholder_parity_repeated_placeholders(self):
        base_string = "Action: {0}, Action: {0}, Parameter: {1}"
        target_string = "Aktion: {0}, Parameter: {1}"
        self.assertFalse(check_placeholder_parity(base_string, target_string))

        base_string_2 = "Action: {0}, Parameter: {1}"
        target_string_2 = "Aktion: {0}, Aktion: {0}, Parameter: {1}"
        self.assertFalse(check_placeholder_parity(base_string_2, target_string_2))

        base_string_3 = "Action: {0}, Action: {0}"
        target_string_3 = "Aktion: {0}, Aktion: {0}"
        self.assertTrue(check_placeholder_parity(base_string_3, target_string_3))

    def test_encoding_and_mojibake_success(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.properties', encoding='utf-8') as f:
            f.write("key.one=verfügbar\n")
            f.write("key.two=München\n")
            temp_path = f.name
        
        try:
            errors = check_encoding_and_mojibake(temp_path)
            self.assertEqual(errors, [])
        finally:
            os.remove(temp_path)

    def test_encoding_is_not_utf8(self):
        # Write bytes that are valid in latin-1 but not in utf-8
        content_bytes = "key.one=verf\xfcgbare Videos".encode('latin-1')
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.properties') as f:
            f.write(content_bytes)
            temp_path = f.name

        try:
            errors = check_encoding_and_mojibake(temp_path)
            self.assertEqual(len(errors), 1)
            self.assertIn("is not a valid UTF-8 file", errors[0])
        finally:
            os.remove(temp_path)

    def test_mojibake_detection(self):
        # This text is valid UTF-8, but contains characters that are
        # symptomatic of double-encoding (mojibake).
        # "verfÃ¼gbar" is the mojibake for "verfügbar".
        # We also explicitly include the Unicode replacement character \uFFFD.
        mojibake_content = "key.one=verfÃ¼gbar\nkey.two=Ã¤Ã¶Ã¼\nkey.three=this contains the replacement char \uFFFD"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.properties', encoding='utf-8') as f:
            f.write(mojibake_content)
            temp_path = f.name
            
        try:
            errors = check_encoding_and_mojibake(temp_path)
            self.assertEqual(len(errors), 2)
            self.assertTrue(any("Potential mojibake detected" in e for e in errors))
            self.assertTrue(any("contains the official Unicode replacement character" in e for e in errors))
        finally:
            os.remove(temp_path)

    def test_key_synchronization(self):
        # Create temporary source and target files
        source_content = "key.one=One\nkey.two=Two\n# comment\nkey.three=Three"
        target_content = "key.one=Eins\nkey.three=Drei\nkey.four=Vier"

        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f_source:
            f_source.write(source_content)
            source_path = f_source.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f_target:
            f_target.write(target_content)
            target_path = f_target.name

        try:
            # Run the synchronization
            missing_keys, extra_keys = synchronize_keys(target_path, source_path)

            # Read the modified target file and check its content
            with open(target_path, 'r', encoding='utf-8') as f_target_mod:
                modified_content = f_target_mod.read()

            # Parse the content to check keys and values
            _, modified_translations = parse_properties_file(target_path)

            # Assertions
            self.assertIn("key.two=Two", modified_content)  # Missing key added from source
            self.assertNotIn("key.four", modified_content)  # Extra key removed
            self.assertIn("key.one=Eins", modified_content) # Existing key preserved
            self.assertLess(modified_content.index("key.one=Eins"), modified_content.index("key.two=Two"))
            self.assertLess(modified_content.index("key.two=Two"), modified_content.index("key.three=Drei"))
            self.assertEqual(len(modified_translations), 3)
            self.assertEqual(missing_keys, {"key.two"})
            self.assertEqual(extra_keys, {"key.four"})

        finally:
            os.remove(source_path)
            os.remove(target_path)

    def test_key_synchronization_preserves_comment_relative_position(self):
        source_content = "key.one=One\nkey.two=Two\n# section marker\nkey.three=Three\n"
        target_content = "key.one=Uno\n# section marker\nkey.three=Tres\n"

        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f_source:
            f_source.write(source_content)
            source_path = f_source.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f_target:
            f_target.write(target_content)
            target_path = f_target.name

        try:
            synchronize_keys(target_path, source_path)

            with open(target_path, 'r', encoding='utf-8') as f_target_mod:
                modified_content = f_target_mod.read()

            self.assertLess(modified_content.index("key.two=Two"), modified_content.index("# section marker"))
            self.assertLess(modified_content.index("# section marker"), modified_content.index("key.three=Tres"))
        finally:
            os.remove(source_path)
            os.remove(target_path)


if __name__ == '__main__':
    unittest.main()
