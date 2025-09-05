import unittest
import os
import tempfile
import textwrap

# To be created
from src.translate_localization_files import lint_properties_file

class TestValidationLogic(unittest.TestCase):

    def test_linting_finds_common_errors(self):
        """
        Tests that our linter can detect common errors found in PR reviews:
        1. Malformed keys with double dots (..).
        2. Invalid Java escape sequences (e.g., \\U).
        """
        # Create a properties file with known errors
        bad_content = textwrap.dedent("""
            # This key is malformed
            key.one..bad=Some value

            # This key is correct
            key.two.good=Another value

            # This value has a bad escape sequence
            key.three.bad.escape=\\n\\Usando Tor externo
        """)

        errors = []
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.properties', encoding='utf-8') as f:
            f.write(bad_content)
            temp_path = f.name
        
        try:
            errors = lint_properties_file(temp_path)
        finally:
            os.remove(temp_path)
        
        self.assertEqual(len(errors), 2, "Linter should have found exactly 2 errors.")

        # Check for specific error messages
        self.assertIn("Malformed key 'key.one..bad'", errors[0])
        self.assertIn("Invalid escape sequence in value for key 'key.three.bad.escape'", errors[1])


if __name__ == '__main__':
    unittest.main() 