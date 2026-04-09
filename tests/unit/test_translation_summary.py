import json
import os
import tempfile
import unittest

os.environ['OPENAI_API_KEY'] = 'DUMMY_KEY_FOR_TESTING'

from src.translate_localization_files import generate_translation_summary

# Codes used across all tests — mirrors a realistic subset of production config
SUPPORTED_CODES = ["de", "es", "fr", "pt_BR", "af_ZA"]


class TestTranslationSummary(unittest.TestCase):
    """Tests for generate_translation_summary(), which produces a JSON file
    consumed by the shell script to build descriptive PR titles."""

    def _run_summary(self, processed_files, new_keys, updated_keys):
        with tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.json'
        ) as f:
            path = f.name
        generate_translation_summary(
            path,
            processed_files=processed_files,
            new_keys_count=new_keys,
            updated_keys_count=updated_keys,
            supported_codes=SUPPORTED_CODES,
        )
        with open(path, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        os.remove(path)
        return summary

    def test_summary_with_new_keys_and_locales(self):
        """A typical run that translated new keys across multiple locales."""
        summary = self._run_summary(
            processed_files=[
                "bisq_easy_de.properties",
                "bisq_easy_es.properties",
                "bisq_easy_fr.properties",
                "mu_sig_de.properties",
            ],
            new_keys=12,
            updated_keys=3,
        )

        self.assertEqual(summary["files_count"], 4)
        self.assertEqual(summary["new_keys_count"], 12)
        self.assertEqual(summary["updated_keys_count"], 3)
        self.assertIn("bisq_easy", summary["modules"])
        self.assertIn("mu_sig", summary["modules"])
        self.assertEqual(len(summary["modules"]), 2)
        self.assertIn("de", summary["locales"])
        self.assertIn("es", summary["locales"])
        self.assertIn("fr", summary["locales"])
        self.assertTrue(summary["title"].startswith("Update translations"))

    def test_summary_single_module(self):
        """When only one module is affected, title names it directly."""
        summary = self._run_summary(
            processed_files=["chat_de.properties", "chat_es.properties"],
            new_keys=5,
            updated_keys=0,
        )

        self.assertEqual(summary["modules"], ["chat"])
        self.assertIn("chat", summary["title"])

    def test_summary_empty_run(self):
        """When no files were processed, the summary reflects that."""
        summary = self._run_summary([], 0, 0)

        self.assertEqual(summary["files_count"], 0)
        self.assertEqual(summary["modules"], [])
        self.assertEqual(summary["locales"], [])

    def test_summary_title_length_capped(self):
        """PR title must stay under 72 characters for git best practices."""
        summary = self._run_summary(
            processed_files=[f"module_{i}_de.properties" for i in range(20)],
            new_keys=100,
            updated_keys=50,
        )

        self.assertLessEqual(len(summary["title"]), 72)

    def test_summary_extracts_locale_from_country_code(self):
        """Locale codes like pt_BR should be extracted correctly."""
        summary = self._run_summary(
            processed_files=[
                "bisq_easy_pt_BR.properties",
                "bisq_easy_af_ZA.properties",
            ],
            new_keys=2,
            updated_keys=0,
        )

        self.assertIn("pt_BR", summary["locales"])
        self.assertIn("af_ZA", summary["locales"])
        self.assertEqual(summary["modules"], ["bisq_easy"])

    def test_summary_title_includes_key_counts(self):
        """Title should mention key counts when available."""
        summary = self._run_summary(
            processed_files=["app_de.properties"],
            new_keys=7,
            updated_keys=0,
        )

        self.assertIn("7 new", summary["title"])

    def test_summary_title_new_and_updated(self):
        """Title should mention both new and updated counts."""
        summary = self._run_summary(
            processed_files=["app_de.properties"],
            new_keys=3,
            updated_keys=5,
        )

        self.assertIn("3 new", summary["title"])
        self.assertIn("5 updated", summary["title"])


if __name__ == '__main__':
    unittest.main()
