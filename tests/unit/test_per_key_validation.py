"""
Unit tests for per-key validation functionality.

Tests the ability to validate individual translation keys and selectively
revert only failed keys to source instead of discarding entire translation files.
"""

from src.translate_localization_files import run_per_key_validation


class TestPerKeyValidation:
    """Test suite for per-key validation logic."""

    def test_all_keys_valid(self):
        """When all translations are valid, return all translations unchanged."""
        source_translations = {
            "key1": "Hello {0}",
            "key2": "Welcome {0} and {1}",
            "key3": "No placeholders here"
        }

        final_translations = {
            "key1": "Hola {0}",
            "key2": "Bienvenido {0} y {1}",
            "key3": "Sin marcadores aquí"
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(valid_translations) == 3
        assert len(failed_keys) == 0
        assert valid_translations["key1"] == "Hola {0}"
        assert valid_translations["key2"] == "Bienvenido {0} y {1}"
        assert valid_translations["key3"] == "Sin marcadores aquí"

    def test_single_key_fails_placeholder_count(self):
        """When one key has wrong placeholder count, only that key reverts to source."""
        source_translations = {
            "key1": "Hello {0}",
            "key2": "Welcome {0} and {1}",
            "key3": "Score of {0} is below {1} for range {2}"
        }

        final_translations = {
            "key1": "Hola {0}",
            "key2": "Bienvenido {0} y {1}",
            "key3": "Score {0} is below {1} for range"  # Missing {2}
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(valid_translations) == 3
        assert len(failed_keys) == 1
        assert "key3" in failed_keys

        # Valid keys keep their translations
        assert valid_translations["key1"] == "Hola {0}"
        assert valid_translations["key2"] == "Bienvenido {0} y {1}"

        # Failed key reverts to source
        assert valid_translations["key3"] == "Score of {0} is below {1} for range {2}"

    def test_multiple_keys_fail(self):
        """When multiple keys fail, all failed keys revert to source."""
        source_translations = {
            "key1": "Address {0} in transaction {1}",
            "key2": "Amount {0}",
            "key3": "Valid translation"
        }

        final_translations = {
            "key1": "Transaction {1} address",  # Missing {0}
            "key2": "Amount {0} with extra {1}",  # Extra {1}
            "key3": "Traducción válida"
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(valid_translations) == 3
        assert len(failed_keys) == 2
        assert "key1" in failed_keys
        assert "key2" in failed_keys

        # Valid key keeps translation
        assert valid_translations["key3"] == "Traducción válida"

        # Failed keys revert to source
        assert valid_translations["key1"] == "Address {0} in transaction {1}"
        assert valid_translations["key2"] == "Amount {0}"

    def test_placeholder_reordering_is_valid(self):
        """Placeholder reordering (same count, different order) should be valid."""
        source_translations = {
            "key1": "User {0} sent {1} to {2}"
        }

        final_translations = {
            "key1": "{2} received {1} from {0}"  # Reordered but same placeholders
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(failed_keys) == 0
        assert valid_translations["key1"] == "{2} received {1} from {0}"

    def test_empty_translations(self):
        """Handle empty translation dictionaries gracefully."""
        source_translations = {}
        final_translations = {}

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(valid_translations) == 0
        assert len(failed_keys) == 0

    def test_missing_source_key(self):
        """When a key exists in final but not source, keep the final translation."""
        source_translations = {
            "key1": "Hello {0}"
        }

        final_translations = {
            "key1": "Hola {0}",
            "key2": "Extra key {0}"  # Not in source
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        # Should handle gracefully - validate against empty source
        assert len(valid_translations) == 2
        assert valid_translations["key1"] == "Hola {0}"

    def test_escaped_single_quotes_preserved(self):
        """Escaped single quotes ('') should not affect placeholder validation."""
        source_translations = {
            "key1": "Address ''{0}'' in transaction ''{1}''"
        }

        final_translations = {
            "key1": "Adresse ''{0}'' in Transaktion ''{1}''"
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(failed_keys) == 0
        assert valid_translations["key1"] == "Adresse ''{0}'' in Transaktion ''{1}''"

    def test_escaped_quotes_with_missing_placeholder(self):
        """Escaped quotes with missing placeholder should fail validation."""
        source_translations = {
            "key1": "Address ''{0}'' in transaction ''{1}'' is ''{2}''"
        }

        final_translations = {
            "key1": "Transaction ''{1}'' address is ''{2}''"  # Missing {0}
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(failed_keys) == 1
        assert "key1" in failed_keys
        assert valid_translations["key1"] == "Address ''{0}'' in transaction ''{1}'' is ''{2}''"

    def test_no_placeholders_always_valid(self):
        """Keys without placeholders should always pass validation."""
        source_translations = {
            "key1": "Simple text",
            "key2": "Another simple text"
        }

        final_translations = {
            "key1": "Texto simple",
            "key2": "Otro texto simple"
        }

        valid_translations, failed_keys = run_per_key_validation(
            final_translations,
            source_translations,
            "test.properties"
        )

        assert len(failed_keys) == 0
        assert len(valid_translations) == 2
