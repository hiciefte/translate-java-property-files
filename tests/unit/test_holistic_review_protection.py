"""
Unit tests for holistic review placeholder protection.

Tests the ability to protect placeholders during holistic review phase
to prevent the AI from modifying, removing, or adding placeholders.
"""

import pytest
from src.translate_localization_files import (
    protect_placeholders_in_properties,
    restore_placeholders_in_properties,
    extract_placeholders
)


class TestHolisticReviewPlaceholderProtection:
    """Test suite for placeholder protection in holistic review."""

    def test_protect_single_placeholder(self):
        """Single placeholder should be replaced with protection token."""
        content = "key1=Hello {0}"

        protected_content, placeholder_map = protect_placeholders_in_properties(content)

        assert "{0}" not in protected_content
        assert "key1=Hello __PH_" in protected_content
        assert len(placeholder_map) == 1
        assert "{0}" in placeholder_map.values()

    def test_protect_multiple_placeholders_same_line(self):
        """Multiple placeholders on same line should all be protected."""
        content = "key1=Welcome {0} and {1}"

        protected_content, placeholder_map = protect_placeholders_in_properties(content)

        assert "{0}" not in protected_content
        assert "{1}" not in protected_content
        assert protected_content.count("__PH_") == 2
        assert len(placeholder_map) == 2

    def test_protect_placeholders_across_multiple_keys(self):
        """Placeholders in multiple keys should all be protected."""
        content = """key1=Hello {0}
key2=Score {0} below {1} for {2}
key3=No placeholders"""

        protected_content, placeholder_map = protect_placeholders_in_properties(content)

        assert "{0}" not in protected_content
        assert "{1}" not in protected_content
        assert "{2}" not in protected_content
        assert protected_content.count("__PH_") == 4  # 1 + 3 + 0
        assert "No placeholders" in protected_content  # Unchanged

    def test_protect_escaped_single_quotes_with_placeholders(self):
        """Escaped single quotes around placeholders should be preserved."""
        content = "key1=Address ''{0}'' in transaction ''{1}''"

        protected_content, placeholder_map = protect_placeholders_in_properties(content)

        assert "''" in protected_content  # Escaped quotes preserved
        assert "{0}" not in protected_content
        assert "{1}" not in protected_content
        assert protected_content.count("__PH_") == 2

    def test_restore_protected_placeholders(self):
        """Protected placeholders should be restored to original values."""
        original = "key1=Hello {0} and {1}"

        protected, placeholder_map = protect_placeholders_in_properties(original)
        restored = restore_placeholders_in_properties(protected, placeholder_map)

        assert restored == original
        assert "{0}" in restored
        assert "{1}" in restored
        assert "__PH_" not in restored

    def test_restore_maintains_escaped_quotes(self):
        """Restoration should maintain escaped single quotes."""
        original = "key1=Address ''{0}'' in ''{1}''"

        protected, placeholder_map = protect_placeholders_in_properties(original)
        restored = restore_placeholders_in_properties(protected, placeholder_map)

        assert restored == original
        assert "''{0}''" in restored
        assert "''{1}''" in restored

    def test_protect_multiline_properties(self):
        """Multiline property values should have all placeholders protected."""
        content = """key1=Your score {0} is below {1}\\n\\
for minimum range {2}.\\n\\
Bisq Easy''s model."""

        protected, placeholder_map = protect_placeholders_in_properties(content)

        assert "{0}" not in protected
        assert "{1}" not in protected
        assert "{2}" not in protected
        assert "Bisq Easy''s model" in protected  # Text preserved
        assert len(placeholder_map) == 3

    def test_empty_content(self):
        """Empty content should return empty results."""
        content = ""

        protected, placeholder_map = protect_placeholders_in_properties(content)

        assert protected == ""
        assert len(placeholder_map) == 0

    def test_no_placeholders(self):
        """Content without placeholders should pass through unchanged."""
        content = """key1=Hello world
key2=No placeholders here"""

        protected, placeholder_map = protect_placeholders_in_properties(content)

        assert protected == content
        assert len(placeholder_map) == 0

    def test_unique_protection_tokens(self):
        """Each placeholder should get a unique protection token."""
        content = "key1={0} and {0}"  # Same placeholder repeated

        protected, placeholder_map = protect_placeholders_in_properties(content)

        # Each occurrence should get its own unique token
        tokens = [k for k in placeholder_map.keys()]
        assert len(tokens) == len(set(tokens))  # All unique

        # But they should all map to the same value
        values = list(placeholder_map.values())
        assert all(v == "{0}" for v in values)

    def test_restore_with_ai_modifications(self):
        """Restoration should work even if AI modified surrounding text."""
        original = "key1=Your score {0} is below {1}"

        protected, placeholder_map = protect_placeholders_in_properties(original)

        # Simulate AI modifying the text but keeping tokens
        token1, token2 = list(placeholder_map.keys())
        ai_modified = f"key1=Score {token1} below {token2} for range"

        restored = restore_placeholders_in_properties(ai_modified, placeholder_map)

        assert "{0}" in restored
        assert "{1}" in restored
        assert "__PH_" not in restored
        assert "Score {0} below {1} for range" in restored

    def test_protection_preserves_file_structure(self):
        """Protection should maintain comments and blank lines."""
        content = """# Comment
key1=Hello {0}

key2=World {1}"""

        protected, placeholder_map = protect_placeholders_in_properties(content)

        assert "# Comment" in protected
        assert "\n\n" in protected  # Blank line preserved
        assert "__PH_" in protected
