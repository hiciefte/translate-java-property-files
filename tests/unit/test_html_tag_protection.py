"""
Unit tests for HTML tag and placeholder protection in translations.

This test module verifies that:
1. Placeholders like {0}, {1}, etc. are properly protected
2. HTML tags like <{0} style=code> are properly protected
3. Text between placeholders and HTML tags is NOT protected and can be translated
"""

import pytest
from src.translate_localization_files import (
    extract_placeholders,
    restore_placeholders,
    protect_placeholders_in_properties,
    restore_placeholders_in_properties
)


class TestPlaceholderExtraction:
    """Test the extract_placeholders function for individual text strings"""

    def test_simple_placeholder_protection(self):
        """Test that simple placeholders are protected"""
        text = "Hello {0}, welcome to {1}"
        processed, mapping = extract_placeholders(text)

        # Should have 2 placeholders protected
        assert len(mapping) == 2

        # All original placeholders should be in the mapping
        assert "{0}" in mapping.values()
        assert "{1}" in mapping.values()

        # The processed text should contain placeholder tokens
        assert "__PH_" in processed

        # Should NOT contain the original placeholders
        assert "{0}" not in processed
        assert "{1}" not in processed

        # The translatable text should remain
        assert "Hello" in processed
        assert "welcome to" in processed

    def test_html_tag_protection(self):
        """Test that HTML-like tags are protected"""
        text = "Click <button>here</button> to continue"
        processed, mapping = extract_placeholders(text)

        # Should have 2 HTML tags protected
        assert len(mapping) == 2

        # Tags should be in mapping
        assert "<button>" in mapping.values()
        assert "</button>" in mapping.values()

        # Translatable text should remain
        assert "Click" in processed
        assert "here" in processed
        assert "to continue" in processed

    def test_html_tag_with_placeholder_inside(self):
        """Test HTML tags that contain placeholders (like <{0} style=code>)"""
        text = "The price is <{0} style=offer-details-code>"
        processed, mapping = extract_placeholders(text)

        # The HTML tag regex matches the ENTIRE tag including the placeholder inside
        # This is correct behavior - the whole tag is treated as one protected unit
        assert len(mapping) == 1

        # The entire HTML tag (including placeholder inside) should be in mapping
        assert "<{0} style=offer-details-code>" in mapping.values()

        # Translatable text should remain
        assert "The price is" in processed

    def test_problematic_case_1_only_placeholders(self):
        """
        Test case from issue: {0} <{1} style=offer-details-code>
        This case has no translatable text - only placeholders and HTML tag.
        """
        text = "{0} <{1} style=offer-details-code>"
        processed, mapping = extract_placeholders(text)

        # Should protect placeholders and HTML tag
        assert len(mapping) == 2
        assert "{0}" in mapping.values()

        # Check if HTML tag with placeholder is protected
        html_tag_protected = any(
            "style=offer-details-code>" in v for v in mapping.values()
        )
        assert html_tag_protected

        # After removing all tokens, should have minimal/no translatable text
        remaining = processed
        for token in mapping.keys():
            remaining = remaining.replace(token, "")
        remaining = remaining.strip()

        # Should be empty or just whitespace
        assert len(remaining) == 0 or remaining.isspace()

    def test_problematic_case_2_text_with_placeholders(self):
        """
        Test case from issue: Fixed price. {0} {1} market price of {2} <{3} style=offer-details-code>
        The text "market price of" should remain translatable.
        """
        text = "Fixed price. {0} {1} market price of {2} <{3} style=offer-details-code>"
        processed, mapping = extract_placeholders(text)

        # Should protect 4 items: {0}, {1}, {2}, and the HTML tag
        assert len(mapping) == 4

        # All placeholders should be protected
        assert "{0}" in mapping.values()
        assert "{1}" in mapping.values()
        assert "{2}" in mapping.values()

        # HTML tag should be protected
        html_tag_protected = any(
            "style=offer-details-code>" in v for v in mapping.values()
        )
        assert html_tag_protected

        # CRITICAL: Translatable text should remain
        assert "Fixed price." in processed
        assert "market price of" in processed

        # Verify the translatable text after removing tokens
        remaining = processed
        for token in mapping.keys():
            remaining = remaining.replace(token, "")
        remaining = ' '.join(remaining.split())  # Normalize whitespace

        # Should contain the translatable phrases
        assert "Fixed price." in remaining
        assert "market price of" in remaining

    def test_text_between_multiple_placeholders(self):
        """Test that text appearing between multiple placeholders is preserved"""
        text = "Buy {0} BTC at {1} market price using {2}"
        processed, mapping = extract_placeholders(text)

        # Should protect 3 placeholders
        assert len(mapping) == 3

        # Translatable text should be preserved
        assert "Buy" in processed
        assert "BTC at" in processed
        assert "market price using" in processed

    def test_placeholder_restoration(self):
        """Test that placeholders can be correctly restored after translation"""
        text = "Hello {0}, you have {1} messages"
        processed, mapping = extract_placeholders(text)

        # Simulate a translation that keeps the tokens
        simulated_translation = processed.replace("Hello", "Hola").replace(
            "you have", "tienes"
        ).replace("messages", "mensajes")

        # Restore placeholders
        restored = restore_placeholders(simulated_translation, mapping)

        # Should have original placeholders back
        assert "{0}" in restored
        assert "{1}" in restored

        # Should have translated text
        assert "Hola" in restored
        assert "tienes" in restored
        assert "mensajes" in restored

        # Should NOT have tokens
        assert "__PH_" not in restored


class TestPropertiesFileProtection:
    """Test the protect_placeholders_in_properties function for full file content"""

    def test_protect_multiple_properties(self):
        """Test protecting placeholders across multiple property lines"""
        content = """
key1=Hello {0}
key2=Fixed price. {0} {1} market price of {2} <{3} style=offer-details-code>
key3=Simple text without placeholders
"""
        protected, mapping = protect_placeholders_in_properties(content)

        # Should protect all placeholders and HTML tags
        assert len(mapping) >= 4  # At least {0}, {1}, {2}, and HTML tag from key2

        # All original placeholders should be protected
        assert "{0}" not in protected
        assert "{1}" not in protected

        # Translatable text should remain
        assert "Hello" in protected
        assert "Fixed price." in protected
        assert "market price of" in protected
        assert "Simple text without placeholders" in protected

    def test_restore_properties_placeholders(self):
        """Test that placeholders can be restored in full properties content"""
        content = "key=Hello {0}, welcome to {1}"
        protected, mapping = protect_placeholders_in_properties(content)

        # Restore
        restored = restore_placeholders_in_properties(protected, mapping)

        # Should match original
        assert restored == content

    def test_empty_content(self):
        """Test handling of empty content"""
        protected, mapping = protect_placeholders_in_properties("")

        assert protected == ""
        assert mapping == {}

    def test_content_without_placeholders(self):
        """Test content that has no placeholders to protect"""
        content = "key=Simple text without any placeholders"
        protected, mapping = protect_placeholders_in_properties(content)

        # Content should be unchanged
        assert protected == content

        # No placeholders should be in mapping
        assert len(mapping) == 0


class TestEdgeCases:
    """Test edge cases and complex scenarios"""

    def test_nested_braces_in_html(self):
        """Test HTML tags that contain braces"""
        text = "Value: <span data-value='{0}'>{1}</span>"
        processed, mapping = extract_placeholders(text)

        # Should protect placeholders and HTML tags
        assert len(mapping) >= 2

        # Translatable text should remain
        assert "Value:" in processed

    def test_multiple_html_tags(self):
        """Test multiple HTML tags in sequence"""
        text = "Click <a href='#'>here</a> or <button>there</button>"
        processed, mapping = extract_placeholders(text)

        # Should protect multiple tags
        assert len(mapping) == 4  # 2 opening tags, 2 closing tags

        # Translatable text should remain
        assert "Click" in processed
        assert "here" in processed
        assert "or" in processed
        assert "there" in processed

    def test_html_tag_without_spaces(self):
        """Test HTML tags that are immediately adjacent to text"""
        text = "Start<tag>middle</tag>end"
        processed, mapping = extract_placeholders(text)

        # Tags should be protected
        assert "<tag>" in mapping.values()
        assert "</tag>" in mapping.values()

        # Text should remain
        assert "Start" in processed
        assert "middle" in processed
        assert "end" in processed

    def test_placeholder_at_start_and_end(self):
        """Test placeholders at the beginning and end of text"""
        text = "{0} some text here {1}"
        processed, mapping = extract_placeholders(text)

        # Placeholders should be protected
        assert len(mapping) == 2

        # Text should remain
        assert "some text here" in processed

    def test_only_placeholders_no_text(self):
        """Test string that is only placeholders"""
        text = "{0}{1}{2}"
        processed, mapping = extract_placeholders(text)

        # All placeholders protected
        assert len(mapping) == 3

        # Should be only tokens left
        remaining = processed
        for token in mapping.keys():
            remaining = remaining.replace(token, "")

        # Should be empty or minimal
        assert len(remaining.strip()) == 0


class TestRealWorldExamples:
    """Test with actual examples from the bisq properties files"""

    def test_bisq_quote_side_amount(self):
        """Test: bisqEasy.offerDetails.quoteSideAmount={0} <{1} style=offer-details-code>"""
        text = "{0} <{1} style=offer-details-code>"
        processed, mapping = extract_placeholders(text)

        # This case has no translatable text, which is correct
        assert len(mapping) == 2

        remaining = processed
        for token in mapping.keys():
            remaining = remaining.replace(token, "")

        # Should be minimal/empty
        assert len(remaining.strip()) == 0

    def test_bisq_price_details_fix(self):
        """Test: bisqEasy.offerDetails.priceDetails.fix=Fixed price. {0} {1} market price of {2} <{3} style=offer-details-code>"""
        text = "Fixed price. {0} {1} market price of {2} <{3} style=offer-details-code>"
        processed, mapping = extract_placeholders(text)

        # Should have 4 protected items
        assert len(mapping) == 4

        # CRITICAL: The key translatable phrases must remain
        assert "Fixed price." in processed
        assert "market price of" in processed

        # Verify by checking what remains after token removal
        remaining = processed
        for token in mapping.keys():
            remaining = remaining.replace(token, "")
        remaining = ' '.join(remaining.split())

        # These phrases must be translatable
        assert "Fixed price." in remaining
        assert "market price of" in remaining
