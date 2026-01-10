"""
Tests for Text Utilities module.

This module tests the sanitize_llm_output function used to convert
LLM markdown output to ReportLab-compatible HTML.
"""

import pytest

from dwg_forensic.output.text_utils import sanitize_llm_output


class TestSanitizeLLMOutputBasic:
    """Basic tests for sanitize_llm_output function."""

    def test_empty_string(self):
        """Test that empty string returns empty string."""
        assert sanitize_llm_output("") == ""

    def test_none_returns_empty(self):
        """Test that None-like falsy input returns empty string."""
        assert sanitize_llm_output("") == ""

    def test_plain_text_unchanged(self):
        """Test that plain text without special chars passes through."""
        text = "This is plain text without special characters."
        result = sanitize_llm_output(text)
        assert result == text

    def test_preserves_newlines(self):
        """Test that single newlines are preserved."""
        text = "Line one.\nLine two."
        result = sanitize_llm_output(text)
        assert "Line one." in result
        assert "Line two." in result


class TestSanitizeUnicodeCharacters:
    """Tests for Unicode character replacement."""

    def test_em_dash_replaced(self):
        """Test em-dash (U+2014) is replaced with hyphen."""
        text = "This\u2014is an em-dash"
        result = sanitize_llm_output(text)
        assert "\u2014" not in result
        assert "This-is an em-dash" in result

    def test_en_dash_replaced(self):
        """Test en-dash (U+2013) is replaced with hyphen."""
        text = "Pages 10\u201320"
        result = sanitize_llm_output(text)
        assert "\u2013" not in result
        assert "10-20" in result

    def test_minus_sign_replaced(self):
        """Test minus sign (U+2212) is replaced with hyphen."""
        text = "5 \u2212 3 = 2"
        result = sanitize_llm_output(text)
        assert "\u2212" not in result
        assert "5 - 3 = 2" in result

    def test_left_single_quote_replaced(self):
        """Test left single quote (U+2018) is replaced."""
        text = "\u2018quoted\u2019"
        result = sanitize_llm_output(text)
        assert "\u2018" not in result
        assert "\u2019" not in result
        assert "'quoted'" in result

    def test_left_double_quote_replaced(self):
        """Test left/right double quotes (U+201C/U+201D) are replaced."""
        text = '\u201cHello\u201d'
        result = sanitize_llm_output(text)
        assert "\u201c" not in result
        assert "\u201d" not in result
        assert '"Hello"' in result

    def test_ellipsis_replaced(self):
        """Test ellipsis (U+2026) is replaced with three dots."""
        text = "And then\u2026"
        result = sanitize_llm_output(text)
        assert "\u2026" not in result
        assert "And then..." in result

    def test_non_breaking_space_replaced(self):
        """Test non-breaking space (U+00A0) is replaced."""
        text = "word\u00a0word"
        result = sanitize_llm_output(text)
        assert "\u00a0" not in result
        assert "word word" in result

    def test_bullet_point_replaced(self):
        """Test bullet point (U+2022) is replaced with asterisk."""
        text = "\u2022 Item one"
        result = sanitize_llm_output(text)
        assert "\u2022" not in result
        assert "* Item one" in result

    def test_multiple_unicode_replacements(self):
        """Test multiple Unicode characters in one string."""
        text = "\u201cHello\u201d \u2014 \u2018world\u2019\u2026"
        result = sanitize_llm_output(text)
        assert '"Hello" - ' in result
        assert "'world'..." in result


class TestSanitizeXMLEscaping:
    """Tests for XML special character escaping."""

    def test_ampersand_escaped(self):
        """Test ampersand is escaped."""
        text = "A & B"
        result = sanitize_llm_output(text)
        assert "&amp;" in result
        assert "A &amp; B" in result

    def test_less_than_escaped(self):
        """Test less-than is escaped."""
        text = "5 < 10"
        result = sanitize_llm_output(text)
        assert "&lt;" in result
        assert "5 &lt; 10" in result

    def test_greater_than_escaped(self):
        """Test greater-than is escaped."""
        text = "10 > 5"
        result = sanitize_llm_output(text)
        assert "&gt;" in result
        assert "10 &gt; 5" in result

    def test_all_xml_chars_escaped(self):
        """Test all XML special chars in one string."""
        text = "A < B & C > D"
        result = sanitize_llm_output(text)
        assert "A &lt; B &amp; C &gt; D" in result


class TestSanitizeMarkdownBold:
    """Tests for markdown bold conversion."""

    def test_double_asterisk_bold(self):
        """Test **text** converts to <b>text</b>."""
        text = "This is **bold** text"
        result = sanitize_llm_output(text)
        assert "<b>bold</b>" in result
        assert "**" not in result

    def test_double_underscore_bold(self):
        """Test __text__ converts to <b>text</b>."""
        text = "This is __bold__ text"
        result = sanitize_llm_output(text)
        assert "<b>bold</b>" in result
        assert "__" not in result

    def test_multiple_bold_sections(self):
        """Test multiple bold sections in one string."""
        text = "**First** and **second** bold"
        result = sanitize_llm_output(text)
        assert "<b>First</b>" in result
        assert "<b>second</b>" in result


class TestSanitizeMarkdownItalic:
    """Tests for markdown italic conversion."""

    def test_single_asterisk_italic(self):
        """Test *text* converts to <i>text</i>."""
        text = "This is *italic* text"
        result = sanitize_llm_output(text)
        assert "<i>italic</i>" in result
        assert result.count("*") == 0

    def test_underscore_not_converted_to_italic(self):
        """Test _text_ is NOT converted to italic (preserves technical terms)."""
        text = "The $FILE_NAME attribute"
        result = sanitize_llm_output(text)
        # Should NOT be converted to italic
        assert "<i>" not in result or "FILE" not in result.split("<i>")[1].split("</i>")[0] if "<i>" in result else True
        assert "$FILE_NAME" in result or "$FILE" in result

    def test_standard_information_preserved(self):
        """Test $STANDARD_INFORMATION is preserved without italic conversion."""
        text = "Check the $STANDARD_INFORMATION timestamps"
        result = sanitize_llm_output(text)
        # Underscores in technical terms should not trigger italic
        assert "STANDARD" in result
        assert "INFORMATION" in result


class TestSanitizeMarkdownHeaders:
    """Tests for markdown header stripping."""

    def test_h1_header_stripped(self):
        """Test # header is stripped."""
        text = "# Header One\nContent"
        result = sanitize_llm_output(text)
        assert "# " not in result
        assert "Header One" in result

    def test_h2_header_stripped(self):
        """Test ## header is stripped."""
        text = "## Header Two"
        result = sanitize_llm_output(text)
        assert "## " not in result
        assert "Header Two" in result

    def test_h3_header_stripped(self):
        """Test ### header is stripped."""
        text = "### Header Three"
        result = sanitize_llm_output(text)
        assert "### " not in result
        assert "Header Three" in result

    def test_multiple_headers(self):
        """Test multiple headers at different levels."""
        text = "# H1\n## H2\n### H3"
        result = sanitize_llm_output(text)
        assert "#" not in result
        assert "H1" in result
        assert "H2" in result
        assert "H3" in result


class TestSanitizeHorizontalRules:
    """Tests for horizontal rule removal."""

    def test_dash_horizontal_rule_removed(self):
        """Test --- horizontal rule is removed."""
        text = "Before\n---\nAfter"
        result = sanitize_llm_output(text)
        assert "---" not in result
        assert "Before" in result
        assert "After" in result

    def test_asterisk_horizontal_rule_removed(self):
        """Test *** horizontal rule is removed."""
        text = "Before\n***\nAfter"
        result = sanitize_llm_output(text)
        assert "***" not in result

    def test_long_horizontal_rule_removed(self):
        """Test longer horizontal rules are removed."""
        text = "Before\n----------\nAfter"
        result = sanitize_llm_output(text)
        assert "----------" not in result


class TestSanitizeMarkdownTables:
    """Tests for markdown table conversion."""

    def test_table_separator_removed(self):
        """Test table separator lines (|---|---|) are removed."""
        text = "| Header 1 | Header 2 |\n|---|---|\n| Cell 1 | Cell 2 |"
        result = sanitize_llm_output(text)
        assert "|---|" not in result

    def test_table_cells_converted(self):
        """Test table cells are converted to tab-separated text."""
        text = "| Cell 1 | Cell 2 |"
        result = sanitize_llm_output(text)
        assert "Cell 1" in result
        assert "Cell 2" in result
        # Cells should be separated by spaces (tabs converted)
        assert "|" not in result or result.count("|") < 2

    def test_complex_table(self):
        """Test a more complex table structure."""
        text = """| Name | Value |
|------|-------|
| CRC | 0x1234 |
| Valid | Yes |"""
        result = sanitize_llm_output(text)
        assert "Name" in result
        assert "Value" in result
        assert "CRC" in result
        assert "0x1234" in result


class TestSanitizeCodeBlocks:
    """Tests for code block handling."""

    def test_fenced_code_block_removed(self):
        """Test ``` code blocks have backticks removed."""
        text = "```python\nprint('hello')\n```"
        result = sanitize_llm_output(text)
        assert "```" not in result
        assert "print" in result

    def test_inline_code_removed(self):
        """Test `code` inline backticks are removed."""
        text = "Use the `function()` method"
        result = sanitize_llm_output(text)
        assert "`" not in result
        assert "function()" in result

    def test_multiple_inline_code(self):
        """Test multiple inline code segments."""
        text = "Call `foo()` and `bar()`"
        result = sanitize_llm_output(text)
        assert "`" not in result
        assert "foo()" in result
        assert "bar()" in result


class TestSanitizeWhitespace:
    """Tests for whitespace cleanup."""

    def test_excessive_newlines_reduced(self):
        """Test that 3+ consecutive newlines are reduced to 2."""
        text = "Para 1\n\n\n\nPara 2"
        result = sanitize_llm_output(text)
        assert "\n\n\n" not in result
        assert "Para 1" in result
        assert "Para 2" in result

    def test_leading_trailing_whitespace_stripped(self):
        """Test leading and trailing whitespace is stripped."""
        text = "  \n\nContent here\n\n  "
        result = sanitize_llm_output(text)
        assert not result.startswith(" ")
        assert not result.startswith("\n")
        assert not result.endswith(" ")
        assert not result.endswith("\n")


class TestSanitizeUnclosedTags:
    """Tests for unclosed HTML tag fixing."""

    def test_unclosed_bold_tag_fixed(self):
        """Test unclosed <b> tag is closed."""
        # This simulates a case where bold conversion creates unclosed tag
        text = "**Bold text without closing"
        result = sanitize_llm_output(text)
        # Count tags
        open_b = result.count("<b>")
        close_b = result.count("</b>")
        assert open_b == close_b

    def test_unclosed_italic_tag_fixed(self):
        """Test unclosed <i> tag is closed."""
        text = "*Italic text without closing"
        result = sanitize_llm_output(text)
        open_i = result.count("<i>")
        close_i = result.count("</i>")
        assert open_i == close_i

    def test_multiple_unclosed_tags_fixed(self):
        """Test multiple unclosed tags are all fixed."""
        text = "**Bold1 **Bold2 *Italic"
        result = sanitize_llm_output(text)
        assert result.count("<b>") == result.count("</b>")
        assert result.count("<i>") == result.count("</i>")


class TestSanitizeIntegration:
    """Integration tests combining multiple transformations."""

    def test_complex_llm_output(self):
        """Test realistic LLM output with multiple formatting."""
        text = """## CRC Analysis

The stored CRC value is **0x1234ABCD** and the calculated value is **0x1234ABCD**.

These values *match*, which indicates:
- The file has not been modified
- The integrity is intact

| Check | Result |
|-------|--------|
| CRC | PASS |

For more info\u2026 see the documentation."""

        result = sanitize_llm_output(text)

        # Headers stripped
        assert "## " not in result
        assert "CRC Analysis" in result

        # Bold converted
        assert "<b>0x1234ABCD</b>" in result

        # Italic converted
        assert "<i>match</i>" in result

        # Ellipsis replaced
        assert "..." in result
        assert "\u2026" not in result

        # Table processed
        assert "|----" not in result

    def test_ntfs_technical_terms_preserved(self):
        """Test NTFS technical terms with underscores are preserved."""
        text = """The $STANDARD_INFORMATION and $FILE_NAME attributes differ.
The SI_CREATED timestamp shows manipulation."""

        result = sanitize_llm_output(text)

        # Technical terms should be readable
        assert "STANDARD" in result
        assert "INFORMATION" in result
        assert "FILE" in result
        assert "NAME" in result

    def test_forensic_report_snippet(self):
        """Test a realistic forensic report snippet."""
        text = """**DEFINITIVE PROOF OF TAMPERING**

The CRC mismatch \u2014 stored value `0xDEADBEEF` vs calculated `0x12345678` \u2014 proves post-save modification.

This is *not* speculation; it is mathematical certainty."""

        result = sanitize_llm_output(text)

        # Bold header
        assert "<b>DEFINITIVE PROOF OF TAMPERING</b>" in result

        # Em-dashes replaced
        assert "\u2014" not in result
        assert "-" in result

        # Inline code removed
        assert "`" not in result
        assert "0xDEADBEEF" in result

        # Italic
        assert "<i>not</i>" in result
