"""
DWG Forensic Tool - Text Utilities

Utilities for text processing in report generation.
"""

import re


def sanitize_llm_output(text: str) -> str:
    """
    Sanitize LLM output for ReportLab compatibility.

    Converts markdown formatting to HTML and fixes character encoding issues.
    ReportLab's Paragraph class accepts a subset of HTML, not markdown.

    Args:
        text: Raw LLM output text

    Returns:
        Sanitized text ready for ReportLab Paragraph
    """
    if not text:
        return ""

    # Step 1: Fix character encoding - replace problematic Unicode characters
    # Em-dash, en-dash, and other dashes to regular hyphen
    text = text.replace('\u2014', '-')  # Em-dash
    text = text.replace('\u2013', '-')  # En-dash
    text = text.replace('\u2212', '-')  # Minus sign
    text = text.replace('\u2010', '-')  # Hyphen
    text = text.replace('\u2011', '-')  # Non-breaking hyphen

    # Smart quotes to regular quotes
    text = text.replace('\u2018', "'")  # Left single quote
    text = text.replace('\u2019', "'")  # Right single quote
    text = text.replace('\u201c', '"')  # Left double quote
    text = text.replace('\u201d', '"')  # Right double quote

    # Other problematic characters
    text = text.replace('\u2026', '...')  # Ellipsis
    text = text.replace('\u00a0', ' ')    # Non-breaking space
    text = text.replace('\u2022', '*')    # Bullet point
    text = text.replace('\u00b7', '*')    # Middle dot

    # Step 2: Escape XML special characters BEFORE adding HTML tags
    # But be careful not to double-escape
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')

    # Step 3: Convert markdown formatting to HTML
    # Bold: **text** or __text__ -> <b>text</b>
    text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__([^_]+)__', r'<b>\1</b>', text)

    # Italic: *text* -> <i>text</i> (but not ** which is bold)
    # NOTE: We do NOT convert _text_ to italic because underscores appear in
    # technical terms like $FILE_NAME, $STANDARD_INFORMATION, etc.
    text = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'<i>\1</i>', text)

    # Step 4: Handle markdown headers - convert to bold
    # ### Header -> Header (bold handled by caller)
    text = re.sub(r'^#{1,6}\s*', '', text, flags=re.MULTILINE)

    # Step 5: Handle markdown horizontal rules
    text = re.sub(r'^-{3,}$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\*{3,}$', '', text, flags=re.MULTILINE)

    # Step 6: Handle markdown tables - convert to plain text
    # Tables with | will be converted to tab-separated text
    lines = text.split('\n')
    processed_lines = []
    for line in lines:
        # Skip table separator lines (|---|---|)
        if re.match(r'^\s*\|[-:\s|]+\|\s*$', line):
            continue
        # Convert table rows to plain text with tabs
        if '|' in line and line.strip().startswith('|') and line.strip().endswith('|'):
            # Remove leading/trailing pipes and split by |
            cells = line.strip()[1:-1].split('|')
            # Clean up cells and join with tabs
            cleaned_cells = [cell.strip() for cell in cells]
            processed_lines.append('    '.join(cleaned_cells))
        else:
            processed_lines.append(line)

    text = '\n'.join(processed_lines)

    # Step 7: Handle code blocks (basic handling - just remove the backticks)
    text = re.sub(r'```[a-z]*\n?', '', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)

    # Step 8: Clean up excessive whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = text.strip()

    # Step 9: Safety check - fix unclosed HTML tags
    # Count opening and closing tags for b and i, close any unclosed ones
    for tag in ['b', 'i']:
        open_count = len(re.findall(f'<{tag}>', text))
        close_count = len(re.findall(f'</{tag}>', text))
        if open_count > close_count:
            # Add missing closing tags at the end
            text += f'</{tag}>' * (open_count - close_count)

    return text
