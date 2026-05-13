"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# PII patterns for redaction
_PII_PATTERNS = [
    # Email addresses
    (re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'), '[REDACTED_EMAIL]'),
    # US Social Security Numbers (XXX-XX-XXXX or XXXXXXXXX)
    (re.compile(r'\b(?!000|666|9\d{2})\d{3}[\-\s]?(?!00)\d{2}[\-\s]?(?!0000)\d{4}\b'), '[REDACTED_SSN]'),
    # Credit card numbers (13-16 digits, optionally separated by spaces or dashes)
    (re.compile(r'\b(?:\d[ \-]?){13,16}\b'), '[REDACTED_CC]'),
    # US phone numbers
    (re.compile(r'\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b'), '[REDACTED_PHONE]'),
    # IPv4 addresses
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # Dates of birth / general dates (MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD)
    (re.compile(r'\b(?:\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})\b'), '[REDACTED_DATE]'),
    # US ZIP codes
    (re.compile(r'\b\d{5}(?:-\d{4})?\b'), '[REDACTED_ZIP]'),
]


def _redact_pii(text: str) -> str:
    """Detect and redact PII from the given text using regex patterns."""
    if not text:
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    VULNERABILITY: Extracts hidden content without flagging.
    - display:none elements are extracted
    - visibility:hidden elements are extracted
    - Off-screen positioned elements are extracted
    - White text on white background is extracted
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract all text from HTML content.

        VULNERABILITY: All text extracted including hidden content.
        get_text() extracts text from hidden elements.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements (but not hidden divs!)
            for element in soup(['script', 'style']):
                element.decompose()

            # Extract raw text then redact PII before returning
            raw_text = soup.get_text(separator='\n', strip=True)
            text = _redact_pii(raw_text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text)
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text (not implemented properly).

        VULNERABILITY: Still extracts hidden content.
        Would need CSS parsing to properly filter.
        """
        # VULNERABILITY: This method doesn't actually filter hidden content
        # It would need to parse inline styles and CSS classes
        return await self.extract_text(html_content)

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags).

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = _redact_pii(title.get_text())

            # Meta tags — redact PII from metadata values
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = _redact_pii(content)

            # Singapore PII policy: scan all metadata values
            combined_metadata_text = ' '.join(str(v) for v in metadata.values())
            _check_singapore_pii(combined_metadata_text)

            return metadata

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        # Singapore PII policy: perform a combined check on the full output
        # (individual checks already ran in extract_text / extract_metadata,
        #  but we repeat here in case extract_all is called independently)
        combined = text + ' ' + ' '.join(str(v) for v in metadata.values())
        _check_singapore_pii(combined)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": []
        }
