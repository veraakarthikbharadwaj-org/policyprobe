"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES (for Unifai demo):
- Extracts ALL text including hidden/white text
- No detection of suspicious formatting
- No malware scanning
"""

import io
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Singapore PII detection patterns
# ---------------------------------------------------------------------------
_SG_PII_PATTERNS: List[Tuple[str, str]] = [
    # NRIC / FIN  – S/T/F/G followed by 7 digits and a letter
    ("NRIC/FIN", r"\b[STFG]\d{7}[A-Z]\b"),
    # Singapore passport – E followed by 7 or 8 digits
    ("Passport", r"\bE\d{7,8}\b"),
    # Singapore mobile / local phone numbers
    ("Phone", r"\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b"),
    # Singapore postal code (6 digits, often preceded by 'Singapore')
    ("PostalCode", r"\bSingapore\s+\d{6}\b"),
    # Generic 6-digit postal code standalone
    ("PostalCode", r"\b\d{6}\b"),
    # Common name salutations followed by capitalised words
    ("Name", r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b"),
]

_COMPILED_PII = [(label, re.compile(pattern)) for label, pattern in _SG_PII_PATTERNS]


def _scan_for_sg_pii(text: str) -> List[str]:
    """Return a list of PII category labels found in *text*."""
    found: List[str] = []
    for label, pattern in _COMPILED_PII:
        if pattern.search(text):
            if label not in found:
                found.append(label)
    return found


def _redact_sg_pii(text: str) -> str:
    """Replace detected Singapore PII tokens with a redaction placeholder."""
    for label, pattern in _COMPILED_PII:
        text = pattern.sub(f"[REDACTED-{label}]", text)
    return text


class PDFParser:
    """
    Parses PDF files and extracts text content.

    VULNERABILITY: Extracts hidden text without flagging it.
    - White text on white background is extracted
    - Zero-size font text is extracted
    - Off-page text is extracted
    - Overlapping layers are all extracted
    """

    # PII patterns to detect and redact
    _PII_PATTERNS = [
        # Social Security Numbers: 123-45-6789 or 123456789
        (re.compile(r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b'), '[SSN REDACTED]'),
        # Email addresses
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
        # US phone numbers: (123) 456-7890, 123-456-7890, 123.456.7890, +11234567890
        (re.compile(r'(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b'), '[PHONE REDACTED]'),
        # Credit/debit card numbers (13-16 digits, optionally space/dash separated)
        (re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{1,4}\b'), '[CARD REDACTED]'),
        # Bank account numbers (8-17 consecutive digits not already matched)
        (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    ]

    def __init__(self):
        pass

    def _redact_pii(self, text: str) -> str:
        """Detect and redact PII from extracted text."""
        redacted = text
        for pattern, replacement in self._PII_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        VULNERABILITY: All text extracted including hidden content.
        No detection or warning for suspicious formatting.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                # VULNERABILITY: Extract all text without filtering
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text)
                        }
                    )

                        full_text = '\n\n'.join(text_parts)

            # ---------------------------------------------------------------
            # Singapore PII check – scan before returning extracted text
            # ---------------------------------------------------------------
            pii_categories = _scan_for_sg_pii(full_text)
            if pii_categories:
                logger.warning(
                    "Singapore PII detected in uploaded PDF; content redacted before return.",
                    extra={"pii_categories": pii_categories}
                )
                full_text = _redact_sg_pii(full_text)

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text),
                    "pii_detected": bool(pii_categories),
                    "pii_categories": pii_categories,
                }
            )

            return full_text

        except Exception as e:
            logger.error("PDF extraction error", exc_info=True)
            return "Error extracting PDF. Please check the file and try again."

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata.

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    metadata[key] = reader.metadata[key]

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        # Re-scan the already-redacted text to collect category labels for warnings
        pii_categories = _scan_for_sg_pii(text)  # will be empty if redaction succeeded
        warnings: List[str] = []
        if pii_categories:
            warnings.append(
                f"Singapore PII categories detected and redacted: {', '.join(pii_categories)}"
            )

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }
