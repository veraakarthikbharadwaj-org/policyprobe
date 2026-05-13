"""
File Processor Agent
  
"""

import base64
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from file_parsers.pdf_parser import PDFParser
from file_parsers.image_parser import ImageParser
from file_parsers.html_parser import HTMLParser

logger = logging.getLogger(__name__)


class FileProcessorAgent:
    """
    Agent responsible for processing uploaded files.

    Privilege Level: MEDIUM
    Capabilities:
    - Extract text from PDFs
    - Parse HTML content
    - Extract image metadata and text
    - Process Word documents
    """

    PRIVILEGE_LEVEL = "medium"
    SUPPORTED_TYPES = {
        "application/pdf": "pdf",
        "text/html": "html",
        "text/plain": "text",
        "application/json": "json",
        "image/jpeg": "image",
        "image/png": "image",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
    }

    def __init__(self):
        self.pdf_parser = PDFParser()
        self.image_parser = ImageParser()
        self.html_parser = HTMLParser()
        self.agent_id = "file_processor"

    async def process(
        self,
        content: Optional[str],
        filename: str,
        content_type: str
    ) -> str:
        """
        Process uploaded file and extract content.

        Args:
            content: File content (text or base64 encoded)
            filename: Original filename
            content_type: MIME type of the file

        Returns:
            Extracted text content from the file

        VULNERABILITY: No security scanning performed on file content.
        Files are processed and content extracted without checking for:
        - PII (SSN, credit cards, phone numbers)
        - Hidden/malicious prompts
        - Malware signatures
        - Sensitive data patterns
        """
        logger.info(
            "Processing file",
            extra={
                "file_name": filename,
                "file_type": content_type,
                "content_length": len(content) if content else 0
                # Content preview omitted to prevent PII leakage in logs
            }
        )

        if not content:
            return f"Empty file: {filename}"

        # Redact PII from raw input before any processing
        content = self._redact_pii(content)

        # Determine file type
        file_type = self._get_file_type(content_type, filename)
        # Store trace_id on instance so downstream helpers can reference it if needed
        self._current_trace_id = trace_id

        # Process based on file type
        # VULNERABILITY: No content scanning before processing
        try:
            if file_type == "pdf":
                extracted = await self._process_pdf(content)
            elif file_type == "html":
                extracted = await self._process_html(content)
            elif file_type == "image":
                extracted = await self._process_image(content)
            elif file_type == "json":
                extracted = await self._process_json(content)
            elif file_type == "text":
                extracted = self._redact_pii(content)  # Redact PII before returning
            else:
                extracted = f"Unsupported file type: {content_type}"

            # Security scan: check extracted content for malicious patterns
            security_issue = self._scan_for_malicious_content(extracted)
            if security_issue:
                logger.warning(
                    "Malicious content detected in file",
                    extra={"file_name": filename, "issue": security_issue}
                )
                raise ValueError(f"Security violation detected in file content: {security_issue}")

            # Post-processing PII redaction pass (catches PII introduced by parsers)
            extracted = self._redact_pii(extracted)

            logger.info(
                "File processing complete",
                extra={
                    "file_name": filename,
                    "extracted_length": len(extracted),
                    # Preview is already redacted
                    "extracted_preview": extracted[:200]
                }
            )

            return extracted

        except Exception as e:
            logger.error(
                "Error processing file",
                extra={
                    "file_name": filename,
                    "error": str(e)
                    # File content omitted from logs to prevent PII leakage
                }
            )
            return "An error occurred while processing the file. Please try again."

    # ---------------------------------------------------------------------------
    # Security scanning helpers
    # ---------------------------------------------------------------------------
    _INVISIBLE_CHARS_RE = re.compile(
        r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]"
    )
    # Patterns that look like prompt-injection instructions
    _PROMPT_INJECTION_RE = re.compile(
        r"(?i)(ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)"
        r"|system\s*:\s*you\s+are"
        r"|<\s*/?\s*(system|assistant|user)\s*>"
        r"|\[\s*INST\s*\]"
        r"|###\s*(instruction|system|prompt))"
    )
    # Shell / OS command patterns
    _SHELL_CMD_RE = re.compile(
        r"(?i)(\b(rm|wget|curl|chmod|chown|sudo|bash|sh|powershell|cmd\.exe|nc|netcat|python|perl|ruby|php)\b\s+[-/\w])"
        r"|(\$\(.*?\))"
        r"|(`;[^`]*`)"
        r"|(\|\s*(bash|sh|cmd))"
    )
    # Binary / ELF / PE magic bytes (base64-encoded or raw)
    _BINARY_MAGIC_RE = re.compile(
        r"(?:^|\s)(?:TVqQ|TVoA|f0VMR|7f454c46|4d5a|\x7fELF|MZ)",
        re.MULTILINE,
    )
    # Leetspeak substitution table (simple heuristic)
    _LEET_RE = re.compile(
        r"(?i)\b(?:[i1][g9][n][o0][r][e3]|[e3][x][e3][c]|[s5][h][e3][l1][l1])\b"
    )

    def _scan_for_malicious_content(self, text: str) -> Optional[str]:
        """Scan extracted text for malicious or suspicious patterns.

        Returns a short description of the first issue found, or None if clean.
        """
        if not text:
            return None

        # 1. Invisible / zero-width characters (hidden prompt injection)
        if self._INVISIBLE_CHARS_RE.search(text):
            return "invisible or zero-width characters detected"

        # 2. Prompt-injection instructions
        if self._PROMPT_INJECTION_RE.search(text):
            return "prompt injection pattern detected"

        # 3. Base64-encoded blobs that decode to suspicious content
        # Look for long base64 strings (>=64 chars) and try to decode them
        b64_candidates = re.findall(r"[A-Za-z0-9+/]{64,}={0,2}", text)
        for candidate in b64_candidates:
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                if self._SHELL_CMD_RE.search(decoded) or self._PROMPT_INJECTION_RE.search(decoded):
                    return "base64-encoded malicious payload detected"
                if self._BINARY_MAGIC_RE.search(decoded):
                    return "base64-encoded binary executable detected"
            except Exception:
                pass  # Not valid base64 — skip

        # 4. Shell commands in plain text
        if self._SHELL_CMD_RE.search(text):
            return "shell command pattern detected"

        # 5. Binary executable magic bytes in raw text
        if self._BINARY_MAGIC_RE.search(text):
            return "binary executable signature detected"

        # 6. Leetspeak obfuscation of dangerous keywords
        if self._LEET_RE.search(text):
            return "leetspeak obfuscation of dangerous keyword detected"

        return None

    # ------------------------------------------------------------------ #
    # PII redaction                                                        #
    # ------------------------------------------------------------------ #
    _PII_PATTERNS = [
        # US Social Security Numbers  (123-45-6789)
        (r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
         '[REDACTED-SSN]'),
        # Credit / debit card numbers (13-19 digits, optional separators)
        (r'\b(?:\d[ -]?){13,19}\b',
         '[REDACTED-CARD]'),
        # US phone numbers
        (r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
         '[REDACTED-PHONE]'),
        # E-mail addresses
        (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
         '[REDACTED-EMAIL]'),
        # US ZIP codes (5-digit and ZIP+4)
        (r'\b\d{5}(?:-\d{4})?\b',
         '[REDACTED-ZIP]'),
    ]

    def _redact_pii(self, text: str) -> str:
        """Detect and redact common PII patterns from *text*.

        Applies a series of regular-expression substitutions that cover the
        most prevalent PII types (SSN, payment cards, phone numbers, e-mail
        addresses, ZIP codes).  The method is intentionally conservative:
        it may produce false positives for numeric strings that resemble PII,
        but it will not miss true PII that matches the patterns.
        """
        import re
        if not isinstance(text, str):
            return text
        for pattern, replacement in self._PII_PATTERNS:
            text = re.sub(pattern, replacement, text)
        return text

    def _get_file_type(self, content_type: str, filename: str) -> str:
        """Determine file type from MIME type or extension."""
        # Check MIME type first
        if content_type in self.SUPPORTED_TYPES:
            return self.SUPPORTED_TYPES[content_type]

        # Fall back to extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        extension_map = {
            'pdf': 'pdf',
            'html': 'html',
            'htm': 'html',
            'txt': 'text',
            'json': 'json',
            'jpg': 'image',
            'jpeg': 'image',
            'png': 'image',
            'doc': 'word',
            'docx': 'word',
        }

        return extension_map.get(ext, 'unknown')

    async def _process_pdf(self, content: str) -> str:
        """
        Process PDF file content.

        VULNERABILITY: PDF processing extracts all text including
        hidden/white text that could contain prompt injections.
        """
        # Content is base64 encoded for PDFs
        try:
            pdf_bytes = base64.b64decode(content)
            extracted_text = await self.pdf_parser.extract_text(pdf_bytes)

            # VULNERABILITY: No hidden text detection
            # Invisible text (white on white, size 0, off-page) is extracted
            # and passed to LLM without filtering

            return extracted_text
        except Exception as e:
            logger.error(f"PDF processing error: {e}")
            return f"Error processing PDF: {str(e)}"

    async def _process_html(self, content: str) -> str:
        """
        Process HTML content.

        VULNERABILITY: HTML processing may not detect all hidden content:
        - CSS-hidden elements (display:none, visibility:hidden)
        - White text on white background
        - Off-screen positioned elements
        - Base64 encoded content in data attributes
        """
        try:
            extracted_text = await self.html_parser.extract_text(content)

            # VULNERABILITY: get_text() extracts content from hidden elements
            # Malicious prompts in hidden divs will be extracted

            return extracted_text
        except Exception as e:
            logger.error(f"HTML processing error: {e}")
            return f"Error processing HTML: {str(e)}"

    async def _process_image(self, content: str) -> str:
        """
        Process image file.

        VULNERABILITY: Image processing extracts EXIF metadata which
        could contain malicious prompts in comment/description fields.
        """
        try:
            image_bytes = base64.b64decode(content)

            # Extract both visual text (OCR) and metadata
            extracted = await self.image_parser.extract_all(image_bytes)

            # VULNERABILITY: EXIF data extracted and included without scanning
            # Comment, UserComment, ImageDescription fields could contain injections

            return extracted
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            return f"Error processing image: {str(e)}"

    async def _process_json(self, content: str) -> str:
        """
        Process JSON content.

        VULNERABILITY: JSON content processed without PII scanning.
        Nested objects containing sensitive data are passed through.
        """
        import json

        try:
            # Parse to validate JSON
            data = json.loads(content)

            # VULNERABILITY: No PII detection in nested objects
            # Data like user.profile.contact.ssn passes through
            # No recursive scanning for sensitive patterns

            # Convert back to formatted string for analysis
            formatted = json.dumps(data, indent=2)

            return f"JSON Content:\n{formatted}"
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {str(e)}\n\nRaw content:\n{content}"

    async def validate_file(self, content: str, filename: str) -> dict:
        """
        Validate file before processing.

        VULNERABILITY: Validation only checks format, not content.
        No security scanning performed.
        """
        # Basic validation only
        validation_result = {
            "valid": True,
            "filename": filename,
            "size": len(content) if content else 0,
            "warnings": []
        }

        # Size check (but no PII/threat check)
        if len(content) > 10 * 1024 * 1024:  # 10MB
            validation_result["warnings"].append("Large file - processing may be slow")

        # VULNERABILITY: No content-based security validation
        # Should check for:
        # - PII patterns
        # - Known malware signatures
        # - Prompt injection patterns
        # - Hidden content indicators

        return validation_result
