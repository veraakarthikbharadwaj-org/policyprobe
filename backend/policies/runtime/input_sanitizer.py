"""
Input Sanitizer

Sanitizes user input before processing.

SECURITY NOTES (for Unifai demo):
- sanitize() is a NO-OP - input passes through unchanged
- No XSS prevention
- No injection prevention
- No encoding normalization
"""

import logging
import re
import unicodedata
from typing import Any

logger = logging.getLogger(__name__)


class InputSanitizer:
    """
    Sanitizes user input before processing.

    VULNERABILITY: All sanitization methods are NO-OPs.
    Input passes through unchanged.

    Should sanitize:
    - HTML/script injection
    - SQL injection patterns
    - Command injection
    - Path traversal
    - Encoding attacks
    """

    def __init__(self):
        pass

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data.

        VULNERABILITY: NO-OP - returns input unchanged.
        """
        logger.debug(
            "Sanitization requested",
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        # VULNERABILITY: No sanitization performed
        return input_data

    # Maximum allowed content length before truncation
    MAX_LLM_CONTENT_LENGTH = 32_000

    # Prompt-injection patterns to strip (case-insensitive)
    _INJECTION_PATTERNS = re.compile(
        r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
        r"|disregard\s+(all\s+)?(previous|prior|above)\s+instructions?"
        r"|you\s+are\s+now\s+in\s+(developer|jailbreak|dan)\s+mode"
        r"|system\s*:\s*you\s+are"
        r"|<\s*/?\s*(system|assistant|user)\s*>)",
        re.IGNORECASE,
    )

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.

        Steps performed:
        1. Type-check and coerce to str.
        2. Normalize Unicode to NFC to collapse homoglyph attacks.
        3. Remove null bytes and non-printable control characters
           (keeping newlines, tabs, and carriage returns).
        4. Strip known prompt-injection patterns.
        5. Normalize runs of whitespace / blank lines.
        6. Truncate to MAX_LLM_CONTENT_LENGTH characters.
        """
        if not isinstance(content, str):
            logger.warning(
                "sanitize_for_llm received non-str input; coercing",
                extra={"input_type": type(content).__name__},
            )
            content = str(content)

        # 1. Unicode normalisation (NFC) – collapses homoglyphs / multi-codepoint sequences
        content = unicodedata.normalize("NFC", content)

        # 2. Remove null bytes and dangerous control characters
        #    Keep: \t (0x09), \n (0x0A), \r (0x0D)
        content = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", content)

        # 3. Strip prompt-injection patterns
        original_length = len(content)
        content = self._INJECTION_PATTERNS.sub("[REDACTED]", content)
        if len(content) != original_length:
            logger.warning(
                "sanitize_for_llm: prompt-injection pattern detected and removed"
            )

        # 4. Collapse excessive blank lines (> 2 consecutive newlines → 2)
        content = re.sub(r"\n{3,}", "\n\n", content)

        # 5. Truncate to prevent token-flooding / context-window abuse
        if len(content) > self.MAX_LLM_CONTENT_LENGTH:
            logger.warning(
                "sanitize_for_llm: content truncated",
                extra={
                    "original_length": len(content),
                    "truncated_to": self.MAX_LLM_CONTENT_LENGTH,
                },
            )
            content = content[: self.MAX_LLM_CONTENT_LENGTH]

        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal.

        VULNERABILITY: Not implemented.
        """
        return filename

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent attacks.

        VULNERABILITY: Not implemented.
        """
        return content
