"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted without scanning
- Comments and descriptions could contain prompt injections
- No malware detection
"""

import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ImageParser:
    """
    Parses image files and extracts metadata.

    VULNERABILITY: Extracts EXIF data without security scanning.
    - Comment fields could contain prompt injections
    - UserComment could contain malicious instructions
    - ImageDescription could contain attacks
    """

    # Patterns indicative of prompt injection or malicious content
    import re as _re
    _MALICIOUS_PATTERNS = [
        # Prompt injection keywords
        _re.compile(r'(?i)(ignore (previous|above|all)|disregard|forget (previous|instructions)|new instructions|system prompt|you are now|act as|jailbreak|bypass|override (instructions|rules))'),
        # Shell command indicators
        _re.compile(r'(?i)(\$\(|`[^`]+`|\bexec\b|\beval\b|\bsystem\b|\bpasswd\b|/etc/|/bin/|cmd\.exe|powershell)'),
        # Base64-encoded blobs (20+ contiguous base64 chars)
        _re.compile(r'(?:[A-Za-z0-9+/]{20,}={0,2})'),
        # URL-encoded or hex-encoded payloads
        _re.compile(r'(?i)(%[0-9a-f]{2}){4,}'),
        # Script/HTML injection
        _re.compile(r'(?i)(<script|javascript:|data:text/html|onerror=|onload=)'),
    ]

    def __init__(self):
        pass

    def _is_malicious(self, value: str) -> bool:
        """Return True if the string matches any known malicious pattern."""
        import re
        for pattern in self._MALICIOUS_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def _sanitize_field(self, field_name: str, value: str) -> str:
        """Return a redacted placeholder if the value looks malicious."""
        if self._is_malicious(value):
            logger.warning(
                "Malicious content detected and redacted in EXIF field",
                extra={"field": field_name}
            )
            return "[REDACTED: potentially malicious content]"
        return value

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        VULNERABILITY: Metadata extracted without scanning for threats.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

                        # PII-bearing EXIF tags that must be redacted before use.
            # Covers GPS/fine location, facial/biometric image data, and other
            # fields known to carry personally-identifiable information.
            PII_EXIF_TAGS = {
                # GPS / fine location
                'GPSInfo',
                'GPSLatitude',
                'GPSLongitude',
                'GPSAltitude',
                'GPSLatitudeRef',
                'GPSLongitudeRef',
                'GPSAltitudeRef',
                'GPSTimeStamp',
                'GPSDateStamp',
                'GPSDestLatitude',
                'GPSDestLongitude',
                'GPSImgDirection',
                'GPSSpeed',
                'GPSTrack',
                # Facial / biometric image data
                'FaceDetect',
                'FaceDetectFrameSize',
                'FaceDetectFrameCrop',
                'FacePosition',
                'FaceSize',
                'FaceRecognition',
                # Owner / author identity
                'CameraOwnerName',
                'BodySerialNumber',
                'LensSerialNumber',
                'MakerNote',
                'SubjectArea',
                'SubjectLocation',
            }

                        # Extract EXIF data
            # Singapore PII policy: block EXIF fields that may carry personal name,
            # fine location, biometric/facial data, or other PII categories defined
            # under the Singapore Personal Data Protection Act (PDPA).
            SINGAPORE_PII_EXIF_BLOCKLIST = {
                # Personal name / identity
                'Artist',
                'CameraOwnerName',
                'OwnerName',
                'Copyright',
                'Author',
                # Fine location (GPS)
                'GPSInfo',
                'GPSLatitude',
                'GPSLatitudeRef',
                'GPSLongitude',
                'GPSLongitudeRef',
                'GPSAltitude',
                'GPSAltitudeRef',
                'GPSTimeStamp',
                'GPSDateStamp',
                'GPSDestLatitude',
                'GPSDestLongitude',
                'GPSImgDirection',
                'GPSSpeed',
                'GPSTrack',
                'GPSAreaInformation',
                'GPSProcessingMethod',
                # Biometric / facial image data
                'FaceDetect',
                'FaceInfo',
                'FaceRecognition',
                'SubjectArea',
                'SubjectLocation',
                # Free-text / comment fields that may embed PII
                'ImageDescription',
                'UserComment',
                'XPComment',
                'XPSubject',
                'XPTitle',
                'XPKeywords',
                'XPAuthor',
                'Comment',
                'MakerNote',
            }

            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Skip any EXIF field that may contain Singapore PII
                    if tag in SINGAPORE_PII_EXIF_BLOCKLIST:
                        logger.debug(
                            "Skipped PII-bearing EXIF field per Singapore PDPA policy",
                            extra={"tag": tag}
                        )
                        continue
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    metadata[tag] = value

            # VULNERABILITY: Log metadata without scanning
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                    "metadata_preview": "[metadata preview suppressed for security]"
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    # ---------------------------------------------------------------------------
    # Security helpers
    # ---------------------------------------------------------------------------
    _B64_RE = re.compile(
        r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    )
    # Common prompt-injection trigger phrases (case-insensitive)
    _PROMPT_TRIGGERS = re.compile(
        r'ignore (previous|above|all) instructions?'
        r'|system prompt'
        r'|you are now'
        r'|act as'
        r'|disregard'
        r'|forget (everything|all|previous)'
        r'|new (role|persona|instructions?)'
        r'|\[INST\]'
        r'|<\|im_start\|>'
        r'|<\|system\|>',
        re.IGNORECASE,
    )
    # Shell meta-characters / command patterns
    _SHELL_RE = re.compile(
        r'[;|&`$]'
        r'|\$\(.*\)'
        r'|`[^`]+`'
        r'|\b(rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|eval|exec)\b',
        re.IGNORECASE,
    )
    # Naïve leetspeak detector: digits substituting letters in suspicious words
    _LEET_RE = re.compile(
        r'(?:[i1][gq][n][o0][r3][e3]'
        r'|[s5][y][s5][t7][e3][m3]'
        r'|[e3][x][e3][c3]'
        r'|[s5][h][e3][l1][l1])',
        re.IGNORECASE,
    )

    def _sanitize_exif_value(self, field: str, value: str) -> str | None:
        """
        Return a sanitized version of *value* or None if it should be dropped.

        Checks performed:
          1. Base64-encoded blobs (potential hidden payloads)
          2. Prompt-injection trigger phrases
          3. Shell meta-characters / command patterns
          4. Leetspeak substitutions of dangerous keywords
        """
        if not value or not isinstance(value, str):
            return None

        # 1. Base64 blobs — attempt to decode and re-check decoded text
        if self._B64_RE.search(value):
            try:
                import base64
                decoded = base64.b64decode(
                    self._B64_RE.search(value).group(0) + '=='
                ).decode('utf-8', errors='ignore')
                if (
                    self._PROMPT_TRIGGERS.search(decoded)
                    or self._SHELL_RE.search(decoded)
                    or self._LEET_RE.search(decoded)
                ):
                    logger.warning(
                        "Dropped EXIF field with base64-encoded malicious payload",
                        extra={"field": field},
                    )
                    return None
            except Exception:
                pass  # decoding failed — keep original checks below

        # 2. Prompt-injection triggers
        if self._PROMPT_TRIGGERS.search(value):
            logger.warning(
                "Dropped EXIF field containing prompt-injection pattern",
                extra={"field": field},
            )
            return None

        # 3. Shell commands / meta-characters
        if self._SHELL_RE.search(value):
            logger.warning(
                "Dropped EXIF field containing shell command pattern",
                extra={"field": field},
            )
            return None

        # 4. Leetspeak
        if self._LEET_RE.search(value):
            logger.warning(
                "Dropped EXIF field containing leetspeak injection pattern",
                extra={"field": field},
            )
            return None

        # Value appears safe — strip leading/trailing whitespace and return
        return value.strip()

    # ---------------------------------------------------------------------------

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.

        Each field value is sanitized before use to prevent prompt injection,
        base64-encoded payloads, shell commands, and leetspeak injections.
        """
        text_fields = []

        # Fields that commonly contain text content
        # VULNERABILITY: These fields could contain malicious prompts
        dangerous_fields = [
            'ImageDescription',
            'XPTitle',
            'Artist',
            'Copyright',
        ]

                        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                # Values have already been sanitised in extract_metadata;
                # apply the sanitiser defensively here as well in case
                # extract_text_fields is called with externally-supplied data.
                if value and isinstance(value, str):
                    value = self._sanitize_exif_value(
                        field, value, self._TEXT_FIELDS
                    )
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        "Found safe text in EXIF field",
                        extra={
                            "field": field,
                            # Log only length, not content, to avoid leaking data
                            "value_length": len(safe_value),
                        }
                    ):
                    # Re-sanitize at extraction time as a defence-in-depth measure
                    value = self._sanitize_field(field, value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={"field": field}
                    )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.

        VULNERABILITY: All metadata including potentially malicious
        content is extracted and returned without filtering.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            # text_content has already been sanitized by extract_text_fields
            result_parts.append(f"Image Metadata:\n{text_content}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        return '\n\n'.join(result_parts)
