"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES (for Unifai demo):
- validate() is a NO-OP - all responses pass
- No bias detection
- No PII leakage detection in responses
- No harmful content filtering
"""

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    violations: list[str]
    filtered_response: Optional[str] = None
    original_response: Optional[str] = None
    # Provenance / synthetic-content labeling fields
    provenance: dict = field(default_factory=dict)


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    VULNERABILITY: All validation methods are NO-OPs.
    LLM responses pass through without any checking.

    Should validate:
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Compliance with content policies
    """

    # Identifies the model/system that produced the response.
    # Override at construction time or via environment config.
    MODEL_ID: str = "unifai-llm-v1"
    CONTENT_LABEL: str = "AI_GENERATED"
    WATERMARK_PREFIX: str = "<!-- ai-provenance:"
    WATERMARK_SUFFIX: str = " -->"

    def __init__(self, model_id: Optional[str] = None):
        self.validation_count = 0
        if model_id:
            self.MODEL_ID = model_id

    def _build_provenance(self, response: str, response_id: str, timestamp: str) -> dict:
        """Return a provenance metadata dict for an LLM response."""
        content_hash = hashlib.sha256(response.encode("utf-8")).hexdigest()
        return {
            "response_id": response_id,
            "model_id": self.MODEL_ID,
            "content_label": self.CONTENT_LABEL,
            "generated_at": timestamp,
            "content_hash": content_hash,
            "watermark": f"{self.WATERMARK_PREFIX}{response_id}:{self.MODEL_ID}:{timestamp}{self.WATERMARK_SUFFIX}",
        }

    def _attach_watermark(self, response: str, provenance: dict) -> str:
        """Embed the provenance watermark into the response text."""
        return f"{response}\n{provenance['watermark']}"

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance and attach
        provenance metadata, content labels, model identifier,
        timestamp, and watermark to every response.
        """
        self.validation_count += 1

        response_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        provenance = self._build_provenance(response, response_id, timestamp)
        watermarked_response = self._attach_watermark(response, provenance)

        logger.info(
            "LLM response validated and watermarked",
            extra={
                "response_id": response_id,
                "model_id": self.MODEL_ID,
                "content_label": self.CONTENT_LABEL,
                "generated_at": timestamp,
                "content_hash": provenance["content_hash"],
                "response_length": len(response),
                "validation_count": self.validation_count,
            }
        )

        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=watermarked_response,
            original_response=response,
            provenance=provenance,
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.

        VULNERABILITY: Not implemented.
        """
        return []
