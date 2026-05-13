"""
Policy Enforcement Modules

Contains modules for detecting and enforcing security policies:
- PII Detection: Identifies personally identifiable information
- Prompt Injection: Detects hidden/malicious prompts
- Content Scanner: Extracts and analyzes hidden content

SECURITY NOTES:
All policy modules perform active security scanning and enforcement.
Inputs are sanitized and validated before being passed to the AI model.
"""

import inspect

from .pii_detection import PIIDetector, PIIDetectionResult
from .prompt_injection import PromptInjectionDetector, ThreatDetectionResult
from .content_scanner import ContentScanner


def _assert_not_noop(cls, method_name: str) -> None:
    """
    Raise RuntimeError if the given method on cls appears to be a NO-OP
    (i.e. its source contains a known stub marker or the body is only
    'pass' / 'return None' / 'return True' with no real logic).
    """
    method = getattr(cls, method_name, None)
    if method is None:
        return
    try:
        source = inspect.getsource(method)
    except (OSError, TypeError):
        return

    noop_markers = [
        "NO-OP",
        "no-op",
        "noop",
        "pass through",
        "pass-through",
        "not implemented",
        "placeholder",
        "stub",
    ]
    source_lower = source.lower()
    for marker in noop_markers:
        if marker in source_lower:
            raise RuntimeError(
                f"Security policy violation: {cls.__name__}.{method_name} appears to be "
                f"a NO-OP/stub implementation. Uploaded file content MUST be actively "
                f"scanned for malicious prompts and hidden content. "
                f"Replace the stub with a real scanning implementation."
            )


# Enforce that critical scanning methods are not NO-OP stubs at import time.
_assert_not_noop(PromptInjectionDetector, "detect")
_assert_not_noop(PromptInjectionDetector, "scan")
_assert_not_noop(PromptInjectionDetector, "analyze")
_assert_not_noop(ContentScanner, "scan")
_assert_not_noop(ContentScanner, "extract")
_assert_not_noop(ContentScanner, "analyze")


__all__ = [
    "PIIDetector",
    "PIIDetectionResult",
    "PromptInjectionDetector",
    "ThreatDetectionResult",
    "ContentScanner",
]
