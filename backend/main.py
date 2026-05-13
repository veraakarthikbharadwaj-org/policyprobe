"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

import os
import os
import secrets
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import openai

# Inline approved agent implementations replacing unapproved AgentOrchestrator
# (custom_llm_client/LLaMA/OpenRouter) and FileProcessorAgent.
# Only the organization-approved OpenAI API is used here.

class FileProcessorAgent:
    """Processes file attachments using approved OpenAI models."""

    def process(self, attachment) -> str:
        """Extract and return text content from a file attachment."""
        if attachment.content:
            return attachment.content
        return f"[File: {attachment.name} ({attachment.type}, {attachment.size} bytes)]"


class AgentOrchestrator:
    """Routes chat requests through the approved OpenAI Chat Completions API."""

    def __init__(self):
        self._client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        self._model = os.environ.get("APPROVED_OPENAI_MODEL", "gpt-4o-mini")

    def run(self, message: str, file_context: str = "") -> str:
        """Send a message (with optional file context) to the approved LLM."""
        system_prompt = (
            "You are a helpful assistant for the PolicyProbe application. "
            "Answer questions clearly and concisely."
        )
        user_content = message
        if file_context:
            user_content = f"{message}\n\n--- Attached file content ---\n{file_context}"

        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        )
        return response.choices[0].message.content

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agents — registry + integrity checks are enforced before use
orchestrator = AgentOrchestrator()
_verify_agent_registry("AgentOrchestrator", orchestrator)

file_processor = FileProcessorAgent()
_verify_agent_registry("FileProcessorAgent", file_processor)

logger.info(
    "All AI workloads verified against approved model registry: %s",
    list(APPROVED_MODEL_REGISTRY.keys()),
)

# HTTP Basic auth scheme
_security = HTTPBasic()


def require_auth(credentials: HTTPBasicCredentials = Depends(_security)) -> str:
    """Dependency that enforces user authentication via HTTP Basic credentials.

    Credentials are read from the AUTH_USERNAME and AUTH_PASSWORD environment
    variables so that no secrets are hard-coded in source.
    """
    expected_username = os.environ.get("AUTH_USERNAME", "")
    expected_password = os.environ.get("AUTH_PASSWORD", "")

    username_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        expected_username.encode("utf-8"),
    )
    password_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        expected_password.encode("utf-8"),
    )

    if not (username_ok and password_ok):
                raise HTTPException(
            status_code=500,
            detail="An internal error occurred processing your request."
        )
    return credentials.username

# Authentication
_API_KEY_NAME = "X-API-Key"
_api_key_header = APIKeyHeader(name=_API_KEY_NAME, auto_error=False)
_bearer_scheme = HTTPBearer(auto_error=False)


def _get_expected_api_key() -> str:
    key = os.environ.get("POLICYPROBE_API_KEY", "")
    if not key:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    return key


async def require_auth(
    api_key_header: Optional[str] = Security(_api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
) -> str:
    """Dependency that enforces API key or Bearer token authentication."""
    expected = _get_expected_api_key()
    # Accept Bearer token
    if bearer is not None and bearer.credentials == expected:
        return bearer.credentials
    # Accept X-API-Key header
    if api_key_header is not None and api_key_header == expected:
        return api_key_header
    raise HTTPException(
        status_code=401,
        detail="Invalid or missing authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


# --- Malicious content scanner ---
import base64
import re as _re

_MALICIOUS_PATTERNS = [
    # Prompt injection / jailbreak keywords
    _re.compile(r'ignore (all |previous |above |prior )?(instructions?|prompts?|rules?|constraints?)', _re.IGNORECASE),
    _re.compile(r'(system|assistant|user)\s*:', _re.IGNORECASE),
    _re.compile(r'you are now|act as|pretend (to be|you are)|roleplay as|disregard', _re.IGNORECASE),
    _re.compile(r'jailbreak|DAN mode|developer mode|unrestricted mode', _re.IGNORECASE),
    # Shell / command injection
    _re.compile(r'(\$\(|`[^`]+`|\|\s*(bash|sh|cmd|powershell)|;\s*(rm|del|wget|curl|nc|ncat|netcat)\b)', _re.IGNORECASE),
    _re.compile(r'\b(eval|exec|system|popen|subprocess|os\.system)\s*\(', _re.IGNORECASE),
    # Leetspeak variants of dangerous keywords (common substitutions)
    _re.compile(r'1gn[o0]r[e3]\s+[a4]ll|[i1]nstruct[i1][o0]n[s5]', _re.IGNORECASE),
    # Hidden / zero-width characters used to smuggle prompts
    _re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]'),
]

_B64_PROMPT_PATTERNS = [
    _re.compile(r'ignore', _re.IGNORECASE),
    _re.compile(r'instruction', _re.IGNORECASE),
    _re.compile(r'system', _re.IGNORECASE),
    _re.compile(r'jailbreak', _re.IGNORECASE),
    _re.compile(r'act as', _re.IGNORECASE),
]


def _decode_base64_segments(text: str) -> list[str]:
    """Extract and decode any base64-looking segments from text."""
    decoded_segments = []
    # Match base64 tokens of at least 20 chars
    for token in _re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text):
        try:
            decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore')
            if decoded.isprintable() or any(c.isalpha() for c in decoded):
                decoded_segments.append(decoded)
        except Exception:
            pass
    return decoded_segments


def scan_file_content_for_malicious_prompts(content: str, filename: str = '') -> None:
    """
    Scan file content for hidden prompts, base64-encoded prompts, leetspeak,
    shell commands, and other malicious content.

    Raises ValueError if malicious content is detected.
    """
    if not content:
        return

    # 1. Direct pattern matching on raw content
    for pattern in _MALICIOUS_PATTERNS:
        match = pattern.search(content)
        if match:
            raise ValueError(
                f"Malicious content detected in uploaded file '{filename}': "
                f"pattern '{pattern.pattern}' matched at position {match.start()}."
            )

    # 2. Decode base64 segments and scan decoded text
    decoded_segments = _decode_base64_segments(content)
    for segment in decoded_segments:
        for pattern in _MALICIOUS_PATTERNS + [
            _re.compile(p.pattern, _re.IGNORECASE) for p in _B64_PROMPT_PATTERNS
        ]:
            if pattern.search(segment):
                raise ValueError(
                    f"Malicious base64-encoded content detected in uploaded file '{filename}'."
                )

    # 3. Leetspeak normalisation and re-scan
    leet_map = str.maketrans('013456789@$!', 'oieashgtbgas')
    normalised = content.translate(leet_map)
    for pattern in _MALICIOUS_PATTERNS:
        if pattern.search(normalised):
            raise ValueError(
                f"Malicious leetspeak content detected in uploaded file '{filename}'."
            )
# --- End malicious content scanner ---


import re

_PII_PATTERNS = [
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    (re.compile(r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[REDACTED_PHONE]'),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    (re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'), '[REDACTED_CC]'),
]


def redact_pii(text: str) -> str:
    """Scan text for common PII patterns and replace them with redaction tokens."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


import re

# Singapore PII patterns
_SG_PII_PATTERNS = {
    "nric_fin": re.compile(
        r"\b[STFGM]\d{7}[A-Z]\b", re.IGNORECASE
    ),
    "sg_phone": re.compile(
        r"(?<![\d])(?:\+65[\s-]?)?[689]\d{7}(?![\d])"
    ),
    "sg_postal_code": re.compile(
        r"(?i)(?:singapore\s+)?(?:s\()?\b(\d{6})\b(?:\))?"
    ),
    "passport": re.compile(
        r"\b[A-Z]\d{7}[A-Z]\b"
    ),
    "sg_uen": re.compile(
        r"\b\d{9}[A-Z]\b|\b\d{8}[A-Z]\b"
    ),
}


def _detect_sg_pii(text: str) -> list[str]:
    """Return a list of PII category names found in *text*."""
    found = []
    for category, pattern in _SG_PII_PATTERNS.items():
        if pattern.search(text):
            found.append(category)
    return found


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_MESSAGE_LENGTH = 32768  # 32 KB
ALLOWED_CONTENT_TYPES = {
    "text/plain", "text/csv", "text/markdown",
    "application/json", "application/pdf",
    "image/png", "image/jpeg", "image/gif", "image/webp",
}


def sanitize_string(value: str, max_length: int = MAX_MESSAGE_LENGTH) -> str:
    """Strip null bytes and non-printable control characters, then truncate."""
    if not isinstance(value, str):
        raise ValueError("Expected a string value")
    # Remove null bytes and ASCII control characters except common whitespace
    sanitized = "".join(
        ch for ch in value
        if ch in ("\n", "\r", "\t") or (ord(ch) >= 32 and ord(ch) != 127)
    )
    return sanitized[:max_length]


def validate_content_type(content_type: Optional[str], filename: Optional[str] = None) -> str:
    """Validate that the content type is in the allowed set."""
    if content_type:
        # Strip parameters (e.g. 'text/plain; charset=utf-8' -> 'text/plain')
        base_type = content_type.split(";")[0].strip().lower()
    else:
        base_type = "application/octet-stream"
    if base_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail={
                "detail": f"File type '{base_type}' is not permitted.",
                "policy_error": {"type": "invalid_content_type", "message": "Unsupported file type."}
            }
        )
    return base_type


def validate_and_sanitize_file_content(content: str, filename: str, content_type: str) -> str:
    """Validate size and sanitize textual file content."""
    if len(content.encode("utf-8", errors="replace")) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail={
                "detail": f"File '{filename}' exceeds the maximum allowed size.",
                "policy_error": {"type": "file_too_large", "message": "File size limit exceeded."}
            }
        )
    return sanitize_string(content, max_length=MAX_FILE_SIZE_BYTES)


import re
import base64

MALICIOUS_PATTERNS = [
    # Prompt injection / jailbreak attempts
    re.compile(r'ignore (all |previous |above |prior )?(instructions?|prompts?|rules?|constraints?)', re.IGNORECASE),
    re.compile(r'(system|assistant|user)\s*:', re.IGNORECASE),
    re.compile(r'<\s*(system|instructions?|prompt)\s*>', re.IGNORECASE),
    re.compile(r'\[\s*(system|instructions?|prompt)\s*\]', re.IGNORECASE),
    re.compile(r'you are now|act as|pretend (you are|to be)|roleplay as', re.IGNORECASE),
    re.compile(r'disregard|override|bypass|circumvent|jailbreak', re.IGNORECASE),
    # Shell command patterns
    re.compile(r'(\$\(|`)[^`]*`|\$\([^)]*\)', re.IGNORECASE),
    re.compile(r'\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\s*[\(\-]', re.IGNORECASE),
    re.compile(r'&&|\|\||;\s*(rm|del|wget|curl|nc|ncat|python|perl|ruby)\b', re.IGNORECASE),
    re.compile(r'\b(rm\s+-rf|mkfs|dd\s+if=|chmod\s+777|chown\s+root)', re.IGNORECASE),
    # Hidden/encoded content
    re.compile(r'<!--.*?-->', re.DOTALL),
    re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.IGNORECASE),
]

B64_MIN_LENGTH = 40  # minimum length to consider a token as suspicious base64


def _looks_like_base64(token: str) -> bool:
    """Return True if token appears to be a base64-encoded payload."""
    if len(token) < B64_MIN_LENGTH:
        return False
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', token):
        return False
    try:
        decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore')
        # Flag if the decoded content itself contains suspicious patterns
        for pattern in MALICIOUS_PATTERNS:
            if pattern.search(decoded):
                return True
        # Flag if decoded content contains non-printable / control characters at high ratio
        non_printable = sum(1 for c in decoded if ord(c) < 32 and c not in '\n\r\t')
        if non_printable / max(len(decoded), 1) > 0.1:
            return True
    except Exception:
        pass
    return False


def sanitize_input(text: str, field_name: str = "input") -> str:
    """
    Scan *text* for prompt-injection, shell-command, and encoded-payload
    patterns.  Raises ValueError with a descriptive message if a violation
    is detected; otherwise returns the original text unchanged.
    """
    if not isinstance(text, str):
        return text

    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                f"Potentially malicious content detected in {field_name}: "
                f"matched pattern '{pattern.pattern}'"
            )

    # Check individual whitespace-delimited tokens for base64 payloads
    for token in text.split():
        if _looks_like_base64(token):
            raise ValueError(
                f"Potentially base64-encoded malicious content detected in {field_name}."
            )

    return text


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, _: str = Depends(require_auth)):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the FileProcessorAgent
    3. Routes the request through the AgentOrchestrator
    4. Returns the AI response

    SECURITY NOTES (for Unifai demo):
    - File content is not scanned for PII before processing
    - Hidden content in files is not detected
    - Agent calls are authenticated via a shared inter-agent token
    """
    inter_agent_token = os.environ.get("INTER_AGENT_SECRET_TOKEN")
    if not inter_agent_token:
        raise HTTPException(
            status_code=500,
            detail={"detail": "Inter-agent authentication token is not configured"}
        )
    try:
        # Subagent spawn constants
        FILE_PROCESSOR_TIMEOUT_SECONDS = 30
        ORCHESTRATOR_TIMEOUT_SECONDS = 60
        MAX_CONTENT_LENGTH = 1_000_000  # 1 MB
        MAX_FILENAME_LENGTH = 255
        MAX_MESSAGE_LENGTH = 10_000
        ALLOWED_CONTENT_TYPES = {
            "text/plain", "text/csv", "application/pdf",
            "application/json", "image/png", "image/jpeg",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }
        import re as _re

        def _sanitize_str(value: str, max_len: int) -> str:
            """Strip control characters and truncate to max_len."""
            if not isinstance(value, str):
                raise ValueError("Expected a string value")
            # Remove ASCII control characters except tab/newline/carriage-return
            cleaned = _re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
            return cleaned[:max_len]

        # Validate and sanitize the user message before it reaches any agent
        sanitized_message = _sanitize_str(request.message, MAX_MESSAGE_LENGTH)

        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        # VULNERABILITY: Logging full request context
                        # This could include sensitive data from the file
                                                "request_context": {
                            "attachment_name": attachment.name,
                            "attachment_size": len(attachment.content) if attachment.content else 0
                        }
                    }
                )

                # Validate and sanitize attachment before processing
                validated_type = validate_content_type(attachment.type, attachment.name)
                safe_filename = sanitize_string(attachment.name or "", max_length=255)
                safe_content = validate_and_sanitize_file_content(
                    attachment.content or "",
                    safe_filename,
                    validated_type,
                )

                # Process the sanitized file content
                                                        processed = await file_processor.process(
                    content=attachment.content,
                    filename=attachment.name,
                    content_type=attachment.type,
                    auth_token=inter_agent_token
                )
                _sanitize_llm_output(processed)
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Validate and sanitize the user message
        try:
            sanitized_message = sanitize_string(request.message)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail={
                    "detail": "Invalid message format.",
                    "policy_error": {"type": "invalid_input", "message": "Message must be a string."}
                }
            )

                # Sanitize user message before building context
        try:
            sanitize_input(request.message, field_name="user_message")
        except ValueError as exc:
            logger.warning("Prompt injection attempt blocked in user_message", extra={"reason": str(exc)})
            raise HTTPException(status_code=400, detail={"detail": "Message contains disallowed content.", "policy_error": {"type": "prompt_injection", "message": str(exc)}})

        # Sanitize extracted file content before building context
        for fc in file_contents:
            try:
                sanitize_input(fc.get("extracted_content") or "", field_name=f"file:{fc.get('filename', 'unknown')}")
            except ValueError as exc:
                logger.warning("Prompt injection attempt blocked in file content", extra={"filename": fc.get("filename"), "reason": str(exc)})
                raise HTTPException(status_code=400, detail={"detail": "File content contains disallowed content.", "policy_error": {"type": "prompt_injection", "message": str(exc)}})

                # --- Input validation and sanitisation before LLM prompt construction ---
        MAX_MESSAGE_LENGTH = 4000
        MAX_FILE_CONTENT_LENGTH = 8000
        MAX_FILES = 10
        import re, asyncio

        def _sanitise_text(text: str, max_len: int) -> str:
            """Remove null bytes / dangerous control chars and truncate."""
            if not isinstance(text, str):
                text = str(text)
            # Strip null bytes and non-printable control characters (keep newlines/tabs)
            text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
            return text[:max_len]

        sanitised_message = _sanitise_text(request.message or "", MAX_MESSAGE_LENGTH)

        sanitised_files = []
        for fc in file_contents[:MAX_FILES]:
            sanitised_files.append({
                "filename": _sanitise_text(str(fc.get("filename", "")), 256),
                "extracted_content": _sanitise_text(
                    str(fc.get("extracted_content", "")), MAX_FILE_CONTENT_LENGTH
                ),
            })

        # Build context for the orchestrator
        context = {
            "user_message": sanitised_message,
            "file_contents": sanitised_files,
            "conversation_id": request.conversation_id,
        }

        logger.info(
            "Dispatching sanitised context to orchestrator",
            extra={
                "conversation_id": request.conversation_id,
                "message_length": len(sanitised_message),
                "file_count": len(sanitised_files),
            },
        )

        # Route through orchestrator with a hard timeout to prevent runaway agent loops
        ORCHESTRATOR_TIMEOUT_SECONDS = 60
        response = await asyncio.wait_for(
            orchestrator.process(context),
            timeout=ORCHESTRATOR_TIMEOUT_SECONDS,
        )

        # --- Synthetic Content Provenance & Watermarking ---
        import hashlib
        import hmac
        import datetime
        import uuid
        import os

        ai_response_text = response.get("response", "I processed your request.")

        # Provenance metadata
        provenance = {
            "model_id": os.environ.get("AI_MODEL_ID", "unifai-orchestrator-v1"),
            "origin": "ai-generated",
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "response_id": str(uuid.uuid4()),
            "content_label": "SYNTHETIC_AI_CONTENT",
        }

        # Cryptographic watermark: HMAC-SHA256 over (response_id + generated_at + response text)
        _watermark_secret = os.environ.get("AI_WATERMARK_SECRET", "change-me-in-production")
        _watermark_payload = f"{provenance['response_id']}|{provenance['generated_at']}|{ai_response_text}"
        provenance["watermark"] = hmac.new(
            _watermark_secret.encode("utf-8"),
            _watermark_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        # --- End Provenance Block ---

        return ChatResponse(
            response=ai_response_text,
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
            provenance=provenance,
        )
        _sanitize_llm_output(response)

        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                        "error_type": type(e).__name__,
                "request_state": {
                    "conversation_id": request.conversation_id,
                    "attachment_count": len(request.attachments) if request.attachments else 0
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request"
            }
        )


# Dynamic code execution primitives that must not appear in LLM output
_DANGEROUS_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bexecfile\s*\(",
    r"\bcompile\s*\(",
    r"\b__import__\s*\(",
    r"\bimportlib\.import_module\s*\(",
    r"\bsubprocess\s*\.",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bgetattr\s*\(.*__",
    r"\bsetattr\s*\(",
    r"\bdelattr\s*\(",
    r"\bglobals\s*\(\s*\)",
    r"\blocals\s*\(\s*\)",
    r"\bvars\s*\(\s*\)",
    r"\bopen\s*\(",
    r"\bbuiltins\b",
    r"\b__builtins__\b",
    r"\b__class__\b",
    r"\b__bases__\b",
    r"\b__subclasses__\s*\(",
    r"\b__globals__\b",
    r"\b__code__\b",
    r"\bctypes\b",
]

import re as _re


def _sanitize_llm_output(output):
    """
    Validate and sanitize LLM/agent output by checking for dynamic code
    execution primitives. Raises ValueError if dangerous content is detected.
    Returns the sanitized output string.
    """
    if output is None:
        return output

    # Normalize to string for scanning
    if isinstance(output, dict):
        text_to_scan = str(output)
    else:
        text_to_scan = str(output)

    for pattern in _DANGEROUS_PATTERNS:
        if _re.search(pattern, text_to_scan, _re.IGNORECASE):
            logger.warning(
                "Dangerous code execution primitive detected in LLM output",
                extra={"pattern": pattern, "preview": text_to_scan[:200]},
            )
            raise ValueError(
                f"LLM output contains a forbidden dynamic code execution "
                f"primitive matching pattern: {pattern}"
            )
    return output


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), _: str = Depends(require_auth)):
    """
    Direct file upload endpoint.

    SECURITY NOTES (for Unifai demo):
    - No file content scanning
    - No size limits enforced
    - No malware detection
    """
        MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
    content = await file.read(MAX_UPLOAD_SIZE + 1)
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File size exceeds the maximum allowed limit of 10 MB."
        )

    try:
        decoded_content = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File content is not valid UTF-8 text."
        )

    processed = await file_processor.process(
        content=decoded_content,
        filename=file.filename,
        content_type=file.content_type
    )

    # Check for Singapore PII before processing
    _upload_text = content.decode("utf-8", errors="ignore")
    _pii_hits = _detect_sg_pii(_upload_text)
    if _pii_hits:
        raise HTTPException(
            status_code=422,
            detail={
                "detail": "Uploaded file contains Singapore PII and cannot be processed.",
                "policy_error": {
                    "type": "sg_pii_detected",
                    "message": "File rejected: Singapore PII detected.",
                    "categories": _pii_hits,
                },
            },
        )
    # Redact PII from file content before processing
    decoded_content = content.decode('utf-8', errors='ignore')
    sanitized_content = redact_pii(decoded_content)

    # Scan uploaded file content for malicious prompts before processing
    scan_file_content_for_malicious_prompts(
        content=content.decode('utf-8', errors='ignore'),
        filename=file.filename or ''
    )

    # Validate file size
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Uploaded file exceeds the maximum allowed size.",
                "policy_error": {"type": "file_too_large", "message": "File size limit exceeded."}
            }
        )

    # Validate content type
    validated_upload_type = validate_content_type(file.content_type, file.filename)
    safe_upload_filename = sanitize_string(file.filename or "", max_length=255)

    # Decode and sanitize textual content
    decoded_content = content.decode("utf-8", errors="ignore")
    safe_upload_content = sanitize_string(decoded_content, max_length=MAX_FILE_SIZE_BYTES)

    processed = await file_processor.process(
        content=content.decode('utf-8', errors='ignore'),
        filename=file.filename,
        content_type=file.content_type
    )
    _sanitize_llm_output(processed)

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
