"""
Tech Support Agent

Handles general technical support queries with low privilege level.
Can escalate to higher-privilege agents when needed.

SECURITY NOTES (for Unifai demo):
- Low privilege agent can escalate without proper verification
- User context passed without sanitization
"""

import logging
import base64
import hashlib
import os


def _encrypt_pii(value: str) -> str:
    """
    Encrypt a PII string using a secret key from the environment.
    Uses XOR + base64 as a lightweight symmetric cipher.
    In production, replace with a KMS-backed AES-GCM implementation.
    """
    secret = os.environ.get("PII_ENCRYPTION_KEY", "default-secret-key-change-me")
    key_bytes = hashlib.sha256(secret.encode()).digest()
    value_bytes = value.encode("utf-8")
    encrypted = bytes(
        b ^ key_bytes[i % len(key_bytes)]
        for i, b in enumerate(value_bytes)
    )
    return base64.urlsafe_b64encode(encrypted).decode("utf-8")
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity
from llm.approved import ApprovedLLMClient

logger = logging.getLogger(__name__)


# Explicit allow list: only agents named here may be invoked by TechSupportAgent
TECH_SUPPORT_ALLOWED_ESCALATION_TARGETS: frozenset[str] = frozenset({
    # No cross-agent escalation is permitted for TechSupportAgent.
    # Add agent identifiers here only after a formal security review.
})


class TechSupportAgent:
    """
    Technical support agent for handling general user queries.

    Privilege Level: LOW
    Capabilities:
    - Answer general questions
    - Provide technical guidance
    - Escalate to specialized agents
    """

    ALLOWED_ROLES = ["user", "tech_support", "admin"]
    PRIVILEGE_LEVEL = "low"

    def __init__(self, llm_client: ApprovedLLMClient):
        self.llm_client = llm_client
        self.agent_id = "tech_support"
        self.agent_name = "Tech Support Agent"

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request from orchestrator or direct call.

        Args:
            context: Request context with user message and metadata
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary
        """
        # Validate the incoming token before processing
        token = headers.get("X-Agent-Token") if headers else None
        if not token:
            logger.warning("Request received without an auth token; rejecting.")
            return {
                "error": "Unauthorized: missing authentication token",
                "agent": self.agent_id
            }
        if not caller.verify_token(token):
            logger.warning("Request received with an invalid auth token; rejecting.")
            return {
                "error": "Unauthorized: invalid authentication token",
                "agent": self.agent_id
            }
        logger.debug(f"Received request with validated token: {token[:10]}...")

        user_message = self._sanitize_input(context.get("user_message", ""))

        # Check if this needs escalation to finance
        if self._needs_finance_escalation(user_message):
            logger.info(
                "Tech support escalating to finance",
                extra={
                    "reason": "Financial query detected",
                    "user_message": user_message[:100]
                }
            )
            # VULNERABILITY: Escalating to high-privilege agent without proper auth
            return await self._escalate_to_finance(user_message, context, token=token)

        # Handle the query directly
        response = await self._process_query(user_message, context)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    def _sanitize_input(self, text: str) -> str:
        """
        Sanitize untrusted user input before interpolation into LLM prompts.

        - Enforces a maximum length to prevent prompt-flooding attacks.
        - Strips or escapes characters commonly used in prompt-injection
          (e.g. backticks, angle brackets, null bytes, and leading/trailing
          whitespace that could hide injected instructions).
        """
        import re
        MAX_LENGTH = 2000
        if not isinstance(text, str):
            return ""
        # Truncate to maximum allowed length
        text = text[:MAX_LENGTH]
        # Remove null bytes and other non-printable control characters
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        # Escape angle brackets to prevent HTML/XML injection into prompts
        text = text.replace("<", "&lt;").replace(">", "&gt;")
        # Remove backtick sequences used to break out of code-block framing
        text = text.replace("`", "'")
        # Strip leading/trailing whitespace that could hide injected lines
        text = text.strip()
        return text

    def _needs_finance_escalation(self, message: str) -> bool:
        """Check if message requires finance agent access."""
        finance_triggers = [
            "quarterly report", "financial statement", "budget",
            "revenue numbers", "profit margin", "expense report",
            "balance sheet", "cash flow", "earnings"
        ]
        message_lower = message.lower()
        return any(trigger in message_lower for trigger in finance_triggers)

        # Static policy: defines which agents may escalate to which targets
    # and whether human approval is required.
    ESCALATION_POLICY: dict = {
        # tech_support is NOT permitted to directly call finance
        "allowed_targets": [],
        "requires_human_approval": True,
    }

    async def _escalate_to_finance(
        self,
        query: str,
        original_context: dict
    ) -> dict[str, Any]:
        """
        Escalate query to finance agent.

        Privilege escalation is blocked: tech support agents do not have
        authorization to call the high-privilege FinanceAgent directly.
        A human operator must review and approve any such escalation.
        """
        # --- Static policy check ---
        if "finance" not in self.ESCALATION_POLICY.get("allowed_targets", []):
            logger.warning(
                "Privilege escalation attempt blocked by static policy",
                extra={
                    "agent_id": self.agent_id,
                    "attempted_target": "finance",
                    "privilege_level": self.PRIVILEGE_LEVEL,
                }
            )
            raise PermissionError(
                f"Agent '{self.agent_id}' (privilege_level={self.PRIVILEGE_LEVEL}) "
                "is not authorized to escalate to FinanceAgent. "
                "Human approval is required before this operation can proceed."
            )

        # --- Human-in-the-loop gate (reached only if policy allows) ---
        if self.ESCALATION_POLICY.get("requires_human_approval", True):
            raise PermissionError(
                "Escalation to FinanceAgent requires explicit human approval. "
                "Please contact an authorized operator to perform this action."
            )

        # If policy is ever updated to permit escalation, construct the
        # identity WITHOUT claiming internal status and use only the
        # agent's actual privilege level.
        from .finance import FinanceAgent  # noqa: F401 – kept for future use

        true_identity = AgentIdentity(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=False  # never claim internal status to bypass checks
        )

        finance_agent = FinanceAgent(self.llm_client)

        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=true_identity
            # No hardcoded escalation token
        )

        return {
            "response": f"[Escalated to Finance Agent]\n\n{finance_response.get('response', '')}",
            "agent": self.agent_id,
            "escalated_to": "finance",
            "privilege_level": self.PRIVILEGE_LEVEL
        }
        )

                # --- Resource bounds & input validation for subagent spawn ---
        import asyncio
        import re
        import logging
        import time

        _ESCALATION_TIMEOUT_SECONDS = 30          # hard wall-clock limit
        _MAX_ESCALATION_ATTEMPTS    = 3           # max retries / iterations
        _MAX_QUERY_LENGTH           = 500         # character cap on forwarded query
        _ALLOWED_FINANCE_PATTERN    = re.compile(
            r'^[\w\s.,;:\-\'"()%$@!?]+$', re.UNICODE
        )

        # 1. Sanitize: strip control characters and leading/trailing whitespace
        sanitized_query = re.sub(r'[\x00-\x1f\x7f]', '', query).strip()

        # 2. Enforce length bound
        if len(sanitized_query) > _MAX_QUERY_LENGTH:
            sanitized_query = sanitized_query[:_MAX_QUERY_LENGTH]

        # 3. Validate that the query contains only expected characters
        if not _ALLOWED_FINANCE_PATTERN.match(sanitized_query):
            raise ValueError(
                "Escalation query contains disallowed characters and was rejected."
            )

        # 4. Enforce that at least one known finance keyword is present
        finance_triggers = [
            "quarterly report", "financial statement", "budget",
            "revenue numbers", "profit margin", "expense report",
            "balance sheet", "cash flow", "earnings"
        ]
        if not any(kw in sanitized_query.lower() for kw in finance_triggers):
            raise ValueError(
                "Escalation query does not match any permitted finance topic."
            )

        # 5. Structured trace log for auditability
        _logger = logging.getLogger(__name__)
        _logger.info(
            "subagent_spawn",
            extra={
                "event":          "finance_escalation",
                "caller_agent":   self.agent_id,
                "target_agent":   "finance",
                "query_length":   len(sanitized_query),
                "timestamp_utc":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "max_timeout_s":  _ESCALATION_TIMEOUT_SECONDS,
                "max_attempts":   _MAX_ESCALATION_ATTEMPTS,
            }
        )

        # 6. Bounded iteration guard + hard timeout
        finance_response = None
        last_exc: Exception | None = None
        for _attempt in range(1, _MAX_ESCALATION_ATTEMPTS + 1):
            try:
                finance_response = await asyncio.wait_for(
                    finance_agent.handle(
                        context={
                            "user_message":    sanitized_query,
                            "escalated_from":  self.agent_id,
                            "original_context": original_context,
                        },
                        caller=escalation_identity,
                        headers={},
                    ),
                    timeout=_ESCALATION_TIMEOUT_SECONDS,
                )
                break  # success — exit retry loop
            except asyncio.TimeoutError as exc:
                _logger.warning(
                    "finance_escalation_timeout",
                    extra={"attempt": _attempt, "timeout_s": _ESCALATION_TIMEOUT_SECONDS}
                )
                last_exc = exc
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "finance_escalation_error",
                    extra={"attempt": _attempt, "error": str(exc)}
                )
                last_exc = exc
                break  # non-timeout errors are not retried

        if finance_response is None:
            raise RuntimeError(
                f"Finance agent escalation failed after {_MAX_ESCALATION_ATTEMPTS} "
                f"attempt(s): {last_exc}"
            )

        completion_ts = datetime.datetime.utcnow().isoformat() + "Z"
        logger.info(
            "Agent escalation audit – completed",
            extra={
                "audit_event": "agent_escalation_response",
                "trace_id": escalation_trace_id,
                "source_agent": self.agent_id,
                "target_agent": "finance",
                "timestamp": completion_ts,
            }
        )
        if not escalation_token:
            raise ValueError(
                "TECH_SUPPORT_ESCALATION_TOKEN environment variable is not set"
            )
        finance_response = await finance_agent.handle(
            context={
                "user_message": query,
                "escalated_from": self.agent_id,
                "original_context": original_context
            },
            caller=escalation_identity,
            headers={"X-Agent-Token": escalation_token}
        )

        return {
            "response": f"[Escalated to Finance Agent]\n\n{finance_response.get('response', '')}",
            "agent": self.agent_id,
            "escalated_to": "finance",
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    async def _process_query(
        self,
        message: str,
        context: dict
    ) -> str:
        """
        Process a general tech support query.

        VULNERABILITY: User message sent to LLM without sanitization
        or content scanning.
        """
        system_prompt = """You are a helpful technical support agent for PolicyProbe.
You can help users with:
- General questions about the application
- Technical troubleshooting
- Document analysis guidance
- Policy compliance questions

Be helpful, professional, and concise in your responses."""

        # VULNERABILITY: Direct user input to LLM without scanning
        # Re-assert registry approval immediately before inference to guard
        # against runtime registry mutations.
        _assert_model_approved(self._model_id)

        response = await self.llm_client.chat(
            model=self._model_id,          # pinned, versioned model identifier
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ]
        )

        # Attach model identity to the raw response object so callers can
        # audit which model produced the output.
        if isinstance(response, dict):
            response.setdefault("model_identity", {
                "model_id": self._model_id,
                "provider": self._model_entry["provider"],
                "pinned_version": self._model_entry["version"],
                "registry_approved": self._model_entry["approved"],
            })

        # Validate and sanitize LLM output before returning
        sanitized = self._validate_llm_response(response)
        return sanitized

    # Dynamic code execution primitives that must not appear in LLM output
    _DANGEROUS_PATTERNS = [
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'\bcompile\s*\(',
        r'\b__import__\s*\(',
        r'\bexecfile\s*\(',
        r'\bgetattr\s*\(.*__',
        r'\bsetattr\s*\(',
        r'\bdelattr\s*\(',
        r'\bvars\s*\(',
        r'\bglobals\s*\(',
        r'\blocals\s*\(',
        r'\bsubprocess\b',
        r'\bos\.system\s*\(',
        r'\bos\.popen\s*\(',
    ]

    def _validate_llm_response(self, response: str) -> str:
        """
        Validate and sanitize LLM output.

        Checks for the presence of eval, exec, or any dynamic code
        execution primitives in the LLM response. Raises a ValueError
        if dangerous patterns are detected, preventing prompt-injection
        or code-execution payloads from propagating to callers.
        """
        import re

        if not isinstance(response, str):
            raise ValueError(
                "LLM response validation failed: response is not a string."
            )

        for pattern in self._DANGEROUS_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                logger.warning(
                    "Dangerous pattern detected in LLM response; "
                    "response suppressed.",
                    extra={"pattern": pattern}
                )
                raise ValueError(
                    "LLM response contains a forbidden dynamic code "
                    "execution primitive and has been blocked."
                )

        # Strip any null bytes or non-printable control characters
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', response)
        return sanitized

    async def get_user_context(self, user_id: str) -> dict:
        """
        Retrieve user context for personalized support.

        VULNERABILITY: Returns full user context including potentially
        sensitive information without filtering.
        """
        # Simulated user context retrieval
        # In a real app, this would query a database
        user_context = {
            "user_id": user_id,
            "subscription_tier": "enterprise",
            "recent_queries": [
                "How do I upload files?",
                "What file types are supported?",
                "Can I access financial reports?"
            ],
            "preferences": {
                "language": "en",
                "timezone": "America/New_York"
            },
            # VULNERABILITY: Sensitive data in context
            "internal_notes": "VIP customer - handle with priority",
                        "account_details": {
                "contact_email": None,  # Retrieved from database at runtime
                "phone": None  # Retrieved from database at runtime
            }
        }

        logger.info(
            "Retrieved user context",
            extra={
                "user_id": user_id,
                "subscription_tier": user_context.get("subscription_tier")
            }
        )

        return user_context
