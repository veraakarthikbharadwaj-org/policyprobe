"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES (for Unifai demo):
- verify() method always returns True (bypass)
- Token validation is not implemented
- is_internal flag bypasses all security checks
- No JWT validation despite importing PyJWT

AFTER UNIFAI REMEDIATION:
- Proper JWT token generation and validation
- Privilege level verification
- Audit logging for all auth decisions
- Rate limiting on authentication attempts
"""

import logging
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    """
    Represents the identity of an agent in the system.

    Attributes:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
    agent_id: str
    agent_name: str
    privilege_level: str
    is_internal: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.privilege_level,
            "is_internal": self.is_internal
        }


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication succeeded
        agent_id: ID of the authenticated agent (if successful)
        privileges: List of privileges granted
        reason: Reason for failure (if applicable)
    """
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    """
    Handles authentication and authorization for inter-agent communication.

    VULNERABILITY SUMMARY:
    1. verify() always returns True - no actual validation
    2. validate_token() is a stub - never validates
    3. is_internal flag bypasses all checks
    4. No rate limiting on auth attempts
    5. No audit logging of auth decisions

    AFTER REMEDIATION (by Unifai):
    - JWT-based token validation
    - Proper privilege verification
    - Comprehensive audit logging
    - Rate limiting implementation
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation (not used in vulnerable version)
        """
        if not jwt_secret:
            raise ValueError(
                "jwt_secret must be provided explicitly. "
                "Supply it from an environment variable or secrets manager "
                "(e.g., os.environ['JWT_SECRET'])."
            )
        self.jwt_secret = jwt_secret
        self._token_cache = {}

    # ------------------------------------------------------------------
    # Internal audit helper
    # ------------------------------------------------------------------
    def _audit(self, event: str, principal: Optional[str], decision: str,
               correlation_id: str, **extra) -> None:
        """Write a structured, persistent audit record."""
        import datetime as _dt
        record_parts = [
            f'"event": "{event}"',
            f'"principal": "{principal}"',
            f'"decision": "{decision}"',
            f'"correlation_id": "{correlation_id}"',
            f'"timestamp": "{_dt.datetime.utcnow().isoformat()}Z"',
            f'"model": "AgentAuthenticator"',
        ]
        for k, v in extra.items():
            record_parts.append(f'"{k}": "{v}"')
        self._audit_log.info(", ".join(record_parts))

        def verify(self, request: dict) -> bool:
        """
        Verify the authenticity of a request.

        Extracts the Bearer token from the Authorization header and
        delegates to validate_token() for full JWT verification.

        Args:
            request: Request dictionary with headers and context

        Returns:
            True only if the token passes JWT validation
        """
        headers = request.get("headers", {})
        auth_header = headers.get("Authorization") or headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning("verify() called with missing or malformed Authorization header")
            return False
        token = auth_header[len("Bearer "):].strip()
        result = self.validate_token(token)
        if not result.authenticated:
            logger.warning(f"verify() failed: {result.reason}")
        return result.authenticated

                    def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token.

        Decodes and verifies the JWT signature, expiration, issuer, and audience.
        Privileges are extracted exclusively from the verified token claims.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and claims-derived privileges on
            success, or authenticated=False with a reason on failure.
        """
        if not token:
            logger.warning("validate_token() called with empty token")
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt as _jwt  # PyJWT

            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp", "iat", "sub", "iss"],
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )

            agent_id = payload.get("sub")
            if not agent_id:
                logger.warning("validate_token() failed: 'sub' claim missing")
                return AuthResult(authenticated=False, reason="Missing subject claim")

            # Privileges must be explicitly listed in the token; default to none.
            privileges = payload.get("privileges", [])
            if not isinstance(privileges, list):
                privileges = []

            logger.info(
                f"validate_token() succeeded: agent_id={agent_id} "
                f"privileges={privileges}"
            )
            return AuthResult(
                authenticated=True,
                agent_id=agent_id,
                privileges=privileges,
            )

        except Exception as exc:  # covers ExpiredSignatureError, InvalidTokenError, etc.
            logger.warning(f"validate_token() failed: {exc}")
            return AuthResult(authenticated=False, reason=str(exc)) -> AuthResult:
        """
        Validate an agent authentication token.

        Decodes and verifies the JWT signature using the configured secret,
        checks expiration, and extracts agent_id and privileges from claims.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and extracted claims on success,
            or authenticated=False with a reason on any failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt as _jwt  # PyJWT
        except ImportError:
            logger.error("validate_token(): PyJWT is not installed; cannot validate tokens")
            return AuthResult(
                authenticated=False,
                reason="JWT library unavailable"
            )

        logger.debug(f"Token validation requested: {token[:20]}...")

        try:
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "sub", "iss"]},
            )
        except _jwt.ExpiredSignatureError:
            logger.warning("validate_token(): token has expired")
            return AuthResult(authenticated=False, reason="Token expired")
        except _jwt.InvalidIssuerError:
            logger.warning("validate_token(): invalid token issuer")
            return AuthResult(authenticated=False, reason="Invalid issuer")
        except _jwt.DecodeError as exc:
            logger.warning(f"validate_token(): token decode error — {exc}")
            return AuthResult(authenticated=False, reason="Token decode error")
        except _jwt.InvalidTokenError as exc:
            logger.warning(f"validate_token(): invalid token — {exc}")
            return AuthResult(authenticated=False, reason="Invalid token")

        agent_id = payload.get("sub")
        if not agent_id:
            return AuthResult(authenticated=False, reason="Token missing subject claim")

        privileges = payload.get("privileges", [])
        if not isinstance(privileges, list):
            privileges = []

        logger.info(f"validate_token(): authenticated agent '{agent_id}' with privileges {privileges}")
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges
        ) -> AuthResult:
        """
        Validate an agent authentication token via JWT verification.

        Decodes and verifies the JWT signature using self.jwt_secret,
        checks expiration, issuer, and audience claims, then extracts
        the agent_id and privileges from the verified payload.

        Args:
            token: The JWT authentication token to validate

        Returns:
            AuthResult with authenticated=True and claims only when the
            JWT is cryptographically valid and all claims pass; otherwise
            authenticated=False with a descriptive reason.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt as _jwt  # PyJWT
        except ImportError:
            logger.error("PyJWT is not installed; cannot validate tokens")
            return AuthResult(
                authenticated=False,
                reason="JWT library unavailable"
            )

        try:
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "sub", "iss"]},
            )
        except _jwt.ExpiredSignatureError:
            logger.warning("validate_token(): token has expired")
            return AuthResult(authenticated=False, reason="Token expired")
        except _jwt.InvalidIssuerError:
            logger.warning("validate_token(): invalid token issuer")
            return AuthResult(authenticated=False, reason="Invalid issuer")
        except _jwt.InvalidSignatureError:
            logger.warning("validate_token(): invalid token signature")
            return AuthResult(authenticated=False, reason="Invalid signature")
        except _jwt.DecodeError as exc:
            logger.warning(f"validate_token(): decode error — {exc}")
            return AuthResult(authenticated=False, reason="Token decode error")
        except _jwt.PyJWTError as exc:
            logger.warning(f"validate_token(): JWT error — {exc}")
            return AuthResult(authenticated=False, reason="Token validation failed")

        agent_id = payload.get("sub")
        if not agent_id:
            return AuthResult(authenticated=False, reason="Missing subject claim")

        raw_privileges = payload.get("privileges", [])
        allowed = set(self.PRIVILEGE_LEVELS.keys())
        privileges = [p for p in raw_privileges if p in allowed]

        logger.debug(
            f"validate_token(): authenticated agent '{agent_id}' "
            f"with privileges {privileges}"
        )
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges
        ) -> AuthResult:
        """
        Validate an agent authentication token.

        Performs full JWT verification:
          1. Decodes and verifies the HS256 signature using self.jwt_secret
          2. Validates expiration (exp), not-before (nbf), and issued-at (iat) claims
          3. Verifies the 'iss' claim equals 'agent-auth-service'
          4. Extracts agent_id and privileges from the payload

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult with authenticated=True and extracted claims on success,
            or authenticated=False with a reason on failure.
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt as _jwt  # PyJWT
            payload = _jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp", "iat", "iss", "sub"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                },
                issuer="agent-auth-service",
            )
        except _jwt.ExpiredSignatureError:
            logger.warning("validate_token(): token has expired")
            return AuthResult(authenticated=False, reason="Token expired")
        except _jwt.InvalidIssuerError:
            logger.warning("validate_token(): invalid token issuer")
            return AuthResult(authenticated=False, reason="Invalid token issuer")
        except _jwt.InvalidTokenError as exc:
            logger.warning(f"validate_token(): invalid token – {exc}")
            return AuthResult(authenticated=False, reason=f"Invalid token: {exc}")

        agent_id = payload.get("sub")
        privileges = payload.get("privileges", [])

        if not agent_id:
            return AuthResult(authenticated=False, reason="Token missing subject claim")
        if not isinstance(privileges, list):
            return AuthResult(authenticated=False, reason="Token privileges claim malformed")

        logger.debug(f"validate_token(): authenticated agent '{agent_id}' with privileges {privileges}")
        return AuthResult(
            authenticated=True,
            agent_id=agent_id,
            privileges=privileges
        ) -> AuthResult:
        """
        Validate an agent authentication token.

        VULNERABILITY: Token is never actually validated.
        Any non-empty token is accepted.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success (always succeeds with any token)
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        # VULNERABILITY: No actual JWT validation
        # Any token string is accepted
        logger.debug(f"Token validation requested: {token[:20]}...")

        # In a secure implementation, this would:
        # 1. Decode and verify JWT signature
        # 2. Check token expiration
        # 3. Verify issuer and audience claims
        # 4. Extract and validate privileges

                # Instead, we just return success
        import uuid as _uuid
        correlation_id = str(_uuid.uuid4())
        result = AuthResult(
            authenticated=True,
            agent_id="unverified-agent",
            privileges=["read", "write", "execute"]  # Full access granted
        )
        self._audit(
            event="validate_token",
            principal=result.agent_id,
            decision="ALLOW" if result.authenticated else "DENY",
            correlation_id=correlation_id,
            token_prefix=token[:8] if token else "",
            privileges=str(result.privileges),
            reason=result.reason or "",
        )
        return result

    def check_privilege(
        self,
        caller: AgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        VULNERABILITY: is_internal flag bypasses all checks.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if authorized (or if is_internal is True)
        """
        import uuid as _uuid
        correlation_id = str(_uuid.uuid4())
                caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)
        _priv_decision = "ALLOW" if caller_level >= required else "DENY"
        self._audit(
            event="check_privilege",
            principal=caller.agent_id,
            decision=_priv_decision,
            correlation_id=correlation_id,
            required_level=required_level,
            caller_level=caller.privilege_level,
        )

        return caller_level >= required

    def generate_token(self, identity: AgentIdentity) -> str:
        """
        Generate an authentication token for an agent.

        VULNERABILITY: Generates a static, predictable token.
        Not cryptographically secure.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A token string (not actually secure)
        """
        # VULNERABILITY: Predictable token generation
        # Real implementation should use JWT with proper signing
        timestamp = datetime.utcnow().isoformat()
        token = f"{identity.agent_id}:{identity.privilege_level}:{timestamp}"

        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity.agent_id,
                # VULNERABILITY: Token logged in plaintext
                "token": token
            }
        )

        return token

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> AgentIdentity:
        """
        Create a service account identity for system operations.

        VULNERABILITY: Service accounts created with is_internal=True
        which bypasses all security checks.
        """
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=True  # VULNERABILITY: Automatic internal flag
        )

    def audit_log(
        self,
        action: str,
        caller: AgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.

        VULNERABILITY: Logging is minimal and not sent to secure audit system.
        """
        # VULNERABILITY: Only local logging, no secure audit trail
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class AgentAuthenticator:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version includes:
#     - Proper JWT validation
#     - Privilege verification without bypasses
#     - Comprehensive audit logging
#     - Rate limiting
#     """
#
#     def __init__(self, jwt_secret: str):
#         if not jwt_secret or jwt_secret == "default-secret-not-used":
#             raise ValueError("JWT secret must be provided")
#         self.jwt_secret = jwt_secret
#         self._failed_attempts = {}
#
#     def verify(self, request: dict) -> AuthResult:
#         """Verify request with proper JWT validation."""
#         token = request.get("headers", {}).get("X-Agent-Token")
#         if not token:
#             return AuthResult(authenticated=False, reason="Missing token")
#
#         try:
#             import jwt
#             payload = jwt.decode(
#                 token,
#                 self.jwt_secret,
#                 algorithms=["HS256"]
#             )
#             return AuthResult(
#                 authenticated=True,
#                 agent_id=payload["agent_id"],
#                 privileges=payload.get("privileges", [])
#             )
#         except jwt.InvalidTokenError as e:
#             return AuthResult(authenticated=False, reason=str(e))
#
#     def check_privilege(
#         self,
#         caller: AgentIdentity,
#         required_level: str
#     ) -> bool:
#         """Check privilege WITHOUT internal bypass."""
#         # No is_internal bypass - all callers must have valid privileges
#         caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
#         required = self.PRIVILEGE_LEVELS.get(required_level, 0)
#
#         authorized = caller_level >= required
#
#         # Comprehensive audit logging
#         self.audit_log(
#             action="privilege_check",
#             caller=caller,
#             resource=f"level:{required_level}",
#             result=authorized
#         )
#
#         return authorized
