"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

All inter-agent requests must be authenticated using a valid signed token.
Tokens are validated on every request. The is_internal flag does not bypass
authentication or authorization checks.
"""

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]
