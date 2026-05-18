"""
Memgar Agent Identity System
==============================

Per-agent cryptographic identity, scoped permissions, ephemeral tokens,
delegation chains, and full audit trail — with zero external dependencies.

Design principles (2026 best practices):

  1. Every agent gets a unique, cryptographically signed identity
  2. Tokens are short-lived and scoped to specific capabilities
  3. One compromised agent cannot affect others (blast radius isolation)
  4. Full delegation chain: who authorized whom to do what
  5. Every action is attributable to exactly one agent + one human principal
  6. Revocation is per-agent, not global credential rotation

Architecture::

    AgentIdentity         — unique identity per agent (Ed25519 keypair)
    AgentToken            — signed, scoped, short-lived access token
    PermissionScope       — capability enum (read_memory, write_memory, etc.)
    AgentRegistry         — registers/revokes agents, issues tokens
    DelegationChain       — tracks authorization chain in multi-agent systems
    IdentityAuditLog      — immutable action log (hash-chained)
    AgentContext          — runtime context injected by auto_protect()

Token structure (JWT-like, no external dep):

    header.payload.signature

    header:  {"alg":"HS256","typ":"AGT"}
    payload: {
      "agent_id": "agt_abc123",
      "scopes":   ["read_memory","write_memory"],
      "iss":      "memgar-registry",
      "sub":      "agt_abc123",
      "iat":      1712345678,
      "exp":      1712345978,      # 5min TTL default
      "jti":      "tok_xyz789",    # unique token ID (for revocation)
      "principal":"user@corp.com", # human who authorized this
      "delegation_depth": 0,       # 0 = direct, 1 = delegated once
    }
    signature: HMAC-SHA256(header + "." + payload, registry_secret)

Usage::

    from memgar.identity import AgentRegistry, PermissionScope

    registry = AgentRegistry(secret_key="your-secret-key")

    # Register a new agent
    identity = registry.register(
        name="email-processor",
        scopes=[PermissionScope.READ_MEMORY, PermissionScope.SCAN_CONTENT],
        owner="alice@corp.com",
        ttl_seconds=300,
    )

    # Issue a token for a task
    token = registry.issue_token(identity.agent_id)

    # Verify before any action
    claims = registry.verify_token(token)

    # Revoke a single agent (others unaffected)
    registry.revoke(identity.agent_id)

    # auto_protect integration
    import memgar
    memgar.auto_protect(agent_id="email-processor", agent_token=token)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Permission Scopes
# ---------------------------------------------------------------------------

class PermissionScope(str, Enum):
    """
    Granular permission scopes for agent capabilities.

    Design: deny-by-default. An agent only has the scopes explicitly granted.
    """
    # Memory operations
    READ_MEMORY     = "read_memory"      # read from memory store
    WRITE_MEMORY    = "write_memory"     # write to memory store
    DELETE_MEMORY   = "delete_memory"    # delete memory entries
    SCAN_CONTENT    = "scan_content"     # run Memgar threat scan

    # Communication
    SEND_EMAIL      = "send_email"
    SEND_SLACK      = "send_slack"
    SEND_TELEGRAM   = "send_telegram"
    SEND_WEBHOOK    = "send_webhook"

    # File system
    READ_FILES      = "read_files"
    WRITE_FILES     = "write_files"
    DELETE_FILES    = "delete_files"

    # Code / shell
    EXECUTE_CODE    = "execute_code"
    RUN_SHELL       = "run_shell"

    # Data / DB
    READ_DATABASE   = "read_database"
    WRITE_DATABASE  = "write_database"
    DELETE_DATABASE = "delete_database"

    # Financial
    READ_FINANCES   = "read_finances"
    WRITE_FINANCES  = "write_finances"
    TRANSFER_FUNDS  = "transfer_funds"

    # External APIs
    CALL_APIS       = "call_apis"
    BROWSE_WEB      = "browse_web"

    # Admin
    MANAGE_AGENTS   = "manage_agents"    # register/revoke other agents
    READ_AUDIT_LOG  = "read_audit_log"
    DELEGATE        = "delegate"         # sub-delegate to other agents

    # Special
    ALL             = "*"                # full access (admin only, use sparingly)


# High-risk scopes that require HITL approval
HIGH_RISK_SCOPES: Set[PermissionScope] = {
    PermissionScope.DELETE_MEMORY,
    PermissionScope.DELETE_FILES,
    PermissionScope.DELETE_DATABASE,
    PermissionScope.RUN_SHELL,
    PermissionScope.EXECUTE_CODE,
    PermissionScope.TRANSFER_FUNDS,
    PermissionScope.MANAGE_AGENTS,
    PermissionScope.ALL,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class AgentStatus(str, Enum):
    ACTIVE    = "active"
    REVOKED   = "revoked"
    SUSPENDED = "suspended"
    EXPIRED   = "expired"


@dataclass
class AgentIdentity:
    """
    Unique, persistent identity for an AI agent.

    Each identity has:
    - A unique agent_id (non-guessable)
    - A set of allowed scopes (least-privilege)
    - An owner (human principal accountable for this agent)
    - A signing secret for token verification
    - Lifecycle timestamps
    """
    agent_id:      str
    name:          str
    description:   str
    scopes:        List[PermissionScope]
    owner:         str              # email/username of responsible human
    status:        AgentStatus
    created_at:    str
    expires_at:    Optional[str]    # None = no expiry (not recommended)
    last_seen:     Optional[str]
    token_ttl:     int              # seconds, default 300
    signing_secret: str             # HMAC secret, stored server-side only
    metadata:      Dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        if self.status != AgentStatus.ACTIVE:
            return False
        if self.expires_at:
            return datetime.fromisoformat(self.expires_at) > datetime.now(tz=timezone.utc)
        return True

    @property
    def has_high_risk_scopes(self) -> bool:
        scopes_set = set(self.scopes)
        return bool(scopes_set & HIGH_RISK_SCOPES) or PermissionScope.ALL in scopes_set

    def has_scope(self, scope: PermissionScope) -> bool:
        return PermissionScope.ALL in self.scopes or scope in self.scopes

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        d = {
            "agent_id":    self.agent_id,
            "name":        self.name,
            "description": self.description,
            "scopes":      [s.value for s in self.scopes],
            "owner":       self.owner,
            "status":      self.status.value,
            "created_at":  self.created_at,
            "expires_at":  self.expires_at,
            "last_seen":   self.last_seen,
            "token_ttl":   self.token_ttl,
            "metadata":    self.metadata,
            "has_high_risk_scopes": self.has_high_risk_scopes,
        }
        if include_secret:
            d["signing_secret"] = self.signing_secret
        return d


@dataclass
class AgentToken:
    """
    A signed, scoped, short-lived access token for one agent.

    Contains:
    - agent_id: which agent this token belongs to
    - scopes: permitted capabilities (subset of agent's registered scopes)
    - exp: expiry timestamp — token is invalid after this
    - jti: unique token ID for revocation without rotating all keys
    - principal: human who triggered the action
    - delegation_depth: 0 = direct, N = delegated N times
    """
    token_string:     str           # the serialized signed token
    agent_id:         str
    scopes:           List[PermissionScope]
    issued_at:        float
    expires_at:       float
    jti:              str           # unique token ID
    principal:        Optional[str]
    delegation_depth: int = 0

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def ttl_remaining(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def has_scope(self, scope: PermissionScope) -> bool:
        return PermissionScope.ALL in self.scopes or scope in self.scopes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id":        self.agent_id,
            "scopes":          [s.value for s in self.scopes],
            "issued_at":       _iso(self.issued_at),
            "expires_at":      _iso(self.expires_at),
            "ttl_remaining_s": round(self.ttl_remaining),
            "jti":             self.jti,
            "principal":       self.principal,
            "delegation_depth": self.delegation_depth,
            "expired":         self.is_expired,
        }


@dataclass
class DelegationLink:
    """One link in a delegation chain."""
    from_agent:  str
    to_agent:    str
    scopes:      List[PermissionScope]   # can only delegate subset of own scopes
    authorized_by: str                   # human or parent agent
    created_at:  str
    expires_at:  Optional[str]
    jti:         str                     # parent token that authorized this

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_agent":    self.from_agent,
            "to_agent":      self.to_agent,
            "scopes":        [s.value for s in self.scopes],
            "authorized_by": self.authorized_by,
            "created_at":    self.created_at,
            "expires_at":    self.expires_at,
            "jti":           self.jti,
        }


@dataclass
class AuditEvent:
    """Immutable, hash-chained audit log entry."""
    event_id:    str
    agent_id:    str
    action:      str
    scope_used:  Optional[str]
    principal:   Optional[str]
    result:      str        # "allowed" | "denied" | "error"
    detail:      str
    timestamp:   str
    token_jti:   Optional[str]
    event_hash:  str        # SHA256 of event + prev_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id":   self.event_id,
            "agent_id":   self.agent_id,
            "action":     self.action,
            "scope_used": self.scope_used,
            "principal":  self.principal,
            "result":     self.result,
            "detail":     self.detail[:200],
            "timestamp":  self.timestamp,
            "token_jti":  self.token_jti,
            "event_hash": self.event_hash,
        }


# ---------------------------------------------------------------------------
# Token codec (no external JWT library needed)
# ---------------------------------------------------------------------------

class _TokenCodec:
    """Minimal JWT-compatible token codec using HMAC-SHA256."""

    @staticmethod
    def encode(payload: Dict[str, Any], secret: str) -> str:
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "AGT"}).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        sig_input = f"{header}.{body}".encode()
        sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{header}.{body}.{sig_b64}"

    @staticmethod
    def decode(token: str, secret: str) -> Dict[str, Any]:
        """Decode and verify. Raises ValueError on invalid/expired token."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        header_b64, body_b64, sig_b64 = parts
        sig_input = f"{header_b64}.{body_b64}".encode()
        expected = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
        if not hmac.compare_digest(expected_b64, sig_b64):
            raise ValueError("Token signature invalid")
        # Decode payload
        padded = body_b64 + "=" * (-len(body_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return payload


# ---------------------------------------------------------------------------
# Agent Registry
# ---------------------------------------------------------------------------

class AgentRegistry:
    """
    Central registry for agent identities.

    Responsibilities:
    - Register new agents (issue identity + signing secret)
    - Issue short-lived, scoped access tokens
    - Verify tokens cryptographically
    - Revoke individual agents (others unaffected)
    - Maintain immutable audit log
    - Manage delegation chains

    Thread-safe. Persists to JSON if store_path given.

    Args:
        secret_key:       Master secret for registry operations.
                          Derive per-agent secrets from this.
        store_path:       Persist registry to this JSON file.
        default_ttl:      Default token TTL in seconds (default 300 = 5min).
        max_delegation:   Max delegation depth (default 3).
        on_violation:     Callback(agent_id, action, reason) on auth failure.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        store_path: Optional[str] = None,
        default_ttl: int = 300,
        max_delegation: int = 3,
        on_violation: Optional[Callable[[str, str, str], None]] = None,
    ) -> None:
        self._master_secret = secret_key or secrets.token_hex(32)
        self._store_path = Path(store_path) if store_path else None
        self._default_ttl = default_ttl
        self._max_delegation = max_delegation
        self._on_violation = on_violation
        self._lock = threading.RLock()

        self._agents: Dict[str, AgentIdentity] = {}
        self._revoked_jtis: Set[str] = set()       # revoked token IDs
        self._delegations: List[DelegationLink] = []
        self._audit: List[AuditEvent] = []
        self._audit_prev_hash = "0" * 64

        self._load()

    # ── Agent lifecycle ─────────────────────────────────────────────────────

    def register(
        self,
        name: str,
        scopes: List[PermissionScope],
        owner: str,
        description: str = "",
        ttl_seconds: int = 300,
        agent_ttl_days: Optional[int] = None,   # identity expiry (None = no expiry)
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentIdentity:
        """
        Register a new agent identity.

        Returns AgentIdentity with unique agent_id and signing_secret.
        The signing_secret should be stored securely — it is NOT stored in
        plaintext in the registry JSON by default.

        Args:
            name:         Human-readable agent name
            scopes:       List of PermissionScope — what this agent can do
            owner:        Email/username of human responsible for this agent
            description:  Purpose of this agent
            ttl_seconds:  Default token TTL for this agent
            agent_ttl_days: Days until this identity expires (None = no expiry)
            metadata:     Additional attributes
        """
        with self._lock:
            agent_id = "agt_" + secrets.token_urlsafe(12)
            # Per-agent signing secret derived from master + agent_id
            signing_secret = hmac.new(
                self._master_secret.encode(),
                f"agent_secret:{agent_id}".encode(),
                hashlib.sha256
            ).hexdigest()

            now = _now()
            expires_at = None
            if agent_ttl_days is not None:
                exp_ts = time.time() + agent_ttl_days * 86400
                expires_at = _iso(exp_ts)

            identity = AgentIdentity(
                agent_id       = agent_id,
                name           = name,
                description    = description,
                scopes         = list(scopes),
                owner          = owner,
                status         = AgentStatus.ACTIVE,
                created_at     = now,
                expires_at     = expires_at,
                last_seen      = None,
                token_ttl      = ttl_seconds,
                signing_secret = signing_secret,
                metadata       = metadata or {},
            )
            self._agents[agent_id] = identity
            self._audit_append(agent_id, "register", None, owner, "allowed",
                               f"Registered '{name}' scopes={[s.value for s in scopes]}")
            self._save()
            return identity

    def revoke(
        self,
        agent_id: str,
        reason: str = "",
        revoked_by: str = "system",
    ) -> bool:
        """
        Revoke a single agent identity.

        All future token verifications for this agent will fail.
        Other agents are unaffected.
        """
        with self._lock:
            identity = self._agents.get(agent_id)
            if not identity:
                return False
            identity.status = AgentStatus.REVOKED
            self._audit_append(agent_id, "revoke", None, revoked_by, "allowed",
                               f"Revoked: {reason}")
            self._save()
            return True

    def suspend(self, agent_id: str, reason: str = "", by: str = "system") -> bool:
        """Temporarily suspend an agent (can be re-activated)."""
        with self._lock:
            identity = self._agents.get(agent_id)
            if not identity:
                return False
            identity.status = AgentStatus.SUSPENDED
            self._audit_append(agent_id, "suspend", None, by, "allowed", reason)
            self._save()
            return True

    def reactivate(self, agent_id: str, by: str = "system") -> bool:
        """Re-activate a suspended agent."""
        with self._lock:
            identity = self._agents.get(agent_id)
            if not identity or identity.status == AgentStatus.REVOKED:
                return False
            identity.status = AgentStatus.ACTIVE
            self._audit_append(agent_id, "reactivate", None, by, "allowed", "")
            self._save()
            return True

    def update_scopes(
        self,
        agent_id: str,
        scopes: List[PermissionScope],
        updated_by: str,
    ) -> bool:
        """Update an agent's permission scopes."""
        with self._lock:
            identity = self._agents.get(agent_id)
            if not identity:
                return False
            old = [s.value for s in identity.scopes]
            identity.scopes = list(scopes)
            self._audit_append(
                agent_id, "update_scopes", None, updated_by, "allowed",
                f"old={old} new={[s.value for s in scopes]}"
            )
            self._save()
            return True

    # ── Token operations ────────────────────────────────────────────────────

    def issue_token(
        self,
        agent_id: str,
        scopes: Optional[List[PermissionScope]] = None,
        principal: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        delegation_depth: int = 0,
        parent_jti: Optional[str] = None,
    ) -> AgentToken:
        """
        Issue a short-lived, scoped access token for an agent.

        Args:
            agent_id:         Which agent to issue for
            scopes:           Requested scopes (must be subset of registered scopes)
                              If None, uses all registered scopes
            principal:        Human who triggered this action
            ttl_seconds:      Token lifetime (default: agent's token_ttl)
            delegation_depth: 0 = direct, N = delegated N times
            parent_jti:       Parent token JTI (for delegation chains)

        Returns:
            AgentToken — use token.token_string to pass to APIs

        Raises:
            ValueError: if agent not found, revoked, or scope not permitted
        """
        with self._lock:
            identity = self._agents.get(agent_id)
            if not identity:
                raise ValueError(f"Agent not found: {agent_id}")
            if not identity.is_active:
                raise ValueError(f"Agent is {identity.status.value}: {agent_id}")

            # Validate requested scopes
            if scopes is None:
                granted_scopes = identity.scopes
            else:
                # Requested scopes must be subset of registered scopes
                if PermissionScope.ALL not in identity.scopes:
                    for s in scopes:
                        if s not in identity.scopes and PermissionScope.ALL not in identity.scopes:
                            raise ValueError(
                                f"Scope '{s.value}' not granted to agent '{agent_id}'. "
                                f"Registered: {[x.value for x in identity.scopes]}"
                            )
                granted_scopes = scopes

            ttl = ttl_seconds or identity.token_ttl
            now = time.time()
            jti = "tok_" + secrets.token_urlsafe(16)

            payload = {
                "iss":    "memgar-registry",
                "sub":    agent_id,
                "iat":    int(now),
                "exp":    int(now + ttl),
                "jti":    jti,
                "scopes": [s.value for s in granted_scopes],
                "name":   identity.name,
                "principal": principal,
                "delegation_depth": delegation_depth,
                "parent_jti": parent_jti,
            }

            token_str = _TokenCodec.encode(payload, identity.signing_secret)
            identity.last_seen = _now()

            token = AgentToken(
                token_string     = token_str,
                agent_id         = agent_id,
                scopes           = granted_scopes,
                issued_at        = now,
                expires_at       = now + ttl,
                jti              = jti,
                principal        = principal,
                delegation_depth = delegation_depth,
            )

            self._audit_append(
                agent_id, "issue_token", None, principal or "system", "allowed",
                f"jti={jti} scopes={[s.value for s in granted_scopes]} ttl={ttl}s"
            )
            self._save()
            return token

    def verify_token(
        self,
        token_string: str,
        required_scope: Optional[PermissionScope] = None,
    ) -> AgentToken:
        """
        Verify a token and optionally check a required scope.

        Returns AgentToken with decoded claims.

        Raises:
            ValueError: if token is invalid, expired, revoked, or missing scope
        """
        # Decode header to get agent_id without verifying yet
        parts = token_string.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed token")
        try:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            payload_raw = json.loads(base64.urlsafe_b64decode(padded))
            agent_id = payload_raw.get("sub", "")
        except Exception:
            raise ValueError("Cannot decode token payload")

        with self._lock:
            identity = self._agents.get(agent_id)
            if not identity:
                raise ValueError(f"Unknown agent: {agent_id}")
            if not identity.is_active:
                raise ValueError(f"Agent {identity.status.value}: {agent_id}")

            # Verify signature + expiry
            try:
                payload = _TokenCodec.decode(token_string, identity.signing_secret)
            except ValueError as e:
                self._on_violation_fire(agent_id, "verify_token", str(e))
                raise

            jti = payload.get("jti", "")
            if jti in self._revoked_jtis:
                raise ValueError(f"Token revoked: {jti}")

            scopes = [PermissionScope(s) for s in payload.get("scopes", [])
                      if s in {p.value for p in PermissionScope}]

            token = AgentToken(
                token_string     = token_string,
                agent_id         = agent_id,
                scopes           = scopes,
                issued_at        = payload["iat"],
                expires_at       = payload["exp"],
                jti              = jti,
                principal        = payload.get("principal"),
                delegation_depth = payload.get("delegation_depth", 0),
            )

            # Scope check
            if required_scope and not token.has_scope(required_scope):
                self._on_violation_fire(
                    agent_id, "scope_check",
                    f"Required '{required_scope.value}', have {[s.value for s in scopes]}"
                )
                self._audit_append(
                    agent_id, "scope_denied", required_scope.value,
                    payload.get("principal"), "denied",
                    f"Missing scope: {required_scope.value}"
                )
                raise ValueError(
                    f"Agent '{agent_id}' lacks scope '{required_scope.value}'"
                )

            identity.last_seen = _now()
            return token

    def revoke_token(self, jti: str) -> None:
        """Revoke a specific token by JTI (without revoking the agent)."""
        with self._lock:
            self._revoked_jtis.add(jti)
            self._save()

    # ── Delegation ───────────────────────────────────────────────────────────

    def delegate(
        self,
        from_token: AgentToken,
        to_agent_id: str,
        scopes: List[PermissionScope],
        ttl_seconds: int = 60,
    ) -> AgentToken:
        """
        Delegate a subset of permissions from one agent to another.

        The delegated token has:
        - Only scopes that the parent token already has
        - delegation_depth = parent.delegation_depth + 1
        - Shorter TTL than parent (capped)
        - parent_jti linking back to the authorizing token

        Raises:
            ValueError: if delegation depth exceeded or scope escalation attempted
        """
        if from_token.is_expired:
            raise ValueError("Cannot delegate from expired token")
        if from_token.delegation_depth >= self._max_delegation:
            raise ValueError(
                f"Max delegation depth ({self._max_delegation}) reached"
            )
        # Anti-escalation: delegated scopes must be subset of parent scopes
        if PermissionScope.ALL not in from_token.scopes:
            for s in scopes:
                if s not in from_token.scopes and PermissionScope.ALL not in from_token.scopes:
                    raise ValueError(
                        f"Cannot delegate scope '{s.value}' not in parent token"
                    )

        # Cap TTL at parent remaining time
        parent_remaining = from_token.ttl_remaining
        actual_ttl = min(ttl_seconds, int(parent_remaining))

        delegated_token = self.issue_token(
            agent_id         = to_agent_id,
            scopes           = scopes,
            principal        = from_token.principal,
            ttl_seconds      = actual_ttl,
            delegation_depth = from_token.delegation_depth + 1,
            parent_jti       = from_token.jti,
        )

        link = DelegationLink(
            from_agent   = from_token.agent_id,
            to_agent     = to_agent_id,
            scopes       = scopes,
            authorized_by= from_token.principal or from_token.agent_id,
            created_at   = _now(),
            expires_at   = _iso(time.time() + actual_ttl),
            jti          = from_token.jti,
        )
        with self._lock:
            self._delegations.append(link)
            self._save()

        return delegated_token

    # ── Queries ──────────────────────────────────────────────────────────────

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._agents.get(agent_id)

    def list_agents(
        self,
        status: Optional[AgentStatus] = None,
        owner: Optional[str] = None,
    ) -> List[AgentIdentity]:
        with self._lock:
            agents = list(self._agents.values())
        if status:
            agents = [a for a in agents if a.status == status]
        if owner:
            agents = [a for a in agents if a.owner == owner]
        return agents

    def audit_log(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        with self._lock:
            events = list(self._audit)
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        return events[-limit:]

    def verify_audit_chain(self) -> tuple[bool, int]:
        """Verify integrity of the audit log hash chain."""
        prev = "0" * 64
        errors = 0
        for event in self._audit:
            computed = _hash_event(event.event_id, event.action, event.timestamp, prev)
            if computed != event.event_hash:
                errors += 1
            prev = event.event_hash
        return errors == 0, errors

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            agents = list(self._agents.values())
        return {
            "total_agents":    len(agents),
            "active":          sum(1 for a in agents if a.status == AgentStatus.ACTIVE),
            "revoked":         sum(1 for a in agents if a.status == AgentStatus.REVOKED),
            "suspended":       sum(1 for a in agents if a.status == AgentStatus.SUSPENDED),
            "revoked_tokens":  len(self._revoked_jtis),
            "delegations":     len(self._delegations),
            "audit_events":    len(self._audit),
        }

    # ── Internal ─────────────────────────────────────────────────────────────

    def _audit_append(
        self,
        agent_id: str,
        action: str,
        scope: Optional[str],
        principal: Optional[str],
        result: str,
        detail: str,
        jti: Optional[str] = None,
    ) -> None:
        now = _now()
        event_id = "evt_" + secrets.token_urlsafe(8)
        event_hash = _hash_event(event_id, action, now, self._audit_prev_hash)
        event = AuditEvent(
            event_id   = event_id,
            agent_id   = agent_id,
            action     = action,
            scope_used = scope,
            principal  = principal,
            result     = result,
            detail     = detail,
            timestamp  = now,
            token_jti  = jti,
            event_hash = event_hash,
        )
        self._audit.append(event)
        self._audit_prev_hash = event_hash
        if len(self._audit) > 10000:
            self._audit = self._audit[-5000:]

    def _on_violation_fire(self, agent_id: str, action: str, reason: str) -> None:
        self._audit_append(agent_id, action, None, None, "denied", reason)
        if self._on_violation:
            try:
                self._on_violation(agent_id, action, reason)
            except Exception:
                pass

    def _signing_secret_for(self, agent_id: str) -> str:
        return hmac.new(
            self._master_secret.encode(),
            f"agent_secret:{agent_id}".encode(),
            hashlib.sha256
        ).hexdigest()

    def _load(self) -> None:
        if not self._store_path or not self._store_path.exists():
            return
        try:
            data = json.loads(self._store_path.read_text(encoding="utf-8"))
            for d in data.get("agents", []):
                identity = AgentIdentity(
                    agent_id       = d["agent_id"],
                    name           = d["name"],
                    description    = d.get("description", ""),
                    scopes         = [PermissionScope(s) for s in d.get("scopes", [])
                                      if s in {p.value for p in PermissionScope}],
                    owner          = d.get("owner", ""),
                    status         = AgentStatus(d.get("status", "active")),
                    created_at     = d.get("created_at", _now()),
                    expires_at     = d.get("expires_at"),
                    last_seen      = d.get("last_seen"),
                    token_ttl      = d.get("token_ttl", 300),
                    signing_secret = d.get("signing_secret") or self._signing_secret_for(d["agent_id"]),
                    metadata       = d.get("metadata", {}),
                )
                self._agents[identity.agent_id] = identity
            self._revoked_jtis = set(data.get("revoked_jtis", []))
            for d in data.get("audit", []):
                self._audit.append(AuditEvent(**d))
            if self._audit:
                self._audit_prev_hash = self._audit[-1].event_hash
        except Exception:
            pass

    def _save(self) -> None:
        if not self._store_path:
            return
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version":      "1.0",
            "saved_at":     _now(),
            "agents":       [a.to_dict(include_secret=True) for a in self._agents.values()],
            "revoked_jtis": list(self._revoked_jtis),
            "delegations":  [d.to_dict() for d in self._delegations],
            "audit":        [e.to_dict() for e in self._audit[-1000:]],
        }
        self._store_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )


# ---------------------------------------------------------------------------
# AgentContext — runtime integration
# ---------------------------------------------------------------------------

@dataclass
class AgentContext:
    """
    Runtime identity context for an agent.

    Injected into auto_protect() so every scan call is attributable
    to a specific agent + human principal.
    """
    agent_id:  str
    token:     AgentToken
    registry:  AgentRegistry

    def verify_scope(self, scope: PermissionScope) -> None:
        """Raise ValueError if this context lacks required scope."""
        if not self.token.has_scope(scope):
            raise ValueError(
                f"Agent '{self.agent_id}' lacks scope '{scope.value}'"
            )

    def log_action(self, action: str, scope: PermissionScope, result: str, detail: str = "") -> None:
        self.registry._audit_append(
            self.agent_id, action, scope.value,
            self.token.principal, result, detail, self.token.jti
        )

    @property
    def is_valid(self) -> bool:
        try:
            self.registry.verify_token(self.token.token_string)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Convenience: global registry singleton
# ---------------------------------------------------------------------------

_global_registry: Optional[AgentRegistry] = None
_registry_lock = threading.Lock()


def get_registry(
    secret_key: Optional[str] = None,
    store_path: Optional[str] = None,
) -> AgentRegistry:
    """Get or create the global AgentRegistry singleton."""
    global _global_registry
    with _registry_lock:
        if _global_registry is None:
            _global_registry = AgentRegistry(
                secret_key=secret_key,
                store_path=store_path,
            )
        return _global_registry


def create_registry(
    secret_key: Optional[str] = None,
    store_path: Optional[str] = None,
    **kwargs,
) -> AgentRegistry:
    """Create a new AgentRegistry (does not affect global singleton)."""
    return AgentRegistry(secret_key=secret_key, store_path=store_path, **kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _hash_event(event_id: str, action: str, ts: str, prev_hash: str) -> str:
    payload = f"{event_id}|{action}|{ts}|{prev_hash}"
    return hashlib.sha256(payload.encode()).hexdigest()
