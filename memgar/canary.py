"""
Canary Token System — proof-of-exfiltration tracer.

Memory poisoning attacks that succeed in injecting instructions are often
*invisible* until the agent acts on them. By the time exfiltration happens,
the operator usually has no way to *prove* the memory store leaked.

Canary tokens solve this. We embed unique, agent-invisible tracer strings
into memory metadata (or, optionally, low-visibility positions in memory
content). The agent should never see, repeat, or transmit them. If a canary
ever appears in:

  * an outbound LLM completion,
  * a tool-call argument,
  * an HTTP request body,
  * a log line emitted to an external destination,

then memory exfiltration has *demonstrably* occurred. The tracer is the proof.

Design properties
-----------------
* **Cryptographically unique.**  16 bytes of `secrets.token_hex` → collision-
  proof and unguessable.
* **Distinctive prefix.**  `mg-cnry-` so scanners can rapid-match without
  false positives on natural text.
* **Per-tenant + per-agent scoping.**  A canary leak tells you *which* tenant
  and *which* agent's memory was compromised.
* **Active expiry.**  Canaries auto-rotate after `ttl_seconds`; old ones stay
  in the leak-detection set for `grace_seconds` so late detections still fire.
* **No data dependency.**  Pure stdlib — no DB, no network.

This module is intentionally tiny and dependency-free so it can be embedded
in any agent runtime, including ones with no Memgar Analyzer in the path.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CANARY_PREFIX = "mg-cnry-"
# 16 bytes = 32 hex chars → 128 bits of entropy
_TOKEN_BYTES = 16

# Match canaries anywhere — case-sensitive on the prefix to avoid normal
# words colliding (e.g. "Canary" the bird) but token body is hex anyway.
_CANARY_RE = re.compile(rf"{re.escape(CANARY_PREFIX)}[0-9a-f]{{{_TOKEN_BYTES * 2}}}")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CanaryToken:
    """A single canary tracer."""
    token: str               # full string, including prefix
    tenant_id: str
    agent_id: str
    created_at: float
    expires_at: float
    label: str = ""          # optional human label ("kb-row-42")

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass
class CanaryLeak:
    """A detected leak event."""
    token: str
    tenant_id: str
    agent_id: str
    label: str
    detected_at: float
    sink: str                # where it leaked: 'llm_output', 'tool_arg', etc.
    excerpt: str             # short surrounding context for forensics

    @property
    def severity(self) -> str:
        return "critical"    # any canary leak is, by definition, critical


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class CanaryTokenManager:
    """Issue, embed, and detect canary tokens.

    Args:
        ttl_seconds: how long a canary stays *active* (eligible for embedding
            in new memory entries). Default 7 days.
        grace_seconds: after expiry, how long we still treat appearances as
            leaks. Default 30 days. This catches slow exfiltration (e.g.
            attacker who collects then publishes weeks later).
        max_active: cap on active canaries to prevent unbounded growth.
    """

    def __init__(
        self,
        ttl_seconds: float = 7 * 24 * 3600,
        grace_seconds: float = 30 * 24 * 3600,
        max_active: int = 10_000,
    ) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self.grace_seconds = float(grace_seconds)
        self.max_active = int(max_active)

        self._active: Dict[str, CanaryToken] = {}
        # Recently-expired canaries we still match against:
        self._grace: Dict[str, CanaryToken] = {}
        # All leaks observed (capped FIFO)
        self._leaks: List[CanaryLeak] = []
        self._max_leaks = 1_000

    # -----------------------------------------------------------------
    # Issuance
    # -----------------------------------------------------------------

    def issue(
        self,
        tenant_id: str,
        agent_id: str,
        label: str = "",
    ) -> CanaryToken:
        """Mint a fresh canary scoped to (tenant_id, agent_id)."""
        self._gc()
        if len(self._active) >= self.max_active:
            # Evict the oldest active canary to grace.
            oldest = min(self._active.values(), key=lambda c: c.created_at)
            self._move_to_grace(oldest.token)

        body = secrets.token_hex(_TOKEN_BYTES)
        token = f"{CANARY_PREFIX}{body}"
        now = time.time()
        canary = CanaryToken(
            token=token,
            tenant_id=tenant_id,
            agent_id=agent_id,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            label=label,
        )
        self._active[token] = canary
        return canary

    def embed_in_metadata(
        self,
        metadata: Optional[Dict[str, str]],
        tenant_id: str,
        agent_id: str,
        label: str = "",
    ) -> Tuple[Dict[str, str], CanaryToken]:
        """Return a copy of `metadata` with a fresh canary attached.

        The canary lives under the `_canary` key so it is invisible to the
        agent's content view but still travels with the entry.
        """
        out = dict(metadata) if metadata else {}
        canary = self.issue(tenant_id, agent_id, label)
        out["_canary"] = canary.token
        return out, canary

    # -----------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------

    def scan(
        self,
        text: str,
        sink: str = "unknown",
    ) -> List[CanaryLeak]:
        """Scan `text` for any active or grace-window canaries.

        Returns the list of leaks detected; empty if clean. Each detection
        is also recorded in the manager's leak log.
        """
        if not text:
            return []
        self._gc()

        leaks: List[CanaryLeak] = []
        now = time.time()
        for match in _CANARY_RE.finditer(text):
            token = match.group(0)
            canary = self._active.get(token) or self._grace.get(token)
            if canary is None:
                # Unknown canary-shaped string. Could be from another tenant
                # or a forged decoy — record it but don't attribute.
                continue

            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            leak = CanaryLeak(
                token=token,
                tenant_id=canary.tenant_id,
                agent_id=canary.agent_id,
                label=canary.label,
                detected_at=now,
                sink=sink,
                excerpt=text[start:end],
            )
            leaks.append(leak)

        for leak in leaks:
            self._leaks.append(leak)
        if len(self._leaks) > self._max_leaks:
            self._leaks = self._leaks[-self._max_leaks :]
        return leaks

    def has_leaked(self, token: str) -> bool:
        """Has this specific canary ever been observed in a sink?"""
        return any(l.token == token for l in self._leaks)

    # -----------------------------------------------------------------
    # Introspection
    # -----------------------------------------------------------------

    @property
    def active_count(self) -> int:
        self._gc()
        return len(self._active)

    @property
    def leaks(self) -> List[CanaryLeak]:
        return list(self._leaks)

    def revoke(self, token: str) -> bool:
        """Remove a canary entirely (no longer matched even in grace)."""
        removed = False
        if token in self._active:
            del self._active[token]
            removed = True
        if token in self._grace:
            del self._grace[token]
            removed = True
        return removed

    def reset(self) -> None:
        self._active.clear()
        self._grace.clear()
        self._leaks.clear()

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _gc(self) -> None:
        now = time.time()
        # Active → grace
        expired = [t for t, c in self._active.items() if c.expires_at <= now]
        for t in expired:
            self._move_to_grace(t)
        # Grace → forgotten
        forget_cutoff = now - self.grace_seconds
        forget = [
            t for t, c in self._grace.items() if c.expires_at <= forget_cutoff
        ]
        for t in forget:
            del self._grace[t]

    def _move_to_grace(self, token: str) -> None:
        canary = self._active.pop(token, None)
        if canary is not None:
            self._grace[token] = canary


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def extract_canaries(text: str) -> List[str]:
    """Return all canary-shaped substrings from `text` (no manager needed)."""
    if not text:
        return []
    return _CANARY_RE.findall(text)


def is_canary(token: str) -> bool:
    """True iff `token` looks like a canary — does NOT verify membership."""
    return bool(_CANARY_RE.fullmatch(token or ""))


__all__ = [
    "CanaryToken",
    "CanaryLeak",
    "CanaryTokenManager",
    "extract_canaries",
    "is_canary",
    "CANARY_PREFIX",
]
