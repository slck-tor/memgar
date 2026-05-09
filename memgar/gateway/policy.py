"""
Gateway policy engine - data-only controls for input, output, and upstream
routing.

The gateway is a security boundary. Besides prompt scanning, it must ensure the
configured upstream cannot be abused as an SSRF primitive. GatewayPolicy keeps
that validation close to the transport configuration while remaining plain data
for env/YAML loading.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from urllib.parse import urlparse


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"


@dataclass
class InputPolicy:
    """What the gateway scans on inbound requests."""

    enabled: bool = True
    block_risk_score: int = 70
    sanitize_risk_score: int = 40
    scan_all_messages: bool = True
    scan_tool_arguments: bool = True
    blocked_models: List[str] = field(default_factory=list)


@dataclass
class OutputPolicy:
    """What the gateway scans on outbound responses."""

    enabled: bool = True
    block_on_canary_leak: bool = True
    redact_patterns: List[str] = field(default_factory=lambda: [
        r"\bsk-[A-Za-z0-9]{20,}\b",
        r"\bxoxb-[A-Za-z0-9-]{20,}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bghp_[A-Za-z0-9]{20,}\b",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    ])
    redaction_token: str = "[REDACTED]"
    jailbreak_response_patterns: List[str] = field(default_factory=lambda: [
        r"(?i)i am (?:now )?in (?:developer|jailbreak|dan) mode",
        r"(?i)system prompt[:\s]+\".+\"",
        r"(?i)my instructions are[:\s]+",
    ])


_LOCAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
}


def _normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _host_matches(host: str, allowed: str) -> bool:
    host = _normalize_host(host)
    allowed = _normalize_host(allowed)
    if allowed.startswith("*."):
        suffix = allowed[1:]
        return host.endswith(suffix) and host != allowed[2:]
    return host == allowed


def _is_private_or_local_host(host: str) -> bool:
    host = _normalize_host(host)
    if host in _LOCAL_HOSTNAMES or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return any((
        ip.is_private,
        ip.is_loopback,
        ip.is_link_local,
        ip.is_multicast,
        ip.is_reserved,
        ip.is_unspecified,
    ))


@dataclass
class GatewayPolicy:
    """Top-level gateway policy bundle."""

    upstream_base_url: str = "https://api.anthropic.com"
    upstream_timeout_seconds: float = 120.0
    forward_request_headers: List[str] = field(default_factory=lambda: [
        "authorization",
        "x-api-key",
        "anthropic-version",
        "anthropic-beta",
        "openai-version",
        "openai-organization",
        "user-agent",
        "content-type",
        "accept",
    ])
    fail_open: bool = False

    # SSRF controls. None means: only the configured upstream_base_url host is
    # allowed. Operators can pass exact hosts or wildcard suffixes like
    # "*.example.com" for multi-region providers.
    allowed_upstream_hosts: Optional[List[str]] = None
    allowed_upstream_schemes: List[str] = field(default_factory=lambda: ["https"])
    allow_private_upstreams: bool = False

    input: InputPolicy = field(default_factory=InputPolicy)
    output: OutputPolicy = field(default_factory=OutputPolicy)

    _compiled_redact: Optional[List[re.Pattern]] = None
    _compiled_jailbreak: Optional[List[re.Pattern]] = None

    def compiled_redactions(self) -> List[re.Pattern]:
        if self._compiled_redact is None:
            self._compiled_redact = [re.compile(p) for p in self.output.redact_patterns]
        return self._compiled_redact

    def compiled_jailbreak(self) -> List[re.Pattern]:
        if self._compiled_jailbreak is None:
            self._compiled_jailbreak = [
                re.compile(p) for p in self.output.jailbreak_response_patterns
            ]
        return self._compiled_jailbreak

    def validate_upstream_base_url(self) -> None:
        """Raise ValueError when upstream_base_url violates SSRF policy."""

        parsed = urlparse(self.upstream_base_url)
        scheme = (parsed.scheme or "").lower()
        host = parsed.hostname
        if not scheme or not host:
            raise ValueError("upstream_base_url must include an absolute scheme and host")
        if scheme not in {s.lower() for s in self.allowed_upstream_schemes}:
            raise ValueError(f"upstream scheme {scheme!r} is not allowed")
        if parsed.username or parsed.password:
            raise ValueError("upstream credentials in URL are not allowed")
        if parsed.query or parsed.fragment:
            raise ValueError("upstream_base_url must not include query or fragment")
        if not self.allow_private_upstreams and _is_private_or_local_host(host):
            raise ValueError(f"private or local upstream host {host!r} is not allowed")

        allowed = self.allowed_upstream_hosts or [host]
        if not any(_host_matches(host, item) for item in allowed):
            raise ValueError(f"upstream host {host!r} is not in the allowlist")

    def build_upstream_url(self, path: str) -> str:
        """Build and validate the final upstream URL for a proxied path."""

        if "\r" in path or "\n" in path:
            raise ValueError("upstream path contains control characters")
        self.validate_upstream_base_url()
        base = self.upstream_base_url.rstrip("/")
        safe_path = path.lstrip("/")
        upstream_url = f"{base}/{safe_path}"

        parsed_base = urlparse(self.upstream_base_url)
        parsed_final = urlparse(upstream_url)
        if parsed_final.scheme != parsed_base.scheme or parsed_final.hostname != parsed_base.hostname:
            raise ValueError("upstream URL host changed during path construction")
        return upstream_url


__all__ = ["GatewayPolicy", "InputPolicy", "OutputPolicy", "PolicyDecision"]
