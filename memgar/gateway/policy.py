"""
Gateway policy engine — what the gateway enforces on every request/response.

Two phases:
  * **Input phase** — runs after the upstream URL is resolved but BEFORE the
    request is forwarded. Scans prompts / messages / tool inputs for
    memory-poisoning attacks. May block or sanitise.
  * **Output phase** — runs as the upstream response streams back. Scans
    completions for canary leaks (proven exfiltration), secret/PII leaks,
    jailbreak text. May redact or terminate the stream.

Policies are pure-data so they can be loaded from YAML / env / DB without
re-importing anything from the gateway runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"


@dataclass
class InputPolicy:
    """What the gateway scans on inbound requests."""
    enabled: bool = True

    # Risk threshold (0..100) at which the request is blocked outright.
    block_risk_score: int = 70
    # Risk threshold at which message content is sanitised before forwarding.
    sanitize_risk_score: int = 40

    # If True, every user/system message in the request is scanned. If False,
    # only the LAST user message is scanned (faster, less defensive).
    scan_all_messages: bool = True

    # Tool/function arguments scan
    scan_tool_arguments: bool = True

    # Disallow upstream model names matching these patterns.
    blocked_models: List[str] = field(default_factory=list)


@dataclass
class OutputPolicy:
    """What the gateway scans on outbound responses."""
    enabled: bool = True

    # Block / redact responses if a canary token leaks. Strongest signal.
    block_on_canary_leak: bool = True

    # PII / secret regexes the gateway redacts in completions.
    redact_patterns: List[str] = field(default_factory=lambda: [
        r"\bsk-[A-Za-z0-9]{20,}\b",                # OpenAI keys
        r"\bxoxb-[A-Za-z0-9-]{20,}\b",             # Slack bot tokens
        r"\bAKIA[0-9A-Z]{16}\b",                   # AWS access key id
        r"\bghp_[A-Za-z0-9]{20,}\b",               # GitHub PAT
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email
    ])
    redaction_token: str = "[REDACTED]"

    # Block jailbreak / system-prompt-leak phrases in the model's reply.
    jailbreak_response_patterns: List[str] = field(default_factory=lambda: [
        r"(?i)i am (?:now )?in (?:developer|jailbreak|dan) mode",
        r"(?i)system prompt[:\s]+\".+\"",
        r"(?i)my instructions are[:\s]+",
    ])


@dataclass
class GatewayPolicy:
    """Top-level gateway policy bundle."""
    upstream_base_url: str = "https://api.anthropic.com"
    upstream_timeout_seconds: float = 120.0
    forward_request_headers: List[str] = field(default_factory=lambda: [
        "authorization", "x-api-key", "anthropic-version",
        "anthropic-beta", "openai-version", "openai-organization",
        "user-agent", "content-type", "accept",
    ])
    fail_open: bool = False  # if a layer crashes, do we forward anyway?

    input: InputPolicy = field(default_factory=InputPolicy)
    output: OutputPolicy = field(default_factory=OutputPolicy)

    # Pre-compiled redaction patterns (filled lazily on first use).
    _compiled_redact: Optional[List[re.Pattern]] = None
    _compiled_jailbreak: Optional[List[re.Pattern]] = None

    def compiled_redactions(self) -> List[re.Pattern]:
        if self._compiled_redact is None:
            self._compiled_redact = [
                re.compile(p) for p in self.output.redact_patterns
            ]
        return self._compiled_redact

    def compiled_jailbreak(self) -> List[re.Pattern]:
        if self._compiled_jailbreak is None:
            self._compiled_jailbreak = [
                re.compile(p) for p in self.output.jailbreak_response_patterns
            ]
        return self._compiled_jailbreak


__all__ = ["GatewayPolicy", "InputPolicy", "OutputPolicy", "PolicyDecision"]
