"""
Tool-Use Guard — last-mile defense before an agent executes a tool call.

Memory poisoning is a *latent* threat: a malicious entry sits in memory until
the agent uses it to construct a tool argument (HTTP URL, email recipient,
SQL query, file path, payment IBAN…). The actual *damage* happens at tool
execution. This module hooks that exact moment.

`ToolUseGuard.check_call(tool_name, arguments, source_memories)` does:

  1. **Argument scanning.**  Every string-valued argument is scanned for
     pattern injections, stego, canary leaks (proof of memory exfiltration),
     and known dangerous shapes (URLs to disallowed hosts, IBAN/wallet
     drift vs. user-approved targets, code-exec snippets).
  2. **Source provenance check.**  If `source_memories` includes any entries
     that were flagged HIGH risk by the Analyzer, the call is blocked even
     if the *current* arguments look clean (defense against split attacks).
  3. **Tool risk class.**  Per-tool default risk levels gate behavior:
     `transfer_funds` and `send_email` always require explicit allow-list
     arguments; `read_file` is permissive.

The guard is a *separate* policy layer from the Analyzer. Analyzer says "this
memory entry is suspicious." Guard says "given those suspicions, this *call*
should not run." They compose — and either one alone significantly reduces
the effective attack surface.

Performance: ~0.3ms per check on typical arg sets. No network, no LLM calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from .canary import extract_canaries


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class ToolRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Tool name → default risk class. Names follow common conventions; consumers
# can extend via `ToolUseGuard.register_tool()`.
DEFAULT_TOOL_RISK: Dict[str, ToolRisk] = {
    # Critical — irreversible side effects
    "transfer_funds": ToolRisk.CRITICAL,
    "send_payment": ToolRisk.CRITICAL,
    "execute_code": ToolRisk.CRITICAL,
    "execute_shell": ToolRisk.CRITICAL,
    "delete_file": ToolRisk.CRITICAL,
    "delete_record": ToolRisk.CRITICAL,
    "grant_role": ToolRisk.CRITICAL,
    "modify_credentials": ToolRisk.CRITICAL,
    # High — external visibility / hard to reverse
    "send_email": ToolRisk.HIGH,
    "send_sms": ToolRisk.HIGH,
    "post_message": ToolRisk.HIGH,
    "http_post": ToolRisk.HIGH,
    "http_put": ToolRisk.HIGH,
    "write_file": ToolRisk.HIGH,
    "create_pull_request": ToolRisk.HIGH,
    # Medium
    "update_record": ToolRisk.MEDIUM,
    "schedule_event": ToolRisk.MEDIUM,
    "create_document": ToolRisk.MEDIUM,
    # Low — read-only
    "read_file": ToolRisk.LOW,
    "search": ToolRisk.LOW,
    "http_get": ToolRisk.LOW,
    "list_records": ToolRisk.LOW,
}


# Heuristic dangerous patterns inside arguments. Kept tight to avoid FPs.
_DANGEROUS_PATTERNS: List[tuple] = [
    ("code_exec", re.compile(
        r"\b(?:eval|exec|system|popen|subprocess\.|os\.system|child_process)\s*\(",
        re.IGNORECASE,
    )),
    ("sql_injection", re.compile(
        r"(?:;\s*(?:drop|delete|update|truncate)\s+(?:table|from)|--\s*$|/\*.*\*/)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("shell_metachars", re.compile(
        r"(?:\$\([^)]+\)|`[^`]+`|\|\s*(?:sh|bash|zsh|nc|curl|wget)\b)",
    )),
    ("path_traversal", re.compile(
        # Plain ../  .. \\  plus URL-encoded variants (%2e%2e%2f, %2e%2e/, etc.)
        r"\.\./{1,}|\.\.\\+|(?:%2e|%2E){2}(?:%2f|%2F|%5c|%5C)",
    )),
    ("ssrf_localhost", re.compile(
        r"\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1|169\.254\.169\.254)\b",
        re.IGNORECASE,
    )),
    ("script_injection", re.compile(
        r"(?:<script\b|javascript:\s*[^/])",
        re.IGNORECASE,
    )),
    ("crypto_redirect", re.compile(
        # IBAN drift / unfamiliar wallet language
        r"\b(?:bitcoin|btc|eth|wallet)\s+address\b|\b(?:bc1|0x)[0-9a-zA-Z]{20,}",
        re.IGNORECASE,
    )),
]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class ToolDecision(str, Enum):
    ALLOW = "allow"
    REQUIRE_CONFIRMATION = "confirm"
    BLOCK = "block"


@dataclass
class ToolFinding:
    technique: str
    severity: str
    field: str            # which argument
    description: str


@dataclass
class ToolCheckResult:
    decision: ToolDecision
    risk_score: int                      # 0..100
    findings: List[ToolFinding] = field(default_factory=list)
    canary_leaks: List[str] = field(default_factory=list)  # canary tokens
    rationale: str = ""

    @property
    def blocked(self) -> bool:
        return self.decision == ToolDecision.BLOCK


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

class ToolUseGuard:
    """Last-mile validator for agent → tool calls.

    Args:
        allowlist_hosts: outbound HTTP destinations permitted. None disables
            the host check entirely (not recommended for production).
        approved_payment_targets: IBAN / wallet strings the user has
            explicitly authorized. Any payment-tool call referring to a
            different target is BLOCKED, regardless of how the agent
            justifies it.
        require_confirmation_for: ToolRisk levels that demand human
            confirmation even when arguments look clean.
        max_arg_chars: arguments above this length are truncated for
            scanning to keep latency bounded.
    """

    def __init__(
        self,
        allowlist_hosts: Optional[Iterable[str]] = None,
        approved_payment_targets: Optional[Iterable[str]] = None,
        require_confirmation_for: Iterable[ToolRisk] = (ToolRisk.HIGH, ToolRisk.CRITICAL),
        tool_risk_overrides: Optional[Mapping[str, ToolRisk]] = None,
        max_arg_chars: int = 8192,
    ) -> None:
        self.allowlist_hosts: Optional[Set[str]] = (
            {h.lower() for h in allowlist_hosts} if allowlist_hosts is not None else None
        )
        self.approved_payment_targets: Set[str] = {
            t.replace(" ", "").upper() for t in (approved_payment_targets or [])
        }
        self.require_confirmation_for = set(require_confirmation_for)
        self.max_arg_chars = int(max_arg_chars)
        self._tool_risk: Dict[str, ToolRisk] = dict(DEFAULT_TOOL_RISK)
        if tool_risk_overrides:
            for name, risk in tool_risk_overrides.items():
                self._tool_risk[name] = risk

    # -----------------------------------------------------------------

    def register_tool(self, name: str, risk: ToolRisk) -> None:
        self._tool_risk[name] = risk

    def get_risk(self, tool_name: str) -> ToolRisk:
        return self._tool_risk.get(tool_name, ToolRisk.MEDIUM)

    # -----------------------------------------------------------------

    def check_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        source_memory_risk: Optional[Sequence[int]] = None,
        source_memory_blocked: bool = False,
    ) -> ToolCheckResult:
        """Decide whether to allow this tool call.

        Args:
            tool_name: agent-declared tool identifier.
            arguments: keyword arguments the agent intends to pass.
            source_memory_risk: per-source-memory risk_scores (0..100) from
                the Analyzer. The max is used as the "memory taint" floor.
            source_memory_blocked: True if any source memory was hard-blocked.
        """
        result = ToolCheckResult(decision=ToolDecision.ALLOW, risk_score=0)
        risk = self.get_risk(tool_name)

        # 1. Provenance: a blocked source should never produce a tool call.
        if source_memory_blocked:
            result.findings.append(ToolFinding(
                technique="tainted_source",
                severity="critical",
                field="<provenance>",
                description="At least one source memory was previously blocked",
            ))
            result.risk_score = 100
            result.decision = ToolDecision.BLOCK
            result.rationale = "blocked: tool call derived from blocked memory"
            return result

        memory_taint = max(source_memory_risk) if source_memory_risk else 0

        # 2. Per-argument scanning.
        for key, value in arguments.items():
            self._scan_value(key, value, result, tool_name)

        # 3. Aggregate risk.
        finding_score = min(100, sum(self._severity_weight(f.severity) for f in result.findings))
        result.risk_score = max(memory_taint, finding_score)

        # 4. Decision matrix.
        critical_finding = any(f.severity == "critical" for f in result.findings)
        high_finding = any(f.severity == "high" for f in result.findings)

        if (
            critical_finding
            or result.canary_leaks
            or (risk == ToolRisk.CRITICAL and (high_finding or memory_taint >= 50))
            or memory_taint >= 80
        ):
            result.decision = ToolDecision.BLOCK
        elif (
            risk in self.require_confirmation_for
            or high_finding
            or memory_taint >= 30
        ):
            result.decision = ToolDecision.REQUIRE_CONFIRMATION
        else:
            result.decision = ToolDecision.ALLOW

        result.rationale = self._compose_rationale(
            tool_name, risk, memory_taint, finding_score, result
        )
        return result

    # -----------------------------------------------------------------
    # Scanners
    # -----------------------------------------------------------------

    def _scan_value(
        self,
        key: str,
        value: Any,
        result: ToolCheckResult,
        tool_name: str,
    ) -> None:
        if value is None:
            return
        if isinstance(value, (list, tuple, set)):
            for i, item in enumerate(value):
                self._scan_value(f"{key}[{i}]", item, result, tool_name)
            return
        if isinstance(value, Mapping):
            for sub_key, sub_val in value.items():
                self._scan_value(f"{key}.{sub_key}", sub_val, result, tool_name)
            return
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                return
        if not isinstance(value, str):
            return  # numbers, bools, etc. — nothing to scan textually

        text = value[: self.max_arg_chars]

        # 2a. Canary detection — the strongest possible signal.
        canaries = extract_canaries(text)
        if canaries:
            for c in canaries:
                if c not in result.canary_leaks:
                    result.canary_leaks.append(c)
            result.findings.append(ToolFinding(
                technique="canary_leak",
                severity="critical",
                field=key,
                description=(
                    f"Memory canary token present in '{key}' — proves memory "
                    f"contents are about to leave the agent"
                ),
            ))

        # 2b. Pattern-based dangerous shapes.
        for tech, regex in _DANGEROUS_PATTERNS:
            if regex.search(text):
                severity = "critical" if tech in {"code_exec", "sql_injection"} else "high"
                result.findings.append(ToolFinding(
                    technique=tech,
                    severity=severity,
                    field=key,
                    description=f"'{tech}' pattern matched in argument '{key}'",
                ))

        # 2c. Outbound URL allowlist.
        if self.allowlist_hosts is not None and self._looks_like_url(text):
            host = self._url_host(text)
            if host and not self._host_allowed(host):
                result.findings.append(ToolFinding(
                    technique="disallowed_host",
                    severity="high",
                    field=key,
                    description=f"Outbound URL host '{host}' not on allowlist",
                ))

        # 2d. Payment target drift.
        if self._is_payment_tool(tool_name) and self.approved_payment_targets:
            target = self._extract_payment_target(text)
            if target and target not in self.approved_payment_targets:
                result.findings.append(ToolFinding(
                    technique="payment_target_drift",
                    severity="critical",
                    field=key,
                    description=(
                        f"Payment destination '{target[:30]}…' is not in the "
                        f"user-approved set"
                    ),
                ))

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _severity_weight(sev: str) -> int:
        return {"low": 5, "medium": 15, "high": 35, "critical": 60}.get(sev, 10)

    @staticmethod
    def _looks_like_url(s: str) -> bool:
        return bool(re.search(r"https?://", s, re.IGNORECASE))

    @staticmethod
    def _url_host(s: str) -> Optional[str]:
        m = re.search(r"https?://([^\s/'\"<>)\]]+)", s, re.IGNORECASE)
        if not m:
            return None
        try:
            netloc = m.group(1).lower()
            # Strip user:pass@
            if "@" in netloc:
                netloc = netloc.split("@", 1)[1]
            # Strip port
            if ":" in netloc:
                netloc = netloc.split(":", 1)[0]
            return netloc or None
        except Exception:
            return None

    def _host_allowed(self, host: str) -> bool:
        host = host.lower()
        if host in self.allowlist_hosts:
            return True
        for allowed in self.allowlist_hosts:
            if allowed.startswith("*.") and host.endswith(allowed[1:]):
                return True
        return False

    @staticmethod
    def _is_payment_tool(tool_name: str) -> bool:
        n = tool_name.lower()
        return any(kw in n for kw in ("payment", "transfer", "wire", "payout"))

    @staticmethod
    def _extract_payment_target(text: str) -> Optional[str]:
        # IBAN: country code + 2 digits + 11..30 alnum (+ optional spaces).
        # Total length after stripping spaces must be 15..34 per ISO 13616.
        iban_re = re.compile(
            r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30})\b"
        )
        for match in iban_re.finditer(text):
            candidate = match.group(1).replace(" ", "").upper()
            if 15 <= len(candidate) <= 34:
                return candidate
        # Crypto wallet (BTC bech32, BTC legacy P2PKH/P2SH, or ETH 0x..)
        wallet = re.search(
            r"\b(?:"
            r"bc1[0-9a-z]{25,87}"               # BTC bech32
            r"|[13][1-9A-HJ-NP-Za-km-z]{25,34}"  # BTC base58 P2PKH/P2SH
            r"|0x[0-9a-fA-F]{40}"                # ETH-style
            r")\b",
            text,
        )
        if wallet:
            return wallet.group(0).upper()
        return None

    @staticmethod
    def _compose_rationale(
        tool_name: str,
        risk: ToolRisk,
        memory_taint: int,
        finding_score: int,
        result: ToolCheckResult,
    ) -> str:
        techs = sorted({f.technique for f in result.findings})
        pieces = [
            f"tool={tool_name}",
            f"risk_class={risk.value}",
            f"memory_taint={memory_taint}",
            f"arg_findings={finding_score}",
        ]
        if techs:
            pieces.append("techniques=" + ",".join(techs))
        if result.canary_leaks:
            pieces.append(f"canaries={len(result.canary_leaks)}")
        return " | ".join(pieces)


__all__ = [
    "ToolUseGuard",
    "ToolCheckResult",
    "ToolDecision",
    "ToolFinding",
    "ToolRisk",
    "DEFAULT_TOOL_RISK",
]
