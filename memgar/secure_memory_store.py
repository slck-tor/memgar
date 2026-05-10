"""
SecureMemoryStore - official write boundary for agent memory.

Every memory write is treated as untrusted input. The store wraps an arbitrary
backend and enforces the same pipeline before persistence:

    untrusted content
      -> runtime analyzer / policy engine
      -> DLP redaction or block
      -> audit event
      -> MemoryVault / MemoryLedger registration
      -> backend write

Direct writes to the wrapped backend bypass this protection. Production agent
integrations should expose only SecureMemoryStore to application code and keep
the raw backend private.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from memgar.models import MemoryEntry
from memgar.runtime import EnforcementAction, EnforcementResult, MemoryRuntimeEnforcer, RuntimePolicy


@dataclass
class DLPFinding:
    """A single DLP match found in memory content."""

    label: str
    start: int
    end: int
    sample: str
    severity: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "sample": self.sample[:16] + ("..." if len(self.sample) > 16 else ""),
            "severity": self.severity,
        }


@dataclass
class DLPPattern:
    """Named regular expression used by the DLP stage."""

    label: str
    pattern: str
    replacement: str
    severity: str = "medium"
    block: bool = False


@dataclass
class DLPPolicy:
    """Config for the SecureMemoryStore DLP stage."""

    enabled: bool = True
    block_high_severity: bool = False
    patterns: List[DLPPattern] = field(default_factory=lambda: [
        DLPPattern(
            label="openai_api_key",
            pattern=r"\bsk-[A-Za-z0-9_-]{20,}\b",
            replacement="[REDACTED:OPENAI_API_KEY]",
            severity="high",
            block=True,
        ),
        DLPPattern(
            label="aws_access_key",
            pattern=r"\bAKIA[0-9A-Z]{16}\b",
            replacement="[REDACTED:AWS_ACCESS_KEY]",
            severity="high",
            block=True,
        ),
        DLPPattern(
            label="github_token",
            pattern=r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
            replacement="[REDACTED:GITHUB_TOKEN]",
            severity="high",
            block=True,
        ),
        DLPPattern(
            label="slack_token",
            pattern=r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
            replacement="[REDACTED:SLACK_TOKEN]",
            severity="high",
            block=True,
        ),
        DLPPattern(
            label="email",
            pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            replacement="[REDACTED:EMAIL]",
            severity="low",
            block=False,
        ),
    ])


@dataclass
class DLPResult:
    """Result of DLP inspection and redaction."""

    original_content: str
    safe_content: str
    findings: List[DLPFinding] = field(default_factory=list)
    blocked: bool = False

    @property
    def was_redacted(self) -> bool:
        return self.safe_content != self.original_content

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocked": self.blocked,
            "was_redacted": self.was_redacted,
            "finding_count": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
        }


class DLPRedactor:
    """Small local DLP redactor for memory writes.

    This is intentionally deterministic and dependency-free. Enterprise users
    can pass their own DLP callable through SecureMemoryStore(dlp=...).
    """

    def __init__(self, policy: Optional[DLPPolicy] = None) -> None:
        self.policy = policy or DLPPolicy()
        self._compiled: List[Tuple[DLPPattern, re.Pattern[str]]] = [
            (item, re.compile(item.pattern)) for item in self.policy.patterns
        ]

    def inspect(self, content: str) -> DLPResult:
        if not self.policy.enabled or not content:
            return DLPResult(original_content=content, safe_content=content)

        findings: List[DLPFinding] = []
        blocked = False
        safe = content

        for item, pattern in self._compiled:
            for match in pattern.finditer(safe):
                findings.append(DLPFinding(
                    label=item.label,
                    start=match.start(),
                    end=match.end(),
                    sample=match.group(0),
                    severity=item.severity,
                ))
                if item.block or (self.policy.block_high_severity and item.severity == "high"):
                    blocked = True
            safe = pattern.sub(item.replacement, safe)

        return DLPResult(
            original_content=content,
            safe_content=safe,
            findings=findings,
            blocked=blocked,
        )


@dataclass
class SecureMemoryStorePolicy:
    """Operational policy for SecureMemoryStore."""

    raise_on_block: bool = True
    raise_on_quarantine: bool = False
    write_quarantined: bool = False
    audit_content_preview_chars: int = 160
    snapshot_every: int = 0
    verify_vault_before_write: bool = False


@dataclass
class SecureWriteResult:
    """Outcome of one SecureMemoryStore write attempt."""

    entry_id: Optional[str]
    action: EnforcementAction
    original_content: str
    safe_content: str
    enforcement: EnforcementResult
    dlp: DLPResult
    metadata: Dict[str, Any] = field(default_factory=dict)
    backend_result: Any = None
    wrote_to_backend: bool = False
    wrote_to_ledger: bool = False
    registered_in_vault: bool = False
    audit_logged: bool = False
    snapshot_id: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.action in (EnforcementAction.ALLOW, EnforcementAction.SANITIZE)

    @property
    def blocked(self) -> bool:
        return self.action == EnforcementAction.BLOCK

    @property
    def quarantined(self) -> bool:
        return self.action == EnforcementAction.QUARANTINE

    @property
    def was_sanitized(self) -> bool:
        return self.enforcement.was_sanitized or self.dlp.was_redacted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "action": self.action.value,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "quarantined": self.quarantined,
            "risk_score": self.enforcement.risk_score,
            "was_sanitized": self.was_sanitized,
            "wrote_to_backend": self.wrote_to_backend,
            "wrote_to_ledger": self.wrote_to_ledger,
            "registered_in_vault": self.registered_in_vault,
            "snapshot_id": self.snapshot_id,
            "dlp": self.dlp.to_dict(),
            "metadata": self.metadata,
            "enforcement": self.enforcement.to_dict(),
        }


class SecureMemoryWriteError(Exception):
    """Raised when SecureMemoryStore refuses to persist a write."""

    def __init__(self, message: str, result: SecureWriteResult) -> None:
        super().__init__(message)
        self.result = result


class SecureMemoryStore:
    """Backend-agnostic secure memory write boundary.

    The wrapped backend can be a Memgar MemoryStore, a MemoryLedger, a list,
    a dict, or any object exposing add(), append(), save(), or write().
    """

    def __init__(
        self,
        backend: Optional[Any] = None,
        *,
        enforcer: Optional[MemoryRuntimeEnforcer] = None,
        runtime_policy: Optional[RuntimePolicy] = None,
        policy_engine: Optional[Any] = None,
        analyzer: Optional[Any] = None,
        dlp: Optional[Any] = None,
        dlp_policy: Optional[DLPPolicy] = None,
        auditor: Optional[Any] = None,
        vault: Optional[Any] = None,
        ledger: Optional[Any] = None,
        quarantine_sink: Optional[Callable[[SecureWriteResult], None]] = None,
        policy: Optional[SecureMemoryStorePolicy] = None,
        agent_id: str = "default",
    ) -> None:
        self.backend = backend
        self.policy = policy or SecureMemoryStorePolicy()
        self.enforcer = enforcer or MemoryRuntimeEnforcer(
            analyzer=analyzer,
            policy=runtime_policy or RuntimePolicy(fail_open=False),
            policy_engine=policy_engine,
            agent_id=agent_id,
        )
        self.dlp = dlp or DLPRedactor(dlp_policy)
        self.auditor = auditor
        self.vault = vault
        self.ledger = ledger
        self.quarantine_sink = quarantine_sink
        self.agent_id = agent_id
        self._write_count = 0
        self._audit_events: List[Dict[str, Any]] = []
        self._last_result: Optional[SecureWriteResult] = None

    @property
    def audit_events(self) -> List[Dict[str, Any]]:
        return list(self._audit_events)

    @property
    def last_result(self) -> Optional[SecureWriteResult]:
        return self._last_result

    def validate_write(
        self,
        content: str,
        *,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tenant_id: str = "",
        principal: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecureWriteResult:
        """Run the full write decision pipeline without persisting."""

        enforcement = self.enforcer.on_memory_write(
            content,
            source_type=source_type,
            source_id=source_id,
            agent_id=agent_id or self.agent_id,
        )
        dlp_result = DLPResult(enforcement.safe_content, enforcement.safe_content)
        action = enforcement.action
        safe_content = enforcement.safe_content

        if enforcement.allowed:
            dlp_result = self._inspect_dlp(enforcement.safe_content)
            safe_content = dlp_result.safe_content
            if dlp_result.blocked:
                action = EnforcementAction.BLOCK

        result = SecureWriteResult(
            entry_id=self._make_entry_id(safe_content, source_id),
            action=action,
            original_content=content,
            safe_content=safe_content,
            enforcement=enforcement,
            dlp=dlp_result,
            metadata=self._build_security_metadata(
                source_type=source_type,
                source_id=source_id,
                agent_id=agent_id or self.agent_id,
                tenant_id=tenant_id,
                principal=principal,
                user_metadata=metadata,
                enforcement=enforcement,
                dlp=dlp_result,
                action=action,
            ),
        )
        return result

    def write(
        self,
        content: str,
        *,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tenant_id: str = "",
        principal: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecureWriteResult:
        """Validate, audit, and persist content if policy allows it."""

        result = self.validate_write(
            content,
            source_type=source_type,
            source_id=source_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            principal=principal,
            metadata=metadata,
        )
        self._last_result = result

        if self.policy.verify_vault_before_write and self.vault is not None:
            verification = self.vault.verify_current()
            if not verification.is_valid:
                result.action = EnforcementAction.BLOCK
                result.metadata["vault_verify_failed"] = True
                result.metadata["vault_violations"] = getattr(verification, "violations", [])

        if result.blocked:
            self._log_audit("block", result)
            if self.policy.raise_on_block:
                raise SecureMemoryWriteError("Secure memory write blocked", result)
            return result

        if result.quarantined and not self.policy.write_quarantined:
            self._route_quarantine(result)
            self._log_audit("quarantine", result)
            if self.policy.raise_on_quarantine:
                raise SecureMemoryWriteError("Secure memory write quarantined", result)
            return result

        entry = MemoryEntry(
            content=result.safe_content,
            source_type=source_type,
            source_id=source_id or result.entry_id,
            metadata=result.metadata,
        )
        result.backend_result = self._write_backend(entry, result.entry_id or self._make_entry_id(result.safe_content, source_id))
        result.wrote_to_backend = self.backend is not None

        if self.ledger is not None:
            self.ledger.append(result.safe_content, metadata=result.metadata, entry_id=result.entry_id)
            result.wrote_to_ledger = True

        if self.vault is not None:
            self.vault.register(entry, entry_id=result.entry_id)
            result.registered_in_vault = True
            self._write_count += 1
            if self.policy.snapshot_every > 0 and self._write_count % self.policy.snapshot_every == 0:
                snapshot = self.vault.take_snapshot(f"secure-memory-store-{self._write_count}")
                result.snapshot_id = snapshot.id

        self._log_audit("write", result)
        return result

    def add(self, entry: Any, **kwargs: Any) -> SecureWriteResult:
        """MemoryStore-compatible alias that accepts MemoryEntry or text."""

        content = _extract_content(entry)
        source_type = kwargs.pop("source_type", getattr(entry, "source_type", "unknown"))
        source_id = kwargs.pop("source_id", getattr(entry, "source_id", None))
        metadata = dict(getattr(entry, "metadata", {}) or {})
        metadata.update(kwargs.pop("metadata", {}) or {})
        return self.write(content, source_type=source_type, source_id=source_id, metadata=metadata, **kwargs)

    def save(self, content: str, **kwargs: Any) -> SecureWriteResult:
        """Generic backend-compatible alias."""

        return self.write(content, **kwargs)

    def get_entries(self, *, scan: bool = True, include_blocked: bool = False) -> List[MemoryEntry]:
        """Read entries from backend and optionally re-scan before returning."""

        entries = self._read_backend_entries()
        if not scan:
            return entries
        checked = self.enforcer.on_memory_read(entries, agent_id=self.agent_id)
        safe_entries: List[MemoryEntry] = []
        for item in checked:
            if item.allowed or include_blocked:
                original = item.chunk
                safe_entries.append(MemoryEntry(
                    content=item.safe_text,
                    source_type=getattr(original, "source_type", "memory_store"),
                    source_id=getattr(original, "source_id", None),
                    metadata=dict(getattr(original, "metadata", {}) or {}),
                ))
        return safe_entries

    def stats(self) -> Dict[str, Any]:
        return {
            "audit_events": len(self._audit_events),
            "last_action": self._last_result.action.value if self._last_result else None,
            "backend": type(self.backend).__name__ if self.backend is not None else None,
            "ledger_enabled": self.ledger is not None,
            "vault_enabled": self.vault is not None,
        }

    def _inspect_dlp(self, content: str) -> DLPResult:
        if hasattr(self.dlp, "inspect"):
            return self.dlp.inspect(content)
        result = self.dlp(content)
        if isinstance(result, DLPResult):
            return result
        if isinstance(result, str):
            return DLPResult(original_content=content, safe_content=result)
        return DLPResult(original_content=content, safe_content=content)

    def _write_backend(self, entry: MemoryEntry, entry_id: str) -> Any:
        backend = self.backend
        if backend is None:
            return entry_id
        if isinstance(backend, list):
            backend.append(entry)
            return entry_id
        if isinstance(backend, dict):
            backend[entry_id] = entry
            return entry_id
        if hasattr(backend, "add"):
            written = backend.add(entry)
            return entry_id if written is None else written
        if hasattr(backend, "append"):
            return backend.append(entry.content, metadata=entry.metadata, entry_id=entry_id)
        if hasattr(backend, "save"):
            written = backend.save(entry.content)
            return entry_id if written is None else written
        if hasattr(backend, "write"):
            written = backend.write(entry.content)
            return entry_id if written is None else written
        raise TypeError("backend must expose add(), append(), save(), write(), or be list/dict")

    def _read_backend_entries(self) -> List[MemoryEntry]:
        backend = self.backend
        if backend is None:
            return []
        if hasattr(backend, "get_entries"):
            return [_coerce_entry(item) for item in backend.get_entries()]
        if isinstance(backend, dict):
            return [_coerce_entry(item) for item in backend.values()]
        if isinstance(backend, list):
            return [_coerce_entry(item) for item in backend]
        if hasattr(backend, "get_range"):
            return [_coerce_entry(item) for item in backend.get_range()]
        return []

    def _route_quarantine(self, result: SecureWriteResult) -> None:
        if self.quarantine_sink is not None:
            self.quarantine_sink(result)

    def _log_audit(self, event: str, result: SecureWriteResult) -> None:
        preview_len = self.policy.audit_content_preview_chars
        payload = {
            "event": event,
            "entry_id": result.entry_id,
            "action": result.action.value,
            "risk_score": result.enforcement.risk_score,
            "was_sanitized": result.was_sanitized,
            "wrote_to_backend": result.wrote_to_backend,
            "content_preview": result.safe_content[:preview_len],
            "metadata": result.metadata,
            "dlp": result.dlp.to_dict(),
            "ts": time.time(),
        }
        self._audit_events.append(payload)
        result.audit_logged = True
        if self.auditor is not None and hasattr(self.auditor, "log_memory_operation"):
            self.auditor.log_memory_operation(
                operation="write",
                content_preview=result.safe_content[:preview_len],
                entry_id=result.entry_id,
                threat_detected=result.action != EnforcementAction.ALLOW,
                details=payload,
            )

    @staticmethod
    def _make_entry_id(content: str, source_id: Optional[str]) -> str:
        if source_id:
            return source_id
        return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:24]

    @staticmethod
    def _build_security_metadata(
        *,
        source_type: str,
        source_id: Optional[str],
        agent_id: str,
        tenant_id: str,
        principal: str,
        user_metadata: Optional[Dict[str, Any]],
        enforcement: EnforcementResult,
        dlp: DLPResult,
        action: EnforcementAction,
    ) -> Dict[str, Any]:
        metadata = dict(user_metadata or {})
        metadata.update({
            "memgar_write_boundary": "SecureMemoryStore",
            "memgar_bypass_warning": "direct backend writes bypass Memgar controls",
            "source_type": source_type,
            "source_id": source_id or "",
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "principal": principal,
            "security_action": action.value,
            "risk_score": enforcement.risk_score,
            "was_sanitized": enforcement.was_sanitized or dlp.was_redacted,
            "dlp_findings": [item.to_dict() for item in dlp.findings],
        })
        return metadata


def wrap_memory_store(backend: Any, **kwargs: Any) -> SecureMemoryStore:
    """Factory for converting an existing backend into a SecureMemoryStore."""

    return SecureMemoryStore(backend=backend, **kwargs)


def _extract_content(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    return str(getattr(entry, "content", entry))


def _coerce_entry(value: Any) -> MemoryEntry:
    if isinstance(value, MemoryEntry):
        return value
    if hasattr(value, "content"):
        return MemoryEntry(
            content=str(getattr(value, "content")),
            source_type=getattr(value, "source_type", "unknown"),
            source_id=getattr(value, "source_id", None),
            metadata=dict(getattr(value, "metadata", {}) or {}),
        )
    return MemoryEntry(content=str(value), source_type="unknown")


__all__ = [
    "DLPFinding",
    "DLPPattern",
    "DLPPolicy",
    "DLPRedactor",
    "DLPResult",
    "SecureMemoryStore",
    "SecureMemoryStorePolicy",
    "SecureMemoryWriteError",
    "SecureWriteResult",
    "wrap_memory_store",
]
