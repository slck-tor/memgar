"""
Memgar OpenAI Assistants Integration
====================================

Memory security for OpenAI Assistants API.

User messages, retrieved messages, and assistant outputs are routed through
UniversalMemoryGuard, which defaults to SecureMemoryStore for consistent DLP,
policy, audit, block, and sanitize behavior.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from .universal import MemoryBlockedError, MemoryProtectionResult, UniversalMemoryGuard

logger = logging.getLogger(__name__)


@dataclass
class MessageScanResult:
    """Result of message scan."""

    message_id: Optional[str]
    role: str
    allowed: bool
    decision: str
    risk_score: int
    threat_type: Optional[str] = None
    content_preview: str = ""
    safe_content: Optional[str] = None


@dataclass
class AssistantScanStats:
    """Statistics for assistant scanning."""

    messages_scanned: int = 0
    threats_blocked: int = 0
    threads_monitored: int = 0


class MemgarAssistantGuard:
    """
    Security wrapper for OpenAI Assistants API.

    Scans all messages and assistant responses for threats. Sanitized user
    content is sent to the API instead of the raw content.
    """

    def __init__(
        self,
        client: Any,
        mode: str = "protect",
        on_threat: str = "block",
        scan_user_messages: bool = True,
        scan_assistant_messages: bool = True,
        callback: Optional[Callable] = None,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        **guard_kwargs: Any,
    ):
        """
        Initialize assistant guard.

        Args:
            client: OpenAI client instance.
            mode: Kept for backward compatibility with the older scanner API.
            on_threat: Action on threat detection: block, warn, log, or allow.
            scan_user_messages: Scan user messages.
            scan_assistant_messages: Scan assistant responses.
            callback: Optional callback on threat.
            memory_guard: Optional preconfigured UniversalMemoryGuard.
            secure_store: Optional preconfigured SecureMemoryStore.
            **guard_kwargs: Forwarded to UniversalMemoryGuard.
        """
        self._client = client
        self._mode = mode
        self._on_threat = on_threat
        self._scan_user = scan_user_messages
        self._scan_assistant = scan_assistant_messages
        self._callback = callback
        self._stats = AssistantScanStats()
        self._threats: List[MessageScanResult] = []
        self._monitored_threads: set = set()
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="openai_assistants",
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        """Return the secure memory boundary used by this adapter."""

        return self._memory_guard

    def _scan_content(
        self,
        content: str,
        role: str,
        message_id: Optional[str] = None,
        *,
        boundary: str = "write",
    ) -> MessageScanResult:
        """Scan message content through UniversalMemoryGuard."""
        self._stats.messages_scanned += 1

        try:
            if boundary == "tool_result":
                protected = self._memory_guard.protect_tool_result(
                    f"openai_assistants:{role}",
                    content,
                    source_type=f"openai_assistants:{role}",
                    source_id=message_id,
                )
            elif boundary == "read":
                protected = self._memory_guard.protect_read(
                    content,
                    source_type=f"openai_assistants:{role}",
                    source_id=message_id,
                )
            else:
                protected = self._memory_guard.protect_write(
                    content,
                    source_type=f"openai_assistants:{role}",
                    source_id=message_id,
                )
        except MemoryBlockedError as exc:
            scan_result = self._scan_result_from_protection(role, message_id, content, exc.result)
            self._record_threat(scan_result)
            raise MemgarAssistantThreatError(
                f"Message blocked: {scan_result.threat_type}",
                scan_result=scan_result,
            ) from exc

        scan_result = self._scan_result_from_protection(role, message_id, content, protected)
        if not scan_result.allowed:
            self._record_threat(scan_result)
        return scan_result

    def _record_threat(self, scan_result: MessageScanResult) -> None:
        self._threats.append(scan_result)
        self._stats.threats_blocked += 1
        logger.warning(
            "Memgar: Threat in %s message - %s (risk: %s)",
            scan_result.role,
            scan_result.threat_type,
            scan_result.risk_score,
        )
        if self._callback:
            self._callback(scan_result)

    def create_thread(self, **kwargs: Any) -> Any:
        """Create a new thread."""
        thread = self._client.beta.threads.create(**kwargs)
        self._monitored_threads.add(thread.id)
        self._stats.threads_monitored += 1

        logger.info("Memgar: Monitoring thread %s", thread.id)
        return thread

    def add_message(
        self,
        thread_id: str,
        content: str,
        role: str = "user",
        **kwargs: Any,
    ) -> Any:
        """Add message to thread with security scanning."""
        safe_content = content
        if role == "user" and self._scan_user:
            scan = self._scan_content(content, role, boundary="write")
            safe_content = scan.safe_content if scan.safe_content is not None else content

        return self._client.beta.threads.messages.create(
            thread_id=thread_id,
            role=role,
            content=safe_content,
            **kwargs,
        )

    def run_assistant(
        self,
        thread_id: str,
        assistant_id: str,
        wait: bool = True,
        poll_interval: float = 1.0,
        **kwargs: Any,
    ) -> Any:
        """Run assistant on thread with monitoring."""
        run = self._client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id,
            **kwargs,
        )

        if not wait:
            return run

        while run.status in ["queued", "in_progress"]:
            time.sleep(poll_interval)
            run = self._client.beta.threads.runs.retrieve(
                thread_id=thread_id,
                run_id=run.id,
            )

        if run.status == "completed" and self._scan_assistant:
            messages = self._client.beta.threads.messages.list(
                thread_id=thread_id,
                order="desc",
                limit=1,
            )

            for msg in messages.data:
                if msg.role == "assistant":
                    self._scan_message_blocks(msg, boundary="tool_result")

        return run

    def get_messages(
        self,
        thread_id: str,
        scan: bool = True,
        **kwargs: Any,
    ) -> List[Any]:
        """Get thread messages with optional scanning."""
        messages = self._client.beta.threads.messages.list(
            thread_id=thread_id,
            **kwargs,
        )

        if scan:
            for msg in messages.data:
                self._scan_message_blocks(msg, boundary="read")

        return messages.data

    def scan_thread(self, thread_id: str) -> List[MessageScanResult]:
        """Scan entire thread for threats."""
        results: List[MessageScanResult] = []
        messages = self._client.beta.threads.messages.list(thread_id=thread_id)

        for msg in messages.data:
            results.extend(self._scan_message_blocks(msg, boundary="read"))
        return results

    def _scan_message_blocks(self, msg: Any, *, boundary: str) -> List[MessageScanResult]:
        results: List[MessageScanResult] = []
        for content_block in getattr(msg, "content", []) or []:
            text_obj = getattr(content_block, "text", None)
            value = getattr(text_obj, "value", None)
            if value is None:
                continue
            scan = self._scan_content(value, getattr(msg, "role", "unknown"), getattr(msg, "id", None), boundary=boundary)
            if scan.safe_content is not None:
                _replace_text_value(content_block, scan.safe_content)
            results.append(scan)
        return results

    @property
    def client(self) -> Any:
        """Get underlying OpenAI client."""
        return self._client

    @property
    def stats(self) -> AssistantScanStats:
        """Get scanning statistics."""
        return self._stats

    @property
    def detected_threats(self) -> List[MessageScanResult]:
        """Get all detected threats."""
        return self._threats.copy()

    def clear_threats(self) -> None:
        """Clear threat history."""
        self._threats.clear()

    @staticmethod
    def _scan_result_from_protection(
        role: str,
        message_id: Optional[str],
        original_content: str,
        protected: MemoryProtectionResult,
    ) -> MessageScanResult:
        return MessageScanResult(
            message_id=message_id,
            role=role,
            allowed=protected.allowed,
            decision=protected.decision,
            risk_score=_risk_score(protected.raw_result),
            threat_type=protected.reason or protected.decision,
            content_preview=original_content[:100],
            safe_content=str(protected.safe_content) if protected.safe_content is not None else None,
        )


class MemgarAssistantThreatError(Exception):
    """Exception raised when assistant threat is detected."""

    def __init__(self, message: str, scan_result: Optional[MessageScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


def _replace_text_value(content_block: Any, safe_content: str) -> None:
    text_obj = getattr(content_block, "text", None)
    try:
        if text_obj is not None:
            text_obj.value = safe_content
    except Exception:
        logger.debug("Memgar: unable to replace assistant message block with sanitized content")


def _risk_score(raw_result: Any) -> int:
    if hasattr(raw_result, "risk_score"):
        return int(getattr(raw_result, "risk_score", 0) or 0)
    enforcement = getattr(raw_result, "enforcement", None)
    if enforcement is not None:
        return int(getattr(enforcement, "risk_score", 0) or 0)
    return 0


# Convenience function
def guard_assistant(client: Any, **kwargs: Any) -> MemgarAssistantGuard:
    """Quick wrapper for OpenAI client with assistant security."""
    return MemgarAssistantGuard(client, **kwargs)
