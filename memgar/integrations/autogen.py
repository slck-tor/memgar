"""
Memgar AutoGen Integration
==========================

Memory security for Microsoft AutoGen multi-agent systems.

All guarded message flows use UniversalMemoryGuard, which defaults to
SecureMemoryStore for policy, DLP, audit metadata, and block/sanitize behavior.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .universal import MemoryBlockedError, MemoryProtectionResult, UniversalMemoryGuard

logger = logging.getLogger(__name__)


@dataclass
class ConversationScanResult:
    """Result of conversation message scan."""

    sender: str
    receiver: str
    allowed: bool
    decision: str
    risk_score: int
    threat_type: Optional[str] = None
    content_preview: str = ""
    safe_content: Optional[str] = None


@dataclass
class AutoGenScanStats:
    """Statistics for AutoGen scanning."""

    messages_scanned: int = 0
    threats_blocked: int = 0
    agents_monitored: int = 0
    conversations: int = 0


class MemgarAutoGenGuard:
    """
    Security guard for AutoGen multi-agent conversations.

    Monitors all agent communications for memory poisoning attacks and sanitizes
    message payloads before they reach the receiving agent whenever Memgar
    returns a sanitize decision.
    """

    def __init__(
        self,
        mode: str = "protect",
        on_threat: str = "block",
        scan_human_input: bool = True,
        scan_agent_output: bool = True,
        callback: Optional[Callable] = None,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        **guard_kwargs: Any,
    ):
        """
        Initialize AutoGen guard.

        Args:
            mode: Kept for backward compatibility with the older scanner API.
            on_threat: Action on threat detection: block, warn, log, or allow.
            scan_human_input: Scan human/user input.
            scan_agent_output: Scan agent responses.
            callback: Optional callback on threat.
            memory_guard: Optional preconfigured UniversalMemoryGuard.
            secure_store: Optional preconfigured SecureMemoryStore.
            **guard_kwargs: Forwarded to UniversalMemoryGuard.
        """
        self._mode = mode
        self._on_threat = on_threat
        self._scan_human = scan_human_input
        self._scan_agent = scan_agent_output
        self._callback = callback
        self._stats = AutoGenScanStats()
        self._threats: List[ConversationScanResult] = []
        self._secured_agents: set = set()
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="autogen_message",
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        """Return the secure memory boundary used by this adapter."""

        return self._memory_guard

    def _scan_message(
        self,
        content: str,
        sender: str,
        receiver: str,
    ) -> ConversationScanResult:
        """Scan message content through UniversalMemoryGuard."""
        self._stats.messages_scanned += 1

        try:
            protected = self._memory_guard.protect_write(
                content,
                source_type="autogen_message",
                source_id=f"{sender}->{receiver}",
            )
        except MemoryBlockedError as exc:
            scan_result = self._scan_result_from_protection(sender, receiver, content, exc.result)
            self._record_threat(scan_result)
            raise MemgarAutoGenThreatError(
                f"Message from {sender} blocked: {scan_result.threat_type}",
                scan_result=scan_result,
            ) from exc

        scan_result = self._scan_result_from_protection(sender, receiver, content, protected)
        if not scan_result.allowed:
            self._record_threat(scan_result)
        return scan_result

    def _record_threat(self, scan_result: ConversationScanResult) -> None:
        self._threats.append(scan_result)
        self._stats.threats_blocked += 1
        logger.warning(
            "Memgar: Threat from %s to %s - %s (risk: %s)",
            scan_result.sender,
            scan_result.receiver,
            scan_result.threat_type,
            scan_result.risk_score,
        )
        if self._callback:
            self._callback(scan_result)

    def secure_agent(self, agent: Any) -> Any:
        """Secure a single AutoGen agent."""
        agent_name = getattr(agent, "name", str(id(agent)))

        if agent_name in self._secured_agents:
            return agent

        if hasattr(agent, "receive"):
            original_receive = agent.receive

            @functools.wraps(original_receive)
            def secured_receive(message: Any, sender: Any, *args: Any, **kwargs: Any) -> Any:
                content = _extract_message_content(message)
                sender_name = getattr(sender, "name", "unknown")
                is_human = "user" in sender_name.lower() or "human" in sender_name.lower()
                should_scan = (is_human and self._scan_human) or (not is_human and self._scan_agent)

                if should_scan and content:
                    scan = self._scan_message(content, sender_name, agent_name)
                    message = _replace_message_content(message, scan.safe_content)

                return original_receive(message, sender, *args, **kwargs)

            agent.receive = secured_receive

        if hasattr(agent, "send"):
            original_send = agent.send

            @functools.wraps(original_send)
            def secured_send(message: Any, recipient: Any, *args: Any, **kwargs: Any) -> Any:
                content = _extract_message_content(message)
                recipient_name = getattr(recipient, "name", "unknown")

                if content and self._scan_agent:
                    scan = self._scan_message(content, agent_name, recipient_name)
                    message = _replace_message_content(message, scan.safe_content)

                return original_send(message, recipient, *args, **kwargs)

            agent.send = secured_send

        self._secured_agents.add(agent_name)
        self._stats.agents_monitored += 1

        logger.info("Memgar: Secured AutoGen agent '%s'", agent_name)
        return agent

    def secure_agents(self, agents: List[Any]) -> List[Any]:
        """Secure multiple AutoGen agents."""
        return [self.secure_agent(agent) for agent in agents]

    def secure_group_chat(self, group_chat: Any) -> Any:
        """Secure an AutoGen GroupChat."""
        if hasattr(group_chat, "agents"):
            self.secure_agents(group_chat.agents)

        self._stats.conversations += 1
        return group_chat

    def create_reply_hook(self) -> Callable:
        """Create a reply function hook for scanning."""

        def hook(
            recipient: Any,
            messages: List[Dict],
            sender: Any,
            config: Any,
        ) -> tuple:
            if messages:
                last_msg = messages[-1]
                content = last_msg.get("content", "")
                sender_name = last_msg.get("name", "unknown")
                recipient_name = getattr(recipient, "name", "unknown")

                if content:
                    try:
                        scan = self._scan_message(content, sender_name, recipient_name)
                    except MemgarAutoGenThreatError:
                        return True, "Message blocked by Memgar security."
                    if scan.safe_content is not None:
                        last_msg["content"] = scan.safe_content
            return False, None

        return hook

    @property
    def stats(self) -> AutoGenScanStats:
        """Get scanning statistics."""
        return self._stats

    @property
    def detected_threats(self) -> List[ConversationScanResult]:
        """Get all detected threats."""
        return self._threats.copy()

    def clear_threats(self) -> None:
        """Clear threat history."""
        self._threats.clear()

    @staticmethod
    def _scan_result_from_protection(
        sender: str,
        receiver: str,
        original_content: str,
        protected: MemoryProtectionResult,
    ) -> ConversationScanResult:
        return ConversationScanResult(
            sender=sender,
            receiver=receiver,
            allowed=protected.allowed,
            decision=protected.decision,
            risk_score=_risk_score(protected.raw_result),
            threat_type=protected.reason or protected.decision,
            content_preview=original_content[:100],
            safe_content=str(protected.safe_content) if protected.safe_content is not None else None,
        )


class MemgarAutoGenThreatError(Exception):
    """Exception raised when AutoGen threat is detected."""

    def __init__(self, message: str, scan_result: Optional[ConversationScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


def _extract_message_content(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("content", ""))
    return str(message)


def _replace_message_content(message: Any, safe_content: Optional[str]) -> Any:
    if safe_content is None:
        return message
    if isinstance(message, dict):
        updated = dict(message)
        updated["content"] = safe_content
        return updated
    return safe_content


def _risk_score(raw_result: Any) -> int:
    if hasattr(raw_result, "risk_score"):
        return int(getattr(raw_result, "risk_score", 0) or 0)
    enforcement = getattr(raw_result, "enforcement", None)
    if enforcement is not None:
        return int(getattr(enforcement, "risk_score", 0) or 0)
    return 0


# Convenience functions
def secure_agent(agent: Any, **kwargs: Any) -> Any:
    """Quick wrapper to secure an AutoGen agent."""
    guard = MemgarAutoGenGuard(**kwargs)
    return guard.secure_agent(agent)


def secure_group_chat(group_chat: Any, **kwargs: Any) -> Any:
    """Quick wrapper to secure an AutoGen GroupChat."""
    guard = MemgarAutoGenGuard(**kwargs)
    return guard.secure_group_chat(group_chat)
