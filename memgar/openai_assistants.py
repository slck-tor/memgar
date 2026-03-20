"""
Memgar OpenAI Assistants Integration
====================================

Memory security for OpenAI Assistants API.

Usage:
    from openai import OpenAI
    from memgar.integrations.openai_assistants import MemgarAssistantGuard
    
    client = OpenAI()
    guard = MemgarAssistantGuard(client)
    
    # Create thread with security
    thread = guard.create_thread()
    
    # Add message with scanning
    guard.add_message(thread.id, "User message here")
    
    # Run assistant with monitoring
    run = guard.run_assistant(thread.id, assistant_id)
"""

from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
import logging
import time

from ..scanner import MemoryScanner
from ..models import Decision, AnalysisResult

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


@dataclass
class AssistantScanStats:
    """Statistics for assistant scanning."""
    messages_scanned: int = 0
    threats_blocked: int = 0
    threads_monitored: int = 0


class MemgarAssistantGuard:
    """
    Security wrapper for OpenAI Assistants API.
    
    Scans all messages and assistant responses for threats.
    
    Example:
        from openai import OpenAI
        from memgar.integrations.openai_assistants import MemgarAssistantGuard
        
        client = OpenAI()
        guard = MemgarAssistantGuard(client, on_threat="block")
        
        # Create secure thread
        thread = guard.create_thread()
        
        # Add message (scanned automatically)
        guard.add_message(thread.id, "Hello, help me with...")
        
        # Run assistant
        result = guard.run_assistant(thread.id, "asst_xxx")
    """
    
    def __init__(
        self,
        client: Any,
        mode: str = "protect",
        on_threat: str = "block",  # block, warn, log
        scan_user_messages: bool = True,
        scan_assistant_messages: bool = True,
        callback: Optional[Callable] = None,
    ):
        """
        Initialize assistant guard.
        
        Args:
            client: OpenAI client instance
            mode: Scan mode (protect, monitor, audit)
            on_threat: Action on threat detection
            scan_user_messages: Scan user messages
            scan_assistant_messages: Scan assistant responses
            callback: Optional callback on threat
        """
        self._client = client
        self._scanner = MemoryScanner(mode=mode)
        self._on_threat = on_threat
        self._scan_user = scan_user_messages
        self._scan_assistant = scan_assistant_messages
        self._callback = callback
        self._stats = AssistantScanStats()
        self._threats: List[MessageScanResult] = []
        self._monitored_threads: set = set()
    
    def _scan_content(
        self,
        content: str,
        role: str,
        message_id: Optional[str] = None
    ) -> MessageScanResult:
        """Scan message content."""
        self._stats.messages_scanned += 1
        
        result = self._scanner.scan(content)
        
        scan_result = MessageScanResult(
            message_id=message_id,
            role=role,
            allowed=result.decision == Decision.ALLOW,
            decision=result.decision.value,
            risk_score=result.risk_score,
            threat_type=result.threat_type,
            content_preview=content[:100],
        )
        
        if not scan_result.allowed:
            self._threats.append(scan_result)
            self._stats.threats_blocked += 1
            
            logger.warning(
                f"Memgar: Threat in {role} message - "
                f"{scan_result.threat_type} (risk: {scan_result.risk_score})"
            )
            
            if self._callback:
                self._callback(scan_result)
            
            if self._on_threat == "block":
                raise MemgarAssistantThreatError(
                    f"Message blocked: {scan_result.threat_type}",
                    scan_result=scan_result
                )
        
        return scan_result
    
    def create_thread(self, **kwargs) -> Any:
        """
        Create a new thread.
        
        Args:
            **kwargs: Arguments for thread creation
            
        Returns:
            Thread object
        """
        thread = self._client.beta.threads.create(**kwargs)
        self._monitored_threads.add(thread.id)
        self._stats.threads_monitored += 1
        
        logger.info(f"Memgar: Monitoring thread {thread.id}")
        return thread
    
    def add_message(
        self,
        thread_id: str,
        content: str,
        role: str = "user",
        **kwargs
    ) -> Any:
        """
        Add message to thread with security scanning.
        
        Args:
            thread_id: Thread ID
            content: Message content
            role: Message role (user/assistant)
            **kwargs: Additional arguments
            
        Returns:
            Message object
        """
        # Scan user messages
        if role == "user" and self._scan_user:
            self._scan_content(content, role)
        
        # Create message
        message = self._client.beta.threads.messages.create(
            thread_id=thread_id,
            role=role,
            content=content,
            **kwargs
        )
        
        return message
    
    def run_assistant(
        self,
        thread_id: str,
        assistant_id: str,
        wait: bool = True,
        poll_interval: float = 1.0,
        **kwargs
    ) -> Any:
        """
        Run assistant on thread with monitoring.
        
        Args:
            thread_id: Thread ID
            assistant_id: Assistant ID
            wait: Wait for completion
            poll_interval: Polling interval in seconds
            **kwargs: Additional arguments
            
        Returns:
            Run object
        """
        # Create run
        run = self._client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id,
            **kwargs
        )
        
        if not wait:
            return run
        
        # Wait for completion
        while run.status in ['queued', 'in_progress']:
            time.sleep(poll_interval)
            run = self._client.beta.threads.runs.retrieve(
                thread_id=thread_id,
                run_id=run.id
            )
        
        # Scan assistant response
        if run.status == 'completed' and self._scan_assistant:
            messages = self._client.beta.threads.messages.list(
                thread_id=thread_id,
                order='desc',
                limit=1
            )
            
            for msg in messages.data:
                if msg.role == 'assistant':
                    for content_block in msg.content:
                        if hasattr(content_block, 'text'):
                            self._scan_content(
                                content_block.text.value,
                                'assistant',
                                msg.id
                            )
        
        return run
    
    def get_messages(
        self,
        thread_id: str,
        scan: bool = True,
        **kwargs
    ) -> List[Any]:
        """
        Get thread messages with optional scanning.
        
        Args:
            thread_id: Thread ID
            scan: Scan messages for threats
            **kwargs: Additional arguments
            
        Returns:
            List of messages
        """
        messages = self._client.beta.threads.messages.list(
            thread_id=thread_id,
            **kwargs
        )
        
        if scan:
            for msg in messages.data:
                for content_block in msg.content:
                    if hasattr(content_block, 'text'):
                        self._scan_content(
                            content_block.text.value,
                            msg.role,
                            msg.id
                        )
        
        return messages.data
    
    def scan_thread(self, thread_id: str) -> List[MessageScanResult]:
        """
        Scan entire thread for threats.
        
        Args:
            thread_id: Thread ID
            
        Returns:
            List of scan results
        """
        results = []
        messages = self._client.beta.threads.messages.list(thread_id=thread_id)
        
        for msg in messages.data:
            for content_block in msg.content:
                if hasattr(content_block, 'text'):
                    result = self._scan_content(
                        content_block.text.value,
                        msg.role,
                        msg.id
                    )
                    results.append(result)
        
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


class MemgarAssistantThreatError(Exception):
    """Exception raised when assistant threat is detected."""
    
    def __init__(self, message: str, scan_result: Optional[MessageScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


# Convenience function
def guard_assistant(client: Any, **kwargs) -> MemgarAssistantGuard:
    """
    Quick wrapper for OpenAI client with assistant security.
    
    Args:
        client: OpenAI client
        **kwargs: Arguments for MemgarAssistantGuard
        
    Returns:
        Guarded assistant wrapper
    """
    return MemgarAssistantGuard(client, **kwargs)
