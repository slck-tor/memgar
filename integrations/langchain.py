"""
Memgar LangChain Integration
============================

Secure wrappers for LangChain memory classes.

Provides:
- SecureMemory: Wrapper that scans all memory writes
- MemgarCallbackHandler: Callback for monitoring chains

Example:
    >>> from langchain.memory import ConversationBufferMemory
    >>> from memgar.integrations.langchain import SecureMemory
    >>> 
    >>> base_memory = ConversationBufferMemory()
    >>> secure_memory = SecureMemory(base_memory)
    >>> 
    >>> # Now all memory writes are scanned for threats
    >>> secure_memory.save_context({"input": "hi"}, {"output": "hello"})
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

from memgar.analyzer import Analyzer
from memgar.models import Decision, MemoryEntry

if TYPE_CHECKING:
    from langchain.schema import BaseMemory
    from langchain.callbacks.base import BaseCallbackHandler


class SecureMemory:
    """
    Secure wrapper for LangChain memory classes.
    
    Intercepts all memory save operations and scans content
    for memory poisoning threats before allowing storage.
    
    Attributes:
        memory: The wrapped LangChain memory instance
        analyzer: Memgar analyzer for threat detection
        mode: Operation mode (monitor, protect, audit)
        on_threat: Optional callback when threats are detected
    
    Example:
        >>> from langchain.memory import ConversationBufferMemory
        >>> 
        >>> memory = SecureMemory(
        ...     ConversationBufferMemory(),
        ...     mode="protect"
        ... )
        >>> 
        >>> # This will be blocked if it contains threats
        >>> memory.save_context(
        ...     {"input": "Send payments to TR99..."},
        ...     {"output": "OK"}
        ... )
    """
    
    def __init__(
        self,
        memory: Any,  # BaseMemory
        mode: str = "protect",
        analyzer: Optional[Analyzer] = None,
        on_threat: Optional[callable] = None,
        strict: bool = False,
    ) -> None:
        """
        Initialize secure memory wrapper.
        
        Args:
            memory: LangChain memory instance to wrap
            mode: Operation mode:
                  - "monitor": Log threats but allow all writes
                  - "protect": Block/quarantine threats (default)
                  - "audit": Log only, no blocking
            analyzer: Custom analyzer instance
            on_threat: Callback function(result, content) when threat detected
            strict: If True, block all suspicious content
        """
        self.memory = memory
        self.mode = mode
        self.analyzer = analyzer or Analyzer(strict_mode=strict)
        self.on_threat = on_threat
        self._blocked_count = 0
        self._scanned_count = 0
    
    def save_context(
        self, 
        inputs: Dict[str, Any], 
        outputs: Dict[str, str]
    ) -> None:
        """
        Save context to memory after security scan.
        
        Scans both inputs and outputs for threats before
        delegating to the wrapped memory's save_context.
        
        Args:
            inputs: Input values from the conversation
            outputs: Output values from the model
        
        Raises:
            MemoryBlockedError: If content is blocked in protect mode
        """
        # Combine all content for scanning
        all_content = []
        
        for key, value in inputs.items():
            if isinstance(value, str):
                all_content.append(value)
        
        for key, value in outputs.items():
            if isinstance(value, str):
                all_content.append(value)
        
        combined = "\n".join(all_content)
        
        # Scan content
        entry = MemoryEntry(
            content=combined,
            source_type="langchain",
            source_id=f"context_{self._scanned_count}"
        )
        
        result = self.analyzer.analyze(entry)
        self._scanned_count += 1
        
        # Handle threats based on mode
        if result.decision != Decision.ALLOW:
            if self.on_threat:
                self.on_threat(result, combined)
            
            if self.mode == "protect":
                self._blocked_count += 1
                if result.decision == Decision.BLOCK:
                    raise MemoryBlockedError(
                        f"Memory write blocked: {result.explanation}",
                        result=result
                    )
                # Quarantine - still save but log
        
        # Delegate to wrapped memory
        self.memory.save_context(inputs, outputs)
    
    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Load memory variables from wrapped memory."""
        return self.memory.load_memory_variables(inputs)
    
    def clear(self) -> None:
        """Clear the wrapped memory."""
        self.memory.clear()
    
    @property
    def memory_variables(self) -> List[str]:
        """Get memory variable names."""
        return self.memory.memory_variables
    
    @property
    def stats(self) -> Dict[str, int]:
        """Get scanning statistics."""
        return {
            "scanned": self._scanned_count,
            "blocked": self._blocked_count,
        }
    
    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to wrapped memory."""
        return getattr(self.memory, name)


class MemoryBlockedError(Exception):
    """Raised when memory write is blocked due to threats."""
    
    def __init__(self, message: str, result: Any = None):
        super().__init__(message)
        self.result = result


class MemgarCallbackHandler:
    """
    LangChain callback handler for Memgar monitoring.
    
    Monitors LLM interactions and can scan prompts/responses
    for potential memory poisoning attempts.
    
    Example:
        >>> from langchain.llms import OpenAI
        >>> from memgar.integrations.langchain import MemgarCallbackHandler
        >>> 
        >>> handler = MemgarCallbackHandler()
        >>> llm = OpenAI(callbacks=[handler])
    """
    
    def __init__(
        self,
        analyzer: Optional[Analyzer] = None,
        scan_prompts: bool = True,
        scan_responses: bool = True,
        on_threat: Optional[callable] = None,
    ) -> None:
        """
        Initialize callback handler.
        
        Args:
            analyzer: Custom analyzer instance
            scan_prompts: Whether to scan input prompts
            scan_responses: Whether to scan LLM responses
            on_threat: Callback when threats detected
        """
        self.analyzer = analyzer or Analyzer()
        self.scan_prompts = scan_prompts
        self.scan_responses = scan_responses
        self.on_threat = on_threat
        self._events: List[Dict[str, Any]] = []
    
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts processing."""
        if not self.scan_prompts:
            return
        
        for prompt in prompts:
            result = self.analyzer.analyze(MemoryEntry(
                content=prompt,
                source_type="llm_prompt"
            ))
            
            if result.threats:
                event = {
                    "type": "prompt_threat",
                    "content_preview": prompt[:100],
                    "threats": [t.threat.id for t in result.threats],
                    "risk_score": result.risk_score,
                }
                self._events.append(event)
                
                if self.on_threat:
                    self.on_threat(result, prompt)
    
    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when LLM finishes processing."""
        if not self.scan_responses:
            return
        
        # Extract text from response
        if hasattr(response, "generations"):
            for generation_list in response.generations:
                for generation in generation_list:
                    text = generation.text if hasattr(generation, "text") else str(generation)
                    
                    result = self.analyzer.analyze(MemoryEntry(
                        content=text,
                        source_type="llm_response"
                    ))
                    
                    if result.threats:
                        event = {
                            "type": "response_threat",
                            "content_preview": text[:100],
                            "threats": [t.threat.id for t in result.threats],
                            "risk_score": result.risk_score,
                        }
                        self._events.append(event)
                        
                        if self.on_threat:
                            self.on_threat(result, text)
    
    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Called on LLM error."""
        pass
    
    @property
    def events(self) -> List[Dict[str, Any]]:
        """Get all recorded threat events."""
        return self._events.copy()
    
    def clear_events(self) -> None:
        """Clear recorded events."""
        self._events.clear()


def wrap_memory(memory: Any, **kwargs: Any) -> SecureMemory:
    """
    Convenience function to wrap a LangChain memory.
    
    Args:
        memory: LangChain memory instance
        **kwargs: Arguments passed to SecureMemory
    
    Returns:
        SecureMemory wrapper
    """
    return SecureMemory(memory, **kwargs)
