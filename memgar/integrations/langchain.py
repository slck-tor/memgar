"""
Memgar LangChain Integration
============================

Memory guard middleware for LangChain applications.

Usage:
    from memgar.integrations.langchain import MemgarMemoryGuard, MemgarCallbackHandler
    
    # Option 1: Wrap memory
    from langchain.memory import ConversationBufferMemory
    
    memory = ConversationBufferMemory()
    guarded_memory = MemgarMemoryGuard(memory)
    
    # Option 2: Use callback handler
    from langchain.chat_models import ChatOpenAI
    
    llm = ChatOpenAI(callbacks=[MemgarCallbackHandler()])
"""

from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
import logging

# Memgar imports
from ..scanner import MemoryScanner
from ..models import Decision, AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of memory scan."""
    allowed: bool
    decision: str
    risk_score: int
    threat_type: Optional[str] = None
    original_content: str = ""


class MemgarMemoryGuard:
    """
    Memory guard wrapper for LangChain memory classes.
    
    Scans all memory operations and blocks/quarantines threats.
    
    Example:
        from langchain.memory import ConversationBufferMemory
        from memgar.integrations.langchain import MemgarMemoryGuard
        
        memory = ConversationBufferMemory()
        guarded = MemgarMemoryGuard(memory)
        
        # Use guarded memory in your chain
        chain = ConversationChain(llm=llm, memory=guarded)
    """
    
    def __init__(
        self,
        memory: Any,
        mode: str = "protect",
        on_threat: str = "block",  # block, warn, log
        callback: Optional[callable] = None,
    ):
        """
        Initialize memory guard.
        
        Args:
            memory: LangChain memory instance to wrap
            mode: Scan mode (protect, monitor, audit)
            on_threat: Action on threat (block, warn, log)
            callback: Optional callback function(ScanResult)
        """
        self._memory = memory
        self._scanner = MemoryScanner(mode=mode)
        self._on_threat = on_threat
        self._callback = callback
        self._blocked_count = 0
        self._scanned_count = 0
    
    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to wrapped memory."""
        return getattr(self._memory, name)
    
    def _scan_content(self, content: str) -> ScanResult:
        """Scan content for threats."""
        self._scanned_count += 1
        result = self._scanner.scan(content)
        
        scan_result = ScanResult(
            allowed=result.decision == Decision.ALLOW,
            decision=result.decision.value,
            risk_score=result.risk_score,
            threat_type=result.threat_type,
            original_content=content[:100],
        )
        
        if self._callback:
            self._callback(scan_result)
        
        return scan_result
    
    def _handle_threat(self, scan_result: ScanResult, content: str) -> str:
        """Handle detected threat based on configuration."""
        self._blocked_count += 1
        
        logger.warning(
            f"Memgar: Threat detected - {scan_result.threat_type} "
            f"(risk: {scan_result.risk_score})"
        )
        
        if self._on_threat == "block":
            raise MemgarThreatError(
                f"Memory poisoning attempt blocked: {scan_result.threat_type}",
                scan_result=scan_result
            )
        elif self._on_threat == "warn":
            logger.warning(f"Memgar: Allowing with warning - {content[:50]}...")
            return content
        else:  # log
            logger.info(f"Memgar: Logged threat - {scan_result.threat_type}")
            return content
    
    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, str]) -> None:
        """
        Scan and save context to memory.
        
        Args:
            inputs: Input variables
            outputs: Output variables
        """
        # Scan inputs
        for key, value in inputs.items():
            if isinstance(value, str):
                result = self._scan_content(value)
                if not result.allowed:
                    self._handle_threat(result, value)
        
        # Scan outputs
        for key, value in outputs.items():
            if isinstance(value, str):
                result = self._scan_content(value)
                if not result.allowed:
                    self._handle_threat(result, value)
        
        # If all clear, save to underlying memory
        self._memory.save_context(inputs, outputs)
    
    def add_memory(self, content: str, **kwargs) -> None:
        """
        Scan and add memory entry.
        
        Args:
            content: Memory content to add
            **kwargs: Additional arguments for underlying memory
        """
        result = self._scan_content(content)
        if not result.allowed:
            self._handle_threat(result, content)
        
        # Add to underlying memory if method exists
        if hasattr(self._memory, 'add_memory'):
            self._memory.add_memory(content, **kwargs)
        elif hasattr(self._memory, 'chat_memory'):
            from langchain.schema import HumanMessage
            self._memory.chat_memory.add_message(HumanMessage(content=content))
    
    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Load memory variables (passthrough, no scanning needed)."""
        return self._memory.load_memory_variables(inputs)
    
    def clear(self) -> None:
        """Clear memory."""
        self._memory.clear()
    
    @property
    def stats(self) -> Dict[str, int]:
        """Get scanning statistics."""
        return {
            "scanned": self._scanned_count,
            "blocked": self._blocked_count,
        }


class MemgarCallbackHandler:
    """
    LangChain callback handler for Memgar.
    
    Monitors all LLM interactions and scans for threats.
    
    Example:
        from langchain.chat_models import ChatOpenAI
        from memgar.integrations.langchain import MemgarCallbackHandler
        
        handler = MemgarCallbackHandler(on_threat="warn")
        llm = ChatOpenAI(callbacks=[handler])
    """
    
    def __init__(
        self,
        mode: str = "protect",
        on_threat: str = "block",
        scan_inputs: bool = True,
        scan_outputs: bool = True,
    ):
        """
        Initialize callback handler.
        
        Args:
            mode: Scan mode
            on_threat: Action on threat (block, warn, log)
            scan_inputs: Scan LLM inputs
            scan_outputs: Scan LLM outputs
        """
        self._scanner = MemoryScanner(mode=mode)
        self._on_threat = on_threat
        self._scan_inputs = scan_inputs
        self._scan_outputs = scan_outputs
        self._threats: List[ScanResult] = []
    
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Scan prompts before LLM call."""
        if not self._scan_inputs:
            return
        
        for prompt in prompts:
            result = self._scanner.scan(prompt)
            if result.decision != Decision.ALLOW:
                scan_result = ScanResult(
                    allowed=False,
                    decision=result.decision.value,
                    risk_score=result.risk_score,
                    threat_type=result.threat_type,
                    original_content=prompt[:100],
                )
                self._threats.append(scan_result)
                
                if self._on_threat == "block":
                    raise MemgarThreatError(
                        f"Input threat blocked: {result.threat_type}",
                        scan_result=scan_result
                    )
    
    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Scan LLM output."""
        if not self._scan_outputs:
            return
        
        # Extract text from response
        if hasattr(response, 'generations'):
            for gen_list in response.generations:
                for gen in gen_list:
                    text = gen.text if hasattr(gen, 'text') else str(gen)
                    result = self._scanner.scan(text)
                    if result.decision != Decision.ALLOW:
                        logger.warning(
                            f"Memgar: Output threat detected - {result.threat_type}"
                        )
    
    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Scan chain inputs."""
        if not self._scan_inputs:
            return
        
        for key, value in inputs.items():
            if isinstance(value, str):
                result = self._scanner.scan(value)
                if result.decision != Decision.ALLOW:
                    logger.warning(
                        f"Memgar: Chain input threat - {result.threat_type}"
                    )
    
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Scan tool inputs."""
        if not self._scan_inputs:
            return
        
        result = self._scanner.scan(input_str)
        if result.decision != Decision.ALLOW:
            if self._on_threat == "block":
                raise MemgarThreatError(
                    f"Tool input blocked: {result.threat_type}"
                )
    
    @property
    def detected_threats(self) -> List[ScanResult]:
        """Get list of detected threats."""
        return self._threats.copy()
    
    def clear_threats(self) -> None:
        """Clear threat history."""
        self._threats.clear()


class MemgarThreatError(Exception):
    """Exception raised when a threat is detected and blocked."""
    
    def __init__(self, message: str, scan_result: Optional[ScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


# Convenience function
def guard_memory(memory: Any, **kwargs) -> MemgarMemoryGuard:
    """
    Quick wrapper to guard a LangChain memory.
    
    Args:
        memory: LangChain memory instance
        **kwargs: Arguments for MemgarMemoryGuard
        
    Returns:
        Guarded memory wrapper
    """
    return MemgarMemoryGuard(memory, **kwargs)
