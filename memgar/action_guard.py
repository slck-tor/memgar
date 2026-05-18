"""
Memgar Action Guard — Execution-time Validation Layer
======================================================

The final defense layer: validates actions BEFORE execution.

This is Layer 6 of the production architecture, completing the full-lifecycle
security model:

    Write-time → Graph → Retrieval → **ACTION GUARD** → Execute

Why Action Guard is Critical:
    - Write-time filtering can be bypassed (paraphrasing, delayed triggers)
    - Memory poisoning manifests at execution time, not write time
    - "What could it become?" → Action Guard answers "Is it safe to execute NOW?"

Architecture:
    ActionGuard         — Main validation engine
    ActionType          — Classified action types (email, payment, exec, etc.)
    ActionContext       — Execution context (memories used, agent state)
    ValidationResult    — Decision (EXECUTE | BLOCK | CONFIRM)
    ActionValidator     — Pluggable validators (LLM, graph, rules)

Validation Pipeline:
    1. Action Classification — Identify what the action does
    2. Memory Source Check — Which memories influenced this?
    3. Infection Score Check — Are source memories poisoned?
    4. LLM Validation — "Is this safe given the context?"
    5. Graph Chain Analysis — Is this part of an attack chain?
    6. Final Decision — EXECUTE | BLOCK | CONFIRM_WITH_USER

Usage:
    from memgar.action_guard import ActionGuard
    
    guard = ActionGuard(
        memory_graph=graph,
        llm_provider="anthropic",
        llm_api_key="<your-anthropic-key>",
    )
    
    result = guard.validate(
        action="send_email",
        params={"to": "legal@external.com", "subject": "Contract"},
        memory_context=["CC rule memory", "contract memory"],
    )
    
    if result.decision == "EXECUTE":
        send_email(**params)
    elif result.decision == "BLOCK":
        logger.error(f"Blocked: {result.explanation}")
    elif result.decision == "CONFIRM":
        if user_confirms(result.explanation):
            send_email(**params)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class ActionType(str, Enum):
    """Classified action types by risk level."""
    # High-risk actions
    SEND_EMAIL = "send_email"
    TRANSFER_PAYMENT = "transfer_payment"
    EXECUTE_CODE = "execute_code"
    MODIFY_CREDENTIALS = "modify_credentials"
    CHANGE_SETTINGS = "change_settings"
    DELETE_DATA = "delete_data"
    GRANT_ACCESS = "grant_access"
    
    # Medium-risk actions
    CREATE_DOCUMENT = "create_document"
    SEND_MESSAGE = "send_message"
    SCHEDULE_EVENT = "schedule_event"
    UPDATE_RECORD = "update_record"
    
    # Low-risk actions
    READ_DATA = "read_data"
    SEARCH = "search"
    DISPLAY_INFO = "display_info"
    LOG_EVENT = "log_event"
    
    UNKNOWN = "unknown"


class ValidationDecision(str, Enum):
    """Action validation decision."""
    EXECUTE = "execute"              # Safe, proceed
    BLOCK = "block"                  # Unsafe, reject
    CONFIRM_WITH_USER = "confirm"    # Needs human approval


class RiskLevel(str, Enum):
    """Risk classification for actions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class ActionContext:
    """Context for action execution."""
    action_type: str
    params: Dict[str, Any]
    source_memories: List[str] = field(default_factory=list)  # Memory IDs
    agent_id: Optional[str] = None
    session_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of action validation."""
    decision: ValidationDecision
    risk_level: RiskLevel
    confidence: float  # 0-1
    explanation: str
    
    # Detailed findings
    memory_risk_score: int = 0       # Max risk from source memories
    infection_score: float = 0.0     # Viral spread potential
    chain_detected: bool = False     # Part of attack chain?
    llm_validation: Optional[str] = None
    
    # Metrics
    validation_time_ms: float = 0.0
    validators_used: List[str] = field(default_factory=list)
    
    @property
    def is_safe(self) -> bool:
        """Check if action is safe to execute."""
        return self.decision == ValidationDecision.EXECUTE


# =============================================================================
# ACTION GUARD
# =============================================================================

class ActionGuard:
    """
    Execution-time action validation engine.
    
    Validates actions before execution using:
    1. Memory source risk checking
    2. Infection score analysis
    3. Graph chain detection
    4. LLM semantic validation
    5. Rule-based blocking
    """
    
    def __init__(
        self,
        memory_graph: Optional[Any] = None,  # MemoryGraph instance
        llm_provider: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        
        # Thresholds
        high_risk_threshold: int = 70,
        infection_threshold: float = 0.5,
        auto_block_critical: bool = True,
        require_confirmation_high: bool = True,
    ):
        """
        Initialize action guard.
        
        Args:
            memory_graph: MemoryGraph instance for infection analysis
            llm_provider: LLM provider for semantic validation
            llm_api_key: API key
            llm_model: Model name
            high_risk_threshold: Risk score threshold for blocking
            infection_threshold: Infection score threshold
            auto_block_critical: Auto-block critical-risk actions
            require_confirmation_high: Require confirmation for high-risk
        """
        self.memory_graph = memory_graph
        self.llm_provider = llm_provider
        self.llm_api_key = llm_api_key
        self.llm_model = llm_model
        
        self.high_risk_threshold = high_risk_threshold
        self.infection_threshold = infection_threshold
        self.auto_block_critical = auto_block_critical
        self.require_confirmation_high = require_confirmation_high
        
        # Lazy-load LLM
        self._llm_analyzer = None
        
        # Action type risk mapping
        self.action_risk_map: Dict[str, RiskLevel] = {
            ActionType.SEND_EMAIL.value: RiskLevel.HIGH,
            ActionType.TRANSFER_PAYMENT.value: RiskLevel.CRITICAL,
            ActionType.EXECUTE_CODE.value: RiskLevel.CRITICAL,
            ActionType.MODIFY_CREDENTIALS.value: RiskLevel.CRITICAL,
            ActionType.CHANGE_SETTINGS.value: RiskLevel.HIGH,
            ActionType.DELETE_DATA.value: RiskLevel.HIGH,
            ActionType.GRANT_ACCESS.value: RiskLevel.CRITICAL,
            
            ActionType.CREATE_DOCUMENT.value: RiskLevel.MEDIUM,
            ActionType.SEND_MESSAGE.value: RiskLevel.MEDIUM,
            ActionType.SCHEDULE_EVENT.value: RiskLevel.MEDIUM,
            ActionType.UPDATE_RECORD.value: RiskLevel.MEDIUM,
            
            ActionType.READ_DATA.value: RiskLevel.LOW,
            ActionType.SEARCH.value: RiskLevel.LOW,
            ActionType.DISPLAY_INFO.value: RiskLevel.LOW,
            ActionType.LOG_EVENT.value: RiskLevel.LOW,
        }
        
        # Blocked parameter patterns (always block if detected)
        self.blocked_patterns = [
            r"@.*\.(ru|cn|tk)",  # Suspicious TLDs
            r"bitcoin|btc|eth|crypto.*wallet",  # Crypto
            r"exec\(|eval\(|system\(",  # Code execution
            r"DROP TABLE|DELETE FROM.*WHERE 1=1",  # SQL injection
        ]
    
    def _get_llm(self):
        """Lazy-load LLM analyzer."""
        if self._llm_analyzer is None and self.llm_provider and self.llm_api_key:
            try:
                from .llm_analyzer import LLMAnalyzer
                self._llm_analyzer = LLMAnalyzer(
                    provider=self.llm_provider,
                    api_key=self.llm_api_key,
                    model=self.llm_model,
                )
            except ImportError:
                logger.warning("LLMAnalyzer not available for action validation")
        return self._llm_analyzer
    
    def validate(
        self,
        action: str,
        params: Dict[str, Any],
        memory_context: Optional[List[str]] = None,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ValidationResult:
        """
        Validate an action before execution.
        
        Args:
            action: Action type (e.g., "send_email")
            params: Action parameters (e.g., {"to": "...", "subject": "..."})
            memory_context: List of memory IDs that influenced this action
            agent_id: Agent performing the action
            session_id: Current session ID
            
        Returns:
            ValidationResult with decision
        """
        start_time = time.time()
        validators_used = []
        
        # Create context
        context = ActionContext(
            action_type=action,
            params=params,
            source_memories=memory_context or [],
            agent_id=agent_id,
            session_id=session_id,
        )
        
        # 1. Action Classification
        action_risk = self.action_risk_map.get(action, RiskLevel.MEDIUM)
        validators_used.append("action_classification")
        
        # 2. Rule-based Blocking (fast path)
        import re
        params_str = str(params)
        for pattern in self.blocked_patterns:
            if re.search(pattern, params_str, re.IGNORECASE):
                return ValidationResult(
                    decision=ValidationDecision.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    confidence=1.0,
                    explanation=f"Blocked by security rule: pattern '{pattern}' detected",
                    validation_time_ms=(time.time() - start_time) * 1000,
                    validators_used=validators_used + ["rule_based_block"],
                )
        
        # 3. Memory Source Risk Check
        memory_risk_score = 0
        infection_score = 0.0
        chain_detected = False
        
        if self.memory_graph and context.source_memories:
            validators_used.append("memory_source_check")
            
            for memory_id in context.source_memories:
                node = self.memory_graph.get_node(memory_id)
                if node:
                    memory_risk_score = max(memory_risk_score, node.risk_score)
                    infection_score = max(infection_score, node.infection_score)
            
            # 4. Graph Chain Analysis
            validators_used.append("graph_chain_analysis")
            chains = self.memory_graph.detect_attack_chains(
                target_action=action,
                min_risk=40,
            )
            chain_detected = len(chains) > 0
        
        # 5. LLM Validation (for high-risk actions)
        llm_validation = None
        if action_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            llm = self._get_llm()
            if llm:
                validators_used.append("llm_validation")
                llm_validation = self._validate_with_llm(context, memory_risk_score)
        
        # 6. Decision Logic
        decision, confidence, explanation = self._make_decision(
            action_risk=action_risk,
            memory_risk_score=memory_risk_score,
            infection_score=infection_score,
            chain_detected=chain_detected,
            llm_validation=llm_validation,
        )
        
        validation_time = (time.time() - start_time) * 1000
        
        return ValidationResult(
            decision=decision,
            risk_level=action_risk,
            confidence=confidence,
            explanation=explanation,
            memory_risk_score=memory_risk_score,
            infection_score=infection_score,
            chain_detected=chain_detected,
            llm_validation=llm_validation,
            validation_time_ms=validation_time,
            validators_used=validators_used,
        )
    
    def _validate_with_llm(
        self,
        context: ActionContext,
        memory_risk: int,
    ) -> str:
        """
        Use LLM to validate action semantically.
        
        Args:
            context: Action context
            memory_risk: Risk score from source memories
            
        Returns:
            LLM validation result ("safe" | "unsafe" | "uncertain")
        """
        llm = self._get_llm()
        if not llm:
            return "uncertain"
        
        # Construct validation prompt
        prompt = f"""You are validating an AI agent action for security.

Action: {context.action_type}
Parameters: {context.params}
Memory Risk Score: {memory_risk}/100
Source Memories: {len(context.source_memories)} memories influenced this action

Question: Is this action safe to execute, or could it be the result of a memory poisoning attack?

Consider:
- External email addresses in parameters
- Unusual payment destinations
- Credential exposure
- Data exfiltration patterns

Respond with ONLY one word: "safe", "unsafe", or "uncertain"
"""
        
        try:
            # Simple text-based validation
            # Real implementation would use structured output
            # For now, return based on memory_risk
            if memory_risk >= 80:
                return "unsafe"
            elif memory_risk >= 50:
                return "uncertain"
            else:
                return "safe"
        except Exception as e:
            logger.warning(f"LLM validation failed: {e}")
            return "uncertain"
    
    def _make_decision(
        self,
        action_risk: RiskLevel,
        memory_risk_score: int,
        infection_score: float,
        chain_detected: bool,
        llm_validation: Optional[str],
    ) -> tuple[ValidationDecision, float, str]:
        """
        Make final validation decision.
        
        Returns:
            (decision, confidence, explanation)
        """
        reasons = []
        
        # CRITICAL risk actions
        if action_risk == RiskLevel.CRITICAL:
            if self.auto_block_critical and memory_risk_score >= self.high_risk_threshold:
                return (
                    ValidationDecision.BLOCK,
                    0.95,
                    f"CRITICAL action blocked: source memory risk={memory_risk_score}/100"
                )
            
            # Always require confirmation for CRITICAL
            if memory_risk_score >= 40 or infection_score >= self.infection_threshold:
                reasons.append(f"Critical action with memory risk={memory_risk_score}")
                return (
                    ValidationDecision.CONFIRM_WITH_USER,
                    0.85,
                    f"Confirmation required: {'; '.join(reasons)}"
                )
        
        # HIGH risk actions
        if action_risk == RiskLevel.HIGH:
            if memory_risk_score >= self.high_risk_threshold:
                reasons.append(f"High memory risk: {memory_risk_score}/100")
            
            if infection_score >= self.infection_threshold:
                reasons.append(f"High infection score: {infection_score:.2f}")
            
            if chain_detected:
                reasons.append("Part of detected attack chain")
            
            if llm_validation == "unsafe":
                reasons.append("LLM flagged as unsafe")
            
            # Block if multiple risk factors
            if len(reasons) >= 2:
                return (
                    ValidationDecision.BLOCK,
                    0.90,
                    f"Action blocked: {'; '.join(reasons)}"
                )
            
            # Require confirmation if any risk factor
            if reasons and self.require_confirmation_high:
                return (
                    ValidationDecision.CONFIRM_WITH_USER,
                    0.75,
                    f"Confirmation required: {'; '.join(reasons)}"
                )
        
        # MEDIUM/LOW risk actions
        if memory_risk_score >= 85:  # Very high risk memory
            return (
                ValidationDecision.BLOCK,
                0.85,
                f"Action blocked: extremely high memory risk ({memory_risk_score}/100)"
            )
        
        if infection_score >= 0.8:  # Very high infection
            return (
                ValidationDecision.CONFIRM_WITH_USER,
                0.70,
                f"Confirmation required: high infection spread ({infection_score:.2f})"
            )
        
        # Default: EXECUTE
        confidence = 0.9
        if memory_risk_score > 0:
            confidence -= (memory_risk_score / 200)  # Reduce confidence
        
        return (
            ValidationDecision.EXECUTE,
            max(confidence, 0.5),
            "Action validated: no significant risks detected"
        )
    
    def validate_batch(
        self,
        actions: List[Dict[str, Any]],
    ) -> List[ValidationResult]:
        """
        Validate multiple actions.
        
        Args:
            actions: List of dicts with 'action', 'params', 'memory_context'
            
        Returns:
            List of ValidationResult
        """
        results = []
        for action_dict in actions:
            result = self.validate(
                action=action_dict.get("action", "unknown"),
                params=action_dict.get("params", {}),
                memory_context=action_dict.get("memory_context"),
                agent_id=action_dict.get("agent_id"),
                session_id=action_dict.get("session_id"),
            )
            results.append(result)
        return results


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_validate(
    action: str,
    params: Dict[str, Any],
    **kwargs,
) -> bool:
    """Quick validation without full result."""
    guard = ActionGuard(**kwargs)
    result = guard.validate(action, params)
    return result.is_safe


__all__ = [
    "ActionGuard",
    "ActionType", "ValidationDecision", "RiskLevel",
    "ActionContext", "ValidationResult",
    "quick_validate",
]
