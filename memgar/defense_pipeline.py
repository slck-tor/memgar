"""
Unified Memgar defense pipeline.

This module wires the existing Memgar layers into one production-friendly
orchestrator without changing the lower-level APIs. The lower-level modules
remain available for advanced users; this class is the "one safe path" for
applications that want the architecture to behave like a single flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from memgar.behavioral_baseline import (
    BaselineIntegration,
    BehavioralBaseline,
    DeviationReport,
)
from memgar.circuit_breaker import AgentHaltedException, CircuitBreaker
from memgar.memory_guard import GuardResult, MemoryGuard
from memgar.memory_ledger import LedgerReport, MemoryLedger
from memgar.secure_retriever import RetrievalResult, SecureMemoryRetriever
from memgar.write_ahead_validator import (
    GuardianVerdict,
    ValidationContext,
    ValidationOutcome,
    WriteAheadValidator,
)


@dataclass
class DefensePipelineResult:
    """Result from processing content through the unified defense pipeline."""

    allowed: bool
    decision: str
    safe_content: str
    guard_result: GuardResult
    guardian_verdict: Optional[GuardianVerdict] = None
    ledger_entry_id: Optional[str] = None
    retrieval_result: Optional[RetrievalResult] = None
    behavior_report: Optional[DeviationReport] = None
    circuit_tripped: bool = False
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def stored(self) -> bool:
        """Return True when the memory was committed to the ledger."""
        return self.ledger_entry_id is not None

    @property
    def quarantined(self) -> bool:
        """Return True when the final decision requires review."""
        return self.decision == "quarantine"

    @property
    def blocked(self) -> bool:
        """Return True when the final decision blocks the content."""
        return self.decision == "block"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the pipeline result for logs, APIs, and dashboards."""
        return {
            "allowed": self.allowed,
            "decision": self.decision,
            "stored": self.stored,
            "ledger_entry_id": self.ledger_entry_id,
            "safe_content": self.safe_content,
            "guard": self.guard_result.to_dict(),
            "guardian": (
                self.guardian_verdict.to_dict()
                if self.guardian_verdict is not None
                else None
            ),
            "retrieval": (
                self.retrieval_result.to_dict()
                if self.retrieval_result is not None
                else None
            ),
            "behavior": (
                self.behavior_report.to_dict()
                if self.behavior_report is not None
                else None
            ),
            "circuit_tripped": self.circuit_tripped,
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }


class MemgarDefensePipeline:
    """
    End-to-end memory defense orchestrator.

    Flow:
    1. Input moderation, sanitization, and provenance via MemoryGuard.
    2. Write-ahead validation via WriteAheadValidator.
    3. Tamper-evident persistence via MemoryLedger.
    4. Trust-aware retrieval via SecureMemoryRetriever.
    5. Behavioral observations and circuit breaker updates.

    The pipeline is conservative by default: blocked/quarantined content is not
    committed to the ledger unless explicitly allowed by configuration.
    """

    def __init__(
        self,
        guard: Optional[MemoryGuard] = None,
        ledger: Optional[MemoryLedger] = None,
        retriever: Optional[SecureMemoryRetriever] = None,
        validator: Optional[WriteAheadValidator] = None,
        baseline: Optional[BehavioralBaseline] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        ledger_path: Optional[str] = None,
        agent_id: str = "default-agent",
        enable_behavioral_monitoring: bool = True,
        enable_circuit_breaker: bool = True,
        allow_quarantined_writes: bool = False,
        retrieve_after_write: bool = False,
        retrieval_top_k: int = 5,
    ) -> None:
        self.agent_id = agent_id
        self.guard = guard or MemoryGuard(session_id=agent_id)
        self.ledger = ledger or MemoryLedger(path=ledger_path)
        self.validator = validator or WriteAheadValidator(block_on_quarantine=False)
        self.retriever = retriever or SecureMemoryRetriever(ledger=self.ledger)
        self.allow_quarantined_writes = bool(allow_quarantined_writes)
        self.retrieve_after_write = bool(retrieve_after_write)
        self.retrieval_top_k = int(retrieval_top_k)

        self.baseline = baseline if enable_behavioral_monitoring else None
        if self.baseline is None and enable_behavioral_monitoring:
            self.baseline = BehavioralBaseline(agent_id=agent_id)
        self.behavior = (
            BaselineIntegration(self.baseline)
            if self.baseline is not None
            else None
        )

        self.circuit_breaker = (
            circuit_breaker if enable_circuit_breaker else None
        )
        if self.circuit_breaker is None and enable_circuit_breaker:
            self.circuit_breaker = CircuitBreaker()

        self._stats: Dict[str, int] = {
            "processed": 0,
            "stored": 0,
            "blocked": 0,
            "quarantined": 0,
            "guardian_rejected": 0,
            "retrievals": 0,
        }

    def process_external_content(
        self,
        content: str,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        source_name: Optional[str] = None,
        source_url: Optional[str] = None,
        source_path: Optional[str] = None,
        source_domain: Optional[str] = None,
        verified: bool = False,
        principal: Optional[str] = None,
        session_history: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        custom_metadata: Optional[Dict[str, Any]] = None,
        expires_in_days: Optional[int] = None,
        retrieve_query: Optional[str] = None,
    ) -> DefensePipelineResult:
        """Process external content before it can influence agent memory."""
        self._stats["processed"] += 1

        if self.circuit_breaker is not None and self.circuit_breaker.is_tripped:
            raise AgentHaltedException(
                "Security circuit breaker active",
                stats=self.circuit_breaker.get_stats(),
            )

        guard_result = self.guard.process(
            content=content,
            source_type=source_type,
            source_id=source_id,
            source_name=source_name,
            source_url=source_url,
            source_path=source_path,
            source_domain=source_domain,
            verified=verified,
            tags=tags,
            custom_metadata=custom_metadata,
            expires_in_days=expires_in_days,
        )

        self._observe_guard(guard_result, source_type, content)

        if not guard_result.allowed:
            decision = "quarantine" if guard_result.decision.value == "quarantine" else "block"
            self._stats["quarantined" if decision == "quarantine" else "blocked"] += 1
            behavior_report = self._check_behavior()
            return DefensePipelineResult(
                allowed=False,
                decision=decision,
                safe_content=guard_result.safe_content,
                guard_result=guard_result,
                behavior_report=behavior_report,
                circuit_tripped=self._circuit_is_tripped(),
                warnings=list(guard_result.warnings),
                metadata={"stage": "memory_guard"},
            )

        verdict = self._validate_write(
            safe_content=guard_result.safe_content,
            original_content=content,
            guard_result=guard_result,
            source_type=source_type,
            source_url=source_url,
            principal=principal,
            session_history=session_history,
            verified=verified,
        )

        if verdict.outcome == ValidationOutcome.REJECT:
            self._stats["guardian_rejected"] += 1
            self._stats["blocked"] += 1
            self._observe_write(guard_result, approved=False, rejected=True, source_type=source_type)
            behavior_report = self._check_behavior()
            return DefensePipelineResult(
                allowed=False,
                decision="block",
                safe_content=verdict.sanitized_content,
                guard_result=guard_result,
                guardian_verdict=verdict,
                behavior_report=behavior_report,
                circuit_tripped=self._circuit_is_tripped(),
                warnings=list(guard_result.warnings) + [verdict.reason],
                metadata={"stage": "write_ahead_validation"},
            )

        if verdict.outcome == ValidationOutcome.QUARANTINE and not self.allow_quarantined_writes:
            self._stats["quarantined"] += 1
            self._observe_write(guard_result, approved=False, rejected=False, source_type=source_type)
            behavior_report = self._check_behavior()
            return DefensePipelineResult(
                allowed=False,
                decision="quarantine",
                safe_content=verdict.sanitized_content,
                guard_result=guard_result,
                guardian_verdict=verdict,
                behavior_report=behavior_report,
                circuit_tripped=self._circuit_is_tripped(),
                warnings=list(guard_result.warnings) + [verdict.reason],
                metadata={"stage": "write_ahead_validation"},
            )

        ledger_entry_id = self._commit_to_ledger(
            content=verdict.sanitized_content,
            guard_result=guard_result,
            verdict=verdict,
            source_type=source_type,
            source_id=source_id,
            source_name=source_name,
            source_url=source_url,
            source_domain=source_domain,
            verified=verified,
            principal=principal,
            tags=tags,
            custom_metadata=custom_metadata,
        )
        self._stats["stored"] += 1
        self._observe_write(guard_result, approved=True, rejected=False, source_type=source_type)

        retrieval_result = None
        if self.retrieve_after_write or retrieve_query:
            retrieval_result = self.retrieve_context(
                query=retrieve_query or verdict.sanitized_content,
                top_k=self.retrieval_top_k,
            )

        behavior_report = self._check_behavior()
        return DefensePipelineResult(
            allowed=True,
            decision=(
                "allow_sanitized"
                if guard_result.was_sanitized
                else "allow"
            ),
            safe_content=verdict.sanitized_content,
            guard_result=guard_result,
            guardian_verdict=verdict,
            ledger_entry_id=ledger_entry_id,
            retrieval_result=retrieval_result,
            behavior_report=behavior_report,
            circuit_tripped=self._circuit_is_tripped(),
            warnings=list(guard_result.warnings),
            metadata={"stage": "committed"},
        )

    def retrieve_context(
        self,
        query: str,
        top_k: Optional[int] = None,
        min_base_score: float = 0.0,
    ) -> RetrievalResult:
        """Retrieve ranked context through the trust-aware retrieval layer."""
        result = self.retriever.retrieve(
            query=query,
            top_k=top_k,
            agent_id=self.agent_id,
            min_base_score=min_base_score,
        )
        self._stats["retrievals"] += 1
        if self.behavior is not None:
            avg_trust = 0.0
            if result.documents:
                avg_trust = sum(d.trust_score for d in result.documents) / len(result.documents)
            self.behavior.on_retrieval(
                anomaly_count=result.anomaly_count,
                filtered_count=result.filtered_count,
                avg_trust=avg_trust,
                total_candidates=result.total_candidates,
            )
        return result

    def verify_memory(self) -> LedgerReport:
        """Verify ledger integrity."""
        return self.ledger.verify()

    def check_behavior(self) -> Optional[DeviationReport]:
        """Run behavioral baseline detection on current observations."""
        return self._check_behavior()

    def stats(self) -> Dict[str, Any]:
        """Return pipeline and component statistics."""
        return {
            **self._stats,
            "guard": self.guard.get_statistics(),
            "retriever": self.retriever.stats(),
            "ledger_entries": len(self.ledger),
            "circuit_tripped": self._circuit_is_tripped(),
        }

    def _validate_write(
        self,
        safe_content: str,
        original_content: str,
        guard_result: GuardResult,
        source_type: str,
        source_url: Optional[str],
        principal: Optional[str],
        session_history: Optional[List[str]],
        verified: bool,
    ) -> GuardianVerdict:
        context = ValidationContext(
            source_type=source_type,
            source_url=source_url,
            agent_id=self.agent_id,
            principal=principal,
            session_history=session_history or [],
            is_verified=verified,
            extra={
                "guard_decision": guard_result.decision.value,
                "risk_score_before": guard_result.risk_score_before,
                "risk_score_after": guard_result.risk_score_after,
                "was_sanitized": guard_result.was_sanitized,
                "original_length": len(original_content),
            },
        )
        return self.validator.validate(
            content=safe_content,
            context=context,
            sanitize_result=guard_result.sanitize_result,
        )

    def _commit_to_ledger(
        self,
        content: str,
        guard_result: GuardResult,
        verdict: GuardianVerdict,
        source_type: str,
        source_id: Optional[str],
        source_name: Optional[str],
        source_url: Optional[str],
        source_domain: Optional[str],
        verified: bool,
        principal: Optional[str],
        tags: Optional[List[str]],
        custom_metadata: Optional[Dict[str, Any]],
    ) -> str:
        trust_raw = int(guard_result.trust_score)
        trust_normalized = max(0.0, min(1.0, trust_raw / 100.0))
        metadata: Dict[str, Any] = {
            **(custom_metadata or {}),
            **verdict.as_metadata(),
            "source_type": source_type,
            "source_id": source_id,
            "source_name": source_name,
            "source_url": source_url,
            "source_domain": source_domain,
            "source_verified": bool(verified),
            "principal": principal,
            "agent_id": self.agent_id,
            "tags": list(tags or []),
            "trust_score": trust_normalized,
            "trust_score_raw": trust_raw,
            "risk_score": int(guard_result.risk_score_after),
            "risk_score_before": int(guard_result.risk_score_before),
            "was_sanitized": bool(guard_result.was_sanitized),
            "guard_entry_id": guard_result.entry_id,
            "guard_decision": guard_result.decision.value,
            "removed_segments_count": len(guard_result.removed_segments),
            "provenance_tracked": bool(guard_result.provenance_tracked),
        }
        return self.ledger.append(content, metadata=metadata)

    def _observe_guard(self, guard_result: GuardResult, source_type: str, content: str) -> None:
        if self.behavior is not None:
            threat_ids = []
            for match in guard_result.threats_detected:
                threat = getattr(match, "threat", match)
                threat_ids.append(str(getattr(threat, "id", "UNKNOWN")))
            self.behavior.on_scan(
                risk_score=int(guard_result.risk_score_before),
                decision=guard_result.decision.value,
                threat_count=len(guard_result.threats_detected),
                threat_ids=threat_ids,
            )

        if self.circuit_breaker is not None:
            try:
                self.circuit_breaker.record_from_result(
                    guard_result,
                    content=content,
                    source=source_type,
                )
            except Exception:
                # Circuit breaker telemetry must never break the primary guard path.
                pass

    def _observe_write(
        self,
        guard_result: GuardResult,
        approved: bool,
        rejected: bool,
        source_type: str,
    ) -> None:
        if self.behavior is not None:
            self.behavior.on_memory_write(
                trust_score=max(0.0, min(1.0, guard_result.trust_score / 100.0)),
                source_type=source_type,
                approved=approved,
                rejected=rejected,
            )

    def _check_behavior(self) -> Optional[DeviationReport]:
        if self.behavior is None:
            return None
        return self.behavior.check()

    def _circuit_is_tripped(self) -> bool:
        return bool(self.circuit_breaker and self.circuit_breaker.is_tripped)


def create_defense_pipeline(
    ledger_path: Optional[str] = None,
    agent_id: str = "default-agent",
    **kwargs: Any,
) -> MemgarDefensePipeline:
    """Convenience factory for the unified defense pipeline."""
    return MemgarDefensePipeline(
        ledger_path=ledger_path,
        agent_id=agent_id,
        **kwargs,
    )
