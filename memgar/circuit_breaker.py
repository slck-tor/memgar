"""
Memgar Circuit Breaker
======================

Automatic agent halting when threat thresholds are exceeded.

The circuit breaker pattern prevents cascading failures by automatically
stopping agent operations when too many threats are detected in a short
time window. This is critical for memory poisoning defense because:

1. Burst attacks: Attackers may flood memory with multiple poisoned entries
2. Propagation prevention: Stop before poison spreads to other agents
3. Human review: Force manual intervention for suspicious activity

Usage:
    from memgar.circuit_breaker import CircuitBreaker, CircuitState
    
    breaker = CircuitBreaker(threshold=5, window_seconds=60)
    
    # In your memory processing loop
    for content in incoming_content:
        result = analyzer.analyze(content)
        
        if result.decision == Decision.BLOCK:
            breaker.record_threat(result)
        
        if breaker.is_tripped:
            # Stop all operations, alert humans
            raise AgentHaltedException(breaker.get_summary())
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"          # Normal operation
    OPEN = "open"              # Tripped, blocking all operations
    HALF_OPEN = "half_open"    # Testing if safe to resume


@dataclass
class ThreatEvent:
    """Record of a detected threat."""
    timestamp: float
    threat_id: str
    severity: str
    risk_score: int
    content_preview: str = ""
    source: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "threat_id": self.threat_id,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "content_preview": self.content_preview[:100],
            "source": self.source,
        }


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker."""
    total_threats: int = 0
    threats_in_window: int = 0
    trips_count: int = 0
    last_trip_time: Optional[float] = None
    state: CircuitState = CircuitState.CLOSED
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_threats": self.total_threats,
            "threats_in_window": self.threats_in_window,
            "trips_count": self.trips_count,
            "last_trip_time": datetime.fromtimestamp(self.last_trip_time).isoformat() if self.last_trip_time else None,
            "state": self.state.value,
        }


class AgentHaltedException(Exception):
    """Raised when circuit breaker trips."""
    
    def __init__(self, message: str, stats: CircuitBreakerStats = None, events: List[ThreatEvent] = None):
        super().__init__(message)
        self.stats = stats
        self.events = events or []


class CircuitBreaker:
    """
    Circuit breaker for AI agent memory protection.
    
    Monitors threat detection rate and automatically halts operations
    when thresholds are exceeded.
    
    Args:
        threshold: Number of threats to trigger trip (default: 5)
        window_seconds: Time window for counting threats (default: 60)
        cooldown_seconds: Time before auto-reset attempt (default: 300)
        on_trip: Callback when breaker trips
        on_reset: Callback when breaker resets
        severity_weights: Weight multipliers by severity
    
    Example:
        breaker = CircuitBreaker(
            threshold=5,
            window_seconds=60,
            on_trip=lambda stats: alert_security_team(stats)
        )
        
        # Record threats as they're detected
        breaker.record_threat(threat_event)
        
        # Check before processing
        if breaker.is_tripped:
            raise AgentHaltedException("Security circuit breaker active")
    """
    
    DEFAULT_SEVERITY_WEIGHTS = {
        "critical": 3.0,
        "high": 2.0,
        "medium": 1.0,
        "low": 0.5,
        "info": 0.1,
    }
    
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 300.0,
        on_trip: Optional[Callable[[CircuitBreakerStats], None]] = None,
        on_reset: Optional[Callable[[], None]] = None,
        severity_weights: Optional[Dict[str, float]] = None,
        auto_reset: bool = False,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.on_trip = on_trip
        self.on_reset = on_reset
        self.severity_weights = severity_weights or self.DEFAULT_SEVERITY_WEIGHTS
        self.auto_reset = auto_reset
        
        self._state = CircuitState.CLOSED
        self._events: deque = deque(maxlen=1000)  # Keep last 1000 events
        self._trips_count = 0
        self._last_trip_time: Optional[float] = None
        self._lock = threading.Lock()
    
    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        with self._lock:
            # Check for auto-reset
            if self.auto_reset and self._state == CircuitState.OPEN:
                if self._last_trip_time and (time.time() - self._last_trip_time) > self.cooldown_seconds:
                    self._state = CircuitState.HALF_OPEN
            return self._state
    
    @property
    def is_tripped(self) -> bool:
        """Check if circuit is open (tripped)."""
        return self.state == CircuitState.OPEN
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self.state == CircuitState.CLOSED
    
    def record_threat(
        self,
        threat_id: str = "UNKNOWN",
        severity: str = "medium",
        risk_score: int = 50,
        content_preview: str = "",
        source: str = "unknown",
    ) -> bool:
        """
        Record a threat event.
        
        Returns True if circuit tripped as a result.
        """
        event = ThreatEvent(
            timestamp=time.time(),
            threat_id=threat_id,
            severity=severity.lower(),
            risk_score=risk_score,
            content_preview=content_preview,
            source=source,
        )
        
        with self._lock:
            self._events.append(event)
            
            # Check if we should trip
            if self._state != CircuitState.OPEN:
                weighted_count = self._get_weighted_threat_count()
                
                if weighted_count >= self.threshold:
                    self._trip()
                    return True
        
        return False
    
    def record_from_result(self, result, content: str = "", source: str = "unknown") -> bool:
        """
        Record threat from AnalysisResult or GuardResult.
        
        Args:
            result: AnalysisResult or GuardResult object
            content: Original content (for preview)
            source: Source identifier
        
        Returns True if circuit tripped.
        """
        if not hasattr(result, 'threats') or not result.threats:
            return False
        
        tripped = False
        for threat_match in result.threats:
            threat = threat_match.threat if hasattr(threat_match, 'threat') else threat_match
            
            if self.record_threat(
                threat_id=getattr(threat, 'id', 'UNKNOWN'),
                severity=getattr(threat.severity, 'value', 'medium') if hasattr(threat, 'severity') else 'medium',
                risk_score=getattr(result, 'risk_score', 50),
                content_preview=content[:100],
                source=source,
            ):
                tripped = True
        
        return tripped
    
    def _get_weighted_threat_count(self) -> float:
        """Calculate weighted threat count in current window."""
        now = time.time()
        cutoff = now - self.window_seconds
        
        weighted_count = 0.0
        for event in self._events:
            if event.timestamp >= cutoff:
                weight = self.severity_weights.get(event.severity, 1.0)
                weighted_count += weight
        
        return weighted_count
    
    def _get_events_in_window(self) -> List[ThreatEvent]:
        """Get all events in current time window."""
        now = time.time()
        cutoff = now - self.window_seconds
        return [e for e in self._events if e.timestamp >= cutoff]
    
    def _trip(self) -> None:
        """Trip the circuit breaker."""
        self._state = CircuitState.OPEN
        self._trips_count += 1
        self._last_trip_time = time.time()
        
        if self.on_trip:
            try:
                self.on_trip(self.get_stats())
            except Exception:
                pass  # Don't let callback errors prevent trip
    
    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        with self._lock:
            self._state = CircuitState.CLOSED
            
            if self.on_reset:
                try:
                    self.on_reset()
                except Exception:
                    pass
    
    def force_trip(self, reason: str = "Manual trip") -> None:
        """Manually trip the circuit breaker."""
        with self._lock:
            self.record_threat(
                threat_id="MANUAL",
                severity="critical",
                risk_score=100,
                content_preview=reason,
                source="manual",
            )
            self._trip()
    
    def get_stats(self) -> CircuitBreakerStats:
        """Get current statistics."""
        with self._lock:
            return CircuitBreakerStats(
                total_threats=len(self._events),
                threats_in_window=len(self._get_events_in_window()),
                trips_count=self._trips_count,
                last_trip_time=self._last_trip_time,
                state=self._state,
            )
    
    def get_recent_events(self, limit: int = 10) -> List[ThreatEvent]:
        """Get most recent threat events."""
        with self._lock:
            events = list(self._events)
            return events[-limit:] if len(events) > limit else events
    
    def get_summary(self) -> Dict[str, Any]:
        """Get full summary for logging/alerting."""
        stats = self.get_stats()
        recent = self.get_recent_events(10)
        
        return {
            "stats": stats.to_dict(),
            "recent_events": [e.to_dict() for e in recent],
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "message": f"Circuit breaker {'TRIPPED' if self.is_tripped else 'OK'}: "
                       f"{stats.threats_in_window} threats in last {self.window_seconds}s "
                       f"(threshold: {self.threshold})",
        }
    
    def check_and_raise(self) -> None:
        """Check circuit state and raise exception if tripped."""
        if self.is_tripped:
            raise AgentHaltedException(
                f"Circuit breaker tripped: {self.get_stats().threats_in_window} threats detected",
                stats=self.get_stats(),
                events=self.get_recent_events(),
            )
    
    def __enter__(self):
        """Context manager entry - check circuit."""
        self.check_and_raise()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        return False


class MultiCircuitBreaker:
    """
    Manage multiple circuit breakers for different scopes.
    
    Useful for:
    - Per-session breakers
    - Per-source breakers
    - Per-agent breakers in multi-agent systems
    
    Example:
        multi = MultiCircuitBreaker(default_threshold=5)
        
        # Get or create breaker for specific session
        breaker = multi.get_breaker("session_123")
        breaker.record_threat(...)
        
        # Check all breakers
        if multi.any_tripped():
            multi.get_tripped_breakers()
    """
    
    def __init__(
        self,
        default_threshold: int = 5,
        default_window: float = 60.0,
        **default_kwargs,
    ):
        self.default_threshold = default_threshold
        self.default_window = default_window
        self.default_kwargs = default_kwargs
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()
    
    def get_breaker(self, scope: str) -> CircuitBreaker:
        """Get or create circuit breaker for scope."""
        with self._lock:
            if scope not in self._breakers:
                self._breakers[scope] = CircuitBreaker(
                    threshold=self.default_threshold,
                    window_seconds=self.default_window,
                    **self.default_kwargs,
                )
            return self._breakers[scope]
    
    def any_tripped(self) -> bool:
        """Check if any breaker is tripped."""
        with self._lock:
            return any(b.is_tripped for b in self._breakers.values())
    
    def get_tripped_breakers(self) -> Dict[str, CircuitBreaker]:
        """Get all tripped breakers."""
        with self._lock:
            return {k: v for k, v in self._breakers.items() if v.is_tripped}
    
    def reset_all(self) -> None:
        """Reset all breakers."""
        with self._lock:
            for breaker in self._breakers.values():
                breaker.reset()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all breakers."""
        with self._lock:
            return {
                scope: breaker.get_summary()
                for scope, breaker in self._breakers.items()
            }
