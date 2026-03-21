"""
Memgar Provenance Tracking System
=================================

Comprehensive metadata tracking for agent memory entries.

Every memory entry is tagged with:
- Timestamp (when created/modified)
- Source information (where it came from)
- Session context (which session created it)
- Trust score (how trustworthy is the source)
- Content hash (for integrity verification)
- Chain of custody (modification history)

Based on Christian Schneider's defense architecture (Layer 2).
"""

import json
import time
import hashlib
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """Type of content source."""
    USER_INPUT = "user_input"           # Direct user message
    DOCUMENT = "document"                # Uploaded document
    EMAIL = "email"                      # Email content
    WEBPAGE = "webpage"                  # Web page fetch
    API = "api"                          # External API response
    TOOL_OUTPUT = "tool_output"          # Tool execution result
    AGENT = "agent"                      # Another agent
    SYSTEM = "system"                    # System generated
    UNKNOWN = "unknown"                  # Unknown source


class TrustLevel(Enum):
    """Trust level of source."""
    VERIFIED = "verified"       # Cryptographically verified
    TRUSTED = "trusted"         # From trusted internal source
    AUTHENTICATED = "authenticated"  # User authenticated
    EXTERNAL = "external"       # External but known source
    UNTRUSTED = "untrusted"     # Unknown/untrusted source
    MALICIOUS = "malicious"     # Known malicious source


# Trust scores by level
TRUST_SCORES = {
    TrustLevel.VERIFIED: 100,
    TrustLevel.TRUSTED: 85,
    TrustLevel.AUTHENTICATED: 70,
    TrustLevel.EXTERNAL: 40,
    TrustLevel.UNTRUSTED: 20,
    TrustLevel.MALICIOUS: 0,
}

# Default trust by source type
SOURCE_TYPE_TRUST = {
    SourceType.USER_INPUT: TrustLevel.AUTHENTICATED,
    SourceType.DOCUMENT: TrustLevel.EXTERNAL,
    SourceType.EMAIL: TrustLevel.EXTERNAL,
    SourceType.WEBPAGE: TrustLevel.UNTRUSTED,
    SourceType.API: TrustLevel.EXTERNAL,
    SourceType.TOOL_OUTPUT: TrustLevel.TRUSTED,
    SourceType.AGENT: TrustLevel.TRUSTED,
    SourceType.SYSTEM: TrustLevel.VERIFIED,
    SourceType.UNKNOWN: TrustLevel.UNTRUSTED,
}


@dataclass
class SourceInfo:
    """Detailed source information."""
    source_type: SourceType
    source_id: str                      # Unique identifier for source
    source_name: Optional[str] = None   # Human readable name
    source_url: Optional[str] = None    # URL if applicable
    source_path: Optional[str] = None   # File path if applicable
    source_domain: Optional[str] = None # Domain for web sources
    verified: bool = False              # Whether source is verified
    
    def to_dict(self) -> Dict:
        return {
            "type": self.source_type.value,
            "id": self.source_id,
            "name": self.source_name,
            "url": self.source_url,
            "path": self.source_path,
            "domain": self.source_domain,
            "verified": self.verified,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "SourceInfo":
        return cls(
            source_type=SourceType(data.get("type", "unknown")),
            source_id=data.get("id", ""),
            source_name=data.get("name"),
            source_url=data.get("url"),
            source_path=data.get("path"),
            source_domain=data.get("domain"),
            verified=data.get("verified", False),
        )


@dataclass
class ModificationRecord:
    """Record of a modification to memory entry."""
    timestamp: str
    action: str  # "create", "update", "sanitize", "review", "flag"
    actor: str   # Who/what made the change
    reason: Optional[str] = None
    changes: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MemoryProvenance:
    """
    Complete provenance metadata for a memory entry.
    
    Tracks the full chain of custody from creation to present.
    """
    # Unique identifiers
    entry_id: str
    session_id: str
    
    # Timing
    created_at: str
    updated_at: str
    expires_at: Optional[str] = None
    
    # Source information
    source: SourceInfo = field(default_factory=lambda: SourceInfo(
        source_type=SourceType.UNKNOWN,
        source_id="unknown"
    ))
    
    # Trust assessment
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    trust_score: int = 20
    trust_factors: List[str] = field(default_factory=list)
    
    # Content integrity
    content_hash: str = ""
    original_content_hash: str = ""
    was_sanitized: bool = False
    sanitization_details: Optional[Dict] = None
    
    # Analysis results
    risk_score: int = 0
    threat_types: List[str] = field(default_factory=list)
    
    # Chain of custody
    modification_history: List[ModificationRecord] = field(default_factory=list)
    
    # Flags
    flagged_for_review: bool = False
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None
    
    # Additional metadata
    tags: List[str] = field(default_factory=list)
    custom_metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return {
            "entry_id": self.entry_id,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "source": self.source.to_dict(),
            "trust_level": self.trust_level.value,
            "trust_score": self.trust_score,
            "trust_factors": self.trust_factors,
            "content_hash": self.content_hash,
            "original_content_hash": self.original_content_hash,
            "was_sanitized": self.was_sanitized,
            "sanitization_details": self.sanitization_details,
            "risk_score": self.risk_score,
            "threat_types": self.threat_types,
            "modification_history": [m.to_dict() for m in self.modification_history],
            "flagged_for_review": self.flagged_for_review,
            "reviewed_by": self.reviewed_by,
            "review_notes": self.review_notes,
            "tags": self.tags,
            "custom_metadata": self.custom_metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "MemoryProvenance":
        """Create from dictionary."""
        history = [
            ModificationRecord(**m) 
            for m in data.get("modification_history", [])
        ]
        
        return cls(
            entry_id=data.get("entry_id", ""),
            session_id=data.get("session_id", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            expires_at=data.get("expires_at"),
            source=SourceInfo.from_dict(data.get("source", {})),
            trust_level=TrustLevel(data.get("trust_level", "untrusted")),
            trust_score=data.get("trust_score", 20),
            trust_factors=data.get("trust_factors", []),
            content_hash=data.get("content_hash", ""),
            original_content_hash=data.get("original_content_hash", ""),
            was_sanitized=data.get("was_sanitized", False),
            sanitization_details=data.get("sanitization_details"),
            risk_score=data.get("risk_score", 0),
            threat_types=data.get("threat_types", []),
            modification_history=history,
            flagged_for_review=data.get("flagged_for_review", False),
            reviewed_by=data.get("reviewed_by"),
            review_notes=data.get("review_notes"),
            tags=data.get("tags", []),
            custom_metadata=data.get("custom_metadata", {}),
        )
    
    def add_modification(
        self,
        action: str,
        actor: str,
        reason: Optional[str] = None,
        changes: Optional[Dict] = None
    ) -> None:
        """Record a modification."""
        record = ModificationRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            actor=actor,
            reason=reason,
            changes=changes,
        )
        self.modification_history.append(record)
        self.updated_at = record.timestamp


@dataclass
class TrackedMemoryEntry:
    """Memory entry with full provenance tracking."""
    content: str
    provenance: MemoryProvenance
    
    def to_dict(self) -> Dict:
        return {
            "content": self.content,
            "provenance": self.provenance.to_dict(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "TrackedMemoryEntry":
        return cls(
            content=data.get("content", ""),
            provenance=MemoryProvenance.from_dict(data.get("provenance", {})),
        )


class ProvenanceTracker:
    """
    Provenance tracking system for agent memory.
    
    Provides comprehensive metadata tracking, trust scoring,
    and forensic analysis capabilities.
    
    Example:
        tracker = ProvenanceTracker(session_id="session_123")
        
        # Track a new memory entry
        entry = tracker.track(
            content="User prefers dark mode",
            source_type=SourceType.USER_INPUT,
            source_id="user_msg_456"
        )
        
        # Entry now has full provenance
        print(entry.provenance.trust_score)  # 70
        print(entry.provenance.content_hash)  # "a1b2c3..."
        
        # Record modification
        entry.provenance.add_modification(
            action="review",
            actor="security_team",
            reason="Routine audit"
        )
    """
    
    def __init__(
        self,
        session_id: Optional[str] = None,
        default_trust_level: TrustLevel = TrustLevel.EXTERNAL,
        trusted_domains: Optional[List[str]] = None,
        trusted_sources: Optional[List[str]] = None,
        storage_path: Optional[str] = None,
    ):
        """
        Initialize provenance tracker.
        
        Args:
            session_id: Current session identifier
            default_trust_level: Default trust for unknown sources
            trusted_domains: List of trusted domains
            trusted_sources: List of trusted source IDs
            storage_path: Path to store provenance data
        """
        self.session_id = session_id or str(uuid.uuid4())
        self.default_trust_level = default_trust_level
        self.trusted_domains = set(trusted_domains or [])
        self.trusted_sources = set(trusted_sources or [])
        self.storage_path = Path(storage_path) if storage_path else None
        
        # In-memory registry
        self._entries: Dict[str, TrackedMemoryEntry] = {}
        
        # Audit log
        self._audit_log: List[Dict] = []
    
    def _generate_entry_id(self) -> str:
        """Generate unique entry ID."""
        return f"mem_{uuid.uuid4().hex[:16]}"
    
    def _compute_hash(self, content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _get_timestamp(self) -> str:
        """Get current UTC timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()
    
    def _determine_trust_level(
        self,
        source: SourceInfo
    ) -> TrustLevel:
        """Determine trust level based on source."""
        # Check if source is explicitly trusted
        if source.source_id in self.trusted_sources:
            return TrustLevel.TRUSTED
        
        # Check domain trust
        if source.source_domain and source.source_domain in self.trusted_domains:
            return TrustLevel.TRUSTED
        
        # Check verification
        if source.verified:
            return TrustLevel.VERIFIED
        
        # Use default for source type
        return SOURCE_TYPE_TRUST.get(source.source_type, self.default_trust_level)
    
    def _calculate_trust_factors(
        self,
        source: SourceInfo,
        trust_level: TrustLevel
    ) -> List[str]:
        """Calculate factors contributing to trust score."""
        factors = []
        
        if source.verified:
            factors.append("+verified_source")
        
        if source.source_id in self.trusted_sources:
            factors.append("+trusted_source_id")
        
        if source.source_domain in self.trusted_domains:
            factors.append("+trusted_domain")
        
        if source.source_type == SourceType.SYSTEM:
            factors.append("+system_generated")
        
        if source.source_type == SourceType.WEBPAGE:
            factors.append("-external_webpage")
        
        if source.source_type == SourceType.UNKNOWN:
            factors.append("-unknown_source")
        
        return factors
    
    def track(
        self,
        content: str,
        source_type: SourceType = SourceType.UNKNOWN,
        source_id: Optional[str] = None,
        source_name: Optional[str] = None,
        source_url: Optional[str] = None,
        source_path: Optional[str] = None,
        source_domain: Optional[str] = None,
        verified: bool = False,
        risk_score: int = 0,
        threat_types: Optional[List[str]] = None,
        was_sanitized: bool = False,
        sanitization_details: Optional[Dict] = None,
        original_content: Optional[str] = None,
        tags: Optional[List[str]] = None,
        custom_metadata: Optional[Dict] = None,
        expires_in_days: Optional[int] = None,
    ) -> TrackedMemoryEntry:
        """
        Create a tracked memory entry with full provenance.
        
        Args:
            content: Memory content
            source_type: Type of source
            source_id: Unique source identifier
            source_name: Human-readable source name
            source_url: Source URL if applicable
            source_path: Source file path if applicable
            source_domain: Source domain for web content
            verified: Whether source is verified
            risk_score: Analyzed risk score
            threat_types: Detected threat types
            was_sanitized: Whether content was sanitized
            sanitization_details: Details of sanitization
            original_content: Original content before sanitization
            tags: Optional tags
            custom_metadata: Additional metadata
            expires_in_days: Auto-expire after days
            
        Returns:
            TrackedMemoryEntry with full provenance
        """
        now = self._get_timestamp()
        entry_id = self._generate_entry_id()
        
        # Create source info
        source = SourceInfo(
            source_type=source_type,
            source_id=source_id or str(uuid.uuid4()),
            source_name=source_name,
            source_url=source_url,
            source_path=source_path,
            source_domain=source_domain,
            verified=verified,
        )
        
        # Determine trust
        trust_level = self._determine_trust_level(source)
        trust_score = TRUST_SCORES[trust_level]
        trust_factors = self._calculate_trust_factors(source, trust_level)
        
        # Compute hashes
        content_hash = self._compute_hash(content)
        original_hash = self._compute_hash(original_content) if original_content else content_hash
        
        # Calculate expiry
        expires_at = None
        if expires_in_days:
            from datetime import timedelta
            expires_at = (
                datetime.now(timezone.utc) + timedelta(days=expires_in_days)
            ).isoformat()
        
        # Create provenance
        provenance = MemoryProvenance(
            entry_id=entry_id,
            session_id=self.session_id,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            source=source,
            trust_level=trust_level,
            trust_score=trust_score,
            trust_factors=trust_factors,
            content_hash=content_hash,
            original_content_hash=original_hash,
            was_sanitized=was_sanitized,
            sanitization_details=sanitization_details,
            risk_score=risk_score,
            threat_types=threat_types or [],
            modification_history=[
                ModificationRecord(
                    timestamp=now,
                    action="create",
                    actor="memgar",
                    reason="Initial creation",
                )
            ],
            tags=tags or [],
            custom_metadata=custom_metadata or {},
        )
        
        # Create entry
        entry = TrackedMemoryEntry(content=content, provenance=provenance)
        
        # Store in registry
        self._entries[entry_id] = entry
        
        # Log
        self._audit_log.append({
            "timestamp": now,
            "action": "track",
            "entry_id": entry_id,
            "source_type": source_type.value,
            "trust_score": trust_score,
        })
        
        return entry
    
    def update_content(
        self,
        entry_id: str,
        new_content: str,
        actor: str,
        reason: str,
    ) -> Optional[TrackedMemoryEntry]:
        """Update content of existing entry."""
        if entry_id not in self._entries:
            return None
        
        entry = self._entries[entry_id]
        old_hash = entry.provenance.content_hash
        new_hash = self._compute_hash(new_content)
        
        entry.content = new_content
        entry.provenance.content_hash = new_hash
        entry.provenance.add_modification(
            action="update",
            actor=actor,
            reason=reason,
            changes={"old_hash": old_hash, "new_hash": new_hash},
        )
        
        return entry
    
    def flag_for_review(
        self,
        entry_id: str,
        reason: str,
        actor: str = "memgar",
    ) -> bool:
        """Flag entry for human review."""
        if entry_id not in self._entries:
            return False
        
        entry = self._entries[entry_id]
        entry.provenance.flagged_for_review = True
        entry.provenance.add_modification(
            action="flag",
            actor=actor,
            reason=reason,
        )
        
        return True
    
    def mark_reviewed(
        self,
        entry_id: str,
        reviewer: str,
        notes: str,
        approved: bool = True,
    ) -> bool:
        """Mark entry as reviewed."""
        if entry_id not in self._entries:
            return False
        
        entry = self._entries[entry_id]
        entry.provenance.flagged_for_review = False
        entry.provenance.reviewed_by = reviewer
        entry.provenance.review_notes = notes
        entry.provenance.add_modification(
            action="review",
            actor=reviewer,
            reason=f"Reviewed: {'approved' if approved else 'rejected'}",
            changes={"approved": approved},
        )
        
        return True
    
    def get_entry(self, entry_id: str) -> Optional[TrackedMemoryEntry]:
        """Get entry by ID."""
        return self._entries.get(entry_id)
    
    def get_all_entries(self) -> List[TrackedMemoryEntry]:
        """Get all tracked entries."""
        return list(self._entries.values())
    
    def get_entries_by_source(
        self,
        source_type: Optional[SourceType] = None,
        source_id: Optional[str] = None,
    ) -> List[TrackedMemoryEntry]:
        """Get entries filtered by source."""
        results = []
        for entry in self._entries.values():
            if source_type and entry.provenance.source.source_type != source_type:
                continue
            if source_id and entry.provenance.source.source_id != source_id:
                continue
            results.append(entry)
        return results
    
    def get_entries_by_trust(
        self,
        min_trust_score: int = 0,
        max_trust_score: int = 100,
    ) -> List[TrackedMemoryEntry]:
        """Get entries filtered by trust score."""
        return [
            entry for entry in self._entries.values()
            if min_trust_score <= entry.provenance.trust_score <= max_trust_score
        ]
    
    def get_flagged_entries(self) -> List[TrackedMemoryEntry]:
        """Get all entries flagged for review."""
        return [
            entry for entry in self._entries.values()
            if entry.provenance.flagged_for_review
        ]
    
    def get_entries_by_session(
        self,
        session_id: str
    ) -> List[TrackedMemoryEntry]:
        """Get entries from specific session."""
        return [
            entry for entry in self._entries.values()
            if entry.provenance.session_id == session_id
        ]
    
    def verify_integrity(self, entry_id: str) -> Dict:
        """Verify content integrity of entry."""
        if entry_id not in self._entries:
            return {"valid": False, "error": "Entry not found"}
        
        entry = self._entries[entry_id]
        current_hash = self._compute_hash(entry.content)
        stored_hash = entry.provenance.content_hash
        
        return {
            "valid": current_hash == stored_hash,
            "current_hash": current_hash,
            "stored_hash": stored_hash,
            "was_modified": current_hash != stored_hash,
        }
    
    def get_chain_of_custody(
        self,
        entry_id: str
    ) -> Optional[List[Dict]]:
        """Get full chain of custody for entry."""
        if entry_id not in self._entries:
            return None
        
        entry = self._entries[entry_id]
        return [m.to_dict() for m in entry.provenance.modification_history]
    
    def export_provenance(self, entry_id: str) -> Optional[Dict]:
        """Export full provenance for entry."""
        if entry_id not in self._entries:
            return None
        return self._entries[entry_id].provenance.to_dict()
    
    def export_all(self) -> Dict:
        """Export all entries with provenance."""
        return {
            "session_id": self.session_id,
            "exported_at": self._get_timestamp(),
            "entry_count": len(self._entries),
            "entries": {
                entry_id: entry.to_dict()
                for entry_id, entry in self._entries.items()
            },
        }
    
    def save_to_file(self, path: Optional[str] = None) -> str:
        """Save all provenance data to file."""
        file_path = Path(path) if path else self.storage_path
        if not file_path:
            file_path = Path(f"provenance_{self.session_id}.json")
        
        data = self.export_all()
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return str(file_path)
    
    def load_from_file(self, path: str) -> int:
        """Load provenance data from file."""
        with open(path) as f:
            data = json.load(f)
        
        entries = data.get("entries", {})
        for entry_id, entry_data in entries.items():
            entry = TrackedMemoryEntry.from_dict(entry_data)
            self._entries[entry_id] = entry
        
        return len(entries)
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log."""
        return self._audit_log.copy()
    
    def get_statistics(self) -> Dict:
        """Get statistics about tracked entries."""
        if not self._entries:
            return {
                "total_entries": 0,
                "by_source_type": {},
                "by_trust_level": {},
                "flagged_count": 0,
                "sanitized_count": 0,
            }
        
        by_source = {}
        by_trust = {}
        flagged = 0
        sanitized = 0
        
        for entry in self._entries.values():
            # Count by source type
            st = entry.provenance.source.source_type.value
            by_source[st] = by_source.get(st, 0) + 1
            
            # Count by trust level
            tl = entry.provenance.trust_level.value
            by_trust[tl] = by_trust.get(tl, 0) + 1
            
            # Count flags
            if entry.provenance.flagged_for_review:
                flagged += 1
            
            # Count sanitized
            if entry.provenance.was_sanitized:
                sanitized += 1
        
        return {
            "total_entries": len(self._entries),
            "by_source_type": by_source,
            "by_trust_level": by_trust,
            "flagged_count": flagged,
            "sanitized_count": sanitized,
            "avg_trust_score": sum(
                e.provenance.trust_score for e in self._entries.values()
            ) / len(self._entries),
        }


# =============================================================================
# FORENSIC ANALYSIS
# =============================================================================

class ForensicAnalyzer:
    """
    Forensic analysis tools for investigating memory poisoning incidents.
    """
    
    def __init__(self, tracker: ProvenanceTracker):
        self.tracker = tracker
    
    def find_suspicious_entries(
        self,
        time_range: Optional[tuple] = None,
        risk_threshold: int = 50,
    ) -> List[TrackedMemoryEntry]:
        """Find entries with suspicious characteristics."""
        suspicious = []
        
        for entry in self.tracker.get_all_entries():
            prov = entry.provenance
            
            # Check risk score
            if prov.risk_score >= risk_threshold:
                suspicious.append(entry)
                continue
            
            # Check trust level
            if prov.trust_level in [TrustLevel.UNTRUSTED, TrustLevel.MALICIOUS]:
                suspicious.append(entry)
                continue
            
            # Check if sanitized
            if prov.was_sanitized:
                suspicious.append(entry)
                continue
        
        return suspicious
    
    def trace_source_impact(
        self,
        source_id: str
    ) -> Dict:
        """Trace all entries from a specific source."""
        entries = self.tracker.get_entries_by_source(source_id=source_id)
        
        return {
            "source_id": source_id,
            "entry_count": len(entries),
            "entries": [e.provenance.entry_id for e in entries],
            "total_risk": sum(e.provenance.risk_score for e in entries),
            "sanitized_count": sum(
                1 for e in entries if e.provenance.was_sanitized
            ),
            "threat_types": list(set(
                t for e in entries for t in e.provenance.threat_types
            )),
        }
    
    def generate_incident_report(
        self,
        entry_ids: List[str]
    ) -> Dict:
        """Generate incident report for specified entries."""
        entries = [
            self.tracker.get_entry(eid)
            for eid in entry_ids
            if self.tracker.get_entry(eid)
        ]
        
        if not entries:
            return {"error": "No entries found"}
        
        return {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(entries),
            "entries": [
                {
                    "entry_id": e.provenance.entry_id,
                    "created_at": e.provenance.created_at,
                    "source": e.provenance.source.to_dict(),
                    "trust_score": e.provenance.trust_score,
                    "risk_score": e.provenance.risk_score,
                    "threat_types": e.provenance.threat_types,
                    "was_sanitized": e.provenance.was_sanitized,
                    "chain_of_custody": [
                        m.to_dict() for m in e.provenance.modification_history
                    ],
                    "content_preview": e.content[:100] + "..."
                    if len(e.content) > 100 else e.content,
                }
                for e in entries
            ],
            "summary": {
                "unique_sources": len(set(
                    e.provenance.source.source_id for e in entries
                )),
                "avg_risk": sum(e.provenance.risk_score for e in entries) / len(entries),
                "threat_types": list(set(
                    t for e in entries for t in e.provenance.threat_types
                )),
            },
        }
    
    def rollback_to_snapshot(
        self,
        snapshot_data: Dict
    ) -> int:
        """Rollback to a previous snapshot state."""
        # Clear current entries
        self.tracker._entries.clear()
        
        # Load snapshot
        count = 0
        for entry_id, entry_data in snapshot_data.get("entries", {}).items():
            entry = TrackedMemoryEntry.from_dict(entry_data)
            self.tracker._entries[entry_id] = entry
            count += 1
        
        return count


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_tracked_memory(
    content: str,
    source_type: str = "user_input",
    session_id: Optional[str] = None,
) -> TrackedMemoryEntry:
    """Quick way to create a tracked memory entry."""
    tracker = ProvenanceTracker(session_id=session_id)
    return tracker.track(
        content=content,
        source_type=SourceType(source_type),
    )


def verify_memory_integrity(entry: TrackedMemoryEntry) -> bool:
    """Verify that memory content hasn't been tampered with."""
    current_hash = hashlib.sha256(entry.content.encode()).hexdigest()
    return current_hash == entry.provenance.content_hash
