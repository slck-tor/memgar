"""Data models for the threat-intelligence feed."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from memgar.models import Severity, Threat, ThreatCategory


@dataclass
class FeedSignature:
    signature_b64: str
    algorithm: str = "ed25519"
    signed_at: str = ""
    signer: str = "memgar-maintainer"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> FeedSignature:
        return cls(
            signature_b64=d.get("signature_b64", ""),
            algorithm=d.get("algorithm", "ed25519"),
            signed_at=d.get("signed_at", ""),
            signer=d.get("signer", "memgar-maintainer"),
        )


@dataclass
class FeedManifest:
    feed_version: str
    published_at: str
    min_memgar_version: str
    pattern_count: int
    bundle_sha256: str
    signature: FeedSignature

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> FeedManifest:
        sig_raw = d.get("signature", {})
        sig = FeedSignature.from_dict(sig_raw) if isinstance(sig_raw, dict) else FeedSignature(signature_b64="")
        return cls(
            feed_version=str(d.get("feed_version", "0.0.0")),
            published_at=str(d.get("published_at", "")),
            min_memgar_version=str(d.get("min_memgar_version", "0.0.0")),
            pattern_count=int(d.get("pattern_count", 0)),
            bundle_sha256=str(d.get("bundle_sha256", "")),
            signature=sig,
        )


@dataclass
class PatternBundle:
    manifest: FeedManifest
    patterns: List[Dict[str, Any]] = field(default_factory=list)

    def bundle_bytes(self) -> bytes:
        """Canonical serialisation of the patterns list used for Ed25519 verification."""
        return json.dumps(self.patterns, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def bundle_sha256(self) -> str:
        return hashlib.sha256(self.bundle_bytes()).hexdigest()

    # Hard limits to prevent DoS via malicious feed
    _MAX_THREATS = 10_000
    _MAX_PATTERNS_PER_THREAT = 500
    _MAX_KEYWORDS_PER_THREAT = 200
    _MAX_PATTERN_LEN = 2_000
    _MAX_ID_LEN = 64
    _MAX_NAME_LEN = 256

    def to_threat_objects(self) -> List[Threat]:
        if len(self.patterns) > self._MAX_THREATS:
            raise ValueError(
                f"Feed contains {len(self.patterns)} threats, exceeds limit of {self._MAX_THREATS}"
            )
        out: List[Threat] = []
        for p in self.patterns:
            try:
                if not isinstance(p, dict):
                    continue

                threat_id = str(p.get("id", ""))[:self._MAX_ID_LEN]
                threat_name = str(p.get("name", ""))[:self._MAX_NAME_LEN]

                raw_patterns = list(p.get("patterns", []))[:self._MAX_PATTERNS_PER_THREAT]
                # Truncate overly long individual patterns (guards against ReDoS)
                raw_patterns = [str(pat)[:self._MAX_PATTERN_LEN] for pat in raw_patterns]

                raw_keywords = list(p.get("keywords", []))[:self._MAX_KEYWORDS_PER_THREAT]

                cat_raw = str(p.get("category", "anomaly")).lower()
                sev_raw = str(p.get("severity", "medium")).lower()
                try:
                    category = ThreatCategory(cat_raw)
                except ValueError:
                    category = ThreatCategory.ANOMALY
                try:
                    severity = Severity(sev_raw)
                except ValueError:
                    severity = Severity.MEDIUM

                out.append(
                    Threat(
                        id=threat_id,
                        name=threat_name,
                        description=str(p.get("description", ""))[:1000],
                        category=category,
                        severity=severity,
                        patterns=raw_patterns,
                        keywords=raw_keywords,
                        examples=list(p.get("examples", []))[:50],
                        mitre_attack=p.get("mitre_attack"),
                    )
                )
            except Exception:
                continue
        return out
