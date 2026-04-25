"""
Dynamic threshold profiles for ML threat blocking.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


@dataclass
class ThresholdProfile:
    """Threshold profile for decisioning."""

    name: str
    block_threshold: float
    suspicious_threshold: float = 0.30
    malicious_threshold: float = 0.50
    critical_threshold: float = 0.75

    def clamp(self) -> "ThresholdProfile":
        def _c(v: float) -> float:
            return max(0.0, min(1.0, float(v)))

        block = _c(self.block_threshold)
        suspicious = min(_c(self.suspicious_threshold), block)
        malicious = max(_c(self.malicious_threshold), block)
        critical = max(_c(self.critical_threshold), malicious)

        self.block_threshold = block
        self.suspicious_threshold = suspicious
        self.malicious_threshold = malicious
        self.critical_threshold = critical
        return self

    def to_dict(self) -> Dict[str, float]:
        """Serialize profile to plain dict for JSON persistence."""
        return asdict(self)


class ThresholdManager:
    """Resolves thresholds by profile or tenant."""

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path
        self._profiles: Dict[str, ThresholdProfile] = {
            # strict security posture: lower threshold => block more
            "strict": ThresholdProfile(
                name="strict",
                block_threshold=0.35,
                suspicious_threshold=0.20,
                malicious_threshold=0.40,
                critical_threshold=0.70,
            ),
            "balanced": ThresholdProfile(
                name="balanced",
                block_threshold=0.50,
                suspicious_threshold=0.30,
                malicious_threshold=0.50,
                critical_threshold=0.75,
            ),
            # lenient security posture: higher threshold => block less
            "lenient": ThresholdProfile(
                name="lenient",
                block_threshold=0.65,
                suspicious_threshold=0.35,
                malicious_threshold=0.60,
                critical_threshold=0.85,
            ),
        }
        self._tenant_profiles: Dict[str, str] = {}
        if config_path:
            self.load(config_path)

    def load(self, config_path: str) -> None:
        """Load profile/tenant overrides from JSON file."""
        path = Path(config_path)
        if not path.exists():
            return

        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)

        profiles = payload.get("profiles", {})
        for name, cfg in profiles.items():
            self._profiles[str(name)] = ThresholdProfile(
                name=str(name),
                block_threshold=float(cfg.get("block_threshold", 0.5)),
                suspicious_threshold=float(cfg.get("suspicious_threshold", 0.3)),
                malicious_threshold=float(cfg.get("malicious_threshold", 0.5)),
                critical_threshold=float(cfg.get("critical_threshold", 0.75)),
            ).clamp()

        tenant_map = payload.get("tenant_profiles", {})
        for tenant_id, profile_name in tenant_map.items():
            self._tenant_profiles[str(tenant_id)] = str(profile_name)

    def register_profile(self, profile: ThresholdProfile) -> None:
        self._profiles[profile.name] = profile.clamp()

    def set_tenant_profile(self, tenant_id: str, profile_name: str) -> None:
        self._tenant_profiles[str(tenant_id)] = str(profile_name)

    def get_profile(self, profile_name: str, fallback_profile: str = "balanced") -> ThresholdProfile:
        """Return a defensive copy of the requested profile."""
        base = self._profiles.get(profile_name, self._profiles[fallback_profile]).clamp()
        return ThresholdProfile(
            name=base.name,
            block_threshold=base.block_threshold,
            suspicious_threshold=base.suspicious_threshold,
            malicious_threshold=base.malicious_threshold,
            critical_threshold=base.critical_threshold,
        )

    def to_dict(self) -> Dict[str, Dict]:
        """Serialize full threshold configuration."""
        return {
            "profiles": {
                name: profile.to_dict()
                for name, profile in self._profiles.items()
            },
            "tenant_profiles": dict(self._tenant_profiles),
        }

    def save(self, config_path: Optional[str] = None) -> Optional[str]:
        """Persist profiles + tenant mappings to JSON."""
        path_str = config_path or self._config_path
        if not path_str:
            return None

        path = Path(path_str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        self._config_path = str(path)
        return str(path)

    def adjust_profile(
        self,
        profile_name: str,
        block_delta: float,
        fallback_profile: str = "balanced",
        min_block: float = 0.20,
        max_block: float = 0.90,
    ) -> ThresholdProfile:
        """
        Shift an existing profile by `block_delta`.

        Negative delta => stricter (lower blocking threshold).
        Positive delta => more lenient (higher blocking threshold).
        """
        current = self.get_profile(profile_name, fallback_profile=fallback_profile)
        delta = float(block_delta)

        min_block = max(0.0, min(1.0, float(min_block)))
        max_block = max(min_block, min(1.0, float(max_block)))

        new_block = max(min_block, min(max_block, current.block_threshold + delta))
        applied_delta = new_block - current.block_threshold

        updated = ThresholdProfile(
            name=current.name,
            block_threshold=new_block,
            suspicious_threshold=current.suspicious_threshold + applied_delta,
            malicious_threshold=current.malicious_threshold + applied_delta,
            critical_threshold=current.critical_threshold + applied_delta,
        ).clamp()
        self.register_profile(updated)
        return updated

    def resolve(
        self,
        tenant_id: Optional[str] = None,
        profile_name: Optional[str] = None,
        threshold_override: Optional[float] = None,
        fallback_profile: str = "balanced",
    ) -> Tuple[float, ThresholdProfile]:
        """
        Resolve final threshold and profile in priority order:
        1) explicit threshold override
        2) explicit profile name
        3) tenant->profile mapping
        4) fallback profile
        """
        chosen_profile_name = profile_name
        if chosen_profile_name is None and tenant_id is not None:
            chosen_profile_name = self._tenant_profiles.get(str(tenant_id))
        if chosen_profile_name is None:
            chosen_profile_name = fallback_profile

        profile = self.get_profile(chosen_profile_name, fallback_profile=fallback_profile).clamp()
        if threshold_override is None:
            return profile.block_threshold, profile

        threshold = max(0.0, min(1.0, float(threshold_override)))
        return threshold, profile
