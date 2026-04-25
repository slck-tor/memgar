"""
Dynamic threshold profiles for ML threat blocking.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
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

        self.block_threshold = _c(self.block_threshold)
        self.suspicious_threshold = _c(self.suspicious_threshold)
        self.malicious_threshold = _c(self.malicious_threshold)
        self.critical_threshold = _c(self.critical_threshold)
        return self


class ThresholdManager:
    """Resolves thresholds by profile or tenant."""

    def __init__(self, config_path: Optional[str] = None):
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

        profile = self._profiles.get(chosen_profile_name, self._profiles[fallback_profile]).clamp()
        if threshold_override is None:
            return profile.block_threshold, profile

        threshold = max(0.0, min(1.0, float(threshold_override)))
        return threshold, profile

