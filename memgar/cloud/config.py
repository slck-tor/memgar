"""Configuration for the memgar cloud control plane and client."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


def _bool_env(name: str, default: bool = False) -> bool:
    val = os.getenv(name, "").lower().strip()
    if val in {"1", "true", "yes", "on"}:
        return True
    if val in {"0", "false", "no", "off"}:
        return False
    return default


@dataclass
class MemgarCloudConfig:
    """Joint config for both server-side and client-side cloud usage.

    Server: instantiate without arguments to read MEMGAR_CLOUD_* env vars.
    Client: same, plus the user-facing `cloud_url` and `api_key`.

    Defaults are conservative — telemetry is OFF, no remote calls are made
    unless the operator explicitly opts in.
    """

    # ─── Client-side ─────────────────────────────────────────────────────
    cloud_url: str = field(
        default_factory=lambda: os.getenv("MEMGAR_CLOUD_URL", "https://api.memgar.com")
    )
    api_key: Optional[str] = field(
        default_factory=lambda: os.getenv("MEMGAR_CLOUD_API_KEY") or None
    )
    telemetry_enabled: bool = field(
        default_factory=lambda: _bool_env("MEMGAR_CLOUD_TELEMETRY", default=False)
    )
    telemetry_interval_seconds: int = field(
        default_factory=lambda: int(os.getenv("MEMGAR_CLOUD_TELEMETRY_INTERVAL", "60"))
    )
    reputation_cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("MEMGAR_CLOUD_REPUTATION_TTL", "300"))
    )
    request_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("MEMGAR_CLOUD_REQUEST_TIMEOUT", "5.0"))
    )

    # ─── Server-side ─────────────────────────────────────────────────────
    server_bind: str = field(
        default_factory=lambda: os.getenv("MEMGAR_CLOUD_BIND", "0.0.0.0:8000")
    )
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "MEMGAR_CLOUD_DATABASE_URL",
            "sqlite:///./memgar_cloud.sqlite3",
        )
    )
    feed_storage_url: str = field(
        default_factory=lambda: os.getenv(
            "MEMGAR_CLOUD_FEED_URL",
            "https://github.com/slcxtor/memgar/releases/latest/download/memgar-feed.json.gz",
        )
    )
    require_api_key: bool = field(
        default_factory=lambda: _bool_env("MEMGAR_CLOUD_REQUIRE_API_KEY", default=True)
    )
    allow_anonymous_telemetry: bool = field(
        default_factory=lambda: _bool_env("MEMGAR_CLOUD_ANON_TELEMETRY", default=False)
    )

    @property
    def configured_for_client_use(self) -> bool:
        """True when the client has enough config to make a live call."""
        return bool(self.cloud_url) and (
            self.api_key is not None or self.allow_anonymous_telemetry
        )

    def __repr__(self) -> str:
        masked_key = "***" if self.api_key else None
        return (
            f"MemgarCloudConfig(cloud_url={self.cloud_url!r}, "
            f"api_key={masked_key!r}, telemetry_enabled={self.telemetry_enabled})"
        )


__all__ = ["MemgarCloudConfig"]
