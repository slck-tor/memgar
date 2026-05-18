"""Opt-in cloud client SDK — hashed-only telemetry + reputation cache.

`CloudClient` is the bridge between a self-hosted memgar `Analyzer` and a
running cloud control plane. It is **off by default**; the user must
explicitly construct it (or set `MEMGAR_CLOUD_TELEMETRY=1` for env-based
opt-in) before any data leaves the process.

What gets sent:
  - SHA-256 hash of the analysed content (`signal_hash`)
  - SHA-256 hash of the source_id (`source_id_hash`)
  - Pattern IDs that fired (these are public; not hashed)
  - Risk score (0-100, integer)
  - Decision verdict (allow/sanitize/quarantine/block)
  - Optional sector tag from config (not user-identifying)

What does NOT get sent: raw content, raw source_id, agent_id, IP, or any
identifying metadata. The threat model is "many honest tenants share
hashes; the aggregator learns *which hashes are seen by multiple
tenants*". A malicious server cannot reverse the hashes back to content.
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .config import MemgarCloudConfig

logger = logging.getLogger("memgar.cloud.client")


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class TelemetryEvent:
    """A single telemetry datapoint (already anonymised on the client side)."""

    signal_hash: str
    source_id_hash: str
    pattern_id: str
    risk_score: int
    decision: str
    sector: Optional[str] = None
    ts: float = field(default_factory=time.time)


class CloudClient:
    """Thin client that batches telemetry and caches reputation lookups.

    Usage:
        client = CloudClient.from_env()
        if client.is_enabled:
            client.report(analysis_result, source_id="rag-doc-42")
            rep = client.reputation("rag-doc-42")
    """

    def __init__(self, config: Optional[MemgarCloudConfig] = None) -> None:
        self.config = config or MemgarCloudConfig()
        self._reputation_cache: Dict[str, tuple[float, float]] = {}  # hash → (ts, score)
        self._send_queue: "queue.Queue[TelemetryEvent]" = queue.Queue(maxsize=10_000)
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None

    # ─── Factories ───────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "CloudClient":
        return cls(MemgarCloudConfig())

    # ─── Public API ──────────────────────────────────────────────────

    @property
    def is_enabled(self) -> bool:
        return (
            self.config.telemetry_enabled
            and self.config.configured_for_client_use
        )

    def start(self) -> None:
        """Begin background event-flushing thread (no-op if disabled)."""
        if not self.is_enabled or self._worker is not None:
            return
        self._worker = threading.Thread(
            target=self._drain_loop, name="memgar-cloud-client", daemon=True,
        )
        self._worker.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout)

    def report(
        self,
        analysis_result: Any,
        *,
        source_id: Optional[str] = None,
        content: str = "",
        sector: Optional[str] = None,
    ) -> None:
        """Enqueue a telemetry event derived from an `AnalysisResult`.

        Silently drops if telemetry is disabled or the queue is full.
        Never raises into the analyser's hot path.
        """
        if not self.is_enabled:
            return
        decision = getattr(analysis_result.decision, "value", str(analysis_result.decision))
        risk = int(getattr(analysis_result, "risk_score", 0))
        threat_ids = sorted({
            t.threat.id for t in getattr(analysis_result, "threats", [])
        })
        sig = _sha256(content)
        src = _sha256(source_id or "")
        for pid in (threat_ids or ["__no_threat__"]):
            event = TelemetryEvent(
                signal_hash=sig, source_id_hash=src, pattern_id=pid,
                risk_score=risk, decision=decision, sector=sector,
            )
            try:
                self._send_queue.put_nowait(event)
            except queue.Full:
                logger.debug("memgar cloud telemetry queue full — dropping event")
                return

    def reputation(self, source_id: str) -> float:
        """Look up reputation for `source_id`. Cached for `reputation_cache_ttl_seconds`.

        Returns 0.5 (neutral) on any failure — caller should treat this
        as "no signal" and fall back to local Layer 3 trust.
        """
        if not self.is_enabled:
            return 0.5
        h = _sha256(source_id)
        now = time.time()
        cached = self._reputation_cache.get(h)
        if cached and (now - cached[0]) < self.config.reputation_cache_ttl_seconds:
            return cached[1]
        try:
            score = self._http_reputation(h)
        except Exception as exc:  # noqa: BLE001
            logger.debug("reputation lookup failed for %s: %s", h[:12], exc)
            return 0.5
        self._reputation_cache[h] = (now, score)
        return score

    # ─── Internals ───────────────────────────────────────────────────

    def _http_post(self, path: str, payload: Any) -> Dict[str, Any]:
        url = f"{self.config.cloud_url.rstrip('/')}{path}"
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.config.request_timeout_seconds) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _http_get(self, path: str) -> Dict[str, Any]:
        url = f"{self.config.cloud_url.rstrip('/')}{path}"
        headers = {"Accept": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=self.config.request_timeout_seconds) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _http_reputation(self, source_id_hash: str) -> float:
        body = self._http_get(f"/v1/reputation/{source_id_hash}")
        return float(body.get("reputation", 0.5))

    def _drain_loop(self) -> None:
        batch: List[TelemetryEvent] = []
        deadline = time.time() + self.config.telemetry_interval_seconds
        while not self._stop.is_set():
            timeout = max(0.0, deadline - time.time())
            try:
                event = self._send_queue.get(timeout=timeout)
                batch.append(event)
            except queue.Empty:
                pass
            now = time.time()
            if batch and (now >= deadline or len(batch) >= 100):
                self._flush(batch)
                batch = []
                deadline = now + self.config.telemetry_interval_seconds
        if batch:
            self._flush(batch)

    def _flush(self, batch: List[TelemetryEvent]) -> None:
        try:
            self._http_post(
                "/v1/telemetry",
                {"events": [asdict(e) for e in batch]},
            )
            logger.debug("Flushed %d telemetry events", len(batch))
        except Exception as exc:  # noqa: BLE001
            logger.debug("telemetry flush failed: %s", exc)


__all__ = ["CloudClient", "TelemetryEvent"]
