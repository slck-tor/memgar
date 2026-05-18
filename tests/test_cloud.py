"""Tests for memgar.cloud — auth, aggregator, client, server."""

from __future__ import annotations

import hashlib
import time

import pytest

from memgar.cloud.aggregator import SignalAggregator, TelemetryRecord
from memgar.cloud.auth import (
    ApiKeyScope, InMemoryTenantStore, InsufficientScope, InvalidApiKey,
    SqliteTenantStore, Tenant, TenantDisabled, generate_raw_key, issue_api_key,
    verify_api_key,
)
from memgar.cloud.client import CloudClient, TelemetryEvent
from memgar.cloud.config import MemgarCloudConfig


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ─── Auth ──────────────────────────────────────────────────────────────


class TestAuthInMemory:
    def test_issue_and_verify_round_trip(self):
        store = InMemoryTenantStore()
        store.upsert_tenant(Tenant(id="t1", name="acme", created_at=time.time()))
        _, raw = issue_api_key(
            store, tenant_id="t1", name="default",
            scopes=[ApiKeyScope.TELEMETRY_WRITE],
        )
        key, tenant = verify_api_key(store, raw_key=raw, required_scope=ApiKeyScope.TELEMETRY_WRITE)
        assert tenant.id == "t1"
        assert ApiKeyScope.TELEMETRY_WRITE in key.scopes

    def test_unknown_key_rejected(self):
        store = InMemoryTenantStore()
        with pytest.raises(InvalidApiKey):
            verify_api_key(store, raw_key=generate_raw_key())

    def test_malformed_key_rejected(self):
        store = InMemoryTenantStore()
        with pytest.raises(InvalidApiKey):
            verify_api_key(store, raw_key="not-a-valid-prefix")

    def test_insufficient_scope_blocked(self):
        store = InMemoryTenantStore()
        store.upsert_tenant(Tenant(id="t1", name="x", created_at=time.time()))
        _, raw = issue_api_key(
            store, tenant_id="t1", name="telemetry-only",
            scopes=[ApiKeyScope.TELEMETRY_WRITE],
        )
        with pytest.raises(InsufficientScope):
            verify_api_key(store, raw_key=raw, required_scope=ApiKeyScope.ADMIN)

    def test_revoked_key_rejected(self):
        store = InMemoryTenantStore()
        store.upsert_tenant(Tenant(id="t1", name="x", created_at=time.time()))
        record, raw = issue_api_key(
            store, tenant_id="t1", name="rev", scopes=[ApiKeyScope.FEED_READ],
        )
        store.revoke_api_key(record.id)
        with pytest.raises(InvalidApiKey):
            verify_api_key(store, raw_key=raw)

    def test_disabled_tenant_blocks_keys(self):
        store = InMemoryTenantStore()
        store.upsert_tenant(Tenant(id="t1", name="x", created_at=time.time()))
        _, raw = issue_api_key(
            store, tenant_id="t1", name="x", scopes=[ApiKeyScope.FEED_READ],
        )
        store.disable_tenant("t1")
        with pytest.raises(TenantDisabled):
            verify_api_key(store, raw_key=raw)


class TestAuthSqlite:
    def test_persistence_round_trip(self, tmp_path):
        db = tmp_path / "tenants.db"
        store1 = SqliteTenantStore(str(db))
        store1.upsert_tenant(Tenant(id="t1", name="persistent", created_at=time.time()))
        _, raw = issue_api_key(
            store1, tenant_id="t1", name="default",
            scopes=[ApiKeyScope.REPUTATION_READ],
        )

        store2 = SqliteTenantStore(str(db))
        key, tenant = verify_api_key(
            store2, raw_key=raw, required_scope=ApiKeyScope.REPUTATION_READ,
        )
        assert tenant.id == "t1"
        assert key.name == "default"


# ─── Aggregator ────────────────────────────────────────────────────────


def _record(tenant="t1", source="evil-doc", pattern="XSESS-001",
            risk=80, decision="block", sector="legal", ts=None):
    return TelemetryRecord(
        tenant_id=tenant,
        received_at=ts or time.time(),
        signal_hash=_sha256("body"),
        source_id_hash=_sha256(source),
        pattern_id=pattern,
        risk_score=risk,
        decision=decision,
        sector=sector,
    )


class TestAggregator:
    def test_ingest_updates_source_stats(self):
        agg = SignalAggregator()
        agg.ingest(_record(risk=70, decision="quarantine"))
        agg.ingest(_record(risk=90, decision="block"))
        card = agg.source_card(_sha256("evil-doc"))
        assert card is not None
        assert card["total_hits"] == 2
        assert card["mean_risk"] == 80
        assert card["block_rate"] == 1.0
        assert card["tenant_count"] == 1

    def test_neutral_reputation_when_insufficient_data(self):
        agg = SignalAggregator(min_observations_for_reputation=5)
        agg.ingest(_record())
        assert agg.reputation(_sha256("evil-doc")) == 0.5

    def test_high_risk_source_gets_low_reputation(self):
        agg = SignalAggregator(min_observations_for_reputation=3)
        for _ in range(10):
            agg.ingest(_record(risk=95, decision="block"))
        score = agg.reputation(_sha256("evil-doc"))
        assert score < 0.3

    def test_low_risk_source_gets_high_reputation(self):
        agg = SignalAggregator(min_observations_for_reputation=3)
        for _ in range(10):
            agg.ingest(_record(risk=5, decision="allow"))
        score = agg.reputation(_sha256("evil-doc"))
        assert score > 0.7

    def test_cross_tenant_penalty_compounds(self):
        agg = SignalAggregator(min_observations_for_reputation=3)
        # 10 hits, all from the same tenant
        for _ in range(10):
            agg.ingest(_record(tenant="t1", risk=50, decision="quarantine"))
        single_tenant_score = agg.reputation(_sha256("evil-doc"))

        agg2 = SignalAggregator(min_observations_for_reputation=3)
        # Same 10 hits but spread across 10 tenants
        for i in range(10):
            agg2.ingest(_record(tenant=f"t{i}", risk=50, decision="quarantine"))
        many_tenant_score = agg2.reputation(_sha256("evil-doc"))

        assert many_tenant_score < single_tenant_score, \
            "cross-tenant signal should compound suspicion"

    def test_sector_baseline_returns_per_thousand_frequency(self):
        agg = SignalAggregator()
        for _ in range(7):
            agg.ingest(_record(sector="legal", pattern="XSESS-001"))
        for _ in range(3):
            agg.ingest(_record(sector="legal", pattern="XSESS-002"))
        # 7 of 10 legal hits are XSESS-001 → 700 per 1000
        assert agg.sector_baseline("legal", "XSESS-001") == pytest.approx(700.0)

    def test_top_patterns_for_sector_sorted(self):
        agg = SignalAggregator()
        for _ in range(7):
            agg.ingest(_record(sector="legal", pattern="XSESS-001"))
        for _ in range(3):
            agg.ingest(_record(sector="legal", pattern="XSESS-002"))
        top = agg.top_patterns_for_sector("legal", n=2)
        assert top[0]["pattern_id"] == "XSESS-001"
        assert top[0]["hits"] == 7

    def test_summary_includes_event_count(self):
        agg = SignalAggregator()
        for _ in range(5):
            agg.ingest(_record())
        s = agg.summary()
        assert s["event_count"] == 5
        assert s["distinct_sources"] == 1


# ─── Client ────────────────────────────────────────────────────────────


class _FakeAnalysisResult:
    def __init__(self, risk=70, decision="block", threat_ids=None):
        from memgar.models import Decision
        self.risk_score = risk
        self.decision = Decision(decision)
        self.threats = []
        for tid in threat_ids or []:
            class _Th:
                def __init__(self, i): self.id = i
            class _M:
                def __init__(self, i): self.threat = _Th(i)
            self.threats.append(_M(tid))


class TestClient:
    def test_disabled_by_default(self):
        c = CloudClient(MemgarCloudConfig())  # telemetry off
        assert c.is_enabled is False

    def test_enabled_requires_api_key(self):
        cfg = MemgarCloudConfig(telemetry_enabled=True, api_key=None)
        assert CloudClient(cfg).is_enabled is False

    def test_enabled_when_key_and_flag_set(self):
        cfg = MemgarCloudConfig(telemetry_enabled=True, api_key="mck_test")
        assert CloudClient(cfg).is_enabled is True

    def test_report_is_noop_when_disabled(self):
        c = CloudClient(MemgarCloudConfig())
        c.report(_FakeAnalysisResult(threat_ids=["XSESS-001"]), source_id="x")
        # No exception, no enqueue — the queue stays empty
        assert c._send_queue.empty()

    def test_reputation_returns_neutral_when_disabled(self):
        c = CloudClient(MemgarCloudConfig())
        assert c.reputation("any-source") == 0.5

    def test_report_hashes_source_id(self):
        cfg = MemgarCloudConfig(telemetry_enabled=True, api_key="mck_test")
        c = CloudClient(cfg)
        c.report(
            _FakeAnalysisResult(threat_ids=["XSESS-001"]),
            source_id="rag-doc-42",
            content="sensitive content here",
        )
        ev = c._send_queue.get_nowait()
        assert ev.source_id_hash == _sha256("rag-doc-42")
        assert ev.signal_hash == _sha256("sensitive content here")
        # Raw content / source_id NEVER on the event
        for value in vars(ev).values():
            if isinstance(value, str):
                assert "rag-doc-42" not in value
                assert "sensitive" not in value

    def test_report_creates_event_per_threat_id(self):
        cfg = MemgarCloudConfig(telemetry_enabled=True, api_key="mck_test")
        c = CloudClient(cfg)
        c.report(
            _FakeAnalysisResult(threat_ids=["XSESS-001", "VECNN-002"]),
            source_id="x",
        )
        events = []
        while not c._send_queue.empty():
            events.append(c._send_queue.get_nowait())
        assert {e.pattern_id for e in events} == {"XSESS-001", "VECNN-002"}


# ─── Server (smoke test only — requires fastapi) ───────────────────────


@pytest.mark.skipif(
    not __import__("memgar.cloud.server").cloud.server.FASTAPI_AVAILABLE,
    reason="fastapi not installed",
)
class TestServerSmoke:
    def test_health_endpoint(self):
        from fastapi.testclient import TestClient
        from memgar.cloud.server import build_app
        client = TestClient(build_app())
        r = client.get("/v1/health")
        assert r.status_code == 200
        assert r.json()["service"] == "memgar-cloud"

    def test_telemetry_requires_auth(self):
        from fastapi.testclient import TestClient
        from memgar.cloud.server import build_app
        client = TestClient(build_app())
        r = client.post("/v1/telemetry", json={"events": []})
        assert r.status_code == 401

    def test_telemetry_ingest_with_valid_key(self):
        from fastapi.testclient import TestClient
        from memgar.cloud.server import build_app

        store = InMemoryTenantStore()
        store.upsert_tenant(Tenant(id="t1", name="x", created_at=time.time()))
        _, raw = issue_api_key(
            store, tenant_id="t1", name="x",
            scopes=[ApiKeyScope.TELEMETRY_WRITE],
        )
        agg = SignalAggregator()
        app = build_app(store=store, aggregator=agg)
        client = TestClient(app)
        r = client.post(
            "/v1/telemetry",
            json={"events": [{
                "signal_hash": _sha256("body"),
                "source_id_hash": _sha256("src"),
                "pattern_id": "XSESS-001",
                "risk_score": 80,
                "decision": "block",
                "sector": "legal",
                "ts": time.time(),
            }]},
            headers={"Authorization": f"Bearer {raw}"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["accepted"] == 1
        assert agg.summary()["event_count"] == 1
