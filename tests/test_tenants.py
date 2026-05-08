"""Tests for multi-tenant API key management (TenantStore)."""

from __future__ import annotations

import time
import tempfile
import os
import pytest

from memgar.tenants import TenantStore, PLAN_LIMITS, PLANS


@pytest.fixture
def store(tmp_path):
    return TenantStore(db_path=str(tmp_path / "tenants.db"))


# ---------------------------------------------------------------------------
# Tenant CRUD
# ---------------------------------------------------------------------------

class TestTenantCRUD:
    def test_create_tenant(self, store):
        t = store.create_tenant("Acme Corp", plan="starter")
        assert t.id
        assert t.name == "Acme Corp"
        assert t.plan == "starter"
        assert t.active is True
        assert t.rate_limit_rpm == PLAN_LIMITS["starter"]

    def test_get_tenant(self, store):
        t = store.create_tenant("Beta Ltd")
        fetched = store.get_tenant(t.id)
        assert fetched is not None
        assert fetched.id == t.id
        assert fetched.name == "Beta Ltd"

    def test_get_nonexistent_tenant(self, store):
        assert store.get_tenant("nope") is None

    def test_list_tenants_empty(self, store):
        assert store.list_tenants() == []

    def test_list_tenants(self, store):
        store.create_tenant("A", plan="free")
        store.create_tenant("B", plan="pro")
        tenants = store.list_tenants()
        assert len(tenants) == 2
        names = {t.name for t in tenants}
        assert names == {"A", "B"}

    def test_deactivate_tenant(self, store):
        t = store.create_tenant("Gone Corp")
        ok = store.deactivate_tenant(t.id)
        assert ok is True
        fetched = store.get_tenant(t.id)
        assert fetched.active is False

    def test_deactivate_nonexistent(self, store):
        assert store.deactivate_tenant("nope") is False

    def test_invalid_plan(self, store):
        with pytest.raises(ValueError, match="Unknown plan"):
            store.create_tenant("Bad Plan Corp", plan="galaxy_brain")

    @pytest.mark.parametrize("plan", PLANS)
    def test_all_plans_create(self, store, plan):
        t = store.create_tenant(f"Tenant-{plan}", plan=plan)
        assert t.rate_limit_rpm == PLAN_LIMITS[plan]


# ---------------------------------------------------------------------------
# API Key CRUD
# ---------------------------------------------------------------------------

class TestApiKeyCRUD:
    def test_create_key(self, store):
        t = store.create_tenant("KeyCo")
        k = store.create_key(t.id, name="production")
        assert k.key.startswith("sk-memgar-")
        assert k.tenant_id == t.id
        assert k.name == "production"
        assert k.active is True
        assert k.request_count == 0
        assert k.last_used_at is None

    def test_key_inherits_plan_rpm(self, store):
        t = store.create_tenant("Pro Corp", plan="pro")
        k = store.create_key(t.id)
        assert k.rate_limit_rpm == PLAN_LIMITS["pro"]

    def test_create_key_nonexistent_tenant(self, store):
        with pytest.raises(ValueError, match="not found"):
            store.create_key("ghost-tenant-id")

    def test_create_key_inactive_tenant(self, store):
        t = store.create_tenant("Defunct")
        store.deactivate_tenant(t.id)
        with pytest.raises(ValueError, match="deactivated"):
            store.create_key(t.id)

    def test_keys_are_unique(self, store):
        t = store.create_tenant("UniqueKeys")
        keys = {store.create_key(t.id).key for _ in range(10)}
        assert len(keys) == 10

    def test_list_keys_for_tenant(self, store):
        t1 = store.create_tenant("T1")
        t2 = store.create_tenant("T2")
        store.create_key(t1.id, name="k1")
        store.create_key(t1.id, name="k2")
        store.create_key(t2.id, name="k3")
        assert len(store.list_keys(tenant_id=t1.id)) == 2
        assert len(store.list_keys(tenant_id=t2.id)) == 1
        assert len(store.list_keys()) == 3

    def test_revoke_key(self, store):
        t = store.create_tenant("RevokeMe")
        k = store.create_key(t.id)
        ok = store.revoke_key(k.key)
        assert ok is True
        assert store.authenticate(k.key) is None

    def test_revoke_nonexistent(self, store):
        assert store.revoke_key("sk-memgar-doesnotexist") is False


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_authenticate_valid_key(self, store):
        t = store.create_tenant("AuthTest")
        k = store.create_key(t.id)
        result = store.authenticate(k.key)
        assert result is not None
        assert result.key == k.key

    def test_authenticate_invalid_key(self, store):
        assert store.authenticate("sk-memgar-garbage") is None

    def test_authenticate_revoked_key(self, store):
        t = store.create_tenant("Revoked")
        k = store.create_key(t.id)
        store.revoke_key(k.key)
        assert store.authenticate(k.key) is None

    def test_authenticate_inactive_tenant(self, store):
        t = store.create_tenant("Dead")
        k = store.create_key(t.id)
        store.deactivate_tenant(t.id)
        # Key of inactive tenant must not authenticate
        assert store.authenticate(k.key) is None

    def test_deactivating_tenant_revokes_all_keys(self, store):
        t = store.create_tenant("MultiKey")
        k1 = store.create_key(t.id, name="a")
        k2 = store.create_key(t.id, name="b")
        store.deactivate_tenant(t.id)
        assert store.authenticate(k1.key) is None
        assert store.authenticate(k2.key) is None


# ---------------------------------------------------------------------------
# Usage tracking
# ---------------------------------------------------------------------------

class TestUsageTracking:
    def test_record_usage_increments_count(self, store):
        t = store.create_tenant("UsageCo")
        k = store.create_key(t.id)
        for _ in range(5):
            store.record_usage(k.key)
        keys = store.list_keys(tenant_id=t.id)
        assert keys[0].request_count == 5

    def test_record_usage_sets_last_used(self, store):
        t = store.create_tenant("TimestampCo")
        k = store.create_key(t.id)
        before = time.time()
        store.record_usage(k.key)
        keys = store.list_keys(tenant_id=t.id)
        assert keys[0].last_used_at is not None
        assert keys[0].last_used_at >= before

    def test_usage_stats(self, store):
        t = store.create_tenant("StatCo")
        k1 = store.create_key(t.id, name="a")
        k2 = store.create_key(t.id, name="b")
        store.record_usage(k1.key)
        store.record_usage(k1.key)
        store.record_usage(k2.key)
        stats = store.usage_stats(t.id)
        assert stats["tenant_id"] == t.id
        assert stats["active_keys"] == 2
        assert stats["total_requests"] == 3
        assert stats["last_active"] is not None


# ---------------------------------------------------------------------------
# SQLite persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_survives_reload(self, tmp_path):
        db = str(tmp_path / "tenants.db")
        store1 = TenantStore(db_path=db)
        t = store1.create_tenant("Persistent Corp")
        k = store1.create_key(t.id)

        store2 = TenantStore(db_path=db)
        assert store2.get_tenant(t.id) is not None
        assert store2.authenticate(k.key) is not None

    def test_usage_persists(self, tmp_path):
        db = str(tmp_path / "tenants.db")
        store1 = TenantStore(db_path=db)
        t = store1.create_tenant("PersistUsage")
        k = store1.create_key(t.id)
        store1.record_usage(k.key)
        store1.record_usage(k.key)

        store2 = TenantStore(db_path=db)
        keys = store2.list_keys(tenant_id=t.id)
        assert keys[0].request_count == 2
