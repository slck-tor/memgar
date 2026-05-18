"""Multi-tenant API key management for Memgar.

Provides SQLite-backed tenant and API key storage with per-key rate limiting,
usage tracking, and plan-based quota enforcement.

Usage
-----
    from memgar.tenants import TenantStore

    store = TenantStore()                                  # ~/.cache/memgar/tenants.db
    store = TenantStore("/data/integrity/tenants.db")      # custom path

    tenant = store.create_tenant("Acme Corp", plan="starter")
    key    = store.create_key(tenant.id, name="production")
    print(key.key)   # sk-memgar-...

    ctx = store.authenticate(key.key)    # → ApiKey | None
    store.record_usage(key.key)
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Plans and their default RPM limits
# ---------------------------------------------------------------------------

PLAN_LIMITS: Dict[str, int] = {
    "free":        60,
    "starter":    300,
    "pro":       1000,
    "enterprise": 5000,
}

PLANS = list(PLAN_LIMITS.keys())


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Tenant:
    id: str
    name: str
    plan: str
    created_at: float
    active: bool = True

    @property
    def rate_limit_rpm(self) -> int:
        return PLAN_LIMITS.get(self.plan, PLAN_LIMITS["free"])


@dataclass
class ApiKey:
    key: str
    tenant_id: str
    name: str
    rate_limit_rpm: int
    created_at: float
    last_used_at: Optional[float] = None
    request_count: int = 0
    active: bool = True


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class TenantStore:
    """Thread-safe SQLite-backed store for tenants and API keys."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS tenants (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        plan        TEXT NOT NULL DEFAULT 'starter',
        created_at  REAL NOT NULL,
        active      INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS api_keys (
        key             TEXT PRIMARY KEY,
        tenant_id       TEXT NOT NULL REFERENCES tenants(id),
        name            TEXT NOT NULL DEFAULT 'default',
        rate_limit_rpm  INTEGER NOT NULL DEFAULT 60,
        created_at      REAL NOT NULL,
        last_used_at    REAL,
        request_count   INTEGER NOT NULL DEFAULT 0,
        active          INTEGER NOT NULL DEFAULT 1
    );

    CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            cache = Path.home() / ".cache" / "memgar"
            cache.mkdir(parents=True, exist_ok=True)
            db_path = str(cache / "tenants.db")
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.executescript(self._SCHEMA)

    @staticmethod
    def _gen_id() -> str:
        return secrets.token_hex(8)

    @staticmethod
    def _gen_key() -> str:
        return "sk-memgar-" + secrets.token_urlsafe(32)

    # ------------------------------------------------------------------
    # Tenants
    # ------------------------------------------------------------------

    def create_tenant(self, name: str, plan: str = "starter") -> Tenant:
        if plan not in PLAN_LIMITS:
            raise ValueError(f"Unknown plan '{plan}'. Choose from: {PLANS}")
        tenant = Tenant(
            id=self._gen_id(),
            name=name,
            plan=plan,
            created_at=time.time(),
        )
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO tenants (id, name, plan, created_at, active) VALUES (?,?,?,?,1)",
                    (tenant.id, tenant.name, tenant.plan, tenant.created_at),
                )
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tenants WHERE id=?", (tenant_id,)
            ).fetchone()
        return self._row_to_tenant(row) if row else None

    def list_tenants(self) -> List[Tenant]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tenants ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_tenant(r) for r in rows]

    def deactivate_tenant(self, tenant_id: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE tenants SET active=0 WHERE id=?", (tenant_id,)
                )
                # Also deactivate all keys for this tenant
                conn.execute(
                    "UPDATE api_keys SET active=0 WHERE tenant_id=?", (tenant_id,)
                )
        return cur.rowcount > 0

    @staticmethod
    def _row_to_tenant(row) -> Tenant:
        return Tenant(
            id=row["id"],
            name=row["name"],
            plan=row["plan"],
            created_at=row["created_at"],
            active=bool(row["active"]),
        )

    # ------------------------------------------------------------------
    # API Keys
    # ------------------------------------------------------------------

    def create_key(self, tenant_id: str, name: str = "default") -> ApiKey:
        tenant = self.get_tenant(tenant_id)
        if tenant is None:
            raise ValueError(f"Tenant '{tenant_id}' not found")
        if not tenant.active:
            raise ValueError(f"Tenant '{tenant_id}' is deactivated")
        api_key = ApiKey(
            key=self._gen_key(),
            tenant_id=tenant_id,
            name=name,
            rate_limit_rpm=tenant.rate_limit_rpm,
            created_at=time.time(),
        )
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO api_keys
                       (key, tenant_id, name, rate_limit_rpm, created_at, active)
                       VALUES (?,?,?,?,?,1)""",
                    (api_key.key, api_key.tenant_id, api_key.name,
                     api_key.rate_limit_rpm, api_key.created_at),
                )
        return api_key

    def authenticate(self, key: str) -> Optional[ApiKey]:
        """Return ApiKey if key is valid and active, else None."""
        with self._connect() as conn:
            row = conn.execute(
                """SELECT k.*, t.active AS tenant_active
                   FROM api_keys k
                   JOIN tenants t ON k.tenant_id = t.id
                   WHERE k.key=? AND k.active=1 AND t.active=1""",
                (key,),
            ).fetchone()
        return self._row_to_key(row) if row else None

    def record_usage(self, key: str) -> None:
        now = time.time()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """UPDATE api_keys
                       SET last_used_at=?, request_count=request_count+1
                       WHERE key=?""",
                    (now, key),
                )

    def revoke_key(self, key: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE api_keys SET active=0 WHERE key=?", (key,)
                )
        return cur.rowcount > 0

    def list_keys(self, tenant_id: Optional[str] = None) -> List[ApiKey]:
        with self._connect() as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM api_keys WHERE tenant_id=? ORDER BY created_at DESC",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM api_keys ORDER BY created_at DESC"
                ).fetchall()
        return [self._row_to_key(r) for r in rows]

    def usage_stats(self, tenant_id: str) -> dict:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS key_count,
                          SUM(request_count) AS total_requests,
                          MAX(last_used_at) AS last_active
                   FROM api_keys
                   WHERE tenant_id=? AND active=1""",
                (tenant_id,),
            ).fetchone()
        return {
            "tenant_id": tenant_id,
            "active_keys": row["key_count"] or 0,
            "total_requests": row["total_requests"] or 0,
            "last_active": row["last_active"],
        }

    @staticmethod
    def _row_to_key(row) -> ApiKey:
        return ApiKey(
            key=row["key"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            rate_limit_rpm=row["rate_limit_rpm"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            request_count=row["request_count"],
            active=bool(row["active"]),
        )
