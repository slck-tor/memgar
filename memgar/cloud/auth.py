"""Multi-tenant API-key authentication for memgar cloud.

API keys are stored as **hashes** (SHA-256) in the tenant DB. The raw key
is shown to the user exactly once on creation and never again. This means a
DB leak alone is not enough to authenticate as a tenant — the attacker
needs the original key.

Each key is scoped: a "telemetry" key cannot read other tenants'
reputation aggregates; an "admin" key can rotate other keys.

This module provides:
  - `ApiKey` and `Tenant` data models
  - `TenantStore` (in-memory + sqlite implementations)
  - `verify_api_key()` / `issue_api_key()` helpers
  - `AuthError` hierarchy for clean HTTP mapping
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, List, Optional, Protocol


# ─── Exceptions ─────────────────────────────────────────────────────────

class AuthError(Exception):
    """Base class for cloud-auth failures."""


class InvalidApiKey(AuthError):
    """The presented key did not match any stored hash."""


class InsufficientScope(AuthError):
    """The key is valid but lacks the requested scope."""


class TenantDisabled(AuthError):
    """The tenant exists but has been administratively disabled."""


# ─── Models ─────────────────────────────────────────────────────────────


class ApiKeyScope(str, Enum):
    TELEMETRY_WRITE = "telemetry:write"
    REPUTATION_READ = "reputation:read"
    FEED_READ = "feed:read"
    ADMIN = "admin"


@dataclass(frozen=True)
class Tenant:
    id: str
    name: str
    created_at: float
    plan: str = "free"
    enabled: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ApiKey:
    id: str
    tenant_id: str
    name: str
    hashed_secret: str
    scopes: List[ApiKeyScope]
    created_at: float
    last_used_at: Optional[float] = None
    revoked: bool = False

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "scopes": [s.value for s in self.scopes],
        }


# ─── Hashing ────────────────────────────────────────────────────────────


_PREFIX = "mck_"  # memgar cloud key — visible prefix so users can grep their secrets


def generate_raw_key() -> str:
    """Generate a fresh raw API key, returned exactly once to the caller."""
    return f"{_PREFIX}{secrets.token_urlsafe(32)}"


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ─── Store protocol + implementations ───────────────────────────────────


class TenantStore(Protocol):
    """Storage backend for tenants and API keys.

    Two implementations ship with memgar: `InMemoryTenantStore` for tests
    and `SqliteTenantStore` for self-hosted deployments. Anything Postgres
    or DynamoDB shaped can be plugged in by implementing this Protocol.
    """

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]: ...
    def list_tenants(self) -> List[Tenant]: ...
    def upsert_tenant(self, tenant: Tenant) -> None: ...
    def disable_tenant(self, tenant_id: str) -> None: ...

    def get_api_key_by_hash(self, hashed: str) -> Optional[ApiKey]: ...
    def list_api_keys(self, tenant_id: str) -> List[ApiKey]: ...
    def upsert_api_key(self, key: ApiKey) -> None: ...
    def revoke_api_key(self, key_id: str) -> None: ...
    def mark_key_used(self, key_id: str, ts: float) -> None: ...


class InMemoryTenantStore:
    """Volatile in-process store — fine for tests and ephemeral demos."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tenants: dict[str, Tenant] = {}
        self._keys: dict[str, ApiKey] = {}             # key_id → ApiKey
        self._by_hash: dict[str, ApiKey] = {}          # hashed → ApiKey

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> List[Tenant]:
        return list(self._tenants.values())

    def upsert_tenant(self, tenant: Tenant) -> None:
        with self._lock:
            self._tenants[tenant.id] = tenant

    def disable_tenant(self, tenant_id: str) -> None:
        with self._lock:
            existing = self._tenants.get(tenant_id)
            if existing:
                self._tenants[tenant_id] = Tenant(
                    id=existing.id, name=existing.name,
                    created_at=existing.created_at, plan=existing.plan,
                    enabled=False,
                )

    def get_api_key_by_hash(self, hashed: str) -> Optional[ApiKey]:
        return self._by_hash.get(hashed)

    def list_api_keys(self, tenant_id: str) -> List[ApiKey]:
        return [k for k in self._keys.values() if k.tenant_id == tenant_id]

    def upsert_api_key(self, key: ApiKey) -> None:
        with self._lock:
            self._keys[key.id] = key
            self._by_hash[key.hashed_secret] = key

    def revoke_api_key(self, key_id: str) -> None:
        with self._lock:
            existing = self._keys.get(key_id)
            if existing:
                revoked = ApiKey(
                    id=existing.id, tenant_id=existing.tenant_id,
                    name=existing.name, hashed_secret=existing.hashed_secret,
                    scopes=existing.scopes, created_at=existing.created_at,
                    last_used_at=existing.last_used_at, revoked=True,
                )
                self._keys[key_id] = revoked
                self._by_hash[existing.hashed_secret] = revoked

    def mark_key_used(self, key_id: str, ts: float) -> None:
        with self._lock:
            existing = self._keys.get(key_id)
            if existing:
                updated = ApiKey(
                    id=existing.id, tenant_id=existing.tenant_id,
                    name=existing.name, hashed_secret=existing.hashed_secret,
                    scopes=existing.scopes, created_at=existing.created_at,
                    last_used_at=ts, revoked=existing.revoked,
                )
                self._keys[key_id] = updated
                self._by_hash[existing.hashed_secret] = updated


class SqliteTenantStore:
    """SQLite-backed persistent store — drop-in for single-node deployments."""

    def __init__(self, db_path: str = "./memgar_cloud.sqlite3") -> None:
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS tenants (
                    id           TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    created_at   REAL NOT NULL,
                    plan         TEXT NOT NULL DEFAULT 'free',
                    enabled      INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    id             TEXT PRIMARY KEY,
                    tenant_id      TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    hashed_secret  TEXT NOT NULL UNIQUE,
                    scopes_json    TEXT NOT NULL,
                    created_at     REAL NOT NULL,
                    last_used_at   REAL,
                    revoked        INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
                );
                CREATE INDEX IF NOT EXISTS idx_keys_hash ON api_keys (hashed_secret);
                CREATE INDEX IF NOT EXISTS idx_keys_tenant ON api_keys (tenant_id);
            """)
            self._db.commit()

    @staticmethod
    def _row_to_tenant(row) -> Tenant:
        return Tenant(
            id=row["id"], name=row["name"], created_at=float(row["created_at"]),
            plan=row["plan"], enabled=bool(row["enabled"]),
        )

    @staticmethod
    def _row_to_key(row) -> ApiKey:
        return ApiKey(
            id=row["id"], tenant_id=row["tenant_id"], name=row["name"],
            hashed_secret=row["hashed_secret"],
            scopes=[ApiKeyScope(s) for s in json.loads(row["scopes_json"])],
            created_at=float(row["created_at"]),
            last_used_at=float(row["last_used_at"]) if row["last_used_at"] is not None else None,
            revoked=bool(row["revoked"]),
        )

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        row = self._db.execute(
            "SELECT * FROM tenants WHERE id = ?", (tenant_id,)
        ).fetchone()
        return self._row_to_tenant(row) if row else None

    def list_tenants(self) -> List[Tenant]:
        return [self._row_to_tenant(r) for r in self._db.execute("SELECT * FROM tenants")]

    def upsert_tenant(self, tenant: Tenant) -> None:
        with self._lock:
            self._db.execute(
                """INSERT INTO tenants (id, name, created_at, plan, enabled)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                       plan=excluded.plan, enabled=excluded.enabled""",
                (tenant.id, tenant.name, tenant.created_at, tenant.plan,
                 int(tenant.enabled)),
            )
            self._db.commit()

    def disable_tenant(self, tenant_id: str) -> None:
        with self._lock:
            self._db.execute("UPDATE tenants SET enabled = 0 WHERE id = ?", (tenant_id,))
            self._db.commit()

    def get_api_key_by_hash(self, hashed: str) -> Optional[ApiKey]:
        row = self._db.execute(
            "SELECT * FROM api_keys WHERE hashed_secret = ?", (hashed,)
        ).fetchone()
        return self._row_to_key(row) if row else None

    def list_api_keys(self, tenant_id: str) -> List[ApiKey]:
        rows = self._db.execute(
            "SELECT * FROM api_keys WHERE tenant_id = ?", (tenant_id,)
        )
        return [self._row_to_key(r) for r in rows]

    def upsert_api_key(self, key: ApiKey) -> None:
        with self._lock:
            self._db.execute(
                """INSERT INTO api_keys
                   (id, tenant_id, name, hashed_secret, scopes_json,
                    created_at, last_used_at, revoked)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name, scopes_json=excluded.scopes_json,
                     last_used_at=excluded.last_used_at, revoked=excluded.revoked""",
                (key.id, key.tenant_id, key.name, key.hashed_secret,
                 json.dumps([s.value for s in key.scopes]),
                 key.created_at, key.last_used_at, int(key.revoked)),
            )
            self._db.commit()

    def revoke_api_key(self, key_id: str) -> None:
        with self._lock:
            self._db.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))
            self._db.commit()

    def mark_key_used(self, key_id: str, ts: float) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE id = ?", (ts, key_id),
            )
            self._db.commit()


# ─── High-level helpers ────────────────────────────────────────────────


def issue_api_key(
    store: TenantStore,
    *,
    tenant_id: str,
    name: str,
    scopes: Iterable[ApiKeyScope],
) -> tuple[ApiKey, str]:
    """Mint a fresh API key. Returns (record, raw_key) — raw_key shown ONCE."""
    raw = generate_raw_key()
    now = datetime.now(timezone.utc).timestamp()
    record = ApiKey(
        id=secrets.token_hex(8),
        tenant_id=tenant_id,
        name=name,
        hashed_secret=_hash(raw),
        scopes=list(scopes),
        created_at=now,
    )
    store.upsert_api_key(record)
    return record, raw


def verify_api_key(
    store: TenantStore,
    *,
    raw_key: str,
    required_scope: Optional[ApiKeyScope] = None,
) -> tuple[ApiKey, Tenant]:
    """Look up `raw_key`, verify scope, return (key_record, tenant)."""
    if not raw_key or not raw_key.startswith(_PREFIX):
        raise InvalidApiKey("malformed API key")
    record = store.get_api_key_by_hash(_hash(raw_key))
    if record is None or record.revoked:
        raise InvalidApiKey("unknown or revoked API key")
    tenant = store.get_tenant(record.tenant_id)
    if tenant is None:
        raise InvalidApiKey("orphaned API key (tenant missing)")
    if not tenant.enabled:
        raise TenantDisabled(f"tenant {tenant.id} is disabled")
    if required_scope is not None and required_scope not in record.scopes:
        raise InsufficientScope(
            f"key {record.id} lacks scope {required_scope.value}"
        )
    store.mark_key_used(record.id, datetime.now(timezone.utc).timestamp())
    return record, tenant


__all__ = [
    "AuthError", "InvalidApiKey", "InsufficientScope", "TenantDisabled",
    "Tenant", "ApiKey", "ApiKeyScope",
    "TenantStore", "InMemoryTenantStore", "SqliteTenantStore",
    "generate_raw_key", "issue_api_key", "verify_api_key",
]
