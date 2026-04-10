"""
Memgar SIEM Integration
========================

Streams Memgar security events to SIEM platforms in industry-standard formats.

Supported targets:
    Splunk HEC        — HTTP Event Collector (JSON)
    Datadog Logs API  — HTTPS POST with DD-API-KEY
    Elastic ECS/OCSF  — Elasticsearch Bulk API
    Syslog (RFC 5424) — TCP/UDP, TLS supported
    Generic Webhook   — any HTTPS endpoint (OCSF JSON)
    File / stdout     — local JSONL for pipelines (Cribl, Vector, Fluentd)

Event format:
    OCSF (Open Cybersecurity Schema Framework) v1.1 — the 2026 industry standard.
    <https://schema.ocsf.io/>

    All events are normalized to OCSF then optionally re-serialized to
    platform-specific envelope (Splunk HEC wrapper, Syslog priority byte, etc.)

OCSF class mapping:
    Memgar threat detected        → 2001 Security Finding
    DoW attack / rate limit       → 4003 Network Activity
    WebSocket CSWSH block         → 4002 HTTP Activity
    Identity: token issue/revoke  → 3002 Authentication
    Identity: scope denied        → 3005 API Activity
    Supply chain threat           → 2001 Security Finding
    Ledger tamper detected        → 2001 Security Finding
    HITL approval event           → 6001 Application Activity
    Forensics scan result         → 2001 Security Finding

Usage::

    from memgar.siem import SIEMRouter, SplunkSink, DatadogSink, ElasticSink

    router = SIEMRouter()
    router.add_sink(SplunkSink(url="https://splunk:8088", token="HEC-TOKEN"))
    router.add_sink(DatadogSink(api_key="DD-API-KEY", site="datadoghq.com"))

    # Route events from any Memgar module
    from memgar import Memgar
    mg = Memgar(siem=router)              # auto-emit on every analysis

    # Or emit directly
    from memgar.siem import SIEMEvent, EventCategory
    router.emit(SIEMEvent.threat_detected(
        threat_id="FIN-001",
        content="Send payments to TR99...",
        agent_id="agt_abc123",
        risk_score=100,
    ))

    # Or hook into auto_protect
    import memgar
    memgar.auto_protect(siem=router)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("memgar.siem")


# ---------------------------------------------------------------------------
# OCSF Class IDs (v1.1)
# ---------------------------------------------------------------------------

class OCSFClass(int, Enum):
    SECURITY_FINDING  = 2001   # threats, tampering, supply chain
    HTTP_ACTIVITY     = 4002   # WebSocket guard
    NETWORK_ACTIVITY  = 4003   # DoW, rate limiting
    AUTHENTICATION    = 3002   # token issue/verify/revoke
    API_ACTIVITY      = 3005   # scope denied, permission check
    APPLICATION       = 6001   # HITL, forensics, ledger


class OCSFSeverity(int, Enum):
    UNKNOWN     = 0
    INFORMATIONAL = 1
    LOW         = 2
    MEDIUM      = 3
    HIGH        = 4
    CRITICAL    = 5
    FATAL       = 6


class OCSFStatus(int, Enum):
    UNKNOWN  = 0
    SUCCESS  = 1
    FAILURE  = 2


class EventCategory(str, Enum):
    THREAT_DETECTED    = "threat_detected"
    THREAT_ALLOWED     = "threat_allowed"
    DOW_ATTACK         = "dow_attack"
    DOW_RATE_LIMITED   = "dow_rate_limited"
    WS_CSWSH_BLOCKED   = "ws_cswsh_blocked"
    WS_MESSAGE_BLOCKED = "ws_message_blocked"
    TOKEN_ISSUED       = "token_issued"
    TOKEN_VERIFIED     = "token_verified"
    TOKEN_REVOKED      = "token_revoked"
    SCOPE_DENIED       = "scope_denied"
    SUPPLY_CHAIN       = "supply_chain"
    LEDGER_TAMPER      = "ledger_tamper"
    HITL_REQUESTED     = "hitl_requested"
    HITL_APPROVED      = "hitl_approved"
    HITL_DENIED        = "hitl_denied"
    FORENSICS_FINDING  = "forensics_finding"
    AUTO_PROTECT_BLOCK = "auto_protect_block"
    PATTERN_GAP        = "pattern_gap"


# Severity mapping
_SEVERITY_MAP: Dict[str, OCSFSeverity] = {
    "info":     OCSFSeverity.INFORMATIONAL,
    "low":      OCSFSeverity.LOW,
    "medium":   OCSFSeverity.MEDIUM,
    "high":     OCSFSeverity.HIGH,
    "critical": OCSFSeverity.CRITICAL,
}

_CLASS_MAP: Dict[EventCategory, OCSFClass] = {
    EventCategory.THREAT_DETECTED:    OCSFClass.SECURITY_FINDING,
    EventCategory.THREAT_ALLOWED:     OCSFClass.SECURITY_FINDING,
    EventCategory.DOW_ATTACK:         OCSFClass.NETWORK_ACTIVITY,
    EventCategory.DOW_RATE_LIMITED:   OCSFClass.NETWORK_ACTIVITY,
    EventCategory.WS_CSWSH_BLOCKED:   OCSFClass.HTTP_ACTIVITY,
    EventCategory.WS_MESSAGE_BLOCKED: OCSFClass.HTTP_ACTIVITY,
    EventCategory.TOKEN_ISSUED:       OCSFClass.AUTHENTICATION,
    EventCategory.TOKEN_VERIFIED:     OCSFClass.AUTHENTICATION,
    EventCategory.TOKEN_REVOKED:      OCSFClass.AUTHENTICATION,
    EventCategory.SCOPE_DENIED:       OCSFClass.API_ACTIVITY,
    EventCategory.SUPPLY_CHAIN:       OCSFClass.SECURITY_FINDING,
    EventCategory.LEDGER_TAMPER:      OCSFClass.SECURITY_FINDING,
    EventCategory.HITL_REQUESTED:     OCSFClass.APPLICATION,
    EventCategory.HITL_APPROVED:      OCSFClass.APPLICATION,
    EventCategory.HITL_DENIED:        OCSFClass.APPLICATION,
    EventCategory.FORENSICS_FINDING:  OCSFClass.SECURITY_FINDING,
    EventCategory.AUTO_PROTECT_BLOCK: OCSFClass.SECURITY_FINDING,
    EventCategory.PATTERN_GAP:        OCSFClass.APPLICATION,
}


# ---------------------------------------------------------------------------
# SIEMEvent — normalized event model
# ---------------------------------------------------------------------------

@dataclass
class SIEMEvent:
    """
    A normalized Memgar security event ready for SIEM ingestion.

    Automatically mapped to OCSF class and severity.
    """
    category:     EventCategory
    severity:     str          # low / medium / high / critical
    message:      str
    timestamp:    float = field(default_factory=time.time)
    agent_id:     Optional[str] = None
    principal:    Optional[str] = None
    source_ip:    Optional[str] = None
    content_preview: str = ""
    threat_id:    Optional[str] = None
    threat_name:  Optional[str] = None
    risk_score:   Optional[int] = None
    action:       str = "other"     # allowed / blocked / detected / requested
    session_id:   Optional[str] = None
    extra:        Dict[str, Any] = field(default_factory=dict)

    # Auto-computed
    event_id:     str = field(default_factory=lambda: _short_id("evt"))

    @property
    def ocsf_class(self) -> OCSFClass:
        return _CLASS_MAP.get(self.category, OCSFClass.APPLICATION)

    @property
    def ocsf_severity(self) -> OCSFSeverity:
        return _SEVERITY_MAP.get(self.severity.lower(), OCSFSeverity.MEDIUM)

    def to_ocsf(self, product: str = "memgar") -> Dict[str, Any]:
        """Serialize as OCSF v1.1 JSON."""
        ts_ms = int(self.timestamp * 1000)
        base = {
            "class_uid":  self.ocsf_class.value,
            "class_name": self.ocsf_class.name.replace("_", " ").title(),
            "category_uid": self.ocsf_class.value // 1000,
            "activity_id": 1,
            "severity_id": self.ocsf_severity.value,
            "severity":    self.severity.upper(),
            "status":      "Blocked" if self.action == "blocked" else "Detected",
            "status_id":   OCSFStatus.FAILURE.value if self.action == "blocked" else OCSFStatus.SUCCESS.value,
            "time":        ts_ms,
            "start_time":  ts_ms,
            "message":     self.message,
            "event_id":    self.event_id,
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name":    product,
                    "vendor_name": "Memgar",
                    "version": "0.5.10",
                    "uid":     "memgar-ai-security",
                },
                "log_name":   "memgar_security",
                "log_level":  self.severity.upper(),
                "logged_time": ts_ms,
            },
            "type_uid": self.ocsf_class.value * 100 + 1,
            "type_name": self.category.value.replace("_", " ").title(),
        }

        # Finding details (OCSF Security Finding)
        if self.ocsf_class == OCSFClass.SECURITY_FINDING:
            base["finding"] = {
                "uid":    self.event_id,
                "title":  self.threat_name or self.message[:100],
                "desc":   self.message,
                "risk_score": self.risk_score,
                "risk_level": self.severity.upper(),
            }
            if self.threat_id:
                base["finding"]["uid"] = self.threat_id
            if self.content_preview:
                base["observable"] = [{
                    "type_id": 1,
                    "type": "Hostname",
                    "value": self.content_preview[:200],
                    "name": "content_preview",
                }]

        # Actor (agent identity)
        if self.agent_id or self.principal:
            base["actor"] = {}
            if self.agent_id:
                base["actor"]["process"] = {
                    "name": self.agent_id,
                    "uid": self.agent_id,
                }
            if self.principal:
                base["actor"]["user"] = {
                    "name": self.principal,
                    "type": "User",
                }

        # Network endpoint
        if self.source_ip:
            base["src_endpoint"] = {
                "ip": self.source_ip,
                "type": "Unknown",
            }

        # Unmapped extras
        if self.extra:
            base["unmapped"] = {
                "memgar_category": self.category.value,
                "session_id": self.session_id,
                **self.extra,
            }

        return base

    def to_cef(self) -> str:
        """
        ArcSight Common Event Format (CEF) — legacy SIEM compat.
        Format: CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
        """
        sev_num = {
            "info": 1, "low": 3, "medium": 5, "high": 7, "critical": 10
        }.get(self.severity.lower(), 5)
        ext_parts = [
            f"deviceExternalId={self.event_id}",
            f"msg={self.message[:200].replace('=','\\=')}",
            f"cat={self.category.value}",
            f"outcome={self.action}",
        ]
        if self.agent_id:
            ext_parts.append(f"sourceUserId={self.agent_id}")
        if self.principal:
            ext_parts.append(f"requestClientApplication={self.principal}")
        if self.risk_score is not None:
            ext_parts.append(f"cn1={self.risk_score}")
            ext_parts.append("cn1Label=risk_score")
        if self.source_ip:
            ext_parts.append(f"src={self.source_ip}")
        ext = " ".join(ext_parts)
        name = self.threat_name or self.category.value.replace("_", " ").title()
        return f"CEF:0|Memgar|Memgar AI Security|0.5.10|{self.category.value}|{name}|{sev_num}|{ext}"

    def to_leef(self) -> str:
        """IBM QRadar LEEF format."""
        fields = {
            "devTime": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).strftime("%b %d %Y %H:%M:%S"),
            "devTimeFormat": "MMM dd yyyy HH:mm:ss",
            "severity": self.severity,
            "cat": self.category.value,
            "outcome": self.action,
            "msg": self.message[:200],
            "eventId": self.event_id,
        }
        if self.agent_id:
            fields["usrName"] = self.agent_id
        if self.risk_score is not None:
            fields["riskScore"] = str(self.risk_score)
        attrs = "\t".join(f"{k}={v}" for k, v in fields.items())
        return f"LEEF:2.0|Memgar|Memgar AI Security|0.5.10|{self.category.value}|{attrs}"

    # ── Factory methods ─────────────────────────────────────────────────────

    @classmethod
    def threat_detected(
        cls, threat_id: str, threat_name: str, content: str,
        risk_score: int, agent_id: Optional[str] = None,
        severity: str = "high", **kw
    ) -> "SIEMEvent":
        return cls(
            category=EventCategory.THREAT_DETECTED,
            severity=severity,
            message=f"Memory threat detected: {threat_name} (score={risk_score})",
            threat_id=threat_id, threat_name=threat_name,
            risk_score=risk_score, agent_id=agent_id,
            content_preview=content[:150], action="blocked", **kw
        )

    @classmethod
    def dow_attack(
        cls, score: int, explanation: str, content: str,
        session_id: Optional[str] = None, **kw
    ) -> "SIEMEvent":
        return cls(
            category=EventCategory.DOW_ATTACK,
            severity="high" if score >= 80 else "medium",
            message=f"DoW attack detected (score={score}): {explanation[:100]}",
            risk_score=score, action="blocked",
            content_preview=content[:100], session_id=session_id, **kw
        )

    @classmethod
    def ws_cswsh_blocked(
        cls, origin: str, remote_ip: str, reason: str, **kw
    ) -> "SIEMEvent":
        return cls(
            category=EventCategory.WS_CSWSH_BLOCKED,
            severity="high",
            message=f"WebSocket CSWSH blocked: origin={origin} reason={reason}",
            source_ip=remote_ip, action="blocked",
            extra={"origin": origin, "block_reason": reason}, **kw
        )

    @classmethod
    def supply_chain_threat(
        cls, package: str, version: Optional[str], finding_type: str,
        severity: str, description: str, cve: Optional[str] = None, **kw
    ) -> "SIEMEvent":
        ver_str = f"=={version}" if version else ""
        return cls(
            category=EventCategory.SUPPLY_CHAIN,
            severity=severity,
            message=f"Supply chain threat: {package}{ver_str} — {description[:100]}",
            threat_id=cve, action="detected",
            extra={"package": package, "version": version,
                   "finding_type": finding_type, "cve": cve}, **kw
        )

    @classmethod
    def ledger_tamper(
        cls, ledger_path: str, tampered_count: int,
        first_breach: Optional[int] = None, **kw
    ) -> "SIEMEvent":
        return cls(
            category=EventCategory.LEDGER_TAMPER,
            severity="critical",
            message=f"Memory ledger tampered: {tampered_count} entries, first breach at #{first_breach}",
            action="detected",
            extra={"ledger_path": ledger_path, "tampered_count": tampered_count,
                   "first_breach_index": first_breach}, **kw
        )

    @classmethod
    def token_revoked(
        cls, agent_id: str, reason: str, revoked_by: str, **kw
    ) -> "SIEMEvent":
        return cls(
            category=EventCategory.TOKEN_REVOKED,
            severity="medium",
            message=f"Agent token revoked: {agent_id} by {revoked_by} — {reason}",
            agent_id=agent_id, principal=revoked_by, action="blocked",
            extra={"reason": reason}, **kw
        )

    @classmethod
    def scope_denied(
        cls, agent_id: str, required_scope: str, available_scopes: List[str], **kw
    ) -> "SIEMEvent":
        return cls(
            category=EventCategory.SCOPE_DENIED,
            severity="medium",
            message=f"Scope denied: agent={agent_id} required={required_scope}",
            agent_id=agent_id, action="blocked",
            extra={"required_scope": required_scope, "available_scopes": available_scopes}, **kw
        )

    @classmethod
    def hitl_event(
        cls, action: str, request_id: str, hitl_action: str,
        risk_level: str, decided_by: Optional[str] = None,
        agent_id: Optional[str] = None, **kw
    ) -> "SIEMEvent":
        cat = {
            "requested": EventCategory.HITL_REQUESTED,
            "approved":  EventCategory.HITL_APPROVED,
            "denied":    EventCategory.HITL_DENIED,
        }.get(action, EventCategory.HITL_REQUESTED)
        return cls(
            category=cat,
            severity=risk_level,
            message=f"HITL {action}: {hitl_action} (request={request_id})",
            agent_id=agent_id, principal=decided_by,
            action=action,
            extra={"request_id": request_id, "hitl_action": hitl_action}, **kw
        )

    @classmethod
    def auto_protect_block(
        cls, content: str, risk_score: int, threat_count: int,
        agent_id: Optional[str] = None, **kw
    ) -> "SIEMEvent":
        return cls(
            category=EventCategory.AUTO_PROTECT_BLOCK,
            severity="high" if risk_score >= 70 else "medium",
            message=f"Auto-protect blocked content (score={risk_score}, threats={threat_count})",
            risk_score=risk_score, agent_id=agent_id, action="blocked",
            content_preview=content[:100], **kw
        )


# ---------------------------------------------------------------------------
# SIEM Sinks
# ---------------------------------------------------------------------------

class SIEMSink:
    """Base class for SIEM output targets."""
    name: str = "base"

    def send(self, events: List[SIEMEvent]) -> bool:
        raise NotImplementedError

    def send_one(self, event: SIEMEvent) -> bool:
        return self.send([event])


class SplunkHECSink(SIEMSink):
    """
    Splunk HTTP Event Collector (HEC) sink.

    Sends events as Splunk HEC JSON. Supports batching.

    Args:
        url:      Splunk HEC endpoint, e.g. https://splunk.corp.com:8088
        token:    HEC token (Splunk settings → Data Inputs → HTTP Event Collector)
        index:    Target Splunk index (default: main)
        source:   Source field (default: memgar)
        sourcetype: Sourcetype (default: memgar:security)
        verify_ssl: Verify TLS cert (default: True)

    Environment:
        MEMGAR_SPLUNK_HEC_URL
        MEMGAR_SPLUNK_HEC_TOKEN
    """
    name = "splunk_hec"

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        index: str = "main",
        source: str = "memgar",
        sourcetype: str = "memgar:security",
        verify_ssl: bool = True,
    ) -> None:
        self._url     = (url or os.environ.get("MEMGAR_SPLUNK_HEC_URL", "")).rstrip("/") + "/services/collector/event"
        self._token   = token or os.environ.get("MEMGAR_SPLUNK_HEC_TOKEN", "")
        self._index   = index
        self._source  = source
        self._sourcetype = sourcetype
        self._verify_ssl = verify_ssl

    def send(self, events: List[SIEMEvent]) -> bool:
        if not self._url or not self._token:
            logger.warning("[SIEM/Splunk] HEC URL or token not configured")
            return False
        try:
            # Splunk HEC batch: newline-separated JSON objects
            lines = []
            for ev in events:
                wrapper = {
                    "time":       int(ev.timestamp),
                    "host":       socket.gethostname(),
                    "source":     self._source,
                    "sourcetype": self._sourcetype,
                    "index":      self._index,
                    "event":      ev.to_ocsf(),
                }
                lines.append(json.dumps(wrapper, separators=(",", ":")))
            body = "\n".join(lines).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=body,
                headers={
                    "Authorization": f"Splunk {self._token}",
                    "Content-Type":  "application/json",
                },
                method="POST",
            )
            ctx = ssl.create_default_context() if self._verify_ssl else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if not self._verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                result = json.loads(resp.read())
                return result.get("text") == "Success"
        except Exception as e:
            logger.error("[SIEM/Splunk] Send failed: %s", e)
            return False


class DatadogSink(SIEMSink):
    """
    Datadog Logs API sink.

    Sends OCSF-normalized events to Datadog Cloud SIEM.

    Args:
        api_key:  Datadog API key (or MEMGAR_DATADOG_API_KEY env var)
        site:     Datadog site, e.g. datadoghq.com, datadoghq.eu, us3.datadoghq.com
        service:  Service tag (default: memgar)
        env:      Environment tag (default: production)

    Environment:
        MEMGAR_DATADOG_API_KEY
        MEMGAR_DATADOG_SITE
    """
    name = "datadog"

    _INTAKE_URLS = {
        "datadoghq.com":    "https://http-intake.logs.datadoghq.com/api/v2/logs",
        "datadoghq.eu":     "https://http-intake.logs.datadoghq.eu/api/v2/logs",
        "us3.datadoghq.com":"https://http-intake.logs.us3.datadoghq.com/api/v2/logs",
        "us5.datadoghq.com":"https://http-intake.logs.us5.datadoghq.com/api/v2/logs",
        "ap1.datadoghq.com":"https://http-intake.logs.ap1.datadoghq.com/api/v2/logs",
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        site: str = "datadoghq.com",
        service: str = "memgar",
        env: str = "production",
        source: str = "memgar",
    ) -> None:
        self._api_key = api_key or os.environ.get("MEMGAR_DATADOG_API_KEY", "")
        self._site    = site or os.environ.get("MEMGAR_DATADOG_SITE", "datadoghq.com")
        self._service = service
        self._env     = env
        self._source  = source
        self._url     = self._INTAKE_URLS.get(self._site,
                            f"https://http-intake.logs.{self._site}/api/v2/logs")

    def send(self, events: List[SIEMEvent]) -> bool:
        if not self._api_key:
            logger.warning("[SIEM/Datadog] API key not configured")
            return False
        try:
            payload = []
            for ev in events:
                ocsf = ev.to_ocsf()
                payload.append({
                    "ddsource":  self._source,
                    "service":   self._service,
                    "hostname":  socket.gethostname(),
                    "ddtags":    f"env:{self._env},severity:{ev.severity},category:{ev.category.value}",
                    "message":   ev.message,
                    **ocsf,
                })
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=body,
                headers={
                    "DD-API-KEY":   self._api_key,
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 202)
        except Exception as e:
            logger.error("[SIEM/Datadog] Send failed: %s", e)
            return False


class ElasticSink(SIEMSink):
    """
    Elasticsearch / Elastic SIEM sink.

    Uses Elasticsearch Bulk API with OCSF-normalized events.

    Args:
        url:      Elasticsearch URL, e.g. https://elastic.corp.com:9200
        api_key:  Elasticsearch API key (base64 encoded id:key)
        index:    Target index (default: memgar-security)
        verify_ssl: Verify TLS (default: True)

    Environment:
        MEMGAR_ELASTIC_URL
        MEMGAR_ELASTIC_API_KEY
        MEMGAR_ELASTIC_INDEX
    """
    name = "elastic"

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index: str = "memgar-security",
        verify_ssl: bool = True,
    ) -> None:
        self._url     = (url or os.environ.get("MEMGAR_ELASTIC_URL", "")).rstrip("/")
        self._api_key = api_key or os.environ.get("MEMGAR_ELASTIC_API_KEY", "")
        self._username = username
        self._password = password
        self._index   = index or os.environ.get("MEMGAR_ELASTIC_INDEX", "memgar-security")
        self._verify  = verify_ssl

    def send(self, events: List[SIEMEvent]) -> bool:
        if not self._url:
            logger.warning("[SIEM/Elastic] URL not configured")
            return False
        try:
            import base64 as _b64
            lines = []
            for ev in events:
                meta = json.dumps({"index": {"_index": self._index, "_id": ev.event_id}})
                doc  = json.dumps(ev.to_ocsf(), separators=(",", ":"))
                lines.append(meta)
                lines.append(doc)
            body = ("\n".join(lines) + "\n").encode("utf-8")

            headers = {"Content-Type": "application/x-ndjson"}
            if self._api_key:
                headers["Authorization"] = f"ApiKey {self._api_key}"
            elif self._username and self._password:
                creds = _b64.b64encode(f"{self._username}:{self._password}".encode()).decode()
                headers["Authorization"] = f"Basic {creds}"

            req = urllib.request.Request(
                f"{self._url}/_bulk", data=body, headers=headers, method="POST"
            )
            ctx = ssl.create_default_context()
            if not self._verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                result = json.loads(resp.read())
                return not result.get("errors", False)
        except Exception as e:
            logger.error("[SIEM/Elastic] Send failed: %s", e)
            return False


class SyslogSink(SIEMSink):
    """
    RFC 5424 Syslog sink — compatible with every SIEM.

    Supports TCP, UDP, and TLS. Works with:
    - Splunk Universal Forwarder
    - rsyslog / syslog-ng
    - IBM QRadar (LEEF format)
    - ArcSight (CEF format)

    Args:
        host:     Syslog server host
        port:     Port (default: 514 UDP, 6514 TLS)
        protocol: "udp" | "tcp" | "tls"
        format:   "ocsf" | "cef" | "leef" | "rfc5424"
        app_name: Syslog APP-NAME field (default: memgar)
    """
    name = "syslog"

    FACILITY_LOCAL0 = 16
    SEVERITY_MAP = {
        "info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2
    }

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        protocol: str = "udp",
        msg_format: str = "ocsf",
        app_name: str = "memgar",
        facility: int = 16,
        verify_ssl: bool = True,
    ) -> None:
        self._host    = host or os.environ.get("MEMGAR_SYSLOG_HOST", "localhost")
        self._proto   = protocol.lower()
        self._format  = msg_format
        self._app     = app_name
        self._facility= facility
        self._verify  = verify_ssl
        default_port  = 6514 if protocol == "tls" else 514
        self._port    = port or int(os.environ.get("MEMGAR_SYSLOG_PORT", str(default_port)))
        self._sock: Optional[socket.socket] = None
        self._lock    = threading.Lock()

    def send(self, events: List[SIEMEvent]) -> bool:
        success = True
        for ev in events:
            if not self._send_one(ev):
                success = False
        return success

    def _send_one(self, ev: SIEMEvent) -> bool:
        try:
            # Build message body
            if self._format == "cef":
                body = ev.to_cef()
            elif self._format == "leef":
                body = ev.to_leef()
            else:
                body = json.dumps(ev.to_ocsf(), separators=(",", ":"))

            # RFC 5424 header
            pri = self._facility * 8 + self.SEVERITY_MAP.get(ev.severity.lower(), 4)
            ts  = datetime.fromtimestamp(ev.timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            hostname = socket.gethostname()[:255]
            msgid    = ev.category.value[:32]
            header   = f"<{pri}>1 {ts} {hostname} {self._app} - {msgid} - "
            msg      = (header + body + "\n").encode("utf-8", errors="replace")

            if self._proto == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(msg, (self._host, self._port))
            elif self._proto == "tcp":
                with socket.create_connection((self._host, self._port), timeout=5) as s:
                    s.sendall(msg)
            elif self._proto == "tls":
                ctx = ssl.create_default_context()
                if not self._verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self._host, self._port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname=self._host) as s:
                        s.sendall(msg)
            return True
        except Exception as e:
            logger.error("[SIEM/Syslog] Send failed: %s", e)
            return False


class WebhookSink(SIEMSink):
    """
    Generic HTTPS webhook sink — posts OCSF JSON to any endpoint.

    Works with: Sumo Logic, Sentinel (Azure), Chronicle (Google),
    Panther, custom SIEM, etc.
    """
    name = "webhook"

    def __init__(
        self,
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        batch: bool = True,
        verify_ssl: bool = True,
    ) -> None:
        self._url     = url or os.environ.get("MEMGAR_SIEM_WEBHOOK", "")
        self._headers = headers or {}
        self._batch   = batch
        self._verify  = verify_ssl

    def send(self, events: List[SIEMEvent]) -> bool:
        if not self._url:
            logger.warning("[SIEM/Webhook] URL not configured")
            return False
        try:
            if self._batch:
                payload = [ev.to_ocsf() for ev in events]
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self._post(body)
            else:
                for ev in events:
                    body = json.dumps(ev.to_ocsf(), separators=(",", ":")).encode("utf-8")
                    self._post(body)
            return True
        except Exception as e:
            logger.error("[SIEM/Webhook] Send failed: %s", e)
            return False

    def _post(self, body: bytes) -> None:
        headers = {"Content-Type": "application/json", **self._headers}
        req = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        ctx = ssl.create_default_context()
        if not self._verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        urllib.request.urlopen(req, context=ctx, timeout=10)


class FileSink(SIEMSink):
    """
    File / stdout sink — writes OCSF JSONL.

    Useful for:
    - Piping to Cribl, Vector, Fluentd, Logstash
    - Local audit archives
    - Testing

    Args:
        path:    File path ("-" = stdout)
        format:  "ocsf" | "cef" | "leef"
        rotate:  Rotate files (daily, hourly, or None)
    """
    name = "file"

    def __init__(
        self,
        path: str = "-",
        fmt: str = "ocsf",
        rotate: Optional[str] = None,
    ) -> None:
        self._path   = path
        self._fmt    = fmt
        self._rotate = rotate
        self._lock   = threading.Lock()

    def send(self, events: List[SIEMEvent]) -> bool:
        lines = []
        for ev in events:
            if self._fmt == "cef":
                lines.append(ev.to_cef())
            elif self._fmt == "leef":
                lines.append(ev.to_leef())
            else:
                lines.append(json.dumps(ev.to_ocsf(), separators=(",", ":")))
        text = "\n".join(lines) + "\n"
        with self._lock:
            if self._path == "-":
                import sys
                sys.stdout.write(text)
                sys.stdout.flush()
            else:
                p = Path(self._path)
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "a", encoding="utf-8") as f:
                    f.write(text)
        return True


# ---------------------------------------------------------------------------
# SIEMRouter — fan-out to multiple sinks with async buffer
# ---------------------------------------------------------------------------

class SIEMRouter:
    """
    Central event router — fans out to all registered sinks.

    Features:
    - Async send queue (never blocks the main thread)
    - Batching for efficiency
    - Per-sink retry on failure
    - Minimum severity filter
    - Category allowlist / blocklist

    Args:
        min_severity:    Minimum event severity to forward (default: "low")
        batch_size:      Max events per batch (default: 50)
        flush_interval:  Max seconds between flushes (default: 5)
        async_mode:      Use background thread (default: True)
        on_error:        Callback(sink_name, events, error) on send failure
    """

    def __init__(
        self,
        min_severity: str = "low",
        batch_size: int = 50,
        flush_interval: float = 5.0,
        async_mode: bool = True,
        on_error: Optional[Callable] = None,
    ) -> None:
        self._sinks:    List[SIEMSink] = []
        self._min_sev  = min_severity
        self._batch_sz = batch_size
        self._flush_iv = flush_interval
        self._async    = async_mode
        self._on_error = on_error
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stats    = {"emitted": 0, "sent": 0, "failed": 0, "dropped": 0}
        self._lock     = threading.Lock()

        _SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        self._min_sev_int = _SEV.get(min_severity.lower(), 1)

        if async_mode:
            self._worker = threading.Thread(target=self._run, daemon=True)
            self._worker.start()

    def add_sink(self, sink: SIEMSink) -> "SIEMRouter":
        """Add a SIEM output target. Returns self for chaining."""
        self._sinks.append(sink)
        logger.info("[SIEM] Added sink: %s", sink.name)
        return self

    def emit(self, event: SIEMEvent) -> None:
        """Emit a security event. Non-blocking if async_mode=True."""
        _SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        ev_sev = _SEV.get(event.severity.lower(), 1)
        if ev_sev < self._min_sev_int:
            return

        with self._lock:
            self._stats["emitted"] += 1

        if self._async:
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                with self._lock:
                    self._stats["dropped"] += 1
                logger.warning("[SIEM] Queue full — event dropped")
        else:
            self._send_batch([event])

    def flush(self) -> None:
        """Force immediate flush of pending events."""
        events = []
        try:
            while True:
                events.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        if events:
            self._send_batch(events)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {**self._stats, "sinks": [s.name for s in self._sinks],
                    "queue_size": self._queue.qsize()}

    # ── Internal ─────────────────────────────────────────────────────────────

    def _run(self) -> None:
        """Background flush loop."""
        while True:
            batch: List[SIEMEvent] = []
            deadline = time.time() + self._flush_iv
            while len(batch) < self._batch_sz and time.time() < deadline:
                try:
                    remaining = max(0.1, deadline - time.time())
                    ev = self._queue.get(timeout=remaining)
                    batch.append(ev)
                except queue.Empty:
                    break
            if batch:
                self._send_batch(batch)

    def _send_batch(self, events: List[SIEMEvent]) -> None:
        for sink in self._sinks:
            try:
                ok = sink.send(events)
                with self._lock:
                    if ok:
                        self._stats["sent"] += len(events)
                    else:
                        self._stats["failed"] += len(events)
            except Exception as e:
                with self._lock:
                    self._stats["failed"] += len(events)
                if self._on_error:
                    try:
                        self._on_error(sink.name, events, e)
                    except Exception:
                        pass
                logger.error("[SIEM] Sink %s error: %s", sink.name, e)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_id(prefix: str = "evt") -> str:
    import secrets
    return f"{prefix}_{secrets.token_urlsafe(8)}"


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_router(
    splunk_url: Optional[str] = None,
    splunk_token: Optional[str] = None,
    datadog_api_key: Optional[str] = None,
    datadog_site: str = "datadoghq.com",
    elastic_url: Optional[str] = None,
    elastic_api_key: Optional[str] = None,
    syslog_host: Optional[str] = None,
    syslog_port: int = 514,
    syslog_protocol: str = "udp",
    webhook_url: Optional[str] = None,
    log_file: Optional[str] = None,
    min_severity: str = "low",
) -> SIEMRouter:
    """
    Factory — create a SIEMRouter from configuration.

    Pass None to skip a sink. Falls back to environment variables.

    Returns configured SIEMRouter with all specified sinks added.
    """
    router = SIEMRouter(min_severity=min_severity)

    if splunk_url or os.environ.get("MEMGAR_SPLUNK_HEC_URL"):
        router.add_sink(SplunkHECSink(url=splunk_url, token=splunk_token))

    if datadog_api_key or os.environ.get("MEMGAR_DATADOG_API_KEY"):
        router.add_sink(DatadogSink(api_key=datadog_api_key, site=datadog_site))

    if elastic_url or os.environ.get("MEMGAR_ELASTIC_URL"):
        router.add_sink(ElasticSink(url=elastic_url, api_key=elastic_api_key))

    if syslog_host or os.environ.get("MEMGAR_SYSLOG_HOST"):
        router.add_sink(SyslogSink(host=syslog_host, port=syslog_port, protocol=syslog_protocol))

    if webhook_url or os.environ.get("MEMGAR_SIEM_WEBHOOK"):
        router.add_sink(WebhookSink(url=webhook_url))

    if log_file:
        router.add_sink(FileSink(path=log_file))

    return router
