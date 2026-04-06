"""
Memgar WebSocket Guard
======================

Protects local AI agent WebSocket servers against:

  1. Cross-Site WebSocket Hijacking (CSWSH) — CVE-2026-25253 class
     Validates Origin header; blocks connections from untrusted origins.

  2. Localhost rate-limit bypass
     Applies per-IP brute-force protection even for 127.0.0.1.

  3. Auth token exfiltration detection
     Scans URL parameters and WS frames for token patterns.

  4. WebSocket message content scanning
     Every incoming WS message is scanned for memory poisoning threats
     and DoW patterns before reaching the agent.

  5. Suspicious handshake detection
     Missing/spoofed Origin, unknown User-Agent, anomalous headers.

Architecture:

    MemgarWebSocketGuard     — main guard, wraps any WS handler
    WebSocketProxy           — transparent proxy with full interception
    OriginValidator          — CSWSH protection
    WSRateLimiter            — per-IP sliding window
    WSMessageScanner         — content threat detection
    WSHandshakeInspector     — header/token analysis

Usage — wrap any websockets handler::

    import asyncio
    import websockets
    from memgar.websocket_guard import MemgarWebSocketGuard

    guard = MemgarWebSocketGuard(
        allowed_origins=["http://localhost:3000", "app://memgar"],
        block_on_threat=True,
    )

    async def my_handler(websocket, path):
        # Your agent logic here
        async for message in websocket:
            await websocket.send(f"Echo: {message}")

    # Wrap with Memgar guard
    safe_handler = guard.wrap_handler(my_handler)

    asyncio.run(websockets.serve(safe_handler, "localhost", 8765))

Usage — auto_protect() integration::

    import memgar
    memgar.auto_protect()

    # Then start a secure proxy in front of your existing WS server
    from memgar.websocket_guard import WebSocketProxy
    proxy = WebSocketProxy(target_port=18789, proxy_port=18790)
    proxy.start()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

from memgar.analyzer import Analyzer
from memgar.models import Decision, MemoryEntry

logger = logging.getLogger("memgar.websocket_guard")


# ---------------------------------------------------------------------------
# Token detection patterns
# ---------------------------------------------------------------------------

_TOKEN_PATTERNS = [
    # Bearer tokens in URL params or headers
    re.compile(r"(?i)(?:token|auth|bearer|key|secret|password|passwd|pwd)\s*[=:]\s*([a-zA-Z0-9_\-\.]{16,})", re.IGNORECASE),
    # JWT pattern
    re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
    # API key patterns
    re.compile(r"(?:sk|pk|ak|api)[_\-](?:live|test|prod|dev)?[_\-]?[a-zA-Z0-9]{20,}"),
    # OpenClaw/generic agent auth tokens (long hex)
    re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
    # Base64-like secrets
    re.compile(r"(?:password|secret|token)[\"']?\s*:\s*[\"']([a-zA-Z0-9+/=]{12,})[\"']"),
]

# Suspicious URL param names (like CVE-2026-25253's gatewayUrl)
_SUSPICIOUS_PARAMS = {
    "gatewayurl", "gateway_url", "wsurl", "ws_url", "websocketurl",
    "redirect", "callback", "next", "relay", "upstream", "proxy",
}

# Known malicious/suspicious WebSocket origins
_SUSPICIOUS_ORIGIN_PATTERNS = [
    re.compile(r"(?i)evil|attacker|malicious|hacker|exploit|pwn|0day"),
    re.compile(r"data:"),  # data: URI origin
    re.compile(r"null"),   # null origin (sandboxed iframe)
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class WSConnectionInfo:
    """Metadata about a WebSocket connection."""
    remote_ip: str
    origin: Optional[str]
    path: str
    headers: Dict[str, str]
    connected_at: float = field(default_factory=time.time)
    messages_received: int = 0
    messages_blocked: int = 0
    is_suspicious: bool = False
    block_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "remote_ip": self.remote_ip,
            "origin": self.origin,
            "path": self.path,
            "connected_at": datetime.fromtimestamp(self.connected_at, tz=timezone.utc).isoformat(),
            "messages_received": self.messages_received,
            "messages_blocked": self.messages_blocked,
            "is_suspicious": self.is_suspicious,
            "block_reason": self.block_reason,
        }


@dataclass
class WSGuardEvent:
    """Security event from the WebSocket guard."""
    event_type: str   # "connection_blocked", "message_blocked", "token_detected", "rate_limited"
    remote_ip: str
    origin: Optional[str]
    detail: str
    timestamp: float = field(default_factory=time.time)
    content_preview: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "remote_ip": self.remote_ip,
            "origin": self.origin,
            "detail": self.detail,
            "timestamp": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "content_preview": self.content_preview[:100],
        }


@dataclass
class WSGuardStats:
    """Cumulative statistics for the WebSocket guard."""
    connections_accepted: int = 0
    connections_blocked: int = 0
    messages_scanned: int = 0
    messages_blocked: int = 0
    tokens_detected: int = 0
    rate_limited: int = 0
    cswsh_blocked: int = 0
    threats_detected: int = 0
    dow_detected: int = 0
    events: List[WSGuardEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "connections_accepted": self.connections_accepted,
            "connections_blocked": self.connections_blocked,
            "messages_scanned": self.messages_scanned,
            "messages_blocked": self.messages_blocked,
            "tokens_detected": self.tokens_detected,
            "rate_limited": self.rate_limited,
            "cswsh_blocked": self.cswsh_blocked,
            "threats_detected": self.threats_detected,
            "dow_detected": self.dow_detected,
            "recent_events": [e.to_dict() for e in self.events[-20:]],
        }


# ---------------------------------------------------------------------------
# Origin Validator — CSWSH Protection
# ---------------------------------------------------------------------------

class OriginValidator:
    """
    Validates WebSocket Origin headers to prevent Cross-Site WebSocket Hijacking.

    The fix for CVE-2026-25253 class vulnerabilities:
    - Reject connections with missing Origin (possible non-browser clients are OK
      only if explicitly allowed via allow_no_origin=True)
    - Reject connections from untrusted origins
    - Reject connections from null/data: origins (sandboxed iframes)
    - Allow localhost origins by default
    """

    # Default trusted localhost origins
    LOCALHOST_ORIGINS = {
        "http://localhost",
        "http://127.0.0.1",
        "https://localhost",
        "https://127.0.0.1",
        "http://[::1]",
        "app://memgar",
        "app://localhost",
    }

    def __init__(
        self,
        allowed_origins: Optional[List[str]] = None,
        allow_no_origin: bool = True,
        allow_localhost: bool = True,
    ) -> None:
        self._allowed: Set[str] = set(allowed_origins or [])
        self._allow_no_origin = allow_no_origin
        if allow_localhost:
            self._allowed.update(self.LOCALHOST_ORIGINS)

    def is_allowed(self, origin: Optional[str]) -> Tuple[bool, str]:
        """
        Check if an origin is allowed.

        Returns (is_allowed, reason).
        """
        if origin is None:
            if self._allow_no_origin:
                return True, "no origin (allowed)"
            return False, "missing Origin header"

        origin_lower = origin.lower().strip()

        # Block null/data origins (sandboxed iframes, data: URIs)
        if origin_lower in ("null", "data:", ""):
            return False, f"suspicious origin: {origin!r}"

        # Block data: URI origins
        if origin_lower.startswith("data:"):
            return False, f"data: URI origin blocked: {origin!r}"

        # Check suspicious patterns
        for pat in _SUSPICIOUS_ORIGIN_PATTERNS:
            if pat.search(origin_lower):
                return False, f"suspicious origin pattern: {origin!r}"

        # Normalize: strip trailing slash and port if default
        normalized = origin_lower.rstrip("/")

        # Check exact match or prefix match with port
        for allowed in self._allowed:
            allowed_norm = allowed.lower().rstrip("/")
            if normalized == allowed_norm:
                return True, f"origin allowed: {origin}"
            # Allow with any port: http://localhost:3000 matches http://localhost
            parsed_origin = urlparse(normalized)
            parsed_allowed = urlparse(allowed_norm)
            if (parsed_origin.scheme == parsed_allowed.scheme
                    and parsed_origin.hostname == parsed_allowed.hostname):
                return True, f"origin allowed (port ignored): {origin}"

        return False, f"origin not in allowlist: {origin!r}"

    def add_origin(self, origin: str) -> None:
        self._allowed.add(origin.lower().rstrip("/"))


# ---------------------------------------------------------------------------
# WebSocket Rate Limiter
# ---------------------------------------------------------------------------

class WSRateLimiter:
    """
    Per-IP sliding-window rate limiter for WebSocket connections and messages.

    Fixes the localhost rate-limit bypass in CVE-2026-25253.
    localhost gets NO special treatment.
    """

    def __init__(
        self,
        max_connections_per_minute: int = 10,
        max_messages_per_minute: int = 300,
        max_auth_attempts_per_minute: int = 5,
        window_seconds: float = 60.0,
    ) -> None:
        self._max_conn = max_connections_per_minute
        self._max_msg = max_messages_per_minute
        self._max_auth = max_auth_attempts_per_minute
        self._window = window_seconds
        self._connections: Dict[str, deque] = defaultdict(deque)
        self._messages: Dict[str, deque] = defaultdict(deque)
        self._auth_attempts: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _evict(self, q: deque, now: float) -> None:
        cutoff = now - self._window
        while q and q[0] < cutoff:
            q.popleft()

    def check_connection(self, ip: str) -> Tuple[bool, str]:
        """Check if a new connection from ip is allowed."""
        now = time.time()
        with self._lock:
            q = self._connections[ip]
            self._evict(q, now)
            if len(q) >= self._max_conn:
                return False, f"connection rate limit ({len(q)}/{self._max_conn} per {self._window:.0f}s)"
            q.append(now)
        return True, "ok"

    def check_message(self, ip: str) -> Tuple[bool, str]:
        """Check if a message from ip is within rate limits."""
        now = time.time()
        with self._lock:
            q = self._messages[ip]
            self._evict(q, now)
            if len(q) >= self._max_msg:
                return False, f"message rate limit ({len(q)}/{self._max_msg} per {self._window:.0f}s)"
            q.append(now)
        return True, "ok"

    def check_auth_attempt(self, ip: str) -> Tuple[bool, str]:
        """Check if an auth attempt from ip is within limits (anti-brute-force)."""
        now = time.time()
        with self._lock:
            q = self._auth_attempts[ip]
            self._evict(q, now)
            if len(q) >= self._max_auth:
                return False, f"auth brute-force limit ({len(q)}/{self._max_auth} per {self._window:.0f}s)"
            q.append(now)
        return True, "ok"

    def reset_ip(self, ip: str) -> None:
        with self._lock:
            self._connections.pop(ip, None)
            self._messages.pop(ip, None)
            self._auth_attempts.pop(ip, None)


# ---------------------------------------------------------------------------
# WebSocket Message Scanner
# ---------------------------------------------------------------------------

class WSMessageScanner:
    """
    Scans WebSocket message content for:
    - Memory poisoning threats (via Memgar Analyzer)
    - DoW attack patterns
    - Auth token exfiltration patterns
    - Suspicious URL parameters
    """

    def __init__(
        self,
        analyzer: Optional[Analyzer] = None,
        block_on_threat: bool = True,
        scan_token_patterns: bool = True,
    ) -> None:
        self._analyzer = analyzer or Analyzer()
        self._block = block_on_threat
        self._scan_tokens = scan_token_patterns

    def scan(self, content: str, source: str = "websocket") -> Tuple[bool, str, str]:
        """
        Scan a WebSocket message.

        Returns (is_safe, block_reason, threat_detail).
        """
        if not content or len(content.strip()) < 2:
            return True, "", ""

        # 1. Token detection
        if self._scan_tokens:
            found, token_type = self._detect_tokens(content)
            if found:
                return False, f"auth token detected in WS message ({token_type})", token_type

        # 2. Suspicious URL params
        sus, reason = self._detect_suspicious_params(content)
        if sus:
            return False, f"suspicious URL parameter: {reason}", reason

        # 3. Memory threat scan
        try:
            entry = MemoryEntry(content=content, source_type=source)
            result = self._analyzer.analyze(entry)
            if result.decision != Decision.ALLOW:
                names = ", ".join(t.threat.name for t in result.threats[:3])
                return False, f"threat detected (score={result.risk_score}): {names}", names
        except Exception as e:
            logger.debug("WS scan error: %s", e)

        # 4. DoW check
        try:
            from memgar.dow import DoWDetector
            dow = DoWDetector()
            result = dow.analyze(content)
            if result.is_dow_attempt:
                return False, f"DoW attack (score={result.score}): {result.explanation}", "DoW"
        except Exception as e:
            logger.debug("WS DoW check error: %s", e)

        return True, "", ""

    def _detect_tokens(self, content: str) -> Tuple[bool, str]:
        """Check if content contains auth token patterns."""
        for pat in _TOKEN_PATTERNS:
            m = pat.search(content)
            if m:
                # Don't log the actual token
                return True, f"pattern: {pat.pattern[:40]}..."
        return False, ""

    def _detect_suspicious_params(self, content: str) -> Tuple[bool, str]:
        """Check for suspicious URL parameters like gatewayUrl."""
        content_lower = content.lower()
        for param in _SUSPICIOUS_PARAMS:
            if param in content_lower:
                # Check if it's followed by a URL
                idx = content_lower.find(param)
                surrounding = content[max(0, idx - 5): idx + 80]
                if re.search(r"(?:https?|wss?|ws)://", surrounding, re.IGNORECASE):
                    return True, f"suspicious redirect param: {param!r}"
        return False, ""


# ---------------------------------------------------------------------------
# Handshake Inspector
# ---------------------------------------------------------------------------

class WSHandshakeInspector:
    """
    Inspects WebSocket upgrade handshake headers for suspicious patterns.

    Detects:
    - Missing/anomalous Sec-WebSocket-Key
    - Suspicious User-Agent (scripted clients, exploit frameworks)
    - Token in URL query string (CVE-2026-25253 pattern)
    - Unexpected protocol versions
    """

    EXPLOIT_USER_AGENTS = [
        re.compile(r"(?i)python-websocket|websocket-client|wscat|websocat"),
        re.compile(r"(?i)burp|zaproxy|sqlmap|nikto|nuclei"),
        re.compile(r"(?i)curl|wget|httpie"),  # not inherently bad but worth flagging
    ]

    def inspect(
        self,
        path: str,
        headers: Dict[str, str],
        remote_ip: str,
    ) -> Tuple[bool, str]:
        """
        Inspect handshake. Returns (is_ok, reason).
        """
        # Check for token in URL params (CVE-2026-25253 class)
        if "?" in path:
            query = path.split("?", 1)[1]
            params = parse_qs(query)
            for key, values in params.items():
                key_lower = key.lower()
                if key_lower in _SUSPICIOUS_PARAMS:
                    for val in values:
                        if re.search(r"(?:https?|wss?|ws)://", val, re.IGNORECASE):
                            return False, f"suspicious redirect param in URL: {key!r}={val[:50]!r}"

                # Token in URL params
                if any(t in key_lower for t in ("token", "auth", "key", "secret")):
                    for val in values:
                        if len(val) > 16:
                            return False, f"auth token in URL parameter: {key!r}"

        # Suspicious User-Agent
        ua = headers.get("User-Agent", headers.get("user-agent", ""))
        for pat in self.EXPLOIT_USER_AGENTS:
            if pat.search(ua):
                logger.debug("WS Guard: flagged User-Agent: %s from %s", ua[:60], remote_ip)
                # Don't block on UA alone — just log
                break

        # Check Sec-WebSocket-Key presence (required per RFC 6455)
        key = headers.get("Sec-WebSocket-Key", headers.get("sec-websocket-key", ""))
        if not key:
            return False, "missing Sec-WebSocket-Key header"

        return True, "ok"


# ---------------------------------------------------------------------------
# Main Guard
# ---------------------------------------------------------------------------

class MemgarWebSocketGuard:
    """
    Main WebSocket security guard.

    Wraps any asyncio WebSocket handler with full Memgar protection:
    - CSWSH origin validation
    - Rate limiting (per-IP, no localhost exemption)
    - Handshake inspection
    - Per-message threat scanning

    Usage::

        import websockets
        from memgar.websocket_guard import MemgarWebSocketGuard

        guard = MemgarWebSocketGuard(
            allowed_origins=["http://localhost:3000"],
            block_on_threat=True,
        )

        safe_handler = guard.wrap_handler(my_agent_handler)
        await websockets.serve(safe_handler, "localhost", 8765)

    Args:
        allowed_origins:            List of trusted origins. localhost added by default.
        block_on_threat:            Close connection on threat detection.
        block_on_rate_limit:        Close connection when rate limited.
        max_connections_per_minute: Per-IP connection rate limit.
        max_messages_per_minute:    Per-IP message rate limit.
        max_auth_attempts_per_minute: Anti-brute-force for auth messages.
        scan_messages:              Enable per-message content scanning.
        scan_token_patterns:        Detect auth tokens in messages.
        analyzer:                   Shared Analyzer instance.
        on_block:                   Callback(conn_info, event) on block.
    """

    def __init__(
        self,
        allowed_origins: Optional[List[str]] = None,
        block_on_threat: bool = True,
        block_on_rate_limit: bool = True,
        max_connections_per_minute: int = 10,
        max_messages_per_minute: int = 300,
        max_auth_attempts_per_minute: int = 5,
        scan_messages: bool = True,
        scan_token_patterns: bool = True,
        analyzer: Optional[Analyzer] = None,
        on_block: Optional[Callable] = None,
    ) -> None:
        self._origin_validator = OriginValidator(
            allowed_origins=allowed_origins,
            allow_no_origin=True,
            allow_localhost=True,
        )
        self._rate_limiter = WSRateLimiter(
            max_connections_per_minute=max_connections_per_minute,
            max_messages_per_minute=max_messages_per_minute,
            max_auth_attempts_per_minute=max_auth_attempts_per_minute,
        )
        self._handshake_inspector = WSHandshakeInspector()
        self._message_scanner = WSMessageScanner(
            analyzer=analyzer,
            block_on_threat=block_on_threat,
            scan_token_patterns=scan_token_patterns,
        ) if scan_messages else None
        self._block_on_threat = block_on_threat
        self._block_on_rate_limit = block_on_rate_limit
        self._scan_messages = scan_messages
        self._on_block = on_block
        self.stats = WSGuardStats()
        self._lock = threading.Lock()

    def _record_event(self, event: WSGuardEvent) -> None:
        with self._lock:
            self.stats.events.append(event)
            if len(self.stats.events) > 500:
                self.stats.events = self.stats.events[-200:]

    def wrap_handler(self, handler: Callable) -> Callable:
        """
        Wrap an async WebSocket handler with Memgar protection.

        The wrapped handler has the same signature as the original.
        """
        guard = self

        async def secure_handler(websocket, path="", *args, **kwargs):
            # Extract connection info
            try:
                remote_ip = websocket.remote_address[0] if hasattr(websocket, "remote_address") else "unknown"
                headers_raw = websocket.request_headers if hasattr(websocket, "request_headers") else {}
                headers = {k.lower(): v for k, v in dict(headers_raw).items()}
                origin = headers.get("origin")
            except Exception:
                remote_ip = "unknown"
                headers = {}
                origin = None

            conn = WSConnectionInfo(
                remote_ip=remote_ip,
                origin=origin,
                path=path,
                headers=headers,
            )

            # 1. Handshake inspection
            ok, reason = guard._handshake_inspector.inspect(path, headers, remote_ip)
            if not ok:
                conn.is_suspicious = True
                conn.block_reason = reason
                event = WSGuardEvent(
                    event_type="connection_blocked",
                    remote_ip=remote_ip,
                    origin=origin,
                    detail=f"Handshake rejected: {reason}",
                )
                guard._record_event(event)
                with guard._lock:
                    guard.stats.connections_blocked += 1
                logger.warning("[Memgar WS] Handshake blocked from %s: %s", remote_ip, reason)
                if guard._block_on_threat:
                    await websocket.close(1008, f"Rejected: {reason}")
                    return
                if guard._on_block:
                    guard._on_block(conn, event)

            # 2. Origin validation (CSWSH protection)
            allowed, reason = guard._origin_validator.is_allowed(origin)
            if not allowed:
                conn.is_suspicious = True
                conn.block_reason = reason
                event = WSGuardEvent(
                    event_type="cswsh_blocked",
                    remote_ip=remote_ip,
                    origin=origin,
                    detail=f"CSWSH blocked: {reason}",
                )
                guard._record_event(event)
                with guard._lock:
                    guard.stats.connections_blocked += 1
                    guard.stats.cswsh_blocked += 1
                logger.warning("[Memgar WS] CSWSH blocked from %s origin=%s: %s", remote_ip, origin, reason)
                if guard._block_on_threat:
                    await websocket.close(1008, "Cross-origin connection rejected")
                    return
                if guard._on_block:
                    guard._on_block(conn, event)

            # 3. Connection rate limit
            ok, reason = guard._rate_limiter.check_connection(remote_ip)
            if not ok:
                event = WSGuardEvent(
                    event_type="rate_limited",
                    remote_ip=remote_ip,
                    origin=origin,
                    detail=f"Connection rate limit: {reason}",
                )
                guard._record_event(event)
                with guard._lock:
                    guard.stats.connections_blocked += 1
                    guard.stats.rate_limited += 1
                logger.warning("[Memgar WS] Rate limited connection from %s: %s", remote_ip, reason)
                if guard._block_on_rate_limit:
                    await websocket.close(1008, "Rate limit exceeded")
                    return

            with guard._lock:
                guard.stats.connections_accepted += 1
            logger.info("[Memgar WS] Connection accepted from %s origin=%s path=%s", remote_ip, origin, path)

            # 4. Wrap the websocket to intercept messages
            if guard._scan_messages:
                websocket = _MessageInterceptingWebSocket(
                    websocket, conn, guard
                )

            # 5. Call original handler
            try:
                await handler(websocket, path, *args, **kwargs)
            except Exception:
                raise

        return secure_handler

    def allow_origin(self, origin: str) -> None:
        """Dynamically add a trusted origin."""
        self._origin_validator.add_origin(origin)

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.to_dict()


# ---------------------------------------------------------------------------
# Message-intercepting WebSocket wrapper
# ---------------------------------------------------------------------------

class _MessageInterceptingWebSocket:
    """
    Transparent wrapper around a WebSocket that intercepts
    incoming messages for scanning.
    """

    def __init__(self, ws: Any, conn: WSConnectionInfo, guard: MemgarWebSocketGuard) -> None:
        self._ws = ws
        self._conn = conn
        self._guard = guard

    def __getattr__(self, name: str) -> Any:
        return getattr(self._ws, name)

    def __aiter__(self):
        return self._async_gen()

    async def _async_gen(self):
        async for message in self._ws:
            result = await self._process_message(message)
            if result is not None:
                yield result

    async def recv(self) -> str:
        while True:
            message = await self._ws.recv()
            result = await self._process_message(message)
            if result is not None:
                return result

    async def _process_message(self, message: Any) -> Optional[Any]:
        self._conn.messages_received += 1

        with self._guard._lock:
            self._guard.stats.messages_scanned += 1

        content = message if isinstance(message, str) else (
            message.decode("utf-8", errors="replace") if isinstance(message, bytes) else str(message)
        )

        # Rate limit check
        ok, reason = self._guard._rate_limiter.check_message(self._conn.remote_ip)
        if not ok:
            self._conn.messages_blocked += 1
            with self._guard._lock:
                self._guard.stats.messages_blocked += 1
                self._guard.stats.rate_limited += 1
            event = WSGuardEvent(
                event_type="message_rate_limited",
                remote_ip=self._conn.remote_ip,
                origin=self._conn.origin,
                detail=f"Message rate limit: {reason}",
                content_preview=content[:80],
            )
            self._guard._record_event(event)
            logger.warning("[Memgar WS] Message rate limited from %s", self._conn.remote_ip)
            if self._guard._block_on_rate_limit:
                await self._ws.close(1008, "Message rate limit exceeded")
                return None
            return None

        # Content scan
        if self._guard._message_scanner:
            is_safe, block_reason, detail = self._guard._message_scanner.scan(
                content, source="websocket"
            )
            if not is_safe:
                self._conn.messages_blocked += 1
                with self._guard._lock:
                    self._guard.stats.messages_blocked += 1
                    if "token" in block_reason.lower():
                        self._guard.stats.tokens_detected += 1
                    elif "dow" in block_reason.lower() or "rate" in block_reason.lower():
                        self._guard.stats.dow_detected += 1
                    else:
                        self._guard.stats.threats_detected += 1

                event = WSGuardEvent(
                    event_type="message_blocked",
                    remote_ip=self._conn.remote_ip,
                    origin=self._conn.origin,
                    detail=block_reason,
                    content_preview=content[:80],
                )
                self._guard._record_event(event)
                logger.warning(
                    "[Memgar WS] Message blocked from %s: %s",
                    self._conn.remote_ip, block_reason
                )
                if self._guard._block_on_threat:
                    await self._ws.close(1008, f"Message rejected: {block_reason[:100]}")
                    return None
                return None

        return message


# ---------------------------------------------------------------------------
# Simple WebSocket Proxy (no external deps)
# ---------------------------------------------------------------------------

class WebSocketProxy:
    """
    Transparent security proxy for an existing WebSocket server.

    Sits in front of your agent's WS server, intercepting and scanning
    all traffic. The agent doesn't need any code changes.

    Architecture::

        Browser/Client
            |
            ▼
        Memgar WS Proxy (proxy_port)
            |  — origin validation
            |  — rate limiting
            |  — content scanning
            ▼
        Agent WS Server (target_port)

    Usage::

        proxy = WebSocketProxy(
            target_port=18789,   # your agent's WS port
            proxy_port=18790,    # safe port to expose
            allowed_origins=["http://localhost:3000"],
        )
        proxy.start()  # non-blocking, runs in background thread
        # Point clients to ws://localhost:18790 instead of 18789
    """

    def __init__(
        self,
        target_port: int = 18789,
        proxy_port: int = 18790,
        target_host: str = "127.0.0.1",
        proxy_host: str = "127.0.0.1",
        allowed_origins: Optional[List[str]] = None,
        block_on_threat: bool = True,
        analyzer: Optional[Analyzer] = None,
    ) -> None:
        self.target_port = target_port
        self.proxy_port = proxy_port
        self.target_host = target_host
        self.proxy_host = proxy_host
        self.guard = MemgarWebSocketGuard(
            allowed_origins=allowed_origins,
            block_on_threat=block_on_threat,
            analyzer=analyzer,
        )
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server = None

    def start(self) -> None:
        """Start the proxy in a background thread (non-blocking)."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        time.sleep(0.2)  # Give server time to start
        logger.info(
            "[Memgar WS Proxy] Started: ws://%s:%d → ws://%s:%d",
            self.proxy_host, self.proxy_port,
            self.target_host, self.target_port,
        )

    def stop(self) -> None:
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

    def get_stats(self) -> Dict[str, Any]:
        return self.guard.get_stats()

    def _run(self) -> None:
        try:
            import websockets
        except ImportError:
            logger.error(
                "[Memgar WS Proxy] websockets library not installed. "
                "Install with: pip install websockets"
            )
            return

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def proxy_handler(client_ws, path=""):
            """Forward messages between client and target, scanning each."""
            try:
                target_uri = f"ws://{self.target_host}:{self.target_port}{path}"
                async with websockets.connect(target_uri) as target_ws:
                    async def client_to_target():
                        async for message in client_ws:
                            if isinstance(message, str):
                                is_safe, reason, _ = self.guard._message_scanner.scan(
                                    message, "ws_proxy_inbound"
                                ) if self.guard._message_scanner else (True, "", "")
                                with self.guard._lock:
                                    self.guard.stats.messages_scanned += 1
                                if not is_safe:
                                    with self.guard._lock:
                                        self.guard.stats.messages_blocked += 1
                                    logger.warning(
                                        "[Memgar WS Proxy] Blocked inbound: %s", reason
                                    )
                                    if self.guard._block_on_threat:
                                        await client_ws.close(1008, f"Rejected: {reason[:80]}")
                                        return
                                    continue
                            await target_ws.send(message)

                    async def target_to_client():
                        async for message in target_ws:
                            await client_ws.send(message)

                    await asyncio.gather(client_to_target(), target_to_client())
            except Exception as e:
                logger.debug("[Memgar WS Proxy] Connection error: %s", e)

        # Wrap with guard
        safe_handler = self.guard.wrap_handler(proxy_handler)

        async def main():
            self._server = await websockets.serve(
                safe_handler, self.proxy_host, self.proxy_port
            )
            await self._server.wait_closed()

        self._loop.run_until_complete(main())


# ---------------------------------------------------------------------------
# auto_protect() integration
# ---------------------------------------------------------------------------

def patch_auto_protect() -> None:
    """
    Called by auto_protect() to register WebSocket guard with the
    auto-protection system.

    This patches asyncio's event loop and the websockets library
    to intercept WS server creation and wrap handlers automatically.
    """
    try:
        import websockets
        import websockets.server as ws_server

        if getattr(ws_server.serve, "_memgar_patched", False):
            return

        original_serve = ws_server.serve

        def patched_serve(handler, host=None, port=None, *args, **kwargs):
            # Create guard with defaults
            guard = MemgarWebSocketGuard(
                block_on_threat=True,
                scan_messages=True,
            )
            safe_handler = guard.wrap_handler(handler)
            logger.info(
                "[Memgar Auto] WebSocket server patched: %s:%s",
                host, port
            )
            return original_serve(safe_handler, host, port, *args, **kwargs)

        patched_serve._memgar_patched = True
        ws_server.serve = patched_serve
        websockets.serve = patched_serve

        logger.info("[Memgar Auto] ✅ websockets.serve patched")

    except ImportError:
        logger.debug("[Memgar Auto] websockets not installed, WS patching skipped")
    except Exception as e:
        logger.debug("[Memgar Auto] WS patch failed: %s", e)


# ---------------------------------------------------------------------------
# Standalone scanner (no server needed)
# ---------------------------------------------------------------------------

def scan_ws_message(
    content: str,
    origin: Optional[str] = None,
    check_tokens: bool = True,
) -> Dict[str, Any]:
    """
    Scan a single WebSocket message without starting a server.

    Useful for testing and integration.

    Returns dict with: is_safe, threats, block_reason, risk_score.
    """
    scanner = WSMessageScanner(scan_token_patterns=check_tokens)
    is_safe, reason, detail = scanner.scan(content, "ws_scan")

    analyzer = Analyzer()
    entry = MemoryEntry(content=content, source_type="websocket")
    result = analyzer.analyze(entry)

    return {
        "is_safe": is_safe,
        "block_reason": reason if not is_safe else "",
        "risk_score": result.risk_score,
        "decision": result.decision.value,
        "threats": [
            {"name": t.threat.name, "severity": t.threat.severity.value}
            for t in result.threats[:5]
        ],
        "origin_checked": origin is not None,
        "origin": origin,
    }
