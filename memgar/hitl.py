"""
Memgar Human-in-the-Loop (HITL) Checkpoint
============================================

Pauses high-impact agent actions and waits for human approval before
executing them. Supports Slack, Telegram, webhook, and CLI channels.

Design principle: "Approve/Deny with timeout → default deny"

    Agent wants to send email
          │
          ▼
    HITLCheckpoint.require("send_email", details)
          │
          ├─► Slack message: "Agent wants to send email to X. [Approve] [Deny]"
          ├─► Telegram message with inline keyboard
          ├─► Webhook POST to your endpoint
          └─► CLI prompt (dev mode)
          │
          ▼  (waits up to timeout_seconds)
          │
    ┌─────┴──────┐
    │ APPROVED   │ DENIED / TIMEOUT
    ▼            ▼
  proceed     HITLDeniedError raised

Architecture:

    HITLCheckpoint     — main entry point, sync + async API
    ApprovalRequest    — pending approval with unique token
    ApprovalResult     — outcome (approved / denied / timeout)
    HITLNotifier       — pluggable notifier base class
    SlackNotifier      — Slack webhook / API
    TelegramNotifier   — Telegram Bot API
    WebhookNotifier    — generic HTTP webhook
    CLINotifier        — terminal prompt (dev/testing)
    HITLServer         — lightweight HTTP server for callback endpoints

Usage — simple::

    from memgar.hitl import HITLCheckpoint

    checkpoint = HITLCheckpoint(
        notifiers=[SlackNotifier(webhook_url="https://hooks.slack.com/...")],
        timeout_seconds=300,
    )

    # Agent code — blocks until approved or timeout
    checkpoint.require(
        action="send_email",
        details={"to": "ceo@company.com", "subject": "Q3 Report"},
        risk_level="high",
    )
    # Only reaches here if approved
    send_the_email()

Usage — decorator::

    @checkpoint.guard(action="delete_file", risk_level="critical")
    def delete_important_file(path: str):
        os.remove(path)

    delete_important_file("/data/important.db")  # pauses for approval

Usage — auto_protect integration::

    import memgar
    memgar.auto_protect(
        hitl_notifiers=[TelegramNotifier(token="...", chat_id="...")],
        hitl_actions=["send_email", "delete_file", "transfer_funds"],
    )
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("memgar.hitl")


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW      = "low"       # informational, no block
    MEDIUM   = "medium"    # warn + require approval
    HIGH     = "high"      # require approval, default deny on timeout
    CRITICAL = "critical"  # require approval, always deny on timeout


class ApprovalStatus(str, Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    DENIED   = "denied"
    TIMEOUT  = "timeout"
    EXPIRED  = "expired"


@dataclass
class ApprovalRequest:
    """A pending human approval request."""
    request_id: str
    action:     str
    details:    Dict[str, Any]
    risk_level: RiskLevel
    created_at: float
    timeout_at: float
    session_id: str
    agent_id:   str
    token:      str                # secret token for callback URL
    status:     ApprovalStatus = ApprovalStatus.PENDING
    decided_at: Optional[float] = None
    decided_by: Optional[str]  = None
    reason:     Optional[str]  = None

    @property
    def is_expired(self) -> bool:
        return time.time() > self.timeout_at

    @property
    def timeout_seconds_remaining(self) -> float:
        return max(0.0, self.timeout_at - time.time())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id":  self.request_id,
            "action":      self.action,
            "details":     self.details,
            "risk_level":  self.risk_level.value,
            "created_at":  _iso(self.created_at),
            "timeout_at":  _iso(self.timeout_at),
            "session_id":  self.session_id,
            "agent_id":    self.agent_id,
            "status":      self.status.value,
            "decided_at":  _iso(self.decided_at) if self.decided_at else None,
            "decided_by":  self.decided_by,
            "reason":      self.reason,
        }


@dataclass
class ApprovalResult:
    """Outcome of a HITL approval request."""
    request_id: str
    status:     ApprovalStatus
    action:     str
    risk_level: RiskLevel
    wait_ms:    float
    decided_by: Optional[str] = None
    reason:     Optional[str] = None

    @property
    def approved(self) -> bool:
        return self.status == ApprovalStatus.APPROVED

    @property
    def denied(self) -> bool:
        return self.status in (ApprovalStatus.DENIED, ApprovalStatus.TIMEOUT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status":     self.status.value,
            "action":     self.action,
            "risk_level": self.risk_level.value,
            "approved":   self.approved,
            "wait_ms":    round(self.wait_ms, 1),
            "decided_by": self.decided_by,
            "reason":     self.reason,
        }


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HITLDeniedError(Exception):
    """Raised when a HITL checkpoint is denied or times out."""
    def __init__(self, msg: str, result: Optional[ApprovalResult] = None) -> None:
        super().__init__(msg)
        self.result = result


class HITLTimeoutError(HITLDeniedError):
    """Raised when a HITL checkpoint times out (no response)."""


# ---------------------------------------------------------------------------
# Notifiers
# ---------------------------------------------------------------------------

class HITLNotifier:
    """Base class for HITL notification channels."""

    def send(self, request: ApprovalRequest, approve_url: str, deny_url: str) -> bool:
        """Send approval request. Returns True if sent successfully."""
        raise NotImplementedError

    def _format_details(self, details: Dict[str, Any]) -> str:
        lines = []
        for k, v in details.items():
            val = str(v)[:200]
            lines.append(f"  • {k}: {val}")
        return "\n".join(lines)

    def _risk_emoji(self, level: RiskLevel) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(level.value, "⚪")


class SlackNotifier(HITLNotifier):
    """
    Send HITL approval requests to Slack via Incoming Webhook.

    Args:
        webhook_url: Slack incoming webhook URL
        channel:     Override channel (optional)
        username:    Bot display name

    Setup:
        1. Go to api.slack.com/apps → Create App → Incoming Webhooks
        2. Activate and copy webhook URL
        3. Pass URL here

    Or via environment variable:
        export MEMGAR_SLACK_WEBHOOK=https://hooks.slack.com/...
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        channel: Optional[str] = None,
        username: str = "Memgar HITL",
    ) -> None:
        self._url = webhook_url or os.environ.get("MEMGAR_SLACK_WEBHOOK", "")
        self._channel = channel
        self._username = username

    def send(self, request: ApprovalRequest, approve_url: str, deny_url: str) -> bool:
        if not self._url:
            logger.warning("[HITL] SlackNotifier: no webhook URL configured")
            return False
        try:
            import urllib.request as req
            emoji = self._risk_emoji(request.risk_level)
            details_text = self._format_details(request.details)
            expires_in = int(request.timeout_seconds_remaining)

            payload = {
                "username": self._username,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"{emoji} Agent Action Requires Approval"}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Action:*\n`{request.action}`"},
                            {"type": "mrkdwn", "text": f"*Risk Level:*\n{request.risk_level.value.upper()}"},
                            {"type": "mrkdwn", "text": f"*Session:*\n{request.session_id}"},
                            {"type": "mrkdwn", "text": f"*Expires in:*\n{expires_in}s"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Details:*\n```{details_text}```"}
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "✅ Approve"},
                                "style": "primary",
                                "url": approve_url,
                                "action_id": "approve",
                            },
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "❌ Deny"},
                                "style": "danger",
                                "url": deny_url,
                                "action_id": "deny",
                            }
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [
                            {"type": "mrkdwn",
                             "text": f"Request ID: `{request.request_id}` | Memgar HITL v0.5.5"}
                        ]
                    }
                ]
            }
            if self._channel:
                payload["channel"] = self._channel

            data = json.dumps(payload).encode("utf-8")
            r = req.urlopen(req.Request(
                self._url, data=data,
                headers={"Content-Type": "application/json"}
            ), timeout=10)
            return r.status == 200
        except Exception as e:
            logger.error("[HITL] Slack send failed: %s", e)
            return False


class TelegramNotifier(HITLNotifier):
    """
    Send HITL approval requests to Telegram via Bot API.

    Args:
        token:   Telegram bot token (from @BotFather)
        chat_id: Target chat/channel ID

    Setup:
        1. Message @BotFather → /newbot → copy token
        2. Start a chat with your bot, get chat_id via getUpdates API
        3. export MEMGAR_TELEGRAM_TOKEN=... MEMGAR_TELEGRAM_CHAT_ID=...

    The bot sends an inline keyboard with Approve/Deny buttons.
    Buttons link to the callback server URL.
    """

    API = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(
        self,
        token: Optional[str] = None,
        chat_id: Optional[str] = None,
    ) -> None:
        self._token   = token   or os.environ.get("MEMGAR_TELEGRAM_TOKEN", "")
        self._chat_id = chat_id or os.environ.get("MEMGAR_TELEGRAM_CHAT_ID", "")

    def send(self, request: ApprovalRequest, approve_url: str, deny_url: str) -> bool:
        if not self._token or not self._chat_id:
            logger.warning("[HITL] TelegramNotifier: token or chat_id not configured")
            return False
        try:
            import urllib.request as req
            emoji = self._risk_emoji(request.risk_level)
            details_text = self._format_details(request.details)
            expires_in = int(request.timeout_seconds_remaining)

            text = (
                f"{emoji} *Agent Action Requires Approval*\n\n"
                f"*Action:* `{request.action}`\n"
                f"*Risk:* {request.risk_level.value.upper()}\n"
                f"*Session:* `{request.session_id}`\n"
                f"*Expires in:* {expires_in}s\n\n"
                f"*Details:*\n```\n{details_text}\n```\n\n"
                f"_Request: {request.request_id}_"
            )

            payload = {
                "chat_id":    self._chat_id,
                "text":       text,
                "parse_mode": "Markdown",
                "reply_markup": {
                    "inline_keyboard": [[
                        {"text": "✅ Approve", "url": approve_url},
                        {"text": "❌ Deny",    "url": deny_url},
                    ]]
                }
            }

            url = self.API.format(token=self._token)
            data = json.dumps(payload).encode("utf-8")
            req.urlopen(req.Request(
                url, data=data,
                headers={"Content-Type": "application/json"}
            ), timeout=10)
            return True
        except Exception as e:
            logger.error("[HITL] Telegram send failed: %s", e)
            return False


class WebhookNotifier(HITLNotifier):
    """
    POST approval requests to any HTTP webhook.

    The webhook receives a JSON body with the full ApprovalRequest
    plus approve_url and deny_url. Your endpoint can render a
    custom UI, send to any other channel, etc.

    Args:
        url:     Webhook endpoint URL
        headers: Additional headers (e.g. Authorization)
    """

    def __init__(
        self,
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._url     = url or os.environ.get("MEMGAR_HITL_WEBHOOK", "")
        self._headers = headers or {}

    def send(self, request: ApprovalRequest, approve_url: str, deny_url: str) -> bool:
        if not self._url:
            logger.warning("[HITL] WebhookNotifier: no URL configured")
            return False
        try:
            import urllib.request as req
            payload = {
                **request.to_dict(),
                "approve_url": approve_url,
                "deny_url":    deny_url,
            }
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", **self._headers}
            r = req.Request(self._url, data=data, headers=headers)
            req.urlopen(r, timeout=10)
            return True
        except Exception as e:
            logger.error("[HITL] Webhook send failed: %s", e)
            return False


class NullNotifier(HITLNotifier):
    """No-op notifier for testing — sends nothing, no CLI fallback."""
    def send(self, request, approve_url, deny_url): return True


class CLINotifier(HITLNotifier):
    """
    Interactive terminal prompt — for development and testing.

    Prints the approval request to stdout and waits for keyboard input.
    Does NOT respect timeout (blocks until input).
    """

    def send(self, request: ApprovalRequest, approve_url: str, deny_url: str) -> bool:
        # Print is handled by HITLCheckpoint._wait_cli — just signal OK
        return True


class EmailNotifier(HITLNotifier):
    """
    Send approval requests via email using SMTP.

    Args:
        smtp_host:   SMTP server host
        smtp_port:   SMTP port (default 587)
        username:    SMTP username / from address
        password:    SMTP password (or app password)
        to_email:    Recipient email address
        use_tls:     Use STARTTLS (default True)

    Or via environment:
        MEMGAR_EMAIL_HOST, MEMGAR_EMAIL_PORT, MEMGAR_EMAIL_USER,
        MEMGAR_EMAIL_PASS, MEMGAR_EMAIL_TO
    """

    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        to_email: Optional[str] = None,
        use_tls: bool = True,
    ) -> None:
        self._host   = smtp_host or os.environ.get("MEMGAR_EMAIL_HOST", "")
        self._port   = smtp_port
        self._user   = username  or os.environ.get("MEMGAR_EMAIL_USER", "")
        self._pass   = password  or os.environ.get("MEMGAR_EMAIL_PASS", "")
        self._to     = to_email  or os.environ.get("MEMGAR_EMAIL_TO", "")
        self._tls    = use_tls

    def send(self, request: ApprovalRequest, approve_url: str, deny_url: str) -> bool:
        if not all([self._host, self._user, self._to]):
            logger.warning("[HITL] EmailNotifier: SMTP not configured")
            return False
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            emoji = self._risk_emoji(request.risk_level)
            details_html = "".join(
                f"<tr><td><b>{k}</b></td><td>{str(v)[:200]}</td></tr>"
                for k, v in request.details.items()
            )
            expires_in = int(request.timeout_seconds_remaining)

            html = f"""
            <h2>{emoji} Agent Action Requires Approval</h2>
            <table border="1" cellpadding="6">
              <tr><td><b>Action</b></td><td><code>{request.action}</code></td></tr>
              <tr><td><b>Risk Level</b></td><td>{request.risk_level.value.upper()}</td></tr>
              <tr><td><b>Session</b></td><td>{request.session_id}</td></tr>
              <tr><td><b>Expires in</b></td><td>{expires_in}s</td></tr>
              {details_html}
            </table>
            <br>
            <a href="{approve_url}" style="background:#22c55e;color:white;padding:10px 20px;text-decoration:none;border-radius:4px">
              ✅ Approve
            </a>
            &nbsp;&nbsp;
            <a href="{deny_url}" style="background:#ef4444;color:white;padding:10px 20px;text-decoration:none;border-radius:4px">
              ❌ Deny
            </a>
            <br><br>
            <small>Request ID: {request.request_id}</small>
            """

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Memgar HITL] {emoji} Approval Required: {request.action}"
            msg["From"]    = self._user
            msg["To"]      = self._to
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self._host, self._port) as s:
                if self._tls:
                    s.starttls()
                if self._pass:
                    s.login(self._user, self._pass)
                s.send_message(msg)
            return True
        except Exception as e:
            logger.error("[HITL] Email send failed: %s", e)
            return False


# ---------------------------------------------------------------------------
# Callback Server — receives Approve/Deny from browser
# ---------------------------------------------------------------------------

_pending_requests: Dict[str, ApprovalRequest] = {}
_pending_lock = threading.Lock()


class _HITLHandler(BaseHTTPRequestHandler):
    """Handles approve/deny callback clicks."""

    def log_message(self, *a): pass  # suppress access log

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        token  = params.get("token", [""])[0]
        action_str = params.get("action", [""])[0]

        with _pending_lock:
            req = next(
                (r for r in _pending_requests.values() if r.token == token),
                None
            )

        if req is None:
            self._respond(404, "Not found or expired")
            return

        if req.is_expired:
            req.status = ApprovalStatus.EXPIRED
            self._respond(410, "Request expired")
            return

        if req.status != ApprovalStatus.PENDING:
            self._respond(200, f"Already {req.status.value}")
            return

        if action_str == "approve":
            req.status     = ApprovalStatus.APPROVED
            req.decided_at = time.time()
            req.decided_by = "http_callback"
            self._respond(200, "✅ Action approved! The agent will proceed.")
            logger.info("[HITL] Approved: %s (%s)", req.action, req.request_id)
        elif action_str == "deny":
            req.status     = ApprovalStatus.DENIED
            req.decided_at = time.time()
            req.decided_by = "http_callback"
            self._respond(200, "❌ Action denied! The agent has been stopped.")
            logger.info("[HITL] Denied: %s (%s)", req.action, req.request_id)
        else:
            self._respond(400, "Invalid action")

    def _respond(self, code: int, message: str) -> None:
        body = f"""<!DOCTYPE html>
<html><head><meta charset=utf-8>
<style>body{{font-family:sans-serif;text-align:center;padding:3rem;background:#0f172a;color:#e2e8f0}}
h1{{font-size:2rem}}p{{color:#94a3b8}}</style></head>
<body><h1>{message}</h1><p>You can close this tab.</p></body></html>""".encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HITLServer:
    """
    Lightweight HTTP server that receives approve/deny callbacks.

    Runs in a background thread. Generates approve/deny URLs for notifiers.

    Args:
        host: Bind host (default: 127.0.0.1)
        port: Listen port (default: 17890)
        public_base_url: Base URL for generated links (use ngrok/tunnel for remote)
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 17890,
        public_base_url: Optional[str] = None,
    ) -> None:
        self.host = host
        self.port = port
        self._base = (public_base_url or f"http://{host}:{port}").rstrip("/")
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._server = HTTPServer((self.host, self.port), _HITLHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("[HITL] Callback server: %s", self._base)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()

    def approve_url(self, token: str) -> str:
        return f"{self._base}/hitl?action=approve&token={token}"

    def deny_url(self, token: str) -> str:
        return f"{self._base}/hitl?action=deny&token={token}"

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ---------------------------------------------------------------------------
# Main Checkpoint
# ---------------------------------------------------------------------------

class HITLCheckpoint:
    """
    Human-in-the-Loop approval checkpoint.

    Blocks agent execution until a human approves or denies the action,
    or until the timeout expires (defaults to deny on timeout).

    Usage::

        checkpoint = HITLCheckpoint(
            notifiers=[
                SlackNotifier(webhook_url="https://hooks.slack.com/..."),
                TelegramNotifier(token="...", chat_id="..."),
            ],
            timeout_seconds=300,   # 5 minutes
            default_on_timeout="deny",
        )

        # In your agent — blocks here
        checkpoint.require(
            action="send_email",
            details={"to": "ceo@company.com", "amount": "$5,000"},
            risk_level="high",
        )
        # Only here if approved ↓
        do_the_action()

    Args:
        notifiers:           List of HITLNotifier instances.
        timeout_seconds:     Max wait time per approval (default 300s).
        default_on_timeout:  "deny" (safe default) or "approve".
        server_port:         Port for callback server (default 17890).
        public_base_url:     Public URL for callback links (ngrok etc).
        session_id:          Session identifier for audit trail.
        agent_id:            Agent identifier.
        on_approved:         Callback(ApprovalResult) on approval.
        on_denied:           Callback(ApprovalResult) on denial.
        raise_on_deny:       Raise HITLDeniedError on denial (default True).
        auto_approve_low:    Auto-approve LOW risk actions (default True).
    """

    def __init__(
        self,
        notifiers: Optional[List[HITLNotifier]] = None,
        timeout_seconds: float = 300.0,
        default_on_timeout: str = "deny",
        server_port: int = 17890,
        public_base_url: Optional[str] = None,
        session_id: str = "default",
        agent_id: str = "agent",
        on_approved: Optional[Callable[[ApprovalResult], None]] = None,
        on_denied: Optional[Callable[[ApprovalResult], None]] = None,
        raise_on_deny: bool = True,
        auto_approve_low: bool = True,
    ) -> None:
        self._notifiers       = notifiers or [CLINotifier()]
        self._timeout         = timeout_seconds
        self._default_timeout = default_on_timeout
        self._session_id      = session_id
        self._agent_id        = agent_id
        self._on_approved     = on_approved
        self._on_denied       = on_denied
        self._raise_on_deny   = raise_on_deny
        self._auto_approve_low = auto_approve_low
        self._stats = {"approved": 0, "denied": 0, "timeout": 0, "auto_approved": 0}

        # Start callback server
        self._server = HITLServer(
            port=server_port,
            public_base_url=public_base_url,
        )
        self._server.start()

    # ── Public API ─────────────────────────────────────────────────────────

    def require(
        self,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        risk_level: str = "high",
        timeout_seconds: Optional[float] = None,
        request_id: Optional[str] = None,
    ) -> ApprovalResult:
        """
        Require human approval before proceeding.

        Blocks until approved, denied, or timeout.

        Args:
            action:          Human-readable action name ("send_email", "delete_file")
            details:         Key-value details shown to the approver
            risk_level:      "low" | "medium" | "high" | "critical"
            timeout_seconds: Override default timeout for this request
            request_id:      Custom request ID (auto-generated if None)

        Returns:
            ApprovalResult

        Raises:
            HITLDeniedError   — if denied and raise_on_deny=True
            HITLTimeoutError  — if timeout and raise_on_deny=True
        """
        level = RiskLevel(risk_level) if isinstance(risk_level, str) else risk_level

        # Auto-approve LOW risk
        if level == RiskLevel.LOW and self._auto_approve_low:
            self._stats["auto_approved"] += 1
            logger.info("[HITL] Auto-approved LOW risk: %s", action)
            return ApprovalResult(
                request_id = request_id or str(uuid.uuid4()),
                status     = ApprovalStatus.APPROVED,
                action     = action,
                risk_level = level,
                wait_ms    = 0.0,
                decided_by = "auto",
                reason     = "auto_approved_low_risk",
            )

        timeout = timeout_seconds or self._timeout
        token   = _make_token()
        rid     = request_id or str(uuid.uuid4())
        now     = time.time()

        req = ApprovalRequest(
            request_id = rid,
            action     = action,
            details    = details or {},
            risk_level = level,
            created_at = now,
            timeout_at = now + timeout,
            session_id = self._session_id,
            agent_id   = self._agent_id,
            token      = token,
        )

        # Register
        with _pending_lock:
            _pending_requests[rid] = req

        try:
            result = self._wait(req, timeout)
        finally:
            with _pending_lock:
                _pending_requests.pop(rid, None)

        # Callbacks
        if result.approved and self._on_approved:
            try: self._on_approved(result)
            except Exception: pass
        elif result.denied and self._on_denied:
            try: self._on_denied(result)
            except Exception: pass

        # Update stats
        self._stats[result.status.value if result.status.value in self._stats else "denied"] += 1

        # Raise
        if self._raise_on_deny and not result.approved:
            if result.status == ApprovalStatus.TIMEOUT:
                raise HITLTimeoutError(
                    f"HITL timeout after {timeout:.0f}s — action '{action}' denied by default",
                    result=result,
                )
            raise HITLDeniedError(
                f"HITL denied — action '{action}' was rejected",
                result=result,
            )

        return result

    def guard(
        self,
        action: str,
        details_fn: Optional[Callable] = None,
        risk_level: str = "high",
    ) -> Callable:
        """
        Decorator — require approval before a function executes.

        Usage::

            @checkpoint.guard(action="delete_file", risk_level="critical")
            def delete_important_file(path: str):
                os.remove(path)
        """
        def decorator(fn: Callable) -> Callable:
            @wraps(fn)
            def wrapper(*args, **kwargs):
                details = {}
                if details_fn:
                    details = details_fn(*args, **kwargs)
                elif args or kwargs:
                    # Auto-extract readable details
                    if args:
                        details["arg0"] = str(args[0])[:200]
                    details.update({k: str(v)[:200] for k, v in list(kwargs.items())[:5]})
                self.require(action=action, details=details, risk_level=risk_level)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    # ── Internal ───────────────────────────────────────────────────────────

    def _wait(self, req: ApprovalRequest, timeout: float) -> ApprovalResult:
        """Send notification and poll for decision."""
        approve_url = self._server.approve_url(req.token)
        deny_url    = self._server.deny_url(req.token)

        t0 = time.perf_counter()

        # Send to all notifiers
        has_cli = any(isinstance(n, CLINotifier) for n in self._notifiers)
        sent = False
        for notifier in self._notifiers:
            if isinstance(notifier, CLINotifier):
                continue
            try:
                if notifier.send(req, approve_url, deny_url):
                    sent = True
                    logger.info("[HITL] Notification sent via %s", type(notifier).__name__)
            except Exception as e:
                logger.error("[HITL] Notifier %s failed: %s", type(notifier).__name__, e)

        # CLI fallback or primary
        if has_cli or not sent:
            result = self._wait_cli(req, timeout)
            elapsed = (time.perf_counter() - t0) * 1000
            return ApprovalResult(
                request_id = req.request_id,
                status     = req.status,
                action     = req.action,
                risk_level = req.risk_level,
                wait_ms    = elapsed,
                decided_by = req.decided_by,
                reason     = req.reason,
            )

        # Poll for callback decision
        poll_interval = 0.5
        deadline = time.time() + timeout
        while time.time() < deadline:
            if req.status != ApprovalStatus.PENDING:
                break
            time.sleep(poll_interval)

        # Timeout
        if req.status == ApprovalStatus.PENDING:
            if self._default_timeout == "approve":
                req.status     = ApprovalStatus.APPROVED
                req.decided_by = "timeout_default_approve"
            else:
                req.status     = ApprovalStatus.TIMEOUT
                req.decided_by = "timeout_default_deny"
            req.decided_at = time.time()

        elapsed = (time.perf_counter() - t0) * 1000
        return ApprovalResult(
            request_id = req.request_id,
            status     = req.status,
            action     = req.action,
            risk_level = req.risk_level,
            wait_ms    = elapsed,
            decided_by = req.decided_by,
            reason     = req.reason,
        )

    def _wait_cli(self, req: ApprovalRequest, timeout: float) -> ApprovalResult:
        """Interactive CLI approval for dev/testing."""
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
            req.risk_level.value, "⚪"
        )
        print(f"\n{'='*60}")
        print(f"{emoji} HITL APPROVAL REQUIRED")
        print(f"{'='*60}")
        print(f"Action:    {req.action}")
        print(f"Risk:      {req.risk_level.value.upper()}")
        print(f"Session:   {req.session_id}")
        print(f"Timeout:   {int(timeout)}s")
        print(f"Details:")
        for k, v in req.details.items():
            print(f"  {k}: {str(v)[:120]}")
        print(f"{'='*60}")

        t0 = time.perf_counter()
        try:
            ans = input("Approve? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"

        elapsed = (time.perf_counter() - t0) * 1000
        if ans in ("y", "yes", "approve"):
            req.status     = ApprovalStatus.APPROVED
            req.decided_by = "cli"
            print("✅ Approved")
        else:
            req.status     = ApprovalStatus.DENIED
            req.decided_by = "cli"
            print("❌ Denied")

        req.decided_at = time.time()
        return ApprovalResult(
            request_id = req.request_id,
            status     = req.status,
            action     = req.action,
            risk_level = req.risk_level,
            wait_ms    = elapsed,
            decided_by = req.decided_by,
        )


# ---------------------------------------------------------------------------
# Predefined high-risk action categories
# ---------------------------------------------------------------------------

HIGH_RISK_ACTIONS = {
    # Financial
    "transfer_funds", "send_payment", "wire_transfer", "pay_invoice",
    "crypto_transfer", "bank_transfer", "purchase", "refund",
    # Data destruction
    "delete_file", "delete_database", "drop_table", "truncate_table",
    "wipe_disk", "rm_rf", "format_drive", "purge_data",
    # Communication
    "send_email", "send_sms", "post_tweet", "post_slack", "send_telegram",
    "publish_post", "broadcast_message", "send_newsletter",
    # Access / credentials
    "change_password", "reset_credentials", "revoke_token", "grant_access",
    "add_admin", "elevate_privileges", "create_api_key",
    # Infrastructure
    "deploy_code", "restart_server", "shutdown_service", "scale_cluster",
    "modify_firewall", "open_port", "ssh_execute", "run_script",
    # Legal / compliance
    "sign_contract", "submit_form", "file_report", "gdpr_delete",
}

CRITICAL_ACTIONS = {
    "wire_transfer", "crypto_transfer", "drop_table", "wipe_disk",
    "rm_rf", "format_drive", "purge_data", "add_admin",
    "elevate_privileges", "modify_firewall", "gdpr_delete",
    "delete_file", "delete_data", "delete_record", "delete_database",
    "delete_bucket", "delete_table", "delete_collection",
}


def classify_action(action: str) -> RiskLevel:
    """Classify an action name into a RiskLevel."""
    action_lower = action.lower().replace("-", "_").replace(" ", "_")
    if action_lower in CRITICAL_ACTIONS:
        return RiskLevel.CRITICAL
    if action_lower in HIGH_RISK_ACTIONS:
        return RiskLevel.HIGH
    # Heuristic keyword scan
    critical_kw = ["delete", "drop", "wipe", "purge", "rm_rf", "format", "admin"]
    high_kw = ["transfer", "pay", "send", "deploy", "restart", "shutdown",
               "password", "credential", "token", "grant", "ssh", "execute"]
    for kw in critical_kw:
        if kw in action_lower:
            return RiskLevel.CRITICAL
    for kw in high_kw:
        if kw in action_lower:
            return RiskLevel.HIGH
    return RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _make_token() -> str:
    return hashlib.sha256(
        f"{uuid.uuid4()}{time.perf_counter_ns()}".encode()
    ).hexdigest()[:32]


def create_checkpoint(
    notifiers: Optional[List[HITLNotifier]] = None,
    timeout_seconds: float = 300.0,
    **kwargs,
) -> HITLCheckpoint:
    """Factory — create a HITLCheckpoint with sensible defaults."""
    if notifiers is None:
        notifiers = [CLINotifier()]
    return HITLCheckpoint(notifiers=notifiers, timeout_seconds=timeout_seconds, **kwargs)
