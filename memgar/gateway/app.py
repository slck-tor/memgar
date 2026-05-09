"""
Memgar AI Gateway — FastAPI reverse proxy with input/output enforcement.

This is the **transport layer** that turns Memgar from a library into a
gateway product. Drop-in compatibility with both Anthropic and OpenAI APIs:

    # before
    client = OpenAI(base_url="https://api.openai.com/v1")

    # after — agent code unchanged otherwise
    client = OpenAI(base_url="https://memgar.local:8080/v1")

Every request is:
  1. **inspected** with ``Analyzer.analyze()`` for poisoning indicators
  2. forwarded upstream when allowed
  3. **streamed back** through ``ResponseFilter`` which scans for canary
     leaks, secrets, jailbreak responses, and redacts / blocks as needed

When ``--use-llm`` is enabled, the gateway can also escalate uncertain
verdicts to Claude itself for adjudication.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from memgar import Analyzer, MemoryEntry
from memgar.models import Decision

from .policy import GatewayPolicy, InputPolicy, OutputPolicy, PolicyDecision

logger = logging.getLogger("memgar.gateway")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_input_texts(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return [{role, content}, ...] for every scannable text in a request.

    Works for both:
      * OpenAI-style:    {"messages": [{"role": ..., "content": ...}]}
      * Anthropic-style: {"messages": [...], "system": "..."}
      * Single-turn:     {"prompt": "...", "input": "..."}
    """
    out: List[Dict[str, str]] = []
    if not isinstance(payload, dict):
        return out

    # System prompt (Anthropic)
    sys_p = payload.get("system")
    if isinstance(sys_p, str):
        out.append({"role": "system", "content": sys_p})

    # Messages array
    messages = payload.get("messages")
    if isinstance(messages, list):
        for m in messages:
            if not isinstance(m, dict):
                continue
            role = m.get("role", "user")
            content = m.get("content")
            if isinstance(content, str):
                out.append({"role": role, "content": content})
            elif isinstance(content, list):
                # multipart content blocks
                for blk in content:
                    if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                        out.append({"role": role, "content": blk["text"]})

    # Legacy single-prompt fields
    for key in ("prompt", "input", "query"):
        v = payload.get(key)
        if isinstance(v, str):
            out.append({"role": "user", "content": v})

    return out


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

class Gateway:
    """The reverse proxy core. Holds an Analyzer and a policy."""

    def __init__(
        self,
        policy: Optional[GatewayPolicy] = None,
        analyzer: Optional[Analyzer] = None,
        policy_engine: Optional[Any] = None,
        quarantine_store: Optional[Any] = None,
        review_notifier: Optional[Any] = None,
        sanitizer: Optional[Any] = None,
        siem_router: Optional[Any] = None,
    ) -> None:
        """
        Args:
            policy: ``GatewayPolicy`` (uses defaults if omitted).
            analyzer: Pre-built ``Analyzer`` (defaults to ``Analyzer(use_llm=False)``).
            policy_engine: Optional ``PolicyEngine``; when present its verdict
                drives the gateway. The gateway will *materialize* SANITIZE
                (rewrites payload text) and QUARANTINE/HUMAN_REVIEW (HTTP 202
                with the quarantine ID) instead of silently downgrading them.
            quarantine_store: Optional ``QuarantineStore``; when present the
                gateway persists any SANITIZE/QUARANTINE/HUMAN_REVIEW request
                so reviewers can inspect the original payload.
            review_notifier: Optional ``ReviewNotifier``; fires on HUMAN_REVIEW.
            sanitizer: Optional sanitizer (defaults to ``InstructionSanitizer``).
                Used to rewrite messages when verdict==SANITIZE.
            siem_router: Optional ``SIEMRouter``; emits ``THREAT_DETECTED``
                events on BLOCK and ``HITL_REQUESTED`` on HUMAN_REVIEW.
        """
        self.policy = policy or GatewayPolicy()
        self.analyzer = analyzer or Analyzer(use_llm=False)
        self._client: Optional[httpx.AsyncClient] = None
        self._policy_engine = policy_engine
        self._quarantine_store = quarantine_store
        self._review_notifier = review_notifier
        self._siem_router = siem_router

        # Default sanitizer
        if sanitizer is not None:
            self._sanitizer = sanitizer
        else:
            try:
                from memgar.sanitizer import InstructionSanitizer
                self._sanitizer = InstructionSanitizer()
            except Exception:
                self._sanitizer = None

        # Back-fill the engine's backends if the caller wired them only here
        if self._policy_engine is not None:
            if (self._quarantine_store is not None
                    and getattr(self._policy_engine, "quarantine_store", None) is None
                    and hasattr(self._policy_engine, "attach_quarantine_store")):
                self._policy_engine.attach_quarantine_store(self._quarantine_store)
            if (self._review_notifier is not None
                    and getattr(self._policy_engine, "review_notifier", None) is None
                    and hasattr(self._policy_engine, "attach_review_notifier")):
                self._policy_engine.attach_review_notifier(self._review_notifier)
            if (self._sanitizer is not None
                    and hasattr(self._policy_engine, "attach_sanitizer")):
                self._policy_engine.attach_sanitizer(self._sanitizer)

    async def startup(self) -> None:
        if self._client is not None:
            # Idempotent — preserves test-injected mock clients.
            return
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.policy.upstream_timeout_seconds),
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )

    async def shutdown(self) -> None:
        if self._client:
            await self._client.aclose()

    # -----------------------------------------------------------------
    # Inbound scanning
    # -----------------------------------------------------------------

    def scan_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspect a request payload and return an enforcement verdict.

        Returns a dict with:
            decision         — gateway PolicyDecision enum
            risk             — worst per-message risk score
            reason           — explanation
            payload          — possibly-sanitized payload for forwarding
            quarantine_id    — set when verdict held the request for review
            notified         — True iff a HUMAN_REVIEW notifier accepted
            matched_rule     — PolicyEngine rule that fired (when applicable)
        """
        ip = self.policy.input
        if not ip.enabled:
            return {
                "decision": PolicyDecision.ALLOW, "risk": 0, "reason": "",
                "payload": payload, "quarantine_id": "", "notified": False,
                "matched_rule": "",
            }

        # Block disallowed model names early
        model = (payload.get("model") or "").lower()
        for blocked in ip.blocked_models:
            if blocked.lower() in model:
                return {
                    "decision": PolicyDecision.BLOCK,
                    "risk": 100,
                    "reason": f"model '{model}' is on the gateway blocklist",
                    "payload": payload,
                    "quarantine_id": "",
                    "notified": False,
                    "matched_rule": "blocked_model",
                }

        max_risk = 0
        worst_explanation = ""
        worst_analysis: Optional[Any] = None
        worst_text = ""
        worst_role = ""

        texts = _extract_input_texts(payload)
        if not ip.scan_all_messages and texts:
            texts = [texts[-1]]

        for entry in texts:
            try:
                result = self.analyzer.analyze(MemoryEntry(
                    content=entry["content"],
                    metadata={"role": entry["role"], "surface": "gateway_input"},
                ))
            except Exception as exc:
                logger.warning("gateway: analyze() failed: %s", exc)
                if self.policy.fail_open:
                    continue
                return {
                    "decision": PolicyDecision.BLOCK, "risk": 100,
                    "reason": f"analyzer error: {exc}", "payload": payload,
                    "quarantine_id": "", "notified": False,
                    "matched_rule": "analyzer_error",
                }

            # Always retain at least one analysis so the PolicyEngine path
            # can fire even on benign payloads (it has rules beyond risk
            # thresholds — block_source, allow_agent, etc.).
            if worst_analysis is None or result.risk_score > max_risk:
                max_risk = result.risk_score
                worst_explanation = result.explanation
                worst_analysis = result
                worst_text = entry["content"]
                worst_role = entry["role"]

            # Hard-BLOCK shortcut applies only when no PolicyEngine is wired —
            # otherwise the engine owns the verdict (it has its own
            # ``analyzer_hard_block`` rule at priority 5, plus rules that may
            # legitimately downgrade an analyzer block, e.g. trusted agent).
            if result.decision == Decision.BLOCK and self._policy_engine is None:
                return self._block_verdict(
                    payload=payload, risk=result.risk_score,
                    reason=result.explanation, matched_rule="analyzer_hard_block",
                    content=entry["content"],
                )

        # Delegate to PolicyEngine when available; fall back to inline thresholds
        if self._policy_engine is not None and worst_analysis is not None:
            from memgar.policy_engine import PolicyVerdict
            pe_decision = self._policy_engine.decide_from_analysis(
                worst_analysis,
                content=worst_text,
                boundary="gateway_input",
                source_type="gateway",
                agent_id=str(payload.get("user", "")),
                was_sanitized=False,
            )
            verdict = pe_decision.verdict

            if verdict == PolicyVerdict.BLOCK:
                return self._block_verdict(
                    payload=payload, risk=max_risk,
                    reason=pe_decision.reason or worst_explanation,
                    matched_rule=pe_decision.matched_rule,
                    content=worst_text,
                )

            if verdict in (PolicyVerdict.QUARANTINE, PolicyVerdict.HUMAN_REVIEW):
                # Engine already persisted to its own quarantine_store (if wired),
                # but if the gateway has its own store and the engine didn't,
                # persist here too so reviewers always see the request.
                qid = pe_decision.quarantine_id or self._persist_quarantine(
                    content=worst_text,
                    reason=pe_decision.reason or worst_explanation,
                    verdict=verdict.value,
                    risk_score=max_risk,
                    role=worst_role,
                    matched_rule=pe_decision.matched_rule,
                    payload_preview=str(payload)[:500],
                )
                gw_decision = (
                    PolicyDecision.QUARANTINE if verdict == PolicyVerdict.QUARANTINE
                    else PolicyDecision.HUMAN_REVIEW
                )
                return {
                    "decision": gw_decision, "risk": max_risk,
                    "reason": pe_decision.reason or worst_explanation,
                    "payload": payload,
                    "quarantine_id": qid,
                    "notified": pe_decision.notified,
                    "matched_rule": pe_decision.matched_rule,
                }

            if verdict == PolicyVerdict.SANITIZE:
                # Rewrite the actual message content rather than passing it
                # through unchanged.  Use engine-supplied cleaned text when
                # available, else fall back to per-message sanitisation.
                sanitised_payload = self._materialize_sanitize(
                    payload, override_text=pe_decision.sanitized_content or None,
                )
                return {
                    "decision": PolicyDecision.SANITIZE, "risk": max_risk,
                    "reason": pe_decision.reason or worst_explanation,
                    "payload": sanitised_payload,
                    "quarantine_id": "", "notified": False,
                    "matched_rule": pe_decision.matched_rule,
                }

            # ALLOW
            return {
                "decision": PolicyDecision.ALLOW, "risk": max_risk,
                "reason": pe_decision.reason or "",
                "payload": payload,
                "quarantine_id": "", "notified": False,
                "matched_rule": pe_decision.matched_rule,
            }

        # ── Fallback: legacy inline threshold logic ──────────────────────────

        if max_risk >= ip.block_risk_score:
            return self._block_verdict(
                payload=payload, risk=max_risk, reason=worst_explanation,
                matched_rule="risk_block_threshold", content=worst_text,
            )
        if max_risk >= ip.sanitize_risk_score:
            sanitised_payload = self._materialize_sanitize(payload)
            return {
                "decision": PolicyDecision.SANITIZE, "risk": max_risk,
                "reason": worst_explanation, "payload": sanitised_payload,
                "quarantine_id": "", "notified": False,
                "matched_rule": "risk_sanitize_threshold",
            }
        return {
            "decision": PolicyDecision.ALLOW, "risk": max_risk,
            "reason": "", "payload": payload,
            "quarantine_id": "", "notified": False, "matched_rule": "",
        }

    # -----------------------------------------------------------------
    # Verdict materializers
    # -----------------------------------------------------------------

    def _block_verdict(
        self,
        *,
        payload: Dict[str, Any],
        risk: int,
        reason: str,
        matched_rule: str,
        content: str,
    ) -> Dict[str, Any]:
        """Build a BLOCK response and emit a SIEM event."""
        self._emit_siem_block(content=content, risk=risk, reason=reason, matched_rule=matched_rule)
        return {
            "decision": PolicyDecision.BLOCK, "risk": risk, "reason": reason,
            "payload": payload, "quarantine_id": "", "notified": False,
            "matched_rule": matched_rule,
        }

    def _materialize_sanitize(
        self,
        payload: Dict[str, Any],
        *,
        override_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Rewrite every scannable message in ``payload`` through the sanitizer.

        If ``override_text`` is provided (engine already produced cleaned text
        for the worst message) the *worst* message is replaced with that text;
        all other messages still go through ``sanitizer.sanitize()``.
        """
        if self._sanitizer is None and override_text is None:
            return payload

        new_payload = dict(payload)

        # System prompt
        sys_p = new_payload.get("system")
        if isinstance(sys_p, str) and self._sanitizer is not None:
            new_payload["system"] = self._sanitize_text(sys_p)

        # Messages
        msgs = new_payload.get("messages")
        if isinstance(msgs, list):
            new_msgs: List[Any] = []
            for m in msgs:
                if not isinstance(m, dict):
                    new_msgs.append(m)
                    continue
                new_m = dict(m)
                content = m.get("content")
                if isinstance(content, str):
                    new_m["content"] = self._sanitize_text(content)
                elif isinstance(content, list):
                    new_blocks: List[Any] = []
                    for blk in content:
                        if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                            new_blk = dict(blk)
                            new_blk["text"] = self._sanitize_text(blk["text"])
                            new_blocks.append(new_blk)
                        else:
                            new_blocks.append(blk)
                    new_m["content"] = new_blocks
                new_msgs.append(new_m)
            new_payload["messages"] = new_msgs

        # Single-prompt fields
        for key in ("prompt", "input", "query"):
            v = new_payload.get(key)
            if isinstance(v, str) and self._sanitizer is not None:
                new_payload[key] = self._sanitize_text(v)

        return new_payload

    def _sanitize_text(self, text: str) -> str:
        if self._sanitizer is None or not text:
            return text
        try:
            sr = self._sanitizer.sanitize(text)
            cleaned = getattr(sr, "sanitized_content", None)
            if cleaned is None:
                cleaned = getattr(sr, "sanitized_text", text)
            return cleaned if isinstance(cleaned, str) else text
        except Exception as exc:
            logger.warning("gateway: sanitizer failed: %s", exc)
            return text

    def _persist_quarantine(
        self,
        *,
        content: str,
        reason: str,
        verdict: str,
        risk_score: int,
        role: str,
        matched_rule: str,
        payload_preview: str,
    ) -> str:
        if self._quarantine_store is None:
            return ""
        try:
            return self._quarantine_store.put(
                content=content,
                reason=reason,
                verdict=verdict,
                boundary="gateway_input",
                source_type=f"gateway:{role}" if role else "gateway",
                risk_score=int(risk_score),
                matched_rule=matched_rule,
                metadata={"payload_preview": payload_preview},
            )
        except Exception as exc:
            logger.warning("gateway: quarantine_store.put failed: %s", exc)
            return ""

    def _emit_siem_block(
        self, *, content: str, risk: int, reason: str, matched_rule: str,
    ) -> None:
        if self._siem_router is None:
            return
        try:
            from memgar.siem import SIEMEvent, EventCategory
            severity = (
                "critical" if risk >= 90
                else "high" if risk >= 70
                else "medium"
            )
            self._siem_router.emit(SIEMEvent(
                category=EventCategory.THREAT_DETECTED,
                severity=severity,
                message=f"Gateway blocked request: {reason}",
                content_preview=(content or "")[:200],
                risk_score=int(risk),
                action="blocked",
                threat_id=matched_rule or None,
                extra={"boundary": "gateway_input", "matched_rule": matched_rule},
            ))
        except Exception as exc:
            logger.debug("gateway SIEM emit failed: %s", exc)

    # -----------------------------------------------------------------
    # Outbound scanning
    # -----------------------------------------------------------------

    def scan_chunk(self, chunk_text: str) -> Dict[str, Any]:
        """Scan a single completion chunk. Returns ``{"text": ..., "block": bool, "leaks": [...]}``."""
        op = self.policy.output
        if not op.enabled or not chunk_text:
            return {"text": chunk_text, "block": False, "leaks": []}

        # Canary leak — strongest possible signal
        leaks = []
        if op.block_on_canary_leak:
            try:
                leaks = self.analyzer.scan_output(chunk_text, sink="gateway_output")
            except Exception:
                leaks = []
            if leaks:
                return {"text": "", "block": True, "leaks": leaks}

        # Jailbreak text in completion
        for pat in self.policy.compiled_jailbreak():
            if pat.search(chunk_text):
                return {"text": "", "block": True, "leaks": []}

        # Secret / PII redaction
        out = chunk_text
        for pat in self.policy.compiled_redactions():
            out = pat.sub(op.redaction_token, out)
        return {"text": out, "block": False, "leaks": []}

    # -----------------------------------------------------------------
    # Forwarding
    # -----------------------------------------------------------------

    async def forward(self, request: Request, path: str) -> Response:
        if self._client is None:
            await self.startup()

        body_bytes = await request.body()
        is_json = (request.headers.get("content-type", "").startswith("application/json"))
        payload: Dict[str, Any] = {}
        if is_json and body_bytes:
            try:
                payload = json.loads(body_bytes)
            except json.JSONDecodeError:
                payload = {}

        # 1. Input scan
        verdict = self.scan_request(payload)

        if verdict["decision"] == PolicyDecision.BLOCK:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "type": "memgar_gateway_blocked",
                        "message": "Request blocked by Memgar gateway",
                        "risk_score": verdict["risk"],
                        "reason": verdict["reason"],
                        "matched_rule": verdict.get("matched_rule", ""),
                    }
                },
            )

        if verdict["decision"] in (PolicyDecision.QUARANTINE, PolicyDecision.HUMAN_REVIEW):
            # Hold the request — it is *not* forwarded upstream. Reviewers can
            # release the quarantine entry and the caller can retry.
            return JSONResponse(
                status_code=202,
                content={
                    "status": verdict["decision"].value,
                    "message": (
                        "Request held for review by Memgar gateway. "
                        "Use the quarantine_id to check status."
                    ),
                    "risk_score": verdict["risk"],
                    "reason": verdict["reason"],
                    "quarantine_id": verdict.get("quarantine_id", ""),
                    "notified": verdict.get("notified", False),
                    "matched_rule": verdict.get("matched_rule", ""),
                },
                headers={
                    "x-memgar-quarantine-id": verdict.get("quarantine_id", ""),
                    "x-memgar-decision": verdict["decision"].value,
                },
            )

        # 2. Forward to upstream
        body_to_send = (
            json.dumps(verdict["payload"]).encode("utf-8") if is_json else body_bytes
        )
        upstream_url = self.policy.upstream_base_url.rstrip("/") + "/" + path.lstrip("/")
        fwd_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() in {h.lower() for h in self.policy.forward_request_headers}
        }
        # Strip Host so httpx sets the upstream Host
        fwd_headers.pop("host", None)

        # 3. Forward & decide stream vs. one-shot
        wants_stream = bool(payload.get("stream"))
        upstream_req = self._client.build_request(
            request.method, upstream_url,
            params=request.query_params,
            headers=fwd_headers,
            content=body_to_send,
        )

        if not wants_stream:
            try:
                upstream_resp = await self._client.send(upstream_req)
            except httpx.HTTPError as exc:
                return JSONResponse(
                    status_code=502,
                    content={"error": {"type": "memgar_upstream_error", "message": str(exc)}},
                )
            text = upstream_resp.text
            scanned = self.scan_chunk(text)
            if scanned["block"]:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "type": "memgar_output_blocked",
                            "message": "Response blocked by Memgar gateway",
                            "canary_leaks": [
                                {"sink": l.sink, "tenant": l.tenant_id, "agent": l.agent_id}
                                for l in scanned["leaks"]
                            ],
                        }
                    },
                )
            return Response(
                content=scanned["text"],
                status_code=upstream_resp.status_code,
                headers={
                    k: v for k, v in upstream_resp.headers.items()
                    if k.lower() not in {"content-encoding", "content-length", "transfer-encoding", "connection"}
                },
                media_type=upstream_resp.headers.get("content-type"),
            )

        # Streaming path
        async def stream_iter() -> AsyncIterator[bytes]:
            try:
                upstream_resp = await self._client.send(upstream_req, stream=True)
            except httpx.HTTPError as exc:
                yield (
                    f"data: {{\"error\": \"upstream_error: {exc}\"}}\n\n"
                ).encode("utf-8")
                return
            try:
                async for chunk in upstream_resp.aiter_text():
                    scanned = self.scan_chunk(chunk)
                    if scanned["block"]:
                        yield b'data: {"error": "memgar_output_blocked"}\n\n'
                        await upstream_resp.aclose()
                        return
                    yield scanned["text"].encode("utf-8")
            finally:
                await upstream_resp.aclose()

        return StreamingResponse(
            stream_iter(),
            media_type="text/event-stream",
            headers={"x-memgar-gateway": "1"},
        )


# ---------------------------------------------------------------------------
# FastAPI factory
# ---------------------------------------------------------------------------

def create_app(
    policy: Optional[GatewayPolicy] = None,
    analyzer: Optional[Analyzer] = None,
    *,
    policy_engine: Optional[Any] = None,
    quarantine_store: Optional[Any] = None,
    review_notifier: Optional[Any] = None,
    sanitizer: Optional[Any] = None,
    siem_router: Optional[Any] = None,
) -> FastAPI:
    gateway = Gateway(
        policy=policy,
        analyzer=analyzer,
        policy_engine=policy_engine,
        quarantine_store=quarantine_store,
        review_notifier=review_notifier,
        sanitizer=sanitizer,
        siem_router=siem_router,
    )

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await gateway.startup()
        try:
            yield
        finally:
            await gateway.shutdown()

    app = FastAPI(title="Memgar Gateway", version="1.0", lifespan=lifespan)

    @app.get("/__memgar/health")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "upstream": gateway.policy.upstream_base_url,
            "input_enabled": gateway.policy.input.enabled,
            "output_enabled": gateway.policy.output.enabled,
        }

    @app.get("/__memgar/policy")
    async def policy_view() -> Dict[str, Any]:
        return {
            "upstream_base_url": gateway.policy.upstream_base_url,
            "input": {
                "enabled": gateway.policy.input.enabled,
                "block_risk_score": gateway.policy.input.block_risk_score,
                "sanitize_risk_score": gateway.policy.input.sanitize_risk_score,
                "scan_all_messages": gateway.policy.input.scan_all_messages,
                "blocked_models": gateway.policy.input.blocked_models,
            },
            "output": {
                "enabled": gateway.policy.output.enabled,
                "block_on_canary_leak": gateway.policy.output.block_on_canary_leak,
                "redact_count": len(gateway.policy.output.redact_patterns),
                "jailbreak_count": len(gateway.policy.output.jailbreak_response_patterns),
            },
        }

    @app.get("/__memgar/quarantine")
    async def list_quarantine() -> Dict[str, Any]:
        store = gateway._quarantine_store
        if store is None:
            return {"enabled": False, "entries": []}
        return {
            "enabled": True,
            "stats": store.stats(),
            "entries": [
                {
                    "id": e.id,
                    "verdict": e.verdict,
                    "boundary": e.boundary,
                    "risk_score": e.risk_score,
                    "reason": e.reason,
                    "agent_id": e.agent_id,
                    "source_type": e.source_type,
                    "matched_rule": e.matched_rule,
                    "created_ts": e.created_ts,
                    "age_seconds": round(e.age_seconds, 1),
                    "content_preview": e.content[:200],
                }
                for e in store.list_pending()
            ],
        }

    @app.post("/__memgar/quarantine/{entry_id}/release")
    async def release_quarantine(entry_id: str, reviewer: str = "anonymous") -> Dict[str, Any]:
        store = gateway._quarantine_store
        if store is None:
            raise HTTPException(status_code=503, detail="No quarantine store configured")
        try:
            entry = store.release(entry_id, reviewer=reviewer)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"entry {entry_id!r} not found")
        except Exception as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return {"status": "released", "entry_id": entry.id, "reviewer": reviewer}

    @app.post("/__memgar/quarantine/{entry_id}/dismiss")
    async def dismiss_quarantine(
        entry_id: str, reviewer: str = "anonymous", note: str = "",
    ) -> Dict[str, Any]:
        store = gateway._quarantine_store
        if store is None:
            raise HTTPException(status_code=503, detail="No quarantine store configured")
        try:
            entry = store.dismiss(entry_id, reviewer=reviewer, note=note)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"entry {entry_id!r} not found")
        except Exception as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return {"status": "dismissed", "entry_id": entry.id, "reviewer": reviewer, "note": note}

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def proxy(full_path: str, request: Request) -> Response:
        return await gateway.forward(request, full_path)

    app.state.gateway = gateway  # tests / introspection
    return app


def run(
    host: str = "0.0.0.0",
    port: int = 8080,
    upstream: str = "https://api.anthropic.com",
    use_llm: bool = False,
    block_risk_score: int = 70,
    sanitize_risk_score: int = 40,
    log_level: str = "info",
) -> None:
    """Programmatic entry point used by the CLI."""
    import uvicorn

    policy = GatewayPolicy(upstream_base_url=upstream)
    policy.input.block_risk_score = int(block_risk_score)
    policy.input.sanitize_risk_score = int(sanitize_risk_score)

    analyzer = Analyzer(use_llm=use_llm)
    app = create_app(policy=policy, analyzer=analyzer)
    uvicorn.run(app, host=host, port=port, log_level=log_level)


__all__ = ["Gateway", "create_app", "run"]
