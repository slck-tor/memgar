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
    ) -> None:
        self.policy = policy or GatewayPolicy()
        self.analyzer = analyzer or Analyzer(use_llm=False)
        self._client: Optional[httpx.AsyncClient] = None

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
        """Return ``{"decision": ..., "risk": ..., "reason": ..., "payload": ...}``.

        ``payload`` may be returned modified (sanitised) when policy says so.
        """
        ip = self.policy.input
        if not ip.enabled:
            return {"decision": PolicyDecision.ALLOW, "risk": 0, "reason": "", "payload": payload}

        # Block disallowed model names early
        model = (payload.get("model") or "").lower()
        for blocked in ip.blocked_models:
            if blocked.lower() in model:
                return {
                    "decision": PolicyDecision.BLOCK,
                    "risk": 100,
                    "reason": f"model '{model}' is on the gateway blocklist",
                    "payload": payload,
                }

        max_risk = 0
        worst_explanation = ""
        sanitised_payload = payload

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
                }

            if result.risk_score > max_risk:
                max_risk = result.risk_score
                worst_explanation = result.explanation

            if result.decision == Decision.BLOCK:
                return {
                    "decision": PolicyDecision.BLOCK, "risk": result.risk_score,
                    "reason": result.explanation, "payload": payload,
                }

        if max_risk >= ip.block_risk_score:
            return {
                "decision": PolicyDecision.BLOCK, "risk": max_risk,
                "reason": worst_explanation, "payload": payload,
            }
        if max_risk >= ip.sanitize_risk_score:
            return {
                "decision": PolicyDecision.SANITIZE, "risk": max_risk,
                "reason": worst_explanation, "payload": sanitised_payload,
            }
        return {
            "decision": PolicyDecision.ALLOW, "risk": max_risk,
            "reason": "", "payload": sanitised_payload,
        }

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
                    }
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

def create_app(policy: Optional[GatewayPolicy] = None, analyzer: Optional[Analyzer] = None) -> FastAPI:
    gateway = Gateway(policy=policy, analyzer=analyzer)

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
