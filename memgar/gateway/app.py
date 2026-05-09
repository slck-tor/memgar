"""
Memgar AI Gateway - FastAPI reverse proxy with input/output enforcement.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from memgar import Analyzer, MemoryEntry
from memgar.models import Decision

from .policy import GatewayPolicy, PolicyDecision

logger = logging.getLogger("memgar.gateway")


Path = List[Any]


# ---------------------------------------------------------------------------
# Request text extraction
# ---------------------------------------------------------------------------

def _append_text(out: List[Dict[str, Any]], role: str, content: str, path: Path, surface: str) -> None:
    if isinstance(content, str) and content:
        out.append({"role": role, "content": content, "path": path, "surface": surface})


def _collect_string_leaves(value: Any, path: Path, out: List[Dict[str, Any]], *, role: str, surface: str) -> None:
    if isinstance(value, str):
        _append_text(out, role, value, path, surface)
    elif isinstance(value, dict):
        for key, child in value.items():
            _collect_string_leaves(child, path + [key], out, role=role, surface=surface)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            _collect_string_leaves(child, path + [idx], out, role=role, surface=surface)


def _extract_input_texts(payload: Dict[str, Any], *, include_tools: bool = True) -> List[Dict[str, Any]]:
    """Return scannable request strings with JSON paths for safe rewriting."""

    out: List[Dict[str, Any]] = []
    if not isinstance(payload, dict):
        return out

    system = payload.get("system")
    if isinstance(system, str):
        _append_text(out, "system", system, ["system"], "system")
    elif isinstance(system, list):
        for idx, block in enumerate(system):
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                _append_text(out, "system", block["text"], ["system", idx, "text"], "system")

    messages = payload.get("messages")
    if isinstance(messages, list):
        for msg_idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "user"))
            content = msg.get("content")
            if isinstance(content, str):
                _append_text(out, role, content, ["messages", msg_idx, "content"], "message")
            elif isinstance(content, list):
                for block_idx, block in enumerate(content):
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        _append_text(
                            out,
                            role,
                            block["text"],
                            ["messages", msg_idx, "content", block_idx, "text"],
                            "message_block",
                        )

            if include_tools:
                function_call = msg.get("function_call")
                if isinstance(function_call, dict):
                    _collect_tool_arguments(
                        function_call.get("arguments"),
                        ["messages", msg_idx, "function_call", "arguments"],
                        out,
                        role=role,
                        surface="function_call_arguments",
                    )
                tool_calls = msg.get("tool_calls")
                if isinstance(tool_calls, list):
                    for call_idx, call in enumerate(tool_calls):
                        if not isinstance(call, dict):
                            continue
                        fn = call.get("function")
                        if isinstance(fn, dict):
                            _collect_tool_arguments(
                                fn.get("arguments"),
                                ["messages", msg_idx, "tool_calls", call_idx, "function", "arguments"],
                                out,
                                role=role,
                                surface="tool_call_arguments",
                            )

    for key in ("prompt", "input", "query"):
        value = payload.get(key)
        if isinstance(value, str):
            _append_text(out, "user", value, [key], key)
        elif include_tools and key == "input" and isinstance(value, (dict, list)):
            _collect_string_leaves(value, [key], out, role="user", surface="input")

    if include_tools:
        top_tool_calls = payload.get("tool_calls")
        if isinstance(top_tool_calls, list):
            for idx, call in enumerate(top_tool_calls):
                if isinstance(call, dict):
                    fn = call.get("function")
                    if isinstance(fn, dict):
                        _collect_tool_arguments(
                            fn.get("arguments"),
                            ["tool_calls", idx, "function", "arguments"],
                            out,
                            role="tool",
                            surface="tool_call_arguments",
                        )
        tools = payload.get("tools")
        if isinstance(tools, list):
            for idx, tool in enumerate(tools):
                if not isinstance(tool, dict):
                    continue
                for key in ("description",):
                    if isinstance(tool.get(key), str):
                        _append_text(out, "tool", tool[key], ["tools", idx, key], "tool_definition")
                fn = tool.get("function")
                if isinstance(fn, dict):
                    for key in ("description",):
                        if isinstance(fn.get(key), str):
                            _append_text(out, "tool", fn[key], ["tools", idx, "function", key], "tool_definition")

    return out


def _collect_tool_arguments(value: Any, path: Path, out: List[Dict[str, Any]], *, role: str, surface: str) -> None:
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except Exception:
            _append_text(out, role, value, path, surface)
            return
        nested: List[Dict[str, Any]] = []
        _collect_string_leaves(decoded, [], nested, role=role, surface=surface)
        if nested:
            # The JSON string itself is the rewrite unit. Sanitizing arbitrary
            # nested offsets inside an encoded JSON string is easy to corrupt;
            # blocking is safer unless the whole encoded value sanitizes cleanly.
            _append_text(out, role, value, path, surface)
        return
    _collect_string_leaves(value, path, out, role=role, surface=surface)


def _set_path(payload: Dict[str, Any], path: Path, value: str) -> bool:
    target: Any = payload
    try:
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        return True
    except Exception:
        return False


def _sanitize_text(content: str) -> Dict[str, Any]:
    try:
        from memgar.sanitizer import InstructionSanitizer, SanitizeAction

        result = InstructionSanitizer().sanitize(content)
        if result.action == SanitizeAction.BLOCK:
            return {"blocked": True, "content": "", "modified": False, "reason": "sanitizer blocked content"}
        sanitized = getattr(result, "sanitized_content", content)
        return {
            "blocked": False,
            "content": sanitized,
            "modified": bool(getattr(result, "was_modified", False)) and sanitized != content,
            "reason": "; ".join(getattr(result, "removal_reasons", []) or []),
        }
    except Exception as exc:
        return {"blocked": False, "content": content, "modified": False, "reason": f"sanitizer error: {exc}"}


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------

class Gateway:
    """Reverse proxy core. Holds an Analyzer, transport policy, and optional PolicyEngine."""

    def __init__(
        self,
        policy: Optional[GatewayPolicy] = None,
        analyzer: Optional[Analyzer] = None,
        policy_engine: Optional[Any] = None,
    ) -> None:
        self.policy = policy or GatewayPolicy()
        self.analyzer = analyzer or Analyzer(use_llm=False)
        self._client: Optional[httpx.AsyncClient] = None
        self._policy_engine = policy_engine

    async def startup(self) -> None:
        self.policy.validate_upstream_base_url()
        if self._client is not None:
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
        ip = self.policy.input
        if not ip.enabled:
            return {"decision": PolicyDecision.ALLOW, "risk": 0, "reason": "", "payload": payload}

        model = (payload.get("model") or "").lower() if isinstance(payload, dict) else ""
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
        analyzer_decision = "allow"
        sanitized_payload = copy.deepcopy(payload)
        was_sanitized = False

        texts = _extract_input_texts(payload, include_tools=ip.scan_tool_arguments)
        if not ip.scan_all_messages and texts:
            texts = [texts[-1]]

        for entry in texts:
            content = entry["content"]
            try:
                result = self.analyzer.analyze(MemoryEntry(
                    content=content,
                    metadata={
                        "role": entry.get("role", "user"),
                        "surface": entry.get("surface", "gateway_input"),
                        "gateway_path": ".".join(map(str, entry.get("path", []))),
                    },
                ))
            except Exception as exc:
                logger.warning("gateway: analyze() failed: %s", exc)
                if self.policy.fail_open:
                    continue
                return {
                    "decision": PolicyDecision.BLOCK,
                    "risk": 100,
                    "reason": f"analyzer error: {exc}",
                    "payload": payload,
                }

            if result.risk_score > max_risk:
                max_risk = int(result.risk_score)
                worst_explanation = result.explanation
            if result.decision == Decision.BLOCK:
                analyzer_decision = "block"
                return {
                    "decision": PolicyDecision.BLOCK,
                    "risk": result.risk_score,
                    "reason": result.explanation,
                    "payload": payload,
                }
            if result.decision == Decision.QUARANTINE and analyzer_decision != "block":
                analyzer_decision = "quarantine"

            if result.risk_score >= ip.sanitize_risk_score:
                sanitized = _sanitize_text(content)
                if sanitized["blocked"]:
                    return {
                        "decision": PolicyDecision.BLOCK,
                        "risk": max(result.risk_score, ip.block_risk_score),
                        "reason": sanitized["reason"] or result.explanation,
                        "payload": payload,
                    }
                if sanitized["modified"]:
                    if _set_path(sanitized_payload, entry["path"], sanitized["content"]):
                        was_sanitized = True

        if self._policy_engine is not None:
            from memgar.policy_engine import PolicyContext, PolicyVerdict

            ctx = PolicyContext(
                content="\n".join(e["content"] for e in texts),
                risk_score=max_risk,
                boundary="gateway_input",
                was_sanitized=was_sanitized,
                analyzer_decision=analyzer_decision,
            )
            pe_decision = self._policy_engine.decide(ctx)
            verdict_map = {
                PolicyVerdict.ALLOW: PolicyDecision.ALLOW,
                PolicyVerdict.SANITIZE: PolicyDecision.SANITIZE,
                PolicyVerdict.QUARANTINE: PolicyDecision.BLOCK,
                PolicyVerdict.HUMAN_REVIEW: PolicyDecision.BLOCK,
                PolicyVerdict.BLOCK: PolicyDecision.BLOCK,
            }
            gw_decision = verdict_map[pe_decision.verdict]
            if gw_decision == PolicyDecision.SANITIZE and not was_sanitized:
                gw_decision = PolicyDecision.BLOCK
            return {
                "decision": gw_decision,
                "risk": max_risk,
                "reason": pe_decision.reason or worst_explanation,
                "payload": sanitized_payload if was_sanitized else payload,
            }

        if max_risk >= ip.block_risk_score:
            return {
                "decision": PolicyDecision.BLOCK,
                "risk": max_risk,
                "reason": worst_explanation,
                "payload": payload,
            }
        if max_risk >= ip.sanitize_risk_score:
            if not was_sanitized:
                return {
                    "decision": PolicyDecision.BLOCK,
                    "risk": max_risk,
                    "reason": worst_explanation or "request required sanitization but no safe rewrite was produced",
                    "payload": payload,
                }
            return {
                "decision": PolicyDecision.SANITIZE,
                "risk": max_risk,
                "reason": worst_explanation,
                "payload": sanitized_payload,
            }
        return {"decision": PolicyDecision.ALLOW, "risk": max_risk, "reason": "", "payload": payload}

    # -----------------------------------------------------------------
    # Outbound scanning
    # -----------------------------------------------------------------

    def scan_chunk(self, chunk_text: str) -> Dict[str, Any]:
        op = self.policy.output
        if not op.enabled or not chunk_text:
            return {"text": chunk_text, "block": False, "leaks": []}

        leaks = []
        if op.block_on_canary_leak:
            try:
                leaks = self.analyzer.scan_output(chunk_text, sink="gateway_output")
            except Exception:
                leaks = []
            if leaks:
                return {"text": "", "block": True, "leaks": leaks}

        for pattern in self.policy.compiled_jailbreak():
            if pattern.search(chunk_text):
                return {"text": "", "block": True, "leaks": []}

        out = chunk_text
        for pattern in self.policy.compiled_redactions():
            out = pattern.sub(op.redaction_token, out)
        return {"text": out, "block": False, "leaks": []}

    # -----------------------------------------------------------------
    # Forwarding
    # -----------------------------------------------------------------

    async def forward(self, request: Request, path: str) -> Response:
        if self._client is None:
            try:
                await self.startup()
            except ValueError as exc:
                return JSONResponse(
                    status_code=502,
                    content={"error": {"type": "memgar_invalid_upstream", "message": str(exc)}},
                )

        body_bytes = await request.body()
        is_json = request.headers.get("content-type", "").startswith("application/json")
        payload: Dict[str, Any] = {}
        if is_json and body_bytes:
            try:
                payload = json.loads(body_bytes)
            except json.JSONDecodeError:
                payload = {}

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

        body_to_send = (
            json.dumps(verdict["payload"], ensure_ascii=False).encode("utf-8")
            if is_json else body_bytes
        )
        try:
            upstream_url = self.policy.build_upstream_url(path)
        except ValueError as exc:
            return JSONResponse(
                status_code=502,
                content={"error": {"type": "memgar_invalid_upstream", "message": str(exc)}},
            )

        allowed_headers = {h.lower() for h in self.policy.forward_request_headers}
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() in allowed_headers}
        fwd_headers.pop("host", None)

        wants_stream = bool(payload.get("stream")) if isinstance(payload, dict) else False
        upstream_req = self._client.build_request(
            request.method,
            upstream_url,
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
            scanned = self.scan_chunk(upstream_resp.text)
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

        async def stream_iter() -> AsyncIterator[bytes]:
            try:
                upstream_resp = await self._client.send(upstream_req, stream=True)
            except httpx.HTTPError as exc:
                yield f'data: {{"error": "upstream_error: {exc}"}}\n\n'.encode("utf-8")
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

        return StreamingResponse(stream_iter(), media_type="text/event-stream", headers={"x-memgar-gateway": "1"})


# ---------------------------------------------------------------------------
# FastAPI factory
# ---------------------------------------------------------------------------

def create_app(
    policy: Optional[GatewayPolicy] = None,
    analyzer: Optional[Analyzer] = None,
    policy_engine: Optional[Any] = None,
) -> FastAPI:
    gateway = Gateway(policy=policy, analyzer=analyzer, policy_engine=policy_engine)

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
        try:
            gateway.policy.validate_upstream_base_url()
            upstream_valid = True
            upstream_error = ""
        except ValueError as exc:
            upstream_valid = False
            upstream_error = str(exc)
        return {
            "status": "ok" if upstream_valid else "degraded",
            "upstream": gateway.policy.upstream_base_url,
            "upstream_valid": upstream_valid,
            "upstream_error": upstream_error,
            "input_enabled": gateway.policy.input.enabled,
            "output_enabled": gateway.policy.output.enabled,
        }

    @app.get("/__memgar/policy")
    async def policy_view() -> Dict[str, Any]:
        return {
            "upstream_base_url": gateway.policy.upstream_base_url,
            "allowed_upstream_hosts": gateway.policy.allowed_upstream_hosts,
            "allow_private_upstreams": gateway.policy.allow_private_upstreams,
            "input": {
                "enabled": gateway.policy.input.enabled,
                "block_risk_score": gateway.policy.input.block_risk_score,
                "sanitize_risk_score": gateway.policy.input.sanitize_risk_score,
                "scan_all_messages": gateway.policy.input.scan_all_messages,
                "scan_tool_arguments": gateway.policy.input.scan_tool_arguments,
                "blocked_models": gateway.policy.input.blocked_models,
            },
            "output": {
                "enabled": gateway.policy.output.enabled,
                "block_on_canary_leak": gateway.policy.output.block_on_canary_leak,
                "redact_count": len(gateway.policy.output.redact_patterns),
                "jailbreak_count": len(gateway.policy.output.jailbreak_response_patterns),
            },
        }

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def proxy(full_path: str, request: Request) -> Response:
        return await gateway.forward(request, full_path)

    app.state.gateway = gateway
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
    import uvicorn

    policy = GatewayPolicy(upstream_base_url=upstream)
    policy.input.block_risk_score = int(block_risk_score)
    policy.input.sanitize_risk_score = int(sanitize_risk_score)
    analyzer = Analyzer(use_llm=use_llm)
    app = create_app(policy=policy, analyzer=analyzer)
    uvicorn.run(app, host=host, port=port, log_level=log_level)


__all__ = ["Gateway", "create_app", "run", "_extract_input_texts"]
