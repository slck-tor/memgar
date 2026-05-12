"""
MCP Server Proxy — wrap any MCP server with Memgar enforcement.

Model Context Protocol traffic is JSON-RPC over stdio or HTTP. From a security
standpoint, MCP carries the most dangerous combination of all AI surfaces:

  * **tool definitions** that can be poisoned by hostile servers
  * **tool inputs** that flow from agent memory (potentially poisoned)
  * **tool outputs** that re-enter agent memory (potentially poisoning it)

Memgar's MCP proxy interposes on every JSON-RPC frame and applies:

  * Layer 1+2.5 + canary scan on tool inputs (``tools/call`` arguments)
  * ToolUseGuard policy on tool calls (host allowlists, payment drift…)
  * Tool argument firewall (schema + field allowlist)
  * Output scan on tool results, redacting / blocking on canary leaks or
    secrets before the result reaches the agent's memory
  * Tool *definition* scan when the server lists tools — we refuse to
    proxy a tool whose description contains injection markers

The proxy is transport-agnostic: ``MCPProxy.handle_frame()`` takes a parsed
JSON-RPC dict and returns a (possibly modified) dict. Wire it under
stdio with the ``run_stdio_proxy()`` helper, or behind FastAPI/HTTPX for
HTTP MCP servers.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from memgar import Analyzer, MemoryEntry
from memgar.tool_use_guard import ToolUseGuard, ToolDecision

logger = logging.getLogger("memgar.gateway.mcp")


# ---------------------------------------------------------------------------
# Decision record
# ---------------------------------------------------------------------------

@dataclass
class MCPDecision:
    allowed: bool
    risk_score: int
    reason: str = ""
    redacted: bool = False
    findings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------

class MCPProxy:
    """Per-server MCP enforcement layer.

    Args:
        analyzer: Memgar Analyzer instance.
        tool_guard: optional ToolUseGuard for policy on tool calls.
        allowlist_hosts: outbound hosts allowed for URL arguments.
        tool_arg_schemas: per-tool JSON-schema-like argument constraints.
        tool_arg_allowlists: per-tool field allowlists.
        block_canary_leaks: redact/block tool *results* containing canaries.
        block_poisoned_definitions: refuse to surface tools whose
            descriptions look like prompt injections.
    """

    def __init__(
        self,
        analyzer: Optional[Analyzer] = None,
        tool_guard: Optional[ToolUseGuard] = None,
        allowlist_hosts: Optional[List[str]] = None,
        tool_arg_schemas: Optional[Dict[str, Dict[str, Any]]] = None,
        tool_arg_allowlists: Optional[Dict[str, Dict[str, List[Any]]]] = None,
        block_canary_leaks: bool = True,
        block_poisoned_definitions: bool = True,
    ) -> None:
        self.analyzer = analyzer or Analyzer(use_llm=False)
        self.tool_guard = tool_guard or ToolUseGuard(allowlist_hosts=allowlist_hosts)
        self.block_canary_leaks = block_canary_leaks
        self.block_poisoned_definitions = block_poisoned_definitions
        self.tool_arg_schemas = tool_arg_schemas or {}
        self.tool_arg_allowlists = tool_arg_allowlists or {}

    # -----------------------------------------------------------------
    # Frame handlers
    # -----------------------------------------------------------------

    def filter_outgoing_request(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        """Agent → Server. Inspect ``tools/call`` invocations.

        Returns the (possibly modified) frame, or a synthetic JSON-RPC error
        response if the call is blocked.
        """
        method = frame.get("method")
        params = frame.get("params") or {}

        if method == "tools/call":
            tool_name = params.get("name") or "unknown_tool"
            arguments = params.get("arguments") or {}
            decision = self._enforce_tool_call(tool_name, arguments)
            if not decision.allowed:
                return self._error_response(
                    frame.get("id"),
                    code=-32001,
                    message="memgar: tool call blocked",
                    data={
                        "risk_score": decision.risk_score,
                        "reason": decision.reason,
                        "findings": decision.findings,
                    },
                )

        return frame

    def filter_incoming_response(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        """Server → Agent. Inspect tool results and tool listings."""
        result = frame.get("result")
        if result is None:
            return frame

        # tools/list response
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            return self._filter_tools_list(frame, result)

        # tools/call response — inspect content blocks for canary leak / poison
        if isinstance(result, dict) and isinstance(result.get("content"), list):
            return self._filter_tool_call_result(frame, result)

        return frame

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _enforce_tool_call(
        self, tool_name: str, arguments: Any
    ) -> MCPDecision:
        parsed_args, parse_error = self._coerce_arguments(arguments)
        if parse_error:
            return MCPDecision(
                allowed=False,
                risk_score=100,
                reason=f"invalid tool arguments: {parse_error}",
                findings=["invalid_json_arguments"],
            )

        schema_result = self._validate_tool_arguments(tool_name, parsed_args)
        if schema_result is not None:
            return schema_result

        try:
            check = self.tool_guard.check_call(tool_name, parsed_args)
        except Exception as exc:
            return MCPDecision(allowed=True, risk_score=0, reason=f"guard error: {exc}")

        if check.decision == ToolDecision.BLOCK:
            return MCPDecision(
                allowed=False,
                risk_score=check.risk_score,
                reason=check.rationale or "tool guard blocked the call",
                findings=[f.technique for f in check.findings],
            )

        # Also analyze the concatenation of string args for poisoning intent
        merged = self._collect_strings(parsed_args)
        if merged:
            try:
                result = self.analyzer.analyze(MemoryEntry(
                    content=merged,
                    metadata={"surface": "mcp_tool_arg", "tool": tool_name},
                ))
                if result.decision.value == "block":
                    return MCPDecision(
                        allowed=False, risk_score=result.risk_score,
                        reason=result.explanation, findings=["analyzer_block"],
                    )
            except Exception:
                pass
        return MCPDecision(allowed=True, risk_score=check.risk_score)

    def _validate_tool_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[MCPDecision]:
        schema = self.tool_arg_schemas.get(tool_name)
        if schema:
            ok, reason, finding = self._validate_schema(arguments, schema)
            if not ok:
                return MCPDecision(
                    allowed=False,
                    risk_score=90,
                    reason=f"schema validation failed for '{tool_name}': {reason}",
                    findings=[finding],
                )

        allowlist = self.tool_arg_allowlists.get(tool_name, {})
        for field, allowed_values in allowlist.items():
            if field not in arguments:
                continue
            value = arguments[field]
            if value not in allowed_values:
                return MCPDecision(
                    allowed=False,
                    risk_score=95,
                    reason=f"field '{field}' value is not allowlisted for '{tool_name}'",
                    findings=[f"allowlist_violation:{field}"],
                )
        return None

    def _validate_schema(self, arguments: Dict[str, Any], schema: Dict[str, Any]) -> tuple[bool, str, str]:
        if schema.get("type") == "object" and not isinstance(arguments, dict):
            return False, "arguments must be an object", "schema_type_mismatch"

        required = schema.get("required", [])
        for key in required:
            if key not in arguments:
                return False, f"missing required field '{key}'", "schema_required_missing"

        properties = schema.get("properties", {})
        additional_allowed = schema.get("additionalProperties", True)
        if not additional_allowed:
            unknown = [key for key in arguments if key not in properties]
            if unknown:
                return False, f"unknown fields not allowed: {', '.join(unknown)}", "schema_unknown_field"

        for field, rules in properties.items():
            if field not in arguments:
                continue
            value = arguments[field]
            declared_type = rules.get("type")
            if declared_type and not self._type_matches(value, declared_type):
                return False, f"field '{field}' expected type '{declared_type}'", "schema_type_mismatch"

            enum_values = rules.get("enum")
            if enum_values is not None and value not in enum_values:
                return False, f"field '{field}' must be one of {enum_values}", "schema_enum_violation"

            if isinstance(value, str):
                min_len = rules.get("minLength")
                max_len = rules.get("maxLength")
                if isinstance(min_len, int) and len(value) < min_len:
                    return False, f"field '{field}' shorter than minLength={min_len}", "schema_min_length"
                if isinstance(max_len, int) and len(value) > max_len:
                    return False, f"field '{field}' longer than maxLength={max_len}", "schema_max_length"
                pattern = rules.get("pattern")
                if isinstance(pattern, str) and re.search(pattern, value) is None:
                    return False, f"field '{field}' does not match pattern", "schema_pattern_mismatch"

            if isinstance(value, (int, float)):
                minimum = rules.get("minimum")
                maximum = rules.get("maximum")
                if isinstance(minimum, (int, float)) and value < minimum:
                    return False, f"field '{field}' below minimum={minimum}", "schema_minimum"
                if isinstance(maximum, (int, float)) and value > maximum:
                    return False, f"field '{field}' above maximum={maximum}", "schema_maximum"

            if isinstance(value, list) and isinstance(rules.get("items"), dict):
                item_type = rules["items"].get("type")
                if item_type and any(not self._type_matches(item, item_type) for item in value):
                    return False, f"field '{field}' has invalid item types", "schema_item_type_mismatch"

        return True, "", ""

    @staticmethod
    def _type_matches(value: Any, declared_type: str) -> bool:
        mapping = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "object": dict,
            "array": list,
        }
        target = mapping.get(declared_type)
        if target is None:
            return True
        if declared_type == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if declared_type == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        return isinstance(value, target)

    @staticmethod
    def _coerce_arguments(arguments: Any) -> tuple[Dict[str, Any], Optional[str]]:
        if isinstance(arguments, dict):
            return arguments, None
        if isinstance(arguments, str):
            try:
                parsed = json.loads(arguments)
            except json.JSONDecodeError as exc:
                return {}, str(exc)
            if isinstance(parsed, dict):
                return parsed, None
            return {}, "decoded JSON arguments must be an object"
        return {}, "arguments must be object or JSON object string"

    def _filter_tools_list(
        self, frame: Dict[str, Any], result: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not self.block_poisoned_definitions:
            return frame
        kept: List[Dict[str, Any]] = []
        rejected: List[str] = []
        for tool in result["tools"]:
            desc = ""
            if isinstance(tool, dict):
                desc = " ".join(
                    str(tool.get(k, "")) for k in ("name", "description")
                )
            try:
                analysis = self.analyzer.analyze(MemoryEntry(
                    content=desc, metadata={"surface": "mcp_tool_def"},
                ))
                if analysis.decision.value == "block":
                    rejected.append(tool.get("name", "unknown"))
                    continue
            except Exception:
                pass
            kept.append(tool)
        if rejected:
            logger.warning("memgar.mcp: rejected poisoned tool definitions: %s", rejected)
        result["tools"] = kept
        return frame

    def _filter_tool_call_result(
        self, frame: Dict[str, Any], result: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not self.block_canary_leaks:
            return frame
        leaked: List[Any] = []
        for block in result["content"]:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                text = block["text"]
                try:
                    leaks = self.analyzer.scan_output(text, sink="mcp_tool_result")
                except Exception:
                    leaks = []
                if leaks:
                    leaked.extend(leaks)
                    block["text"] = "[memgar: redacted — canary leak]"
        if leaked:
            frame.setdefault("_memgar", {})["canary_leaks"] = [
                {"sink": l.sink, "tenant": l.tenant_id, "agent": l.agent_id}
                for l in leaked
            ]
        return frame

    @staticmethod
    def _collect_strings(value: Any) -> str:
        out: List[str] = []

        def walk(v: Any) -> None:
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict):
                for k in v.values():
                    walk(k)
            elif isinstance(v, (list, tuple, set)):
                for k in v:
                    walk(k)

        walk(value)
        return "\n".join(out)

    @staticmethod
    def _error_response(
        request_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        err: Dict[str, Any] = {"code": code, "message": message}
        if data:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": request_id, "error": err}


# ---------------------------------------------------------------------------
# stdio runner
# ---------------------------------------------------------------------------

async def run_stdio_proxy(
    upstream_command: List[str],
    proxy: Optional[MCPProxy] = None,
) -> int:
    """Spawn ``upstream_command`` as an MCP server, mediate stdio frames.

    Implementation note: this is a thin asyncio loop that keeps the process
    transparent — Claude / Cursor / any MCP-aware client launches *us*, we
    launch the real server, and every JSON-RPC frame flows through the
    proxy. Returns the upstream's exit code.
    """
    import asyncio

    proxy = proxy or MCPProxy()
    process = await asyncio.create_subprocess_exec(
        *upstream_command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                   direction: str) -> None:
        while not reader.at_eof():
            line = await reader.readline()
            if not line:
                break
            stripped = line.strip()
            if not stripped:
                writer.write(line)
                await writer.drain()
                continue
            try:
                frame = json.loads(stripped)
            except json.JSONDecodeError:
                writer.write(line)
                await writer.drain()
                continue
            if direction == "outgoing":
                frame = proxy.filter_outgoing_request(frame)
            else:
                frame = proxy.filter_incoming_response(frame)
            writer.write((json.dumps(frame) + "\n").encode("utf-8"))
            await writer.drain()

    loop = asyncio.get_event_loop()
    stdin_reader = asyncio.StreamReader()
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(stdin_reader), open("/dev/stdin", "rb"),
    )

    stdout_transport, _ = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, open("/dev/stdout", "wb"),
    )
    stdout_writer = asyncio.StreamWriter(stdout_transport, _, None, loop)

    await asyncio.gather(
        pipe(stdin_reader, process.stdin, "outgoing"),  # type: ignore
        pipe(process.stdout, stdout_writer, "incoming"),  # type: ignore
    )
    return await process.wait()


__all__ = ["MCPProxy", "MCPDecision", "run_stdio_proxy"]
