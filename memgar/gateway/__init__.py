"""
Memgar AI Gateway
=================

A drop-in reverse proxy that sits between any LLM client and the upstream
provider (Anthropic, OpenAI, Azure, MCP servers, etc.). The agent only
changes its ``base_url``; Memgar transparently:

  * scans every prompt/memory/tool call **on the way in** for poisoning,
    stego, paraphrase attacks, canary leaks
  * scans every completion **on the way out** for canary exfiltration,
    PII / secret leaks, jailbreak responses
  * blocks, sanitises or quarantines based on policy
  * emits OCSF SIEM events + Prometheus metrics for every decision

The gateway is the missing surface that turns Memgar from a library into a
NeuralTrust-style enforcement plane: same policy enforced **whether the
agent is running locally, in a browser, in a service mesh, or as an MCP
server**.

Provided modules
----------------
* ``app``        — FastAPI application (importable + ``memgar gateway`` CLI)
* ``policy``     — InputPolicy / OutputPolicy / GatewayPolicy
* ``providers``  — OpenAI- and Anthropic-compatible endpoints with
                   streaming (SSE) support
* ``mcp_proxy``  — wraps any MCP server with tool-call enforcement
* ``streaming``  — line-buffered SSE filter that also scans deltas
"""

from __future__ import annotations

from .policy import GatewayPolicy, InputPolicy, OutputPolicy, PolicyDecision
from .app import create_app, run

__all__ = [
    "create_app",
    "run",
    "GatewayPolicy",
    "InputPolicy",
    "OutputPolicy",
    "PolicyDecision",
]
