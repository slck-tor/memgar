"""
Memgar Multi-Agent Security Module
===================================

Provides security for multi-agent AI systems and agent-to-agent communication.

Attack Vectors Covered:
- Agent-to-agent message poisoning
- Trust chain exploitation
- Delegation hijacking
- Coordinator manipulation
- Agent swarm attacks
- Cross-agent credential leakage
- Malicious tool definitions
- MCP (Model Context Protocol) injection

Components:
- AgentMessageValidator: Validates messages between agents
- TrustChainManager: Manages trust relationships
- DelegationMonitor: Monitors permission delegation
- SwarmDetector: Detects coordinated swarm attacks
- MCPSecurityLayer: MCP-specific security

Usage:
    from memgar.agents import AgentSecurityGuard
    
    guard = AgentSecurityGuard()
    
    # Validate agent message
    result = guard.validate_message(
        source_agent="agent-1",
        target_agent="agent-2", 
        message=message_content,
    )
    
    # Check tool call
    result = guard.validate_tool_call(
        agent_id="agent-1",
        tool_name="file_read",
        tool_params={"path": "/etc/passwd"},
    )
"""

from .agent_security import AgentSecurityGuard
from .agent_validator import AgentMessageValidator, MessageValidationResult
from .delegation_monitor import DelegationEvent, DelegationMonitor
from .mcp_security import MCPSecurityLayer, MCPValidationResult
from .swarm_detector import SwarmDetector, SwarmThreat
from .trust_chain import TrustChainManager, TrustLevel

__all__ = [
    # Main interface
    "AgentSecurityGuard",
    
    # Components
    "AgentMessageValidator",
    "MessageValidationResult",
    "TrustChainManager", 
    "TrustLevel",
    "DelegationMonitor",
    "DelegationEvent",
    "SwarmDetector",
    "SwarmThreat",
    "MCPSecurityLayer",
    "MCPValidationResult",
]
