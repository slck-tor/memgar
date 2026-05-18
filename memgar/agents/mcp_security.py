"""
Memgar MCP Security Layer
=========================

Security layer for Model Context Protocol (MCP) tool usage:
- Tool definition validation
- Tool call injection detection
- Parameter sanitization
- Response validation
- Permission enforcement

MCP Attack Vectors Covered:
- Malicious tool definitions
- Tool parameter injection
- Tool response poisoning
- Tool chaining attacks
- Permission bypass via tools

Usage:
    from memgar.agents import MCPSecurityLayer
    
    mcp = MCPSecurityLayer()
    
    # Validate tool definition
    result = mcp.validate_tool_definition(tool_schema)
    
    # Validate tool call
    result = mcp.validate_tool_call(
        agent_id="agent-1",
        tool_name="file_read",
        parameters={"path": "/etc/passwd"}
    )
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union


class MCPThreatType(Enum):
    """Types of MCP-related threats."""
    MALICIOUS_TOOL_DEF = "malicious_tool_definition"
    PARAMETER_INJECTION = "parameter_injection"
    RESPONSE_POISONING = "response_poisoning"
    TOOL_CHAINING = "tool_chaining_attack"
    PERMISSION_BYPASS = "permission_bypass"
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"
    EXECUTION_ATTEMPT = "execution_attempt"
    EXFILTRATION_ATTEMPT = "exfiltration_attempt"


@dataclass
class MCPThreat:
    """Represents an MCP security threat."""
    threat_type: MCPThreatType
    severity: str
    confidence: float
    description: str
    tool_name: Optional[str] = None
    agent_id: Optional[str] = None
    blocked_params: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPValidationResult:
    """Result of MCP validation."""
    is_allowed: bool
    risk_score: int
    threats: List[MCPThreat] = field(default_factory=list)
    sanitized_params: Optional[Dict[str, Any]] = None
    blocked_reason: Optional[str] = None
    validation_time_ms: float = 0.0


class MCPSecurityLayer:
    """
    Security layer for Model Context Protocol operations.
    
    Features:
    - Tool definition validation
    - Parameter injection detection
    - Sensitive path/data blocking
    - Rate limiting per tool
    - Tool chain analysis
    - Response validation
    
    Usage:
        mcp = MCPSecurityLayer()
        
        # Validate a tool call
        result = mcp.validate_tool_call(
            agent_id="worker-1",
            tool_name="execute_code",
            parameters={"code": "import os; os.system('rm -rf /')"}
        )
        
        if not result.is_allowed:
            print(f"Blocked: {result.blocked_reason}")
    """
    
    # Dangerous tool patterns
    DANGEROUS_TOOLS = {
        "execute", "exec", "eval", "run", "shell", "system",
        "spawn", "popen", "subprocess", "command",
    }
    
    # Sensitive path patterns
    SENSITIVE_PATHS = [
        r"/etc/(passwd|shadow|sudoers)",
        r"/root/",
        r"~/.ssh/",
        r"\.env$",
        r"\.pem$",
        r"\.key$",
        r"id_rsa",
        r"credentials",
        r"secrets?\.ya?ml",
        r"api[_-]?keys?",
        r"\.aws/",
        r"\.kube/config",
    ]
    
    # Parameter injection patterns
    INJECTION_PATTERNS = [
        r";\s*(rm|del|drop|delete|truncate)",
        r"\|\s*(bash|sh|cmd|powershell)",
        r"`[^`]+`",  # Backtick execution
        r"\$\([^)]+\)",  # Command substitution
        r"&&\s*(rm|del|wget|curl)",
        r"\|\|\s*(rm|del)",
        r">\s*/dev/",
        r"<\s*/etc/",
    ]
    
    # Exfiltration patterns in parameters
    EXFIL_PATTERNS = [
        r"(?i)curl\s+.{0,50}(--data|--upload|-d|-F)",
        r"(?i)wget\s+--post",
        r"(?i)(nc|netcat)\s+-e",
        r"(?i)scp\s+.+@",
        r"(?i)rsync\s+.+@",
        r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",  # Email
    ]
    
    # Prompt injection in tool parameters
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?previous",
        r"(?i)new\s+instruction\s*:",
        r"(?i)system\s*:\s*override",
        r"(?i)forget\s+(all\s+)?rules",
    ]
    
    def __init__(
        self,
        text_analyzer: Optional[Any] = None,
        allowed_tools: Optional[Set[str]] = None,
        blocked_tools: Optional[Set[str]] = None,
        strict_mode: bool = False,
        max_param_length: int = 10000,
    ):
        """
        Initialize MCPSecurityLayer.
        
        Args:
            text_analyzer: Optional Memgar text analyzer
            allowed_tools: Whitelist of allowed tools (if set, only these allowed)
            blocked_tools: Blacklist of blocked tools
            strict_mode: Enable stricter validation
            max_param_length: Maximum parameter string length
        """
        self.text_analyzer = text_analyzer
        self.allowed_tools = allowed_tools
        self.blocked_tools = blocked_tools or set()
        self.strict_mode = strict_mode
        self.max_param_length = max_param_length
        
        # Compile patterns
        self._sensitive_paths = [re.compile(p, re.I) for p in self.SENSITIVE_PATHS]
        self._injection_patterns = [re.compile(p, re.I) for p in self.INJECTION_PATTERNS]
        self._exfil_patterns = [re.compile(p, re.I) for p in self.EXFIL_PATTERNS]
        self._prompt_patterns = [re.compile(p) for p in self.PROMPT_INJECTION_PATTERNS]
        
        # Tool usage tracking
        self._tool_usage: Dict[str, List[datetime]] = {}
        self._tool_rate_limits: Dict[str, int] = {}  # tool -> max per minute
        
        # Threat history
        self._threats: List[MCPThreat] = []
        self._max_threats = 500
    
    def validate_tool_definition(
        self,
        tool_schema: Dict[str, Any],
    ) -> MCPValidationResult:
        """
        Validate a tool definition schema.
        
        Args:
            tool_schema: Tool definition (name, description, parameters, etc.)
            
        Returns:
            MCPValidationResult
        """
        import time
        start_time = time.time()
        
        threats = []
        
        tool_name = tool_schema.get("name", "")
        description = tool_schema.get("description", "")
        
        # Check tool name
        name_lower = tool_name.lower()
        
        # Check against dangerous patterns
        for dangerous in self.DANGEROUS_TOOLS:
            if dangerous in name_lower:
                threats.append(MCPThreat(
                    threat_type=MCPThreatType.MALICIOUS_TOOL_DEF,
                    severity="critical",
                    confidence=0.9,
                    description=f"Tool name contains dangerous keyword: {dangerous}",
                    tool_name=tool_name,
                ))
        
        # Check description for prompt injection
        for pattern in self._prompt_patterns:
            if pattern.search(description):
                threats.append(MCPThreat(
                    threat_type=MCPThreatType.MALICIOUS_TOOL_DEF,
                    severity="critical",
                    confidence=0.95,
                    description="Tool description contains prompt injection",
                    tool_name=tool_name,
                ))
                break
        
        # Check for hidden instructions in schema
        schema_str = json.dumps(tool_schema)
        for pattern in self._prompt_patterns:
            if pattern.search(schema_str):
                threats.append(MCPThreat(
                    threat_type=MCPThreatType.MALICIOUS_TOOL_DEF,
                    severity="critical",
                    confidence=0.9,
                    description="Tool schema contains hidden instructions",
                    tool_name=tool_name,
                ))
                break
        
        # Calculate risk
        risk_score = self._calculate_risk_score(threats)
        is_allowed = risk_score < 30 and not any(t.severity == "critical" for t in threats)
        
        return MCPValidationResult(
            is_allowed=is_allowed,
            risk_score=risk_score,
            threats=threats,
            blocked_reason=threats[0].description if threats and not is_allowed else None,
            validation_time_ms=(time.time() - start_time) * 1000,
        )
    
    def validate_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> MCPValidationResult:
        """
        Validate a tool call from an agent.
        
        Args:
            agent_id: The calling agent
            tool_name: Name of the tool
            parameters: Tool parameters
            context: Optional context
            
        Returns:
            MCPValidationResult
        """
        import time
        start_time = time.time()
        
        threats = []
        blocked_params = []
        
        # Tool whitelist/blacklist check
        if self.allowed_tools and tool_name not in self.allowed_tools:
            threats.append(MCPThreat(
                threat_type=MCPThreatType.PERMISSION_BYPASS,
                severity="high",
                confidence=1.0,
                description=f"Tool '{tool_name}' not in allowed list",
                tool_name=tool_name,
                agent_id=agent_id,
            ))
        
        if tool_name in self.blocked_tools:
            threats.append(MCPThreat(
                threat_type=MCPThreatType.PERMISSION_BYPASS,
                severity="critical",
                confidence=1.0,
                description=f"Tool '{tool_name}' is blocked",
                tool_name=tool_name,
                agent_id=agent_id,
            ))
        
        # Dangerous tool check
        tool_lower = tool_name.lower()
        for dangerous in self.DANGEROUS_TOOLS:
            if dangerous in tool_lower:
                threats.append(MCPThreat(
                    threat_type=MCPThreatType.EXECUTION_ATTEMPT,
                    severity="critical",
                    confidence=0.9,
                    description=f"Attempt to use execution tool: {tool_name}",
                    tool_name=tool_name,
                    agent_id=agent_id,
                ))
        
        # Rate limit check
        if not self._check_rate_limit(tool_name):
            threats.append(MCPThreat(
                threat_type=MCPThreatType.PERMISSION_BYPASS,
                severity="medium",
                confidence=1.0,
                description=f"Rate limit exceeded for tool '{tool_name}'",
                tool_name=tool_name,
                agent_id=agent_id,
            ))
        
        # Parameter validation
        param_threats, sanitized = self._validate_parameters(
            tool_name, parameters, agent_id
        )
        threats.extend(param_threats)
        
        # Track blocked params
        blocked_params = [
            t.blocked_params for t in param_threats if t.blocked_params
        ]
        blocked_params = [p for sublist in blocked_params for p in sublist]
        
        # Use Memgar text analyzer if available
        if self.text_analyzer:
            memgar_threats = self._run_memgar_on_params(parameters, tool_name, agent_id)
            threats.extend(memgar_threats)
        
        # Record tool usage
        self._record_usage(tool_name)
        
        # Calculate risk
        risk_score = self._calculate_risk_score(threats)
        is_allowed = risk_score < 30 and not any(t.severity == "critical" for t in threats)
        
        # Store threats
        for threat in threats:
            self._threats.append(threat)
        if len(self._threats) > self._max_threats:
            self._threats = self._threats[-self._max_threats:]
        
        return MCPValidationResult(
            is_allowed=is_allowed,
            risk_score=risk_score,
            threats=threats,
            sanitized_params=sanitized if is_allowed else None,
            blocked_reason=threats[0].description if threats and not is_allowed else None,
            validation_time_ms=(time.time() - start_time) * 1000,
        )
    
    def validate_tool_response(
        self,
        tool_name: str,
        response: Union[str, Dict[str, Any]],
        agent_id: Optional[str] = None,
    ) -> MCPValidationResult:
        """
        Validate a tool's response for poisoning.
        
        Args:
            tool_name: Name of the tool
            response: The tool's response
            agent_id: The requesting agent
            
        Returns:
            MCPValidationResult
        """
        import time
        start_time = time.time()
        
        threats = []
        
        # Convert to string for analysis
        if isinstance(response, dict):
            response_str = json.dumps(response)
        else:
            response_str = str(response)
        
        # Check for prompt injection in response
        for pattern in self._prompt_patterns:
            if pattern.search(response_str):
                threats.append(MCPThreat(
                    threat_type=MCPThreatType.RESPONSE_POISONING,
                    severity="critical",
                    confidence=0.9,
                    description="Tool response contains prompt injection",
                    tool_name=tool_name,
                    agent_id=agent_id,
                ))
                break
        
        # Check for hidden instructions
        hidden_indicators = [
            "ignore previous",
            "new instruction",
            "system override",
            "admin mode",
        ]
        for indicator in hidden_indicators:
            if indicator.lower() in response_str.lower():
                threats.append(MCPThreat(
                    threat_type=MCPThreatType.RESPONSE_POISONING,
                    severity="high",
                    confidence=0.8,
                    description=f"Tool response contains suspicious content: '{indicator}'",
                    tool_name=tool_name,
                ))
        
        # Use Memgar if available
        if self.text_analyzer and len(response_str) > 20:
            try:
                from ..models import Decision, MemoryEntry
                entry = MemoryEntry(content=response_str[:5000])
                result = self.text_analyzer.analyze(entry)
                
                if result.decision != Decision.ALLOW:
                    threats.append(MCPThreat(
                        threat_type=MCPThreatType.RESPONSE_POISONING,
                        severity="critical",
                        confidence=0.95,
                        description=f"Memgar detected threat in tool response",
                        tool_name=tool_name,
                        metadata={"memgar_risk": result.risk_score},
                    ))
            except Exception:
                pass
        
        risk_score = self._calculate_risk_score(threats)
        is_allowed = risk_score < 30
        
        return MCPValidationResult(
            is_allowed=is_allowed,
            risk_score=risk_score,
            threats=threats,
            blocked_reason=threats[0].description if threats and not is_allowed else None,
            validation_time_ms=(time.time() - start_time) * 1000,
        )
    
    def _validate_parameters(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        agent_id: str,
    ) -> tuple:
        """Validate tool parameters."""
        threats = []
        sanitized = {}
        
        for key, value in parameters.items():
            value_str = str(value)
            param_safe = True
            
            # Length check
            if len(value_str) > self.max_param_length:
                threats.append(MCPThreat(
                    threat_type=MCPThreatType.PARAMETER_INJECTION,
                    severity="medium",
                    confidence=0.7,
                    description=f"Parameter '{key}' exceeds max length",
                    tool_name=tool_name,
                    agent_id=agent_id,
                    blocked_params=[key],
                ))
                param_safe = False
            
            # Sensitive path check
            for pattern in self._sensitive_paths:
                if pattern.search(value_str):
                    threats.append(MCPThreat(
                        threat_type=MCPThreatType.SENSITIVE_DATA_ACCESS,
                        severity="critical",
                        confidence=0.9,
                        description=f"Parameter '{key}' accesses sensitive path",
                        tool_name=tool_name,
                        agent_id=agent_id,
                        blocked_params=[key],
                    ))
                    param_safe = False
                    break
            
            # Injection pattern check
            for pattern in self._injection_patterns:
                if pattern.search(value_str):
                    threats.append(MCPThreat(
                        threat_type=MCPThreatType.PARAMETER_INJECTION,
                        severity="critical",
                        confidence=0.9,
                        description=f"Command injection in parameter '{key}'",
                        tool_name=tool_name,
                        agent_id=agent_id,
                        blocked_params=[key],
                    ))
                    param_safe = False
                    break
            
            # Exfiltration check
            for pattern in self._exfil_patterns:
                if pattern.search(value_str):
                    threats.append(MCPThreat(
                        threat_type=MCPThreatType.EXFILTRATION_ATTEMPT,
                        severity="critical",
                        confidence=0.85,
                        description=f"Data exfiltration attempt in parameter '{key}'",
                        tool_name=tool_name,
                        agent_id=agent_id,
                        blocked_params=[key],
                    ))
                    param_safe = False
                    break
            
            # Prompt injection in params
            for pattern in self._prompt_patterns:
                if pattern.search(value_str):
                    threats.append(MCPThreat(
                        threat_type=MCPThreatType.PARAMETER_INJECTION,
                        severity="critical",
                        confidence=0.95,
                        description=f"Prompt injection in parameter '{key}'",
                        tool_name=tool_name,
                        agent_id=agent_id,
                        blocked_params=[key],
                    ))
                    param_safe = False
                    break
            
            if param_safe:
                sanitized[key] = value
        
        return threats, sanitized
    
    def _run_memgar_on_params(
        self,
        parameters: Dict[str, Any],
        tool_name: str,
        agent_id: str,
    ) -> List[MCPThreat]:
        """Run Memgar analysis on parameters."""
        threats = []
        
        try:
            from ..models import Decision, MemoryEntry
            
            # Analyze each parameter
            for key, value in parameters.items():
                value_str = str(value)
                if len(value_str) < 10:
                    continue
                
                entry = MemoryEntry(content=value_str[:2000])
                result = self.text_analyzer.analyze(entry)
                
                if result.decision != Decision.ALLOW:
                    threats.append(MCPThreat(
                        threat_type=MCPThreatType.PARAMETER_INJECTION,
                        severity="high",
                        confidence=min(result.risk_score / 100, 0.9),
                        description=f"Memgar detected threat in parameter '{key}'",
                        tool_name=tool_name,
                        agent_id=agent_id,
                        blocked_params=[key],
                        metadata={"memgar_risk": result.risk_score},
                    ))
        except Exception:
            pass
        
        return threats
    
    def _check_rate_limit(self, tool_name: str) -> bool:
        """Check if tool is within rate limit."""
        limit = self._tool_rate_limits.get(tool_name, 60)  # Default 60/min
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        if tool_name not in self._tool_usage:
            return True
        
        # Count recent uses
        recent = [t for t in self._tool_usage[tool_name] if t > minute_ago]
        self._tool_usage[tool_name] = recent
        
        return len(recent) < limit
    
    def _record_usage(self, tool_name: str) -> None:
        """Record tool usage."""
        if tool_name not in self._tool_usage:
            self._tool_usage[tool_name] = []
        self._tool_usage[tool_name].append(datetime.now())
    
    def _calculate_risk_score(self, threats: List[MCPThreat]) -> int:
        """Calculate risk score from threats."""
        if not threats:
            return 0
        
        severity_scores = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5,
        }
        
        total = sum(
            severity_scores.get(t.severity, 10) * t.confidence
            for t in threats
        )
        
        return min(100, int(total))
    
    def set_rate_limit(self, tool_name: str, max_per_minute: int) -> None:
        """Set rate limit for a tool."""
        self._tool_rate_limits[tool_name] = max_per_minute
    
    def block_tool(self, tool_name: str) -> None:
        """Add tool to blocked list."""
        self.blocked_tools.add(tool_name)
    
    def allow_tool(self, tool_name: str) -> None:
        """Add tool to allowed list."""
        if self.allowed_tools is not None:
            self.allowed_tools.add(tool_name)
        if tool_name in self.blocked_tools:
            self.blocked_tools.remove(tool_name)
    
    def get_threats(
        self,
        tool_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[MCPThreat]:
        """Get recent MCP threats."""
        threats = self._threats
        
        if tool_name:
            threats = [t for t in threats if t.tool_name == tool_name]
        
        if agent_id:
            threats = [t for t in threats if t.agent_id == agent_id]
        
        return threats[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get MCP security statistics."""
        return {
            "total_threats": len(self._threats),
            "blocked_tools": list(self.blocked_tools),
            "allowed_tools": list(self.allowed_tools) if self.allowed_tools else "all",
            "rate_limits": dict(self._tool_rate_limits),
            "tracked_tools": len(self._tool_usage),
        }
