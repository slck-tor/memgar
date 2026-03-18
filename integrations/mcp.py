"""
Memgar MCP Integration
======================

Security middleware for Model Context Protocol servers.

Intercepts resource writes and tool calls that modify persistent state,
scanning for memory poisoning attacks before allowing the operation.

Example:
    >>> from memgar.integrations.mcp import MCPSecurityMiddleware
    >>> 
    >>> middleware = MCPSecurityMiddleware()
    >>> 
    >>> # Wrap your MCP handlers
    >>> @middleware.protect_resource
    >>> async def handle_resource_write(uri: str, content: str):
    ...     # This will be scanned before execution
    ...     await save_resource(uri, content)
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, List, Optional, TypeVar, Awaitable
from datetime import datetime

from memgar.analyzer import Analyzer
from memgar.models import AnalysisResult, Decision, MemoryEntry, Severity


F = TypeVar("F", bound=Callable[..., Any])


class MCPSecurityMiddleware:
    """
    Security middleware for MCP servers.
    
    Provides decorators and utilities to scan MCP resource writes
    and tool calls for memory poisoning threats.
    
    Attributes:
        analyzer: Memgar analyzer instance
        mode: Operation mode (monitor, protect, audit)
        blocked_operations: List of blocked operation records
    
    Example:
        >>> middleware = MCPSecurityMiddleware(mode="protect")
        >>> 
        >>> @middleware.protect_resource
        >>> async def write_resource(uri: str, content: str):
        ...     # Content is scanned before this runs
        ...     return await db.save(uri, content)
    """
    
    def __init__(
        self,
        mode: str = "protect",
        analyzer: Optional[Analyzer] = None,
        on_block: Optional[Callable[[AnalysisResult, str], None]] = None,
        allowed_uris: Optional[List[str]] = None,
        blocked_uris: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize MCP security middleware.
        
        Args:
            mode: Operation mode:
                  - "monitor": Log threats but allow operations
                  - "protect": Block operations with threats
                  - "audit": Log only
            analyzer: Custom analyzer instance
            on_block: Callback when operation is blocked
            allowed_uris: URI patterns to always allow (whitelist)
            blocked_uris: URI patterns to always block (blacklist)
        """
        self.mode = mode
        self.analyzer = analyzer or Analyzer()
        self.on_block = on_block
        self.allowed_uris = allowed_uris or []
        self.blocked_uris = blocked_uris or []
        self.blocked_operations: List[Dict[str, Any]] = []
        self._scan_count = 0
        self._block_count = 0
    
    def protect_resource(self, func: F) -> F:
        """
        Decorator to protect resource write operations.
        
        Scans content before allowing the write operation.
        
        Args:
            func: Async function that writes to a resource.
                  Must accept (uri: str, content: str) or similar.
        
        Returns:
            Wrapped function that scans before executing.
        
        Example:
            >>> @middleware.protect_resource
            >>> async def save_note(uri: str, content: str):
            ...     return await storage.save(uri, content)
        """
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract content to scan
            content = self._extract_content(args, kwargs)
            uri = self._extract_uri(args, kwargs)
            
            # Check URI whitelist/blacklist
            if self._is_uri_blocked(uri):
                raise MCPSecurityError(f"URI is blocked: {uri}")
            
            if self._is_uri_allowed(uri):
                return await func(*args, **kwargs)
            
            # Scan content
            result = self._scan_content(content, uri, "resource_write")
            
            # Handle based on mode and result
            if result.decision == Decision.BLOCK:
                self._record_block(uri, content, result)
                
                if self.mode == "protect":
                    if self.on_block:
                        self.on_block(result, content)
                    raise MCPSecurityError(
                        f"Resource write blocked: {result.explanation}",
                        result=result
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper  # type: ignore
    
    def protect_tool(
        self, 
        content_param: str = "content",
        scan_output: bool = False
    ) -> Callable[[F], F]:
        """
        Decorator to protect tool calls that modify state.
        
        Args:
            content_param: Name of parameter containing content to scan
            scan_output: Whether to scan the tool's output
        
        Returns:
            Decorator function
        
        Example:
            >>> @middleware.protect_tool(content_param="message")
            >>> async def send_message(to: str, message: str):
            ...     return await messenger.send(to, message)
        """
        def decorator(func: F) -> F:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract content from specified parameter
                content = kwargs.get(content_param, "")
                
                if not content and args:
                    # Try to find content in positional args
                    import inspect
                    sig = inspect.signature(func)
                    params = list(sig.parameters.keys())
                    if content_param in params:
                        idx = params.index(content_param)
                        if idx < len(args):
                            content = args[idx]
                
                # Scan input content
                if content:
                    result = self._scan_content(
                        str(content), 
                        func.__name__, 
                        "tool_call"
                    )
                    
                    if result.decision == Decision.BLOCK and self.mode == "protect":
                        self._record_block(func.__name__, str(content), result)
                        raise MCPSecurityError(
                            f"Tool call blocked: {result.explanation}",
                            result=result
                        )
                
                # Execute tool
                output = await func(*args, **kwargs)
                
                # Optionally scan output
                if scan_output and output:
                    output_result = self._scan_content(
                        str(output),
                        func.__name__,
                        "tool_output"
                    )
                    
                    if output_result.decision == Decision.BLOCK and self.mode == "protect":
                        raise MCPSecurityError(
                            f"Tool output blocked: {output_result.explanation}",
                            result=output_result
                        )
                
                return output
            
            return wrapper  # type: ignore
        
        return decorator
    
    def scan(self, content: str, source: str = "mcp") -> AnalysisResult:
        """
        Manually scan content.
        
        Args:
            content: Content to scan
            source: Source identifier
        
        Returns:
            Analysis result
        """
        return self._scan_content(content, source, "manual")
    
    def _scan_content(
        self, 
        content: str, 
        uri: str, 
        operation: str
    ) -> AnalysisResult:
        """Internal method to scan content."""
        self._scan_count += 1
        
        entry = MemoryEntry(
            content=content,
            source_type=f"mcp:{operation}",
            source_id=uri,
        )
        
        return self.analyzer.analyze(entry)
    
    def _extract_content(self, args: tuple, kwargs: dict) -> str:
        """Extract content from function arguments."""
        # Try common parameter names
        for name in ["content", "text", "data", "body", "message", "value"]:
            if name in kwargs:
                return str(kwargs[name])
        
        # Try second positional argument (first is usually uri)
        if len(args) >= 2:
            return str(args[1])
        
        return ""
    
    def _extract_uri(self, args: tuple, kwargs: dict) -> str:
        """Extract URI from function arguments."""
        for name in ["uri", "url", "path", "resource", "id"]:
            if name in kwargs:
                return str(kwargs[name])
        
        if args:
            return str(args[0])
        
        return "unknown"
    
    def _is_uri_allowed(self, uri: str) -> bool:
        """Check if URI is in whitelist."""
        for pattern in self.allowed_uris:
            if pattern in uri or uri.startswith(pattern):
                return True
        return False
    
    def _is_uri_blocked(self, uri: str) -> bool:
        """Check if URI is in blacklist."""
        for pattern in self.blocked_uris:
            if pattern in uri or uri.startswith(pattern):
                return True
        return False
    
    def _record_block(
        self, 
        uri: str, 
        content: str, 
        result: AnalysisResult
    ) -> None:
        """Record a blocked operation."""
        self._block_count += 1
        self.blocked_operations.append({
            "timestamp": datetime.utcnow().isoformat(),
            "uri": uri,
            "content_preview": content[:100],
            "threats": [t.threat.id for t in result.threats],
            "risk_score": result.risk_score,
            "decision": result.decision.value,
        })
    
    @property
    def stats(self) -> Dict[str, int]:
        """Get middleware statistics."""
        return {
            "scanned": self._scan_count,
            "blocked": self._block_count,
        }


class MCPSecurityError(Exception):
    """Raised when an MCP operation is blocked due to security threats."""
    
    def __init__(self, message: str, result: Optional[AnalysisResult] = None):
        super().__init__(message)
        self.result = result


def create_secure_handler(
    handler: Callable[..., Awaitable[Any]],
    middleware: Optional[MCPSecurityMiddleware] = None,
    **middleware_kwargs: Any,
) -> Callable[..., Awaitable[Any]]:
    """
    Create a secure MCP handler from an existing handler.
    
    Args:
        handler: Original async handler function
        middleware: Optional middleware instance
        **middleware_kwargs: Arguments for creating middleware
    
    Returns:
        Wrapped handler with security scanning
    """
    mw = middleware or MCPSecurityMiddleware(**middleware_kwargs)
    return mw.protect_resource(handler)
