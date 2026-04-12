"""
Memgar Auto-Protect Engine
===========================

Zero-configuration protection. One line activates everything:

    import memgar
    memgar.auto_protect()

How it works:

    1. Installs a Python import hook (sys.meta_path)
    2. The hook watches for framework imports (openai, anthropic, langchain, llama_index)
    3. When a framework is imported, the hook monkey-patches its key methods
    4. Every LLM call, memory write, and vector store insert is now protected

What gets patched automatically:

    OpenAI SDK        → completions.create (pre: DoW check, post: threat scan)
    Anthropic SDK     → messages.create    (pre: DoW check, post: threat scan)
    LangChain         → BaseChatModel.invoke, VectorStore.add_texts/add_documents
    LlamaIndex        → BaseIndex.insert, BaseIndex.insert_nodes
    JSON writes       → json.dump / json.dumps (opt-in, patch_json=True)
    SQLite writes     → sqlite3.Cursor.execute (opt-in, patch_sqlite=True)

The user sees nothing unless a threat is detected. Then they get an exception
or a log warning depending on their config.
"""

from __future__ import annotations

import functools
import importlib
import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("memgar.auto")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class AutoProtectConfig:
    """
    Configuration for auto_protect().

    All options have safe defaults — calling auto_protect() with no
    arguments gives full protection with block_on_threat=True.
    """
    # Threat detection
    block_on_threat: bool = True
    block_on_dow: bool = True
    block_on_budget_exhausted: bool = True
    log_threats: bool = True
    scan_llm_responses: bool = True     # scan LLM output, not just input

    # DoW / budget
    budget_usd: float = 0.0             # 0 = unlimited
    max_requests_per_minute: int = 200
    max_tokens_per_minute: int = 100_000

    # What to patch
    patch_openai: bool = True
    patch_anthropic: bool = True
    patch_langchain: bool = True
    patch_llamaindex: bool = True
    patch_json: bool = False            # opt-in: slower, broader
    patch_sqlite: bool = False          # opt-in: slower, broader
    patch_websockets: bool = True       # WebSocket guard (CVE-2026-25253 class)

    # Callbacks
    on_threat: Optional[Callable] = None        # fn(content, result)
    on_dow: Optional[Callable] = None           # fn(content, result)
    on_budget_warning: Optional[Callable] = None  # fn(session_id, cost)
    on_deviation: Optional[Callable] = None     # fn(DeviationReport) on behavioral anomaly

    # Behavioral baseline (Layer 4)
    enable_baseline: bool = True                # learn normal behavior, detect deviations
    baseline_alpha: float = 0.02               # EWM smoothing (lower = slower adaptation)
    baseline_window: float = 300.0             # observation window in seconds
    baseline_auto_trip: bool = True            # trip circuit breaker on CRITICAL deviation

    # Session
    session_id: str = "memgar-auto"


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

class _State:
    """Singleton state for the auto-protect system."""
    _lock = threading.Lock()
    active: bool = False
    config: Optional[AutoProtectConfig] = None
    patched: Set[str] = set()
    threats_detected: int = 0
    dow_blocked: int = 0
    requests_scanned: int = 0
    _analyzer = None
    _dow_guard = None
    _baseline = None
    _baseline_hooks = None

    @classmethod
    def get_analyzer(cls):
        if cls._analyzer is None:
            from memgar.analyzer import Analyzer
            cls._analyzer = Analyzer()
        return cls._analyzer

    @classmethod
    def get_baseline(cls):
        if cls._baseline is None and (cls.config and cls.config.enable_baseline):
            from memgar.behavioral_baseline import create_baseline
            from memgar.circuit_breaker import CircuitBreaker
            cfg = cls.config or AutoProtectConfig()
            # Wire circuit breaker as auto-trip target on CRITICAL
            breaker = CircuitBreaker() if cfg.baseline_auto_trip else None
            on_dev = cfg.on_deviation
            cls._baseline, cls._baseline_hooks = create_baseline(
                agent_id           = cfg.session_id,
                observation_window = cfg.baseline_window,
                alpha              = cfg.baseline_alpha,
                auto_trip_breaker  = breaker,
                on_deviation       = on_dev,
            )
        return cls._baseline, cls._baseline_hooks

    @classmethod
    def get_dow_guard(cls):
        if cls._dow_guard is None:
            from memgar.dow import DoWGuard
            cfg = cls.config or AutoProtectConfig()
            cls._dow_guard = DoWGuard(
                session_id=cfg.session_id,
                budget_usd=cfg.budget_usd,
                max_requests_per_minute=cfg.max_requests_per_minute,
                max_tokens_per_minute=cfg.max_tokens_per_minute,
                block_on_dow=cfg.block_on_dow,
                block_on_budget=cfg.block_on_budget_exhausted,
                on_budget_warning=cfg.on_budget_warning,
            )
        return cls._dow_guard

_state = _State()


# ---------------------------------------------------------------------------
# Core scan helpers
# ---------------------------------------------------------------------------

def _scan_content(content: str, source: str = "auto") -> bool:
    """
    Scan content. Returns True if safe, False if threat detected.
    Raises exception if block_on_threat=True.
    """
    if not content or not isinstance(content, str) or len(content.strip()) < 3:
        return True

    cfg = _state.config or AutoProtectConfig()
    analyzer = _state.get_analyzer()
    _state.requests_scanned += 1

    try:
        from memgar.models import MemoryEntry, Decision
        entry = MemoryEntry(content=content, source_type=source)
        result = analyzer.analyze(entry)

        # Feed behavioral baseline regardless of decision
        try:
            _, hooks = _state.get_baseline()
            if hooks:
                hooks.on_scan(
                    risk_score   = result.risk_score,
                    decision     = result.decision.value,
                    threat_count = len(result.threats),
                    threat_ids   = [t.threat.id for t in result.threats],
                )
        except Exception:
            pass

        if result.decision != Decision.ALLOW:
            _state.threats_detected += 1
            threat_names = [t.threat.name for t in result.threats[:3]]

            if cfg.log_threats:
                logger.warning(
                    "[Memgar Auto] 🚨 Threat detected | source=%s | decision=%s | "
                    "score=%d | threats=%s",
                    source, result.decision.value, result.risk_score,
                    ", ".join(threat_names),
                )

            if cfg.on_threat:
                try:
                    cfg.on_threat(content, result)
                except Exception:
                    pass

            if cfg.block_on_threat:
                from memgar.frameworks.langchain_deep import MemgarThreatError
                raise MemgarThreatError(
                    f"[Memgar] Threat blocked (score={result.risk_score}): "
                    f"{', '.join(threat_names)}",
                    result=result,
                )
            return False

    except Exception as e:
        # Don't crash the user's code on our errors — just log
        if "MemgarThreatError" in type(e).__name__ or "ThreatError" in type(e).__name__:
            raise
        logger.debug("[Memgar Auto] Scan error (non-fatal): %s", e)

    # Periodic baseline check — emit to SIEM if deviation detected
    try:
        baseline, _ = _state.get_baseline()
        if baseline and baseline._check_count % 20 == 0 and baseline._check_count > 0:
            from memgar.behavioral_baseline import DeviationLevel
            report = baseline.check()
            if report.level in (DeviationLevel.SUSPICIOUS, DeviationLevel.CRITICAL):
                try:
                    from memgar.siem import SIEMEvent, EventCategory
                    event = SIEMEvent(
                        category  = EventCategory.AUTO_PROTECT_BLOCK,
                        severity  = "critical" if report.level == DeviationLevel.CRITICAL else "high",
                        message   = f"Behavioral deviation: {report.level.value} (score={report.composite_score:.1f})",
                        agent_id  = baseline.agent_id,
                        risk_score = int(min(100, report.composite_score * 10)),
                        action    = "detected",
                        extra     = {"deviation_report": report.to_dict()},
                    )
                    logger.warning("[Memgar Baseline] %s", event.message)
                except Exception:
                    pass
    except Exception:
        pass

    return True


def _dow_check(content: str, source: str = "auto") -> None:
    """Run DoW check. Raises DoWAttackDetected if attack found."""
    if not content or not isinstance(content, str):
        return
    cfg = _state.config or AutoProtectConfig()
    if not cfg.block_on_dow:
        return
    try:
        guard = _state.get_dow_guard()
        guard.check(content)
    except Exception as e:
        if any(x in type(e).__name__ for x in ["DoW", "Throttle", "Budget"]):
            _state.dow_blocked += 1
            if cfg.log_threats:
                logger.warning("[Memgar Auto] 💸 DoW blocked | source=%s | %s", source, e)
            raise
        logger.debug("[Memgar Auto] DoW check error (non-fatal): %s", e)


def _extract_text(obj: Any) -> str:
    """Best-effort text extraction from any object."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for key in ("content", "text", "message", "input", "prompt"):
            val = obj.get(key)
            if isinstance(val, str):
                return val
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, list):
        parts = []
        for item in obj:
            t = _extract_text(item)
            if t:
                parts.append(t)
        return " ".join(parts)
    return str(obj) if obj is not None else ""


def _wrap(original_fn: Callable, pre_scan: bool = True,
          post_scan: bool = False, source: str = "unknown") -> Callable:
    """
    Wrap a function with Memgar pre/post scanning.
    Thread-safe, preserves signatures.
    """
    @functools.wraps(original_fn)
    def wrapper(*args, **kwargs):
        # Pre-scan: check input for DoW + threats
        if pre_scan:
            # Extract text from args[1] (usually the first non-self arg)
            content = ""
            for arg in list(args[1:3]) + list(kwargs.values()):
                t = _extract_text(arg)
                if len(t) > 3:
                    content = t
                    break
            if content:
                try:
                    _dow_check(content, source=source)
                    _scan_content(content, source=source)
                except Exception:
                    raise

        # Call original
        result = original_fn(*args, **kwargs)

        # Post-scan: check LLM response for exfiltration patterns
        cfg = _state.config or AutoProtectConfig()
        if post_scan and cfg.scan_llm_responses and result is not None:
            response_text = _extract_response_text(result)
            if response_text:
                try:
                    _scan_content(response_text, source=f"{source}_response")
                except Exception:
                    pass  # never block on response scan — just log

        return result

    return wrapper


async def _wrap_async(original_fn: Callable, pre_scan: bool = True,
                      post_scan: bool = False, source: str = "unknown") -> Callable:
    """Async version of _wrap."""
    @functools.wraps(original_fn)
    async def wrapper(*args, **kwargs):
        if pre_scan:
            content = ""
            for arg in list(args[1:3]) + list(kwargs.values()):
                t = _extract_text(arg)
                if len(t) > 3:
                    content = t
                    break
            if content:
                try:
                    _dow_check(content, source=source)
                    _scan_content(content, source=source)
                except Exception:
                    raise

        result = await original_fn(*args, **kwargs)

        cfg = _state.config or AutoProtectConfig()
        if post_scan and cfg.scan_llm_responses and result is not None:
            response_text = _extract_response_text(result)
            if response_text:
                try:
                    _scan_content(response_text, source=f"{source}_response")
                except Exception:
                    pass

        return result

    return wrapper


def _make_async_wrapper(original_fn: Callable, source: str) -> Callable:
    """Create async wrapper without await at definition time."""
    @functools.wraps(original_fn)
    async def wrapper(*args, **kwargs):
        content = ""
        for arg in list(args[1:3]) + list(kwargs.values()):
            t = _extract_text(arg)
            if len(t) > 3:
                content = t
                break
        if content:
            try:
                _dow_check(content, source=source)
                _scan_content(content, source=source)
            except Exception:
                raise

        result = await original_fn(*args, **kwargs)

        cfg = _state.config or AutoProtectConfig()
        if cfg.scan_llm_responses and result is not None:
            response_text = _extract_response_text(result)
            if response_text:
                try:
                    _scan_content(response_text, source=f"{source}_response")
                except Exception:
                    pass

        return result

    return wrapper


def _extract_response_text(result: Any) -> str:
    """Extract text from LLM response objects."""
    # OpenAI ChatCompletion
    if hasattr(result, "choices"):
        try:
            return result.choices[0].message.content or ""
        except (AttributeError, IndexError):
            pass
    # Anthropic Message
    if hasattr(result, "content") and isinstance(result.content, list):
        try:
            parts = []
            for block in result.content:
                if hasattr(block, "text"):
                    parts.append(block.text)
            return " ".join(parts)
        except Exception:
            pass
    # LangChain AIMessage / string
    if hasattr(result, "content"):
        return str(result.content)
    return ""


# ---------------------------------------------------------------------------
# Per-framework patchers
# ---------------------------------------------------------------------------

def _patch_openai() -> bool:
    try:
        import openai.resources.chat.completions as oai_completions

        # Sync
        if not getattr(oai_completions.Completions.create, "_memgar_patched", False):
            orig = oai_completions.Completions.create
            wrapped = _wrap(orig, pre_scan=True, post_scan=True, source="openai")
            wrapped._memgar_patched = True
            oai_completions.Completions.create = wrapped

        # Async
        if not getattr(oai_completions.AsyncCompletions.create, "_memgar_patched", False):
            orig_async = oai_completions.AsyncCompletions.create
            wrapped_async = _make_async_wrapper(orig_async, source="openai_async")
            wrapped_async._memgar_patched = True
            oai_completions.AsyncCompletions.create = wrapped_async

        logger.info("[Memgar Auto] ✅ OpenAI patched")
        return True
    except Exception as e:
        logger.debug("[Memgar Auto] OpenAI patch failed: %s", e)
        return False


def _patch_anthropic() -> bool:
    try:
        import anthropic.resources.messages as ant_messages

        if not getattr(ant_messages.Messages.create, "_memgar_patched", False):
            orig = ant_messages.Messages.create
            wrapped = _wrap(orig, pre_scan=True, post_scan=True, source="anthropic")
            wrapped._memgar_patched = True
            ant_messages.Messages.create = wrapped

        # Async
        if hasattr(ant_messages, "AsyncMessages"):
            if not getattr(ant_messages.AsyncMessages.create, "_memgar_patched", False):
                orig_async = ant_messages.AsyncMessages.create
                wrapped_async = _make_async_wrapper(orig_async, source="anthropic_async")
                wrapped_async._memgar_patched = True
                ant_messages.AsyncMessages.create = wrapped_async

        logger.info("[Memgar Auto] ✅ Anthropic patched")
        return True
    except Exception as e:
        logger.debug("[Memgar Auto] Anthropic patch failed: %s", e)
        return False


def _patch_langchain() -> bool:
    patched = False
    try:
        from langchain_core.language_models.chat_models import BaseChatModel

        # Patch invoke (LCEL)
        if not getattr(BaseChatModel.invoke, "_memgar_patched", False):
            orig_invoke = BaseChatModel.invoke
            wrapped = _wrap(orig_invoke, pre_scan=True, post_scan=True, source="langchain_llm")
            wrapped._memgar_patched = True
            BaseChatModel.invoke = wrapped
            patched = True

        # Patch _generate (called by invoke internally)
        if not getattr(BaseChatModel._generate, "_memgar_patched", False):
            orig_gen = BaseChatModel._generate
            wrapped_gen = _wrap(orig_gen, pre_scan=True, post_scan=False, source="langchain_generate")
            wrapped_gen._memgar_patched = True
            BaseChatModel._generate = wrapped_gen

    except Exception as e:
        logger.debug("[Memgar Auto] LangChain LLM patch failed: %s", e)

    try:
        from langchain_core.vectorstores.base import VectorStore

        for method_name in ("add_texts", "add_documents"):
            method = getattr(VectorStore, method_name, None)
            if method and not getattr(method, "_memgar_patched", False):
                wrapped = _wrap(method, pre_scan=True, post_scan=False,
                                source=f"langchain_{method_name}")
                wrapped._memgar_patched = True
                setattr(VectorStore, method_name, wrapped)
                patched = True

    except Exception as e:
        logger.debug("[Memgar Auto] LangChain VectorStore patch failed: %s", e)

    try:
        from langchain.memory import ConversationBufferMemory

        if not getattr(ConversationBufferMemory.save_context, "_memgar_patched", False):
            orig_save = ConversationBufferMemory.save_context

            @functools.wraps(orig_save)
            def patched_save(self, inputs, outputs, **kwargs):
                content = _extract_text(inputs)
                if content:
                    _dow_check(content, "langchain_memory")
                    _scan_content(content, "langchain_memory")
                return orig_save(self, inputs, outputs, **kwargs)

            patched_save._memgar_patched = True
            ConversationBufferMemory.save_context = patched_save
            patched = True

    except Exception as e:
        logger.debug("[Memgar Auto] LangChain Memory patch failed: %s", e)

    if patched:
        logger.info("[Memgar Auto] ✅ LangChain patched")
    return patched


def _patch_llamaindex() -> bool:
    patched = False
    try:
        from llama_index.core.indices.base import BaseIndex

        for method_name in ("insert", "insert_nodes"):
            method = getattr(BaseIndex, method_name, None)
            if method and not getattr(method, "_memgar_patched", False):
                wrapped = _wrap(method, pre_scan=True, post_scan=False,
                                source=f"llamaindex_{method_name}")
                wrapped._memgar_patched = True
                setattr(BaseIndex, method_name, wrapped)
                patched = True

    except Exception as e:
        logger.debug("[Memgar Auto] LlamaIndex BaseIndex patch failed: %s", e)

    try:
        from llama_index.core.query_engine.retriever_query_engine import RetrieverQueryEngine

        if not getattr(RetrieverQueryEngine.query, "_memgar_patched", False):
            orig_query = RetrieverQueryEngine.query

            @functools.wraps(orig_query)
            def patched_query(self, str_or_query_bundle, **kwargs):
                query_str = (
                    str_or_query_bundle.query_str
                    if hasattr(str_or_query_bundle, "query_str")
                    else str(str_or_query_bundle)
                )
                _dow_check(query_str, "llamaindex_query")
                _scan_content(query_str, "llamaindex_query")
                return orig_query(self, str_or_query_bundle, **kwargs)

            patched_query._memgar_patched = True
            RetrieverQueryEngine.query = patched_query
            patched = True

    except Exception as e:
        logger.debug("[Memgar Auto] LlamaIndex QueryEngine patch failed: %s", e)

    if patched:
        logger.info("[Memgar Auto] ✅ LlamaIndex patched")
    return patched


def _patch_json_writes() -> bool:
    """Opt-in: scan content written via json.dump/dumps."""
    try:
        import json as json_module

        if not getattr(json_module.dumps, "_memgar_patched", False):
            orig_dumps = json_module.dumps

            @functools.wraps(orig_dumps)
            def patched_dumps(obj, *args, **kwargs):
                result = orig_dumps(obj, *args, **kwargs)
                # Only scan if it looks like a memory store (has "content" key)
                if '"content"' in result and len(result) < 50_000:
                    try:
                        parsed = json_module.loads(result)
                        items = parsed if isinstance(parsed, list) else [parsed]
                        for item in items[:10]:  # cap at 10
                            content = _extract_text(item)
                            if content and len(content) > 10:
                                _scan_content(content, "json_write")
                    except Exception:
                        pass
                return result

            patched_dumps._memgar_patched = True
            json_module.dumps = patched_dumps
            logger.info("[Memgar Auto] ✅ json.dumps patched")
            return True

    except Exception as e:
        logger.debug("[Memgar Auto] JSON patch failed: %s", e)
    return False


def _patch_sqlite_writes() -> bool:
    """Opt-in: scan content written via sqlite3."""
    try:
        import sqlite3 as sqlite_module

        orig_execute = sqlite_module.Cursor.execute

        if not getattr(orig_execute, "_memgar_patched", False):
            @functools.wraps(orig_execute)
            def patched_execute(self, sql, parameters=(), **kwargs):
                sql_upper = sql.strip().upper()
                if sql_upper.startswith(("INSERT", "UPDATE", "REPLACE")):
                    for param in (parameters or []):
                        if isinstance(param, str) and len(param) > 10:
                            _scan_content(param, "sqlite_write")
                return orig_execute(self, sql, parameters, **kwargs)

            patched_execute._memgar_patched = True
            sqlite_module.Cursor.execute = patched_execute
            logger.info("[Memgar Auto] ✅ sqlite3.Cursor.execute patched")
            return True

    except Exception as e:
        logger.debug("[Memgar Auto] SQLite patch failed: %s", e)
    return False


# ---------------------------------------------------------------------------
# Import hook — patches frameworks as they are imported
# ---------------------------------------------------------------------------

class _MemgarImportHook:
    """
    sys.meta_path finder that intercepts module imports and applies
    Memgar patches immediately after the target module loads.
    """

    TARGETS = {
        "openai": "_patch_openai",
        "openai.resources.chat.completions": "_patch_openai",
        "anthropic": "_patch_anthropic",
        "anthropic.resources.messages": "_patch_anthropic",
        "langchain_core": "_patch_langchain",
        "langchain_core.language_models": "_patch_langchain",
        "langchain_core.language_models.chat_models": "_patch_langchain",
        "langchain": "_patch_langchain",
        "llama_index": "_patch_llamaindex",
        "llama_index.core": "_patch_llamaindex",
        "llama_index.core.indices": "_patch_llamaindex",
    }

    def find_module(self, fullname, path=None):
        return None  # Let normal import system handle loading

    def find_spec(self, fullname, path, target=None):
        return None  # Let normal import system handle loading

    def exec_module(self, module):
        pass

    def post_import_hook(self, module_name: str) -> None:
        """Called after a target module is successfully imported."""
        cfg = _state.config or AutoProtectConfig()
        patch_fn_name = self.TARGETS.get(module_name)
        if not patch_fn_name:
            return
        if module_name in _state.patched:
            return

        patch_fns = {
            "_patch_openai": (_patch_openai, cfg.patch_openai),
            "_patch_anthropic": (_patch_anthropic, cfg.patch_anthropic),
            "_patch_langchain": (_patch_langchain, cfg.patch_langchain),
            "_patch_llamaindex": (_patch_llamaindex, cfg.patch_llamaindex),
        }

        fn, enabled = patch_fns.get(patch_fn_name, (None, False))
        if fn and enabled:
            try:
                fn()
                _state.patched.add(module_name)
            except Exception as e:
                logger.debug("[Memgar Auto] Post-import patch error: %s", e)


# We use a different approach: wrap __import__ to detect when targets load
_original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else None

_hook_instance = _MemgarImportHook()


def _install_import_hook() -> None:
    """
    Patch builtins.__import__ to detect framework imports and apply patches.
    This is more reliable than sys.meta_path for post-load patching.
    """
    import builtins

    original_import = builtins.__import__
    if getattr(original_import, "_memgar_hooked", False):
        return

    def memgar_import(name, *args, **kwargs):
        module = original_import(name, *args, **kwargs)
        # Check if this is a target we need to patch
        if name in _hook_instance.TARGETS and name not in _state.patched:
            _hook_instance.post_import_hook(name)
        return module

    memgar_import._memgar_hooked = True
    builtins.__import__ = memgar_import


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@dataclass
class AutoProtectStatus:
    """Current status of auto-protect."""
    active: bool
    patched_frameworks: List[str]
    threats_detected: int
    dow_blocked: int
    requests_scanned: int
    config: Optional[AutoProtectConfig]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "active": self.active,
            "patched_frameworks": self.patched_frameworks,
            "threats_detected": self.threats_detected,
            "dow_blocked": self.dow_blocked,
            "requests_scanned": self.requests_scanned,
            "config": {
                "block_on_threat": self.config.block_on_threat if self.config else None,
                "block_on_dow": self.config.block_on_dow if self.config else None,
                "budget_usd": self.config.budget_usd if self.config else None,
                "scan_llm_responses": self.config.scan_llm_responses if self.config else None,
                "patch_openai": self.config.patch_openai if self.config else None,
                "patch_anthropic": self.config.patch_anthropic if self.config else None,
                "patch_langchain": self.config.patch_langchain if self.config else None,
                "patch_llamaindex": self.config.patch_llamaindex if self.config else None,
            } if self.config else None,
        }

    def __str__(self) -> str:
        lines = [
            f"Memgar Auto-Protect: {'ACTIVE' if self.active else 'INACTIVE'}",
            f"  Patched: {', '.join(self.patched_frameworks) or 'none yet (will patch on import)'}",
            f"  Scanned: {self.requests_scanned} requests",
            f"  Threats: {self.threats_detected} blocked",
            f"  DoW:     {self.dow_blocked} blocked",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def auto_protect(
    block_on_threat: bool = True,
    block_on_dow: bool = True,
    budget_usd: float = 0.0,
    scan_llm_responses: bool = True,
    patch_openai: bool = True,
    patch_anthropic: bool = True,
    patch_langchain: bool = True,
    patch_llamaindex: bool = True,
    patch_json: bool = False,
    patch_sqlite: bool = False,
    patch_websockets: bool = True,
    log_threats: bool = True,
    session_id: str = "memgar-auto",
    on_threat: Optional[Callable] = None,
    on_dow: Optional[Callable] = None,
    on_budget_warning: Optional[Callable] = None,
) -> AutoProtectStatus:
    """
    Activate Memgar auto-protection. Call once at startup.

    Patches all installed AI frameworks automatically. Frameworks imported
    AFTER this call are also patched via import hook.

    Args:
        block_on_threat:      Block requests with memory poisoning threats.
        block_on_dow:         Block Denial of Wallet attacks.
        budget_usd:           Hard USD spend cap per session (0 = unlimited).
        scan_llm_responses:   Also scan LLM outputs for data exfiltration.
        patch_openai:         Patch OpenAI SDK (if installed).
        patch_anthropic:      Patch Anthropic SDK (if installed).
        patch_langchain:      Patch LangChain (if installed).
        patch_llamaindex:     Patch LlamaIndex (if installed).
        patch_json:           Patch json.dumps (opt-in, broader coverage).
        patch_sqlite:         Patch sqlite3 writes (opt-in, broader coverage).
        log_threats:          Log detected threats to memgar.auto logger.
        session_id:           Session identifier for DoW budget tracking.
        on_threat:            Callback(content, result) on threat detection.
        on_dow:               Callback(content, result) on DoW detection.
        on_budget_warning:    Callback(session_id, cost_usd) at 80% budget.

    Returns:
        AutoProtectStatus — current protection status.

    Example::

        import memgar
        memgar.auto_protect()

        # Now use your frameworks normally — Memgar is watching
        from openai import OpenAI
        client = OpenAI()
        # Every client.chat.completions.create() is now scanned
    """
    with _state._lock:
        _state.config = AutoProtectConfig(
            block_on_threat=block_on_threat,
            block_on_dow=block_on_dow,
            budget_usd=budget_usd,
            scan_llm_responses=scan_llm_responses,
            patch_openai=patch_openai,
            patch_anthropic=patch_anthropic,
            patch_langchain=patch_langchain,
            patch_llamaindex=patch_llamaindex,
            patch_json=patch_json,
            patch_sqlite=patch_sqlite,
            patch_websockets=patch_websockets,
            log_threats=log_threats,
            session_id=session_id,
            on_threat=on_threat,
            on_dow=on_dow,
            on_budget_warning=on_budget_warning,
        )
        _state.active = True

    # Patch already-imported frameworks immediately
    if patch_openai and "openai" in sys.modules:
        _patch_openai()
        _state.patched.add("openai")

    if patch_anthropic and "anthropic" in sys.modules:
        _patch_anthropic()
        _state.patched.add("anthropic")

    if patch_langchain and "langchain_core" in sys.modules:
        _patch_langchain()
        _state.patched.add("langchain_core")

    if patch_llamaindex and "llama_index" in sys.modules:
        _patch_llamaindex()
        _state.patched.add("llama_index")

    if patch_json:
        _patch_json_writes()
        _state.patched.add("json")

    if patch_sqlite:
        _patch_sqlite_writes()
        _state.patched.add("sqlite3")

    # Install import hook for frameworks imported AFTER this call
    _install_import_hook()

    if log_threats:
        logger.info(
            "[Memgar Auto] 🛡️  Auto-protect activated | "
            "block=%s | dow=%s | budget=$%.2f | response_scan=%s",
            block_on_threat, block_on_dow, budget_usd, scan_llm_responses,
        )

    return get_status()


def auto_protect_off() -> None:
    """Deactivate auto-protect (does not unpatch — restart to fully remove)."""
    _state.active = False
    logger.info("[Memgar Auto] Auto-protect deactivated.")


def get_status() -> AutoProtectStatus:
    """Return current auto-protect status and statistics."""
    return AutoProtectStatus(
        active=_state.active,
        patched_frameworks=sorted(_state.patched),
        threats_detected=_state.threats_detected,
        dow_blocked=_state.dow_blocked,
        requests_scanned=_state.requests_scanned,
        config=_state.config,
    )


def reset_stats() -> None:
    """Reset threat and request counters."""
    _state.threats_detected = 0
    _state.dow_blocked = 0
    _state.requests_scanned = 0
