"""
Memgar Configuration Management
================================

Comprehensive configuration system with:
- Environment variable support
- Config file support (JSON, YAML, TOML)
- LLM provider configuration
- Model selection and fallback
- Validation and defaults
- Hierarchical override: defaults < config file < env vars

Configuration Hierarchy (lowest to highest priority):
1. Built-in defaults
2. Config file (~/.memgarrc or MEMGAR_CONFIG)
3. Environment variables (MEMGAR_*)

Environment Variables:
    MEMGAR_CONFIG           - Path to config file
    MEMGAR_LLM_PROVIDER     - LLM provider (openai, anthropic, groq, etc.)
    MEMGAR_LLM_MODEL        - Model name
    MEMGAR_LLM_API_KEY      - API key (overrides provider-specific keys)
    MEMGAR_LLM_BASE_URL     - Custom API base URL
    MEMGAR_LLM_TIMEOUT      - Request timeout in seconds
    MEMGAR_LLM_MAX_RETRIES  - Max retry attempts
    MEMGAR_LLM_FALLBACK     - Enable provider fallback (true/false)
    MEMGAR_CACHE_ENABLED    - Enable response caching (true/false)
    MEMGAR_CACHE_TTL        - Cache TTL in seconds
    MEMGAR_SLIDING_WINDOW   - Enable sliding window analysis (true/false)
    MEMGAR_WINDOW_SIZE      - Sliding window size in chars
    MEMGAR_STRICT_MODE      - Enable strict mode (true/false)
    MEMGAR_LOG_LEVEL        - Logging level (DEBUG, INFO, WARNING, ERROR)
"""

import os
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Union
from enum import Enum

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE = "azure"
    GOOGLE = "google"
    MISTRAL = "mistral"
    GROQ = "groq"
    TOGETHER = "together"
    COHERE = "cohere"
    OPENROUTER = "openrouter"
    OLLAMA = "ollama"
    LITELLM = "litellm"
    OPENAI_COMPATIBLE = "openai_compatible"
    AUTO = "auto"  # Auto-detect
    MOCK = "mock"  # For testing


class OutputFormat(str, Enum):
    """Output format options."""
    TEXT = "text"
    JSON = "json"
    TABLE = "table"
    MARKDOWN = "markdown"


class LogLevel(str, Enum):
    """Log level options."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# =============================================================================
# DEFAULT MODEL CONFIGURATIONS
# =============================================================================

DEFAULT_MODELS: Dict[str, List[str]] = {
    "openai": [
        "gpt-4o-mini",
        "gpt-4o",
        "gpt-4-turbo",
        "gpt-3.5-turbo",
    ],
    "anthropic": [
        "claude-3-5-haiku-20241022",
        "claude-3-5-sonnet-20241022",
        "claude-3-haiku-20240307",
        "claude-3-sonnet-20240229",
    ],
    "azure": [
        "gpt-4o",
        "gpt-4-turbo",
        "gpt-35-turbo",
    ],
    "google": [
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-pro",
    ],
    "mistral": [
        "mistral-small-latest",
        "mistral-medium-latest",
        "mistral-large-latest",
        "open-mistral-7b",
    ],
    "groq": [
        "llama-3.1-8b-instant",
        "llama-3.1-70b-versatile",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
    ],
    "together": [
        "meta-llama/Llama-3.2-3B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "mistralai/Mixtral-8x7B-Instruct-v0.1",
    ],
    "cohere": [
        "command-r",
        "command-r-plus",
        "command-light",
    ],
    "openrouter": [
        "meta-llama/llama-3.1-8b-instruct:free",
        "google/gemini-flash-1.5",
        "anthropic/claude-3-haiku",
        "openai/gpt-4o-mini",
    ],
    "ollama": [
        "llama3.2:3b",
        "llama3.1:8b",
        "mistral:7b",
        "gemma2:9b",
        "phi3:mini",
    ],
}

# Provider API key environment variables
PROVIDER_ENV_KEYS: Dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "azure": "AZURE_OPENAI_API_KEY",
    "google": "GOOGLE_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "groq": "GROQ_API_KEY",
    "together": "TOGETHER_API_KEY",
    "cohere": "COHERE_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "litellm": "LITELLM_API_KEY",
    "openai_compatible": "OPENAI_COMPATIBLE_API_KEY",
}

# Provider base URLs
PROVIDER_BASE_URLS: Dict[str, Optional[str]] = {
    "openai": None,
    "anthropic": None,
    "azure": None,  # Uses AZURE_OPENAI_ENDPOINT
    "google": None,
    "mistral": "https://api.mistral.ai/v1",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz/v1",
    "cohere": None,
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",
    "litellm": None,  # Uses LITELLM_BASE_URL
    "openai_compatible": None,  # Uses OPENAI_COMPATIBLE_BASE_URL
}


# =============================================================================
# CONFIGURATION DATACLASSES
# =============================================================================

@dataclass
class LLMConfig:
    """LLM provider and model configuration."""
    
    # Provider settings
    provider: str = "auto"
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    
    # Request settings
    timeout: float = 30.0
    max_retries: int = 2
    max_tokens: int = 500
    
    # Fallback settings
    enable_fallback: bool = True
    fallback_providers: List[str] = field(default_factory=list)
    fallback_models: bool = True
    
    # Cache settings
    cache_enabled: bool = True
    cache_ttl: int = 3600  # seconds
    cache_max_size: int = 1000
    
    # Custom models (override defaults)
    custom_models: Dict[str, List[str]] = field(default_factory=dict)
    
    def get_models(self, provider: str) -> List[str]:
        """Get models for provider, with custom override."""
        if provider in self.custom_models:
            return self.custom_models[provider]
        return DEFAULT_MODELS.get(provider, [])
    
    def get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for provider."""
        # First check explicit key
        if self.api_key:
            return self.api_key
        
        # Then check MEMGAR_LLM_API_KEY
        memgar_key = os.environ.get("MEMGAR_LLM_API_KEY")
        if memgar_key:
            return memgar_key
        
        # Finally check provider-specific env var
        env_var = PROVIDER_ENV_KEYS.get(provider)
        if env_var:
            return os.environ.get(env_var)
        
        return None
    
    def get_base_url(self, provider: str) -> Optional[str]:
        """Get base URL for provider."""
        # First check explicit URL
        if self.base_url:
            return self.base_url
        
        # Then check MEMGAR_LLM_BASE_URL
        memgar_url = os.environ.get("MEMGAR_LLM_BASE_URL")
        if memgar_url:
            return memgar_url
        
        # Check provider-specific env vars
        if provider == "azure":
            return os.environ.get("AZURE_OPENAI_ENDPOINT")
        elif provider == "litellm":
            return os.environ.get("LITELLM_BASE_URL")
        elif provider == "openai_compatible":
            return os.environ.get("OPENAI_COMPATIBLE_BASE_URL")
        
        # Return default
        return PROVIDER_BASE_URLS.get(provider)


@dataclass
class AnalysisConfig:
    """Analysis engine configuration."""

    # Risk thresholds
    risk_threshold_block: int = 80
    risk_threshold_quarantine: int = 40

    # Analysis features
    enable_semantic: bool = False
    use_llm: bool = False
    strict_mode: bool = False

    # Fail-close mode: when True, any input that could not be fully analyzed
    # (because one or more ML/semantic layers are degraded) is escalated to
    # at least Decision.QUARANTINE rather than being allowed through.
    # Recommended for high-risk environments (finance, healthcare, auth flows).
    # Env var: MEMGAR_FAIL_CLOSE=true
    fail_close: bool = False

    # Sliding window
    use_sliding_window: bool = True
    window_size: int = 1000
    window_overlap: int = 200

    # Performance
    max_content_length: int = 1000000  # 1MB
    batch_size: int = 10


@dataclass
class OutputConfig:
    """Output and display configuration."""
    
    output_format: str = "text"
    verbose: bool = False
    color: bool = True
    show_threats: bool = True
    show_explanation: bool = True


@dataclass
class IgnoreConfig:
    """Ignore rules for false positive reduction."""
    
    patterns: List[str] = field(default_factory=list)
    threat_ids: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)


@dataclass
class CloudConfig:
    """Cloud service configuration."""

    enabled: bool = False
    api_key: Optional[str] = None
    api_url: str = "https://api.memgar.io"
    sync_enabled: bool = False


@dataclass
class FeedConfig:
    """Threat intelligence feed configuration."""

    enabled: bool = True
    auto_sync: bool = True
    max_age_days: int = 7
    github_repo: str = "slcxtor/memgar"
    verify_signature: bool = True


@dataclass
class ObservabilityConfig:
    """Prometheus metrics and drift-alert configuration."""

    enabled: bool = False
    port: int = 9090
    drift_alert_threshold: float = 0.2
    drift_window_size: int = 1000


@dataclass
class HunterConfig:
    """Active hunter mode — continuous background scanning of memory stores."""

    enabled: bool = False
    scan_interval_seconds: int = 60
    rescan_clean_after_seconds: int = 3600
    alert_threshold: float = 0.7
    max_entries_per_scan: int = 1000


@dataclass
class MemgarConfig:
    """
    Complete Memgar configuration.

    Combines all sub-configurations into a single object.
    """

    # Sub-configurations
    llm: LLMConfig = field(default_factory=LLMConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    ignore: IgnoreConfig = field(default_factory=IgnoreConfig)
    cloud: CloudConfig = field(default_factory=CloudConfig)
    feed: FeedConfig = field(default_factory=FeedConfig)
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)
    hunter: HunterConfig = field(default_factory=HunterConfig)

    # Logging
    log_level: str = "WARNING"

    # Custom rules
    custom_rules_path: Optional[str] = None

    # Version
    config_version: str = "2.0"


# =============================================================================
# CONFIGURATION LOADING
# =============================================================================

def get_config_path() -> Path:
    """
    Get configuration file path.
    
    Checks in order:
    1. MEMGAR_CONFIG environment variable
    2. ./memgar.json (current directory)
    3. ./memgar.yaml (current directory)
    4. ~/.memgarrc (home directory)
    5. ~/.config/memgar/config.json (XDG config)
    
    Returns:
        Path to configuration file (may not exist)
    """
    # Check env var first
    if "MEMGAR_CONFIG" in os.environ:
        return Path(os.environ["MEMGAR_CONFIG"])
    
    # Check current directory
    for filename in ["memgar.json", "memgar.yaml", "memgar.yml", "memgar.toml"]:
        path = Path.cwd() / filename
        if path.exists():
            return path
    
    # Check home directory
    home_config = Path.home() / ".memgarrc"
    if home_config.exists():
        return home_config
    
    # Check XDG config
    xdg_config = Path.home() / ".config" / "memgar" / "config.json"
    if xdg_config.exists():
        return xdg_config
    
    # Default to home directory
    return home_config


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load YAML config file."""
    try:
        import yaml
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        logger.warning("PyYAML not installed. Install with: pip install pyyaml")
        return {}


def _load_toml(path: Path) -> Dict[str, Any]:
    """Load TOML config file."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            logger.warning("TOML support not available. Install with: pip install tomli")
            return {}
    
    with open(path, "rb") as f:
        return tomllib.load(f)


def _load_json(path: Path) -> Dict[str, Any]:
    """Load JSON config file."""
    with open(path, "r") as f:
        return json.load(f)


def _load_config_file(path: Path) -> Dict[str, Any]:
    """Load config from file based on extension."""
    if not path.exists():
        return {}
    
    suffix = path.suffix.lower()
    
    try:
        if suffix in [".yaml", ".yml"]:
            return _load_yaml(path)
        elif suffix == ".toml":
            return _load_toml(path)
        else:
            return _load_json(path)
    except Exception as e:
        logger.warning(f"Error loading config from {path}: {e}")
        return {}


def _parse_bool(value: Any) -> bool:
    """Parse boolean from various formats."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on")
    return bool(value)


def _parse_int(value: Any, default: int) -> int:
    """Parse integer with default."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _parse_float(value: Any, default: float) -> float:
    """Parse float with default."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _apply_env_overrides(config: MemgarConfig) -> MemgarConfig:
    """Apply environment variable overrides to config."""
    
    # LLM settings
    if "MEMGAR_LLM_PROVIDER" in os.environ:
        config.llm.provider = os.environ["MEMGAR_LLM_PROVIDER"]
    
    if "MEMGAR_LLM_MODEL" in os.environ:
        config.llm.model = os.environ["MEMGAR_LLM_MODEL"]
    
    if "MEMGAR_LLM_API_KEY" in os.environ:
        config.llm.api_key = os.environ["MEMGAR_LLM_API_KEY"]
    
    if "MEMGAR_LLM_BASE_URL" in os.environ:
        config.llm.base_url = os.environ["MEMGAR_LLM_BASE_URL"]
    
    if "MEMGAR_LLM_TIMEOUT" in os.environ:
        config.llm.timeout = _parse_float(os.environ["MEMGAR_LLM_TIMEOUT"], 30.0)
    
    if "MEMGAR_LLM_MAX_RETRIES" in os.environ:
        config.llm.max_retries = _parse_int(os.environ["MEMGAR_LLM_MAX_RETRIES"], 2)
    
    if "MEMGAR_LLM_FALLBACK" in os.environ:
        config.llm.enable_fallback = _parse_bool(os.environ["MEMGAR_LLM_FALLBACK"])
    
    # Cache settings
    if "MEMGAR_CACHE_ENABLED" in os.environ:
        config.llm.cache_enabled = _parse_bool(os.environ["MEMGAR_CACHE_ENABLED"])
    
    if "MEMGAR_CACHE_TTL" in os.environ:
        config.llm.cache_ttl = _parse_int(os.environ["MEMGAR_CACHE_TTL"], 3600)
    
    # Analysis settings
    if "MEMGAR_SLIDING_WINDOW" in os.environ:
        config.analysis.use_sliding_window = _parse_bool(os.environ["MEMGAR_SLIDING_WINDOW"])
    
    if "MEMGAR_WINDOW_SIZE" in os.environ:
        config.analysis.window_size = _parse_int(os.environ["MEMGAR_WINDOW_SIZE"], 1000)
    
    if "MEMGAR_STRICT_MODE" in os.environ:
        config.analysis.strict_mode = _parse_bool(os.environ["MEMGAR_STRICT_MODE"])
    
    if "MEMGAR_USE_LLM" in os.environ:
        config.analysis.use_llm = _parse_bool(os.environ["MEMGAR_USE_LLM"])
    
    # Output settings
    if "MEMGAR_OUTPUT_FORMAT" in os.environ:
        config.output.output_format = os.environ["MEMGAR_OUTPUT_FORMAT"]
    
    if "MEMGAR_VERBOSE" in os.environ:
        config.output.verbose = _parse_bool(os.environ["MEMGAR_VERBOSE"])
    
    if "MEMGAR_COLOR" in os.environ:
        config.output.color = _parse_bool(os.environ["MEMGAR_COLOR"])
    
    # Logging
    if "MEMGAR_LOG_LEVEL" in os.environ:
        config.log_level = os.environ["MEMGAR_LOG_LEVEL"].upper()

    # Feed env overrides
    if "MEMGAR_FEED_ENABLED" in os.environ:
        config.feed.enabled = _parse_bool(os.environ["MEMGAR_FEED_ENABLED"])
    if "MEMGAR_FEED_AUTO_SYNC" in os.environ:
        config.feed.auto_sync = _parse_bool(os.environ["MEMGAR_FEED_AUTO_SYNC"])
    if "MEMGAR_FEED_MAX_AGE_DAYS" in os.environ:
        config.feed.max_age_days = _parse_int(os.environ["MEMGAR_FEED_MAX_AGE_DAYS"], 7)
    if "MEMGAR_FEED_GITHUB_REPO" in os.environ:
        config.feed.github_repo = os.environ["MEMGAR_FEED_GITHUB_REPO"]
    if "MEMGAR_FEED_VERIFY_SIGNATURE" in os.environ:
        config.feed.verify_signature = _parse_bool(os.environ["MEMGAR_FEED_VERIFY_SIGNATURE"])

    # Hunter env overrides
    if "MEMGAR_HUNTER_ENABLED" in os.environ:
        config.hunter.enabled = _parse_bool(os.environ["MEMGAR_HUNTER_ENABLED"])
    if "MEMGAR_HUNTER_SCAN_INTERVAL" in os.environ:
        config.hunter.scan_interval_seconds = _parse_int(os.environ["MEMGAR_HUNTER_SCAN_INTERVAL"], 60)
    if "MEMGAR_HUNTER_RESCAN_TTL" in os.environ:
        config.hunter.rescan_clean_after_seconds = _parse_int(os.environ["MEMGAR_HUNTER_RESCAN_TTL"], 3600)
    if "MEMGAR_HUNTER_ALERT_THRESHOLD" in os.environ:
        config.hunter.alert_threshold = float(os.environ["MEMGAR_HUNTER_ALERT_THRESHOLD"])
    if "MEMGAR_HUNTER_MAX_ENTRIES" in os.environ:
        config.hunter.max_entries_per_scan = _parse_int(os.environ["MEMGAR_HUNTER_MAX_ENTRIES"], 1000)

    # Observability env overrides
    if "MEMGAR_OBSERVABILITY_ENABLED" in os.environ:
        config.observability.enabled = _parse_bool(os.environ["MEMGAR_OBSERVABILITY_ENABLED"])
    if "MEMGAR_OBSERVABILITY_PORT" in os.environ:
        config.observability.port = _parse_int(os.environ["MEMGAR_OBSERVABILITY_PORT"], 9090)
    if "MEMGAR_OBSERVABILITY_DRIFT_THRESHOLD" in os.environ:
        config.observability.drift_alert_threshold = float(
            os.environ["MEMGAR_OBSERVABILITY_DRIFT_THRESHOLD"]
        )
    if "MEMGAR_OBSERVABILITY_DRIFT_WINDOW" in os.environ:
        config.observability.drift_window_size = _parse_int(
            os.environ["MEMGAR_OBSERVABILITY_DRIFT_WINDOW"], 1000
        )

    return config


def _dict_to_config(data: Dict[str, Any]) -> MemgarConfig:
    """Convert dictionary to MemgarConfig."""
    config = MemgarConfig()
    
    # LLM config
    if "llm" in data:
        llm_data = data["llm"]
        config.llm = LLMConfig(
            provider=llm_data.get("provider", "auto"),
            model=llm_data.get("model"),
            api_key=llm_data.get("api_key"),
            base_url=llm_data.get("base_url"),
            timeout=llm_data.get("timeout", 30.0),
            max_retries=llm_data.get("max_retries", 2),
            max_tokens=llm_data.get("max_tokens", 500),
            enable_fallback=llm_data.get("enable_fallback", True),
            fallback_providers=llm_data.get("fallback_providers", []),
            fallback_models=llm_data.get("fallback_models", True),
            cache_enabled=llm_data.get("cache_enabled", True),
            cache_ttl=llm_data.get("cache_ttl", 3600),
            cache_max_size=llm_data.get("cache_max_size", 1000),
            custom_models=llm_data.get("custom_models", {}),
        )
    
    # Analysis config
    if "analysis" in data:
        analysis_data = data["analysis"]
        config.analysis = AnalysisConfig(
            risk_threshold_block=analysis_data.get("risk_threshold_block", 80),
            risk_threshold_quarantine=analysis_data.get("risk_threshold_quarantine", 40),
            enable_semantic=analysis_data.get("enable_semantic", False),
            use_llm=analysis_data.get("use_llm", False),
            strict_mode=analysis_data.get("strict_mode", False),
            use_sliding_window=analysis_data.get("use_sliding_window", True),
            window_size=analysis_data.get("window_size", 1000),
            window_overlap=analysis_data.get("window_overlap", 200),
            max_content_length=analysis_data.get("max_content_length", 1000000),
            batch_size=analysis_data.get("batch_size", 10),
        )
    
    # Output config
    if "output" in data:
        output_data = data["output"]
        config.output = OutputConfig(
            output_format=output_data.get("output_format", "text"),
            verbose=output_data.get("verbose", False),
            color=output_data.get("color", True),
            show_threats=output_data.get("show_threats", True),
            show_explanation=output_data.get("show_explanation", True),
        )
    
    # Ignore config
    if "ignore" in data:
        ignore_data = data["ignore"]
        config.ignore = IgnoreConfig(
            patterns=ignore_data.get("patterns", []),
            threat_ids=ignore_data.get("threat_ids", []),
            domains=ignore_data.get("domains", []),
        )
    
    # Cloud config
    if "cloud" in data:
        cloud_data = data["cloud"]
        config.cloud = CloudConfig(
            enabled=cloud_data.get("enabled", False),
            api_key=cloud_data.get("api_key"),
            api_url=cloud_data.get("api_url", "https://api.memgar.io"),
            sync_enabled=cloud_data.get("sync_enabled", False),
        )
    
    # Feed config
    if "feed" in data:
        fd = data["feed"]
        config.feed = FeedConfig(
            enabled=fd.get("enabled", False),
            auto_sync=fd.get("auto_sync", True),
            max_age_days=fd.get("max_age_days", 7),
            github_repo=fd.get("github_repo", "slcxtor/memgar"),
            verify_signature=fd.get("verify_signature", True),
        )

    # Hunter config
    if "hunter" in data:
        hd = data["hunter"]
        config.hunter = HunterConfig(
            enabled=hd.get("enabled", False),
            scan_interval_seconds=hd.get("scan_interval_seconds", 60),
            rescan_clean_after_seconds=hd.get("rescan_clean_after_seconds", 3600),
            alert_threshold=hd.get("alert_threshold", 0.7),
            max_entries_per_scan=hd.get("max_entries_per_scan", 1000),
        )

    # Observability config
    if "observability" in data:
        od = data["observability"]
        config.observability = ObservabilityConfig(
            enabled=od.get("enabled", False),
            port=od.get("port", 9090),
            drift_alert_threshold=od.get("drift_alert_threshold", 0.2),
            drift_window_size=od.get("drift_window_size", 1000),
        )

    # Top-level settings
    config.log_level = data.get("log_level", "WARNING")
    config.custom_rules_path = data.get("custom_rules_path")
    config.config_version = data.get("config_version", "2.0")
    
    # Legacy format support (v1.x)
    if "output_format" in data and "output" not in data:
        config.output.output_format = data.get("output_format", "text")
        config.output.verbose = data.get("verbose", False)
        config.output.color = data.get("color", True)
    
    if "risk_threshold_block" in data and "analysis" not in data:
        config.analysis.risk_threshold_block = data.get("risk_threshold_block", 80)
        config.analysis.risk_threshold_quarantine = data.get("risk_threshold_quarantine", 40)
        config.analysis.enable_semantic = data.get("enable_semantic", False)
    
    if "ignore_patterns" in data and "ignore" not in data:
        config.ignore.patterns = data.get("ignore_patterns", [])
        config.ignore.threat_ids = data.get("ignore_threat_ids", [])
    
    return config


def load_config(config_path: Optional[Union[str, Path]] = None) -> MemgarConfig:
    """
    Load complete configuration.
    
    Order of precedence (lowest to highest):
    1. Built-in defaults
    2. Config file
    3. Environment variables
    
    Args:
        config_path: Optional path to config file
        
    Returns:
        MemgarConfig instance
    """
    # Get config file path
    if config_path:
        path = Path(config_path)
    else:
        path = get_config_path()
    
    # Load from file
    file_data = _load_config_file(path)
    
    # Convert to config object
    config = _dict_to_config(file_data)
    
    # Apply environment overrides
    config = _apply_env_overrides(config)
    
    return config


def save_config(config: MemgarConfig, path: Optional[Union[str, Path]] = None) -> Path:
    """
    Save configuration to file.
    
    Args:
        config: MemgarConfig instance to save
        path: Optional path (defaults to ~/.memgarrc)
        
    Returns:
        Path to saved file
    """
    if path:
        config_path = Path(path)
    else:
        config_path = get_config_path()
    
    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert to dict
    data = {
        "config_version": config.config_version,
        "log_level": config.log_level,
        "custom_rules_path": config.custom_rules_path,
        "llm": asdict(config.llm),
        "analysis": asdict(config.analysis),
        "output": asdict(config.output),
        "ignore": asdict(config.ignore),
        "cloud": asdict(config.cloud),
    }
    
    # Save based on extension
    suffix = config_path.suffix.lower()
    
    if suffix in [".yaml", ".yml"]:
        try:
            import yaml
            with open(config_path, "w") as f:
                yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
        except ImportError:
            # Fallback to JSON
            config_path = config_path.with_suffix(".json")
            with open(config_path, "w") as f:
                json.dump(data, f, indent=2)
    elif suffix == ".toml":
        try:
            import tomli_w
            with open(config_path, "wb") as f:
                tomli_w.dump(data, f)
        except ImportError:
            # Fallback to JSON
            config_path = config_path.with_suffix(".json")
            with open(config_path, "w") as f:
                json.dump(data, f, indent=2)
    else:
        with open(config_path, "w") as f:
            json.dump(data, f, indent=2)
    
    return config_path


def init_config(path: Optional[Union[str, Path]] = None) -> Path:
    """
    Initialize configuration file with defaults.
    
    Args:
        path: Optional path (defaults to ~/.memgarrc)
        
    Returns:
        Path to created configuration file
    """
    if path:
        config_path = Path(path)
    else:
        config_path = get_config_path()
    
    if config_path.exists():
        return config_path
    
    default_config = MemgarConfig()
    return save_config(default_config, config_path)


# =============================================================================
# GLOBAL CONFIG INSTANCE
# =============================================================================

_global_config: Optional[MemgarConfig] = None


def get_config() -> MemgarConfig:
    """
    Get global configuration instance.
    
    Loads config on first call, then returns cached instance.
    """
    global _global_config
    if _global_config is None:
        _global_config = load_config()
    return _global_config


def set_config(config: MemgarConfig) -> None:
    """Set global configuration instance."""
    global _global_config
    _global_config = config


def reload_config() -> MemgarConfig:
    """Reload configuration from file."""
    global _global_config
    _global_config = load_config()
    return _global_config


# =============================================================================
# EXAMPLE CONFIGURATIONS
# =============================================================================

EXAMPLE_CONFIG_JSON = """{
  "config_version": "2.0",
  "log_level": "WARNING",
  
  "llm": {
    "provider": "auto",
    "model": null,
    "timeout": 30.0,
    "max_retries": 2,
    "enable_fallback": true,
    "fallback_models": true,
    "cache_enabled": true,
    "cache_ttl": 3600,
    "custom_models": {
      "openai": ["gpt-4o-mini", "gpt-4o"],
      "groq": ["llama-3.1-8b-instant", "mixtral-8x7b-32768"]
    }
  },
  
  "analysis": {
    "risk_threshold_block": 80,
    "risk_threshold_quarantine": 40,
    "use_llm": false,
    "strict_mode": false,
    "use_sliding_window": true,
    "window_size": 1000
  },
  
  "output": {
    "output_format": "text",
    "verbose": false,
    "color": true
  },
  
  "ignore": {
    "patterns": ["test payment", "example.com"],
    "threat_ids": ["ANOM-002"]
  }
}"""

EXAMPLE_CONFIG_YAML = """# Memgar Configuration
config_version: "2.0"
log_level: WARNING

llm:
  provider: auto
  model: null
  timeout: 30.0
  max_retries: 2
  enable_fallback: true
  fallback_models: true
  cache_enabled: true
  cache_ttl: 3600
  
  # Custom model lists per provider
  custom_models:
    openai:
      - gpt-4o-mini
      - gpt-4o
    groq:
      - llama-3.1-8b-instant
      - mixtral-8x7b-32768

analysis:
  risk_threshold_block: 80
  risk_threshold_quarantine: 40
  use_llm: false
  strict_mode: false
  use_sliding_window: true
  window_size: 1000

output:
  output_format: text
  verbose: false
  color: true

ignore:
  patterns:
    - test payment
    - example.com
  threat_ids:
    - ANOM-002
"""

EXAMPLE_ENV_SETUP = """# Memgar Environment Variables

# LLM Provider Configuration
export MEMGAR_LLM_PROVIDER=groq
export MEMGAR_LLM_MODEL=llama-3.1-8b-instant

# Or use provider-specific API keys
export GROQ_API_KEY=gsk_xxxxx
export OPENAI_API_KEY=sk-xxxxx
export ANTHROPIC_API_KEY=sk-ant-xxxxx

# Analysis Settings
export MEMGAR_STRICT_MODE=true
export MEMGAR_USE_LLM=true
export MEMGAR_SLIDING_WINDOW=true

# Performance
export MEMGAR_CACHE_ENABLED=true
export MEMGAR_CACHE_TTL=7200

# Logging
export MEMGAR_LOG_LEVEL=INFO
"""
