# ── Stage 1: dependencies ───────────────────────────────────────────────────
FROM python:3.11-slim AS deps

WORKDIR /build

# System deps for onnxruntime + cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev libffi-dev curl git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir \
        ".[server,feed,observability,graph]" \
        transformers==5.7.0 \
        onnxruntime \
        torch==2.11.0 --index-url https://download.pytorch.org/whl/cpu \
        datasets \
        numpy \
        scikit-learn


# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Non-root user for security
RUN groupadd -r memgar && useradd -r -g memgar memgar

# Copy installed packages from deps stage
COPY --from=deps /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=deps /usr/local/bin /usr/local/bin

# Copy application code
COPY memgar/   ./memgar/
COPY ml/       ./ml/
COPY feeds/    ./feeds/

# Model artifacts (baked in; override at runtime via MEMGAR_MODEL_PATH)
# If ml/artifacts/transformer_model/ exists it is bundled here for zero-startup latency
COPY ml/artifacts/ ./ml/artifacts/

# Cache dir lives outside image — mount a volume in production
RUN mkdir -p /data/cache && chown memgar:memgar /data/cache

USER memgar

# ── Environment defaults ────────────────────────────────────────────────────
ENV MEMGAR_CACHE_DIR=/data/cache \
    MEMGAR_FEED_ENABLED=true \
    MEMGAR_OBSERVABILITY_ENABLED=true \
    MEMGAR_OBSERVABILITY_PORT=9090 \
    MEMGAR_ORT_THREADS=2 \
    MEMGAR_TRANSFORMER_THRESHOLD=0.75 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default: run the REST API server
CMD ["python", "-m", "uvicorn", "memgar.server:create_app", \
     "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "2", "--log-level", "info"]
