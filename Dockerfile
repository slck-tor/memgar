# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: build — train the ML model and install all dependencies
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build deps
RUN pip install --no-cache-dir --upgrade pip

# Copy dependency definitions first (layer-cache friendly)
COPY pyproject.toml ./
COPY memgar/          ./memgar/
COPY ml/              ./ml/
COPY scripts/         ./scripts/

# Install the package + ML extras
RUN pip install --no-cache-dir -e "." numpy scikit-learn

# Build the ML model (writes to ml/artifacts/gradient_boost_model.pkl)
RUN python scripts/build_model.py

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: runtime — minimal image with only what's needed to run
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="memgar"
LABEL org.opencontainers.image.description="AI Agent Memory Security"
LABEL org.opencontainers.image.url="https://memgar.io"
LABEL org.opencontainers.image.source="https://github.com/slck-tor/memgar"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Non-root user for security
RUN groupadd -r memgar && useradd -r -g memgar memgar

# Copy installed packages and app from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/memgar /usr/local/bin/memgar
COPY --from=builder /app/memgar  ./memgar
COPY --from=builder /app/ml      ./ml

# Config and examples (optional, useful for documentation/demos)
COPY examples/ ./examples/

RUN chown -R memgar:memgar /app
USER memgar

# Verify install works
RUN memgar --version

# Default: run the CLI
ENTRYPOINT ["memgar"]
CMD ["--help"]
