# ── pyntrace Dashboard — production image ────────────────────────────────────
# Multi-stage build: keeps final image minimal (~200 MB)
#
# Usage:
#   docker build -t pyntrace .
#   docker run -p 7234:7234 pyntrace
#
# Environment variables:
#   PYNTRACE_API_KEY      API key for dashboard auth (optional)
#   PYNTRACE_DB_PATH      SQLite path inside container (default: /data/pyntrace.db)
#   PYNTRACE_CORS_ORIGINS Comma-separated allowed origins

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY pyntrace/ ./pyntrace/

# Install with server extras into a prefix we can copy
RUN pip install --no-cache-dir --prefix=/install ".[server]"

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="pyntrace" \
      org.opencontainers.image.description="LLM security testing & observability dashboard" \
      org.opencontainers.image.source="https://github.com/pinexai/pyntrace" \
      org.opencontainers.image.licenses="MIT"

# Create a non-root user
RUN useradd -m -u 1000 pyntrace

# Copy installed packages
COPY --from=builder /install /usr/local

# Persistent data volume
RUN mkdir -p /data && chown pyntrace:pyntrace /data
VOLUME ["/data"]

USER pyntrace
WORKDIR /home/pyntrace

ENV PYNTRACE_DB_PATH=/data/pyntrace.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 7234

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:7234/health')" || exit 1

CMD ["pyntrace", "serve", "--host", "0.0.0.0", "--port", "7234", "--no-open"]
