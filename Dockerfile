# ==============================================================================
# Dockerfile v2 — Production Multi-Stage Build for DNS Analyzer 2.2.0
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Dependency Builder
# ------------------------------------------------------------------------------
ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
COPY app ./app

# Build isolated virtual environment
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt \
    && /opt/venv/bin/pip install --no-cache-dir --no-build-isolation --no-deps .

# ------------------------------------------------------------------------------
# Stage 2: Test Runner (Verification Stage)
# ------------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS test

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY app ./app
COPY static ./static
COPY tests ./tests
COPY pytest.ini ./

# Run full test suite inside container during build/test verification
RUN pytest -v

# ------------------------------------------------------------------------------
# Stage 3: Production Runtime (v2)
# ------------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

LABEL maintainer="DNS Analyzer Team" \
      version="2.2.0" \
      description="DNS Analyzer 2.2.0 — Security Posture Cockpit & DNS/Email Diagnostic Engine"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000

WORKDIR /app

# Ensure automated test verification passes before assembling final image
COPY --from=test /app/app /tmp/.test_passed
RUN rm -rf /tmp/.test_passed

# Copy isolated virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy only production application code and static assets
COPY app ./app
COPY static ./static

# Security hardening: Create unprivileged system user
RUN useradd -m -u 1000 -s /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

STOPSIGNAL SIGTERM

# Built-in lightweight health check (does not require external curl)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, os; port = os.environ.get('PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health/ready').read()" || exit 1

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
