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

COPY requirements.lock.txt pyproject.toml ./
COPY app ./app
COPY static ./static

# Build isolated virtual environment
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock.txt \
    && /opt/venv/bin/pip install --no-cache-dir --no-build-isolation --no-deps .

# ------------------------------------------------------------------------------
# Stage 2: Test gate. The runtime image depends on this stage, so a failed test
# suite makes the default image build fail. Dev tools never enter the runtime.
# ------------------------------------------------------------------------------
FROM builder AS test

COPY . ./

RUN /opt/venv/bin/pip install --no-cache-dir -r requirements-dev.txt \
    && /opt/venv/bin/pytest -q \
    && touch /tmp/dns-analyzer-tests-passed

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

# Copy isolated virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
COPY --from=test /tmp/dns-analyzer-tests-passed /tmp/dns-analyzer-tests-passed

# Copy only production application code and static assets
COPY app ./app
COPY static ./static

# Nmap is optional at runtime but enables bounded service/version identification.
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && nmap --version >/dev/null \
    && rm -rf /var/lib/apt/lists/*

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
