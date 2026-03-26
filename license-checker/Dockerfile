FROM python:3.12-slim

LABEL maintainer="Plan-B Systems"
LABEL description="License validation service for Plan-B SIEM stack"

# Install curl for healthcheck and tini for proper signal handling
RUN apt-get update && apt-get install -y --no-install-recommends \
        tini \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY checker.py .

# Create data directory
RUN mkdir -p /data

# Run as non-root but we need access to Docker socket (gid 999 or docker group)
# The actual socket GID is mapped at runtime; we run as root inside the container
# to avoid GID mismatch issues across different host systems.

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import json,sys; s=json.load(open('/data/license_state.json')); sys.exit(0)" 2>/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-u", "checker.py"]
