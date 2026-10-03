# Multi-stage lightweight Dockerfile for PQC Drone Swarm
# Debian Slim base (ultra-lightweight ~45MB, glibc standard for C-bindings)
FROM python:3.12-slim

# Prevent Python from writing bytecode and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install minimal build utilities required for C-extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy package manifests first to leverage Docker layer caching
COPY falcon_py/pyproject.toml /app/falcon_py/
COPY pqc-drone-swarm/pyproject.toml /app/pqc-drone-swarm/

# Pre-install dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
    cryptography>=41.0.0 \
    pycryptodome>=3.18.0 \
    numpy>=1.20.0 \
    paho-mqtt>=2.0.0

# Copy source trees
COPY falcon_py/ /app/falcon_py/
COPY pqc-drone-swarm/ /app/pqc-drone-swarm/

# Install the packages in editable mode
RUN pip install --no-cache-dir -e /app/falcon_py && \
    pip install --no-cache-dir -e /app/pqc-drone-swarm

WORKDIR /app/pqc-drone-swarm

# Default entrypoint runs unit tests to verify container integrity
CMD ["python3", "-m", "unittest", "tests/test_swarm.py"]
