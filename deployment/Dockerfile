# Multi-stage Dockerfile for SecureOps Backend
<<<<<<< HEAD
FROM python:3.11 as base
=======
FROM python:3.11-slim as base
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

<<<<<<< HEAD
# Install system dependencies (add python3-dev and libc6-dev for aiohttp build)
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libc6-dev \
=======
# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
    curl \
    git \
    libpq-dev \
    postgresql-client \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create application user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

<<<<<<< HEAD
# Install Python dependencies in a virtual environment
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt

# Ensure venv is used by default
ENV PATH="/opt/venv/bin:$PATH"
=======
# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

# Install security scanning tools
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.47.0

# Copy application code
COPY src/ ./src/
COPY deployment/ ./deployment/

# Create necessary directories
RUN mkdir -p /app/logs /app/scan_results /app/uploads && \
    chown -R appuser:appuser /app

# Copy entrypoint script
COPY deployment/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

<<<<<<< HEAD
# Health check - use Python instead of curl
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1
=======
# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

# Set entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command
<<<<<<< HEAD
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
=======
CMD ["gunicorn", "src.api.main:app", "--config", "deployment/gunicorn.conf.py"]
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
