# Multi-stage Dockerfile for SecureOps AI

# =============================================================================
# Frontend Build Stage
# =============================================================================
FROM node:18-alpine AS frontend-base

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Build for development
FROM frontend-base AS frontend-development
EXPOSE 3010
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3010"]

# Build for production
FROM frontend-base AS frontend-build
RUN npm run build

# =============================================================================
# Frontend Production Stage  
# =============================================================================
FROM nginx:alpine AS frontend-production

# Install curl for health checks
RUN apk add --no-cache curl

# Copy built frontend
COPY --from=frontend-build /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx-frontend.conf /etc/nginx/conf.d/default.conf

# Create nginx user and set permissions
RUN adduser -D -s /bin/sh nginx && \
    chown -R nginx:nginx /usr/share/nginx/html && \
    chmod -R 755 /usr/share/nginx/html

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

EXPOSE 80
USER nginx
CMD ["nginx", "-g", "daemon off;"]

# =============================================================================
# Backend Base Stage
# =============================================================================
FROM python:3.11-slim AS backend-base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    postgresql-client \
    redis-tools \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY backend/requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Backend Development Stage
# =============================================================================
FROM backend-base AS backend-development

# Copy source code
COPY backend/ ./

# Create directories
RUN mkdir -p logs data uploads backups temp

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

EXPOSE 8001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]

# =============================================================================
# Backend Production Stage
# =============================================================================
FROM backend-base AS backend-production

# Copy source code
COPY backend/ ./

# Create directories with proper permissions
RUN mkdir -p logs data uploads backups temp && \
    adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

EXPOSE 8001
CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8001"]
