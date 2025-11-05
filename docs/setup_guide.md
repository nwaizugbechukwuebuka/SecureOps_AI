# SecureOps Setup Guide

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Pre-Installation Checklist](#pre-installation-checklist)
4. [Installation Methods](#installation-methods)
5. [Docker Deployment](#docker-deployment)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Development Setup](#development-setup)
8. [Configuration](#configuration)
9. [Initial Setup and Configuration](#initial-setup-and-configuration)
10. [Integration Setup](#integration-setup)
11. [Monitoring and Logging](#monitoring-and-logging)
12. [Security Hardening](#security-hardening)
13. [Backup and Recovery](#backup-and-recovery)
14. [Troubleshooting](#troubleshooting)
15. [Maintenance](#maintenance)

## Overview

This guide provides step-by-step instructions for deploying and configuring SecureOps, a comprehensive DevSecOps CI/CD Pipeline Monitor. SecureOps can be deployed in various environments, from development workstations to enterprise production clusters.

### Deployment Options

- **Docker Compose**: Quick development and testing setup
- **Kubernetes**: Production-grade orchestrated deployment
- **Manual Installation**: Custom environment deployment
- **Cloud Platforms**: AWS, Azure, GCP deployment guides

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    External Integrations                        │
│  GitHub │ GitLab │ Jenkins │ Azure DevOps │ Security Scanners  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                  Load Balancer (Nginx)                         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                  Frontend (React)                              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                  Backend API (FastAPI)                         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│              Task Workers (Celery)                             │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│          Data Layer (PostgreSQL + Redis)                       │
└─────────────────────────────────────────────────────────────────┘
```

## System Requirements

### Minimum Requirements

#### Hardware
- **CPU**: 2 cores (4 recommended)
- **RAM**: 4 GB (8 GB recommended)
- **Storage**: 20 GB free space (SSD recommended)
- **Network**: Reliable internet connection

#### Software
- **Operating System**: 
  - Ubuntu 20.04+ / Debian 10+
  - CentOS 8+ / RHEL 8+
  - macOS 10.15+
  - Windows 10+ (with WSL2)

### Production Requirements

#### Hardware
- **CPU**: 8+ cores
- **RAM**: 16+ GB (32 GB recommended for large deployments)
- **Storage**: 100+ GB SSD (with backup storage)
- **Network**: High-speed connection with redundancy

#### Software
- **Container Runtime**: Docker 20.10+ or containerd 1.4+
- **Orchestration**: Kubernetes 1.20+ (for K8s deployment)
- **Database**: PostgreSQL 13+ (external or managed)
- **Cache**: Redis 6.0+ (external or managed)

### Supported Platforms

#### Cloud Providers
- **AWS**: EKS, RDS, ElastiCache, ALB
- **Azure**: AKS, Azure Database, Redis Cache, Application Gateway
- **GCP**: GKE, Cloud SQL, Memorystore, Load Balancer
- **DigitalOcean**: Kubernetes, Managed Databases

#### On-Premises
- **VMware vSphere**
- **OpenStack**
- **Bare Metal**

## Pre-Installation Checklist

### Planning Phase

#### Network Planning
- [ ] Determine network architecture (single node vs. cluster)
- [ ] Plan IP address ranges and subnets
- [ ] Configure DNS entries for services
- [ ] Set up SSL/TLS certificates
- [ ] Configure firewall rules

#### Security Planning
- [ ] Define security zones and access controls
- [ ] Plan secret management strategy
- [ ] Configure backup and recovery procedures
- [ ] Set up monitoring and alerting
- [ ] Review compliance requirements

#### Integration Planning
- [ ] Identify CI/CD platforms to integrate
- [ ] List security scanners to configure
- [ ] Plan webhook endpoints and authentication
- [ ] Define notification channels (Slack, email, etc.)

### Environment Preparation

#### DNS Configuration
```bash
# Example DNS entries
secureops.example.com         A    10.0.1.100
api.secureops.example.com     A    10.0.1.100
admin.secureops.example.com   A    10.0.1.100
```

#### SSL Certificate Setup
```bash
# Using Let's Encrypt with certbot
sudo apt-get install certbot
sudo certbot certonly --standalone -d secureops.example.com
sudo certbot certonly --standalone -d api.secureops.example.com
```

#### Firewall Configuration
```bash
# Ubuntu/Debian with ufw
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS
sudo ufw enable

# CentOS/RHEL with firewalld
sudo firewall-cmd --permanent --add-port=22/tcp
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

## Installation Methods

### Method 1: Quick Start (Docker Compose)

#### Prerequisites
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### Download and Setup
```bash
# Clone the repository
git clone https://github.com/secureops/secureops.git
cd secureops

# Copy environment template
cp .env.example .env

# Generate secrets
openssl rand -hex 32 > .secrets/jwt_secret
openssl rand -hex 16 > .secrets/webhook_secret
openssl rand -hex 32 > .secrets/db_password
```

#### Configure Environment
```bash
# Edit .env file
cat > .env << EOF
# Application Configuration
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=$(cat .secrets/jwt_secret)
WEBHOOK_SECRET=$(cat .secrets/webhook_secret)

# Database Configuration
DATABASE_URL=postgresql://secureops:$(cat .secrets/db_password)@postgres:5432/secureops
REDIS_URL=redis://redis:6379/0

# External URLs
FRONTEND_URL=https://secureops.example.com
API_URL=https://api.secureops.example.com

# Email Configuration (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=notifications@example.com
SMTP_PASSWORD=your_app_password

# Notification Configuration (Optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
EOF
```

#### Deploy with Docker Compose
```bash
# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Method 2: Kubernetes Deployment

#### Prerequisites
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

#### Prepare Kubernetes Cluster
```bash
# For local development (kind)
kind create cluster --name secureops --config kind-config.yaml

# For production (example with kubeadm)
sudo kubeadm init --pod-network-cidr=10.244.0.0/16
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

#### Deploy with Helm
```bash
# Add SecureOps Helm repository
helm repo add secureops https://charts.secureops.io
helm repo update

# Create namespace
kubectl create namespace secureops

# Install with Helm
helm install secureops secureops/secureops \
  --namespace secureops \
  --set global.domain=secureops.example.com \
  --set postgresql.auth.password=secure_password \
  --set redis.auth.password=redis_password \
  --values values-production.yaml
```

#### Custom Values File (values-production.yaml)
```yaml
# Global configuration
global:
  domain: secureops.example.com
  storageClass: fast-ssd
  
# Application configuration
api:
  replicaCount: 3
  resources:
    requests:
      memory: "512Mi"
      cpu: "500m"
    limits:
      memory: "1Gi"
      cpu: "1000m"
  
  env:
    ENVIRONMENT: production
    DEBUG: false
    LOG_LEVEL: INFO

frontend:
  replicaCount: 2
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

workers:
  replicaCount: 3
  resources:
    requests:
      memory: "512Mi"
      cpu: "500m"
    limits:
      memory: "1Gi"
      cpu: "1000m"

# Database configuration
postgresql:
  enabled: true
  auth:
    database: secureops
    username: secureops
    password: secure_database_password
  primary:
    persistence:
      size: 100Gi
      storageClass: fast-ssd
  metrics:
    enabled: true

# Redis configuration
redis:
  enabled: true
  auth:
    enabled: true
    password: secure_redis_password
  persistence:
    size: 20Gi
    storageClass: fast-ssd

# Ingress configuration
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  tls:
    enabled: true
    secretName: secureops-tls

# Monitoring
monitoring:
  enabled: true
  prometheus:
    enabled: true
  grafana:
    enabled: true
    adminPassword: secure_grafana_password
```

## Docker Deployment

### Complete Docker Compose Configuration

#### docker-compose.yml
```yaml
version: '3.8'

services:
  # Reverse Proxy
  nginx:
    image: nginx:1.24-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./deployment/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./deployment/ssl:/etc/ssl/certs:ro
      - static_files:/var/www/static:ro
    depends_on:
      - frontend
      - api
    restart: unless-stopped
    networks:
      - secureops-network

  # Frontend
  frontend:
    build:
      context: .
      dockerfile: deployment/frontend.Dockerfile
    environment:
      - REACT_APP_API_URL=https://api.secureops.example.com
      - REACT_APP_WS_URL=wss://api.secureops.example.com/ws
    volumes:
      - static_files:/app/build:ro
    restart: unless-stopped
    networks:
      - secureops-network

  # Backend API
  api:
    build:
      context: .
      dockerfile: deployment/Dockerfile
    environment:
      - DATABASE_URL=postgresql://secureops:${DB_PASSWORD}@postgres:5432/secureops
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
      - WEBHOOK_SECRET=${WEBHOOK_SECRET}
      - ENVIRONMENT=production
      - DEBUG=false
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    networks:
      - secureops-network

  # Celery Workers
  worker:
    build:
      context: .
      dockerfile: deployment/Dockerfile
    command: celery -A src.tasks.celery_app worker --loglevel=info --concurrency=4
    environment:
      - DATABASE_URL=postgresql://secureops:${DB_PASSWORD}@postgres:5432/secureops
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    networks:
      - secureops-network
    deploy:
      replicas: 2

  # Celery Beat Scheduler
  scheduler:
    build:
      context: .
      dockerfile: deployment/Dockerfile
    command: celery -A src.tasks.celery_app beat --loglevel=info
    environment:
      - DATABASE_URL=postgresql://secureops:${DB_PASSWORD}@postgres:5432/secureops
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    networks:
      - secureops-network

  # PostgreSQL Database
  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=secureops
      - POSTGRES_USER=secureops
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_INITDB_ARGS=--encoding=UTF-8 --lc-collate=C --lc-ctype=C
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./deployment/init_db.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "5432:5432"
    restart: unless-stopped
    networks:
      - secureops-network

  # Redis Cache
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    networks:
      - secureops-network

  # Monitoring
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    restart: unless-stopped
    networks:
      - secureops-network

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana:/etc/grafana/provisioning:ro
    restart: unless-stopped
    networks:
      - secureops-network

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
  static_files:

networks:
  secureops-network:
    driver: bridge
```

### Security Scanners Setup

#### trivy-scanner service
```yaml
  # Add to docker-compose.yml services section
  trivy:
    image: aquasec/trivy:latest
    command: server --listen 0.0.0.0:8080
    ports:
      - "8080:8080"
    volumes:
      - trivy_cache:/root/.cache/trivy
    restart: unless-stopped
    networks:
      - secureops-network

volumes:
  trivy_cache:
```

#### Scanner Integration Script
```bash
#!/bin/bash
# scripts/setup-scanners.sh

echo "Setting up security scanners..."

# Install Safety for Python dependency scanning
pip install safety

# Install Bandit for Python static analysis
pip install bandit

# Install npm audit for Node.js
if command -v npm &> /dev/null; then
    echo "npm already installed"
else
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# Install Semgrep for multi-language static analysis
pip install semgrep

# Set up Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

echo "Security scanners setup complete!"
```

## Kubernetes Deployment

### Namespace and RBAC

#### namespace.yaml
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secureops
  labels:
    name: secureops
    app.kubernetes.io/name: secureops
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secureops
  namespace: secureops
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secureops-cluster-role
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: secureops-cluster-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: secureops-cluster-role
subjects:
- kind: ServiceAccount
  name: secureops
  namespace: secureops
```

### ConfigMaps and Secrets

#### configmap.yaml
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: secureops-config
  namespace: secureops
data:
  ENVIRONMENT: "production"
  DEBUG: "false"
  LOG_LEVEL: "INFO"
  CORS_ORIGINS: "https://secureops.example.com"
  DATABASE_HOST: "postgres-service"
  DATABASE_PORT: "5432"
  DATABASE_NAME: "secureops"
  REDIS_HOST: "redis-service"
  REDIS_PORT: "6379"
  REDIS_DB: "0"
  FRONTEND_URL: "https://secureops.example.com"
  API_URL: "https://api.secureops.example.com"
  CELERY_BROKER_URL: "redis://redis-service:6379/0"
  CELERY_RESULT_BACKEND: "redis://redis-service:6379/1"
```

#### secrets.yaml
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secureops-secrets
  namespace: secureops
type: Opaque
data:
  SECRET_KEY: <base64-encoded-secret-key>
  WEBHOOK_SECRET: <base64-encoded-webhook-secret>
  DATABASE_PASSWORD: <base64-encoded-db-password>
  REDIS_PASSWORD: <base64-encoded-redis-password>
  SMTP_PASSWORD: <base64-encoded-smtp-password>
  GRAFANA_PASSWORD: <base64-encoded-grafana-password>
```

### Application Deployments

#### api-deployment.yaml
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureops-api
  namespace: secureops
  labels:
    app: secureops-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secureops-api
  template:
    metadata:
      labels:
        app: secureops-api
    spec:
      serviceAccountName: secureops
      containers:
      - name: api
        image: secureops/api:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          value: postgresql://secureops:$(DATABASE_PASSWORD)@$(DATABASE_HOST):$(DATABASE_PORT)/$(DATABASE_NAME)
        - name: REDIS_URL
          value: redis://:$(REDIS_PASSWORD)@$(REDIS_HOST):$(REDIS_PORT)/$(REDIS_DB)
        envFrom:
        - configMapRef:
            name: secureops-config
        - secretRef:
            name: secureops-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: logs
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: secureops-api-service
  namespace: secureops
spec:
  selector:
    app: secureops-api
  ports:
  - protocol: TCP
    port: 8000
    targetPort: 8000
  type: ClusterIP
```

#### worker-deployment.yaml
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureops-worker
  namespace: secureops
  labels:
    app: secureops-worker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secureops-worker
  template:
    metadata:
      labels:
        app: secureops-worker
    spec:
      serviceAccountName: secureops
      containers:
      - name: worker
        image: secureops/api:latest
        command: ["celery", "-A", "src.tasks.celery_app", "worker", "--loglevel=info", "--concurrency=4"]
        env:
        - name: DATABASE_URL
          value: postgresql://secureops:$(DATABASE_PASSWORD)@$(DATABASE_HOST):$(DATABASE_PORT)/$(DATABASE_NAME)
        - name: REDIS_URL
          value: redis://:$(REDIS_PASSWORD)@$(REDIS_HOST):$(REDIS_PORT)/$(REDIS_DB)
        envFrom:
        - configMapRef:
            name: secureops-config
        - secretRef:
            name: secureops-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        volumeMounts:
        - name: logs
          mountPath: /app/logs
        - name: docker-sock
          mountPath: /var/run/docker.sock
      volumes:
      - name: logs
        emptyDir: {}
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
```

### Ingress Configuration

#### ingress.yaml
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secureops-ingress
  namespace: secureops
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - secureops.example.com
    - api.secureops.example.com
    secretName: secureops-tls
  rules:
  - host: secureops.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: secureops-frontend-service
            port:
              number: 80
  - host: api.secureops.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: secureops-api-service
            port:
              number: 8000
```

## Development Setup

### Local Development Environment

#### Prerequisites Installation
```bash
# Python 3.9+
sudo apt-get update
sudo apt-get install python3.9 python3.9-venv python3.9-dev

# Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Redis
sudo apt-get install redis-server
```

#### Backend Setup
```bash
# Clone repository
git clone https://github.com/secureops/secureops.git
cd secureops

# Create virtual environment
python3.9 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up database
sudo -u postgres createuser -s secureops
sudo -u postgres createdb secureops
psql -U secureops -d secureops -f deployment/init_db.sql

# Create environment file
cp .env.example .env.dev
# Edit .env.dev with development settings

# Run database migrations
alembic upgrade head

# Start development server
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup
```bash
# Navigate to frontend directory
cd src/frontend

# Install dependencies
npm install

# Start development server
npm start

# Open browser to http://localhost:3000
```

#### Worker Setup
```bash
# In a new terminal, activate virtual environment
source venv/bin/activate

# Start Celery worker
celery -A src.tasks.celery_app worker --loglevel=info

# In another terminal, start Celery beat
celery -A src.tasks.celery_app beat --loglevel=info
```

### Development Tools

#### Code Quality Tools
```bash
# Install pre-commit hooks
pre-commit install

# Run linting
flake8 src/
pylint src/
black src/
isort src/

# Run type checking
mypy src/

# Run security scanning
bandit -r src/
safety check
```

#### Testing
```bash
# Run unit tests
pytest src/tests/ -v

# Run with coverage
pytest src/tests/ --cov=src --cov-report=html

# Run integration tests
pytest src/tests/integration/ -v

# Run load tests
locust -f src/tests/load/locustfile.py
```

## Configuration

### Environment Variables

#### Core Configuration
```bash
# Application
ENVIRONMENT=production|development|testing
DEBUG=true|false
SECRET_KEY=your-secret-key-here
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR

# Database
DATABASE_URL=postgresql://user:pass@host:port/db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30

# Redis
REDIS_URL=redis://host:port/db
REDIS_PASSWORD=redis-password

# Celery
CELERY_BROKER_URL=redis://host:port/db
CELERY_RESULT_BACKEND=redis://host:port/db
CELERY_WORKER_CONCURRENCY=4

# Security
WEBHOOK_SECRET=webhook-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION_TIME=3600
PASSWORD_HASH_ALGORITHM=bcrypt

# External URLs
FRONTEND_URL=https://secureops.example.com
API_URL=https://api.secureops.example.com
CORS_ORIGINS=https://secureops.example.com

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=notifications@example.com
SMTP_PASSWORD=app-password
SMTP_TLS=true

# Monitoring
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
GRAFANA_ENABLED=true
GRAFANA_PORT=3000
```

#### Scanner Configuration
```bash
# Trivy
TRIVY_CACHE_DIR=/tmp/trivy-cache
TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db
TRIVY_TIMEOUT=300

# Safety
SAFETY_API_KEY=your-safety-api-key
SAFETY_DB_PATH=/tmp/safety-db

# Bandit
BANDIT_CONFIG_FILE=/etc/bandit/bandit.yaml
BANDIT_EXCLUDE_PATHS=/tmp,/var

# Semgrep
SEMGREP_RULES=auto
SEMGREP_CONFIG_PATH=/etc/semgrep/rules
```

### Configuration Files

#### Application Configuration (config.yaml)
```yaml
# Application settings
app:
  name: SecureOps
  version: 1.0.0
  debug: false
  host: 0.0.0.0
  port: 8000
  
# Database settings
database:
  url: ${DATABASE_URL}
  pool_size: ${DATABASE_POOL_SIZE:20}
  max_overflow: ${DATABASE_MAX_OVERFLOW:30}
  echo: false
  
# Redis settings
redis:
  url: ${REDIS_URL}
  password: ${REDIS_PASSWORD}
  socket_timeout: 30
  socket_connect_timeout: 30
  
# Security settings
security:
  secret_key: ${SECRET_KEY}
  jwt_algorithm: ${JWT_ALGORITHM:HS256}
  jwt_expiration: ${JWT_EXPIRATION_TIME:3600}
  webhook_secret: ${WEBHOOK_SECRET}
  
# Logging settings
logging:
  level: ${LOG_LEVEL:INFO}
  format: detailed
  file_rotation: true
  max_file_size: 100MB
  backup_count: 5
  
# Scanner settings
scanners:
  trivy:
    enabled: true
    timeout: 300
    cache_dir: /tmp/trivy-cache
  safety:
    enabled: true
    timeout: 120
  bandit:
    enabled: true
    timeout: 180
  semgrep:
    enabled: true
    timeout: 300
    
# Notification settings
notifications:
  email:
    enabled: true
    smtp_host: ${SMTP_HOST}
    smtp_port: ${SMTP_PORT:587}
    smtp_user: ${SMTP_USER}
    smtp_password: ${SMTP_PASSWORD}
    use_tls: ${SMTP_TLS:true}
  slack:
    enabled: ${SLACK_ENABLED:false}
    webhook_url: ${SLACK_WEBHOOK_URL}
  webhook:
    enabled: ${WEBHOOK_NOTIFICATIONS_ENABLED:false}
    url: ${WEBHOOK_NOTIFICATION_URL}
    
# Integration settings
integrations:
  github:
    app_id: ${GITHUB_APP_ID}
    private_key_path: ${GITHUB_PRIVATE_KEY_PATH}
    webhook_secret: ${GITHUB_WEBHOOK_SECRET}
  gitlab:
    token: ${GITLAB_TOKEN}
    webhook_secret: ${GITLAB_WEBHOOK_SECRET}
  jenkins:
    url: ${JENKINS_URL}
    username: ${JENKINS_USERNAME}
    token: ${JENKINS_TOKEN}
  azure_devops:
    organization: ${AZURE_DEVOPS_ORG}
    token: ${AZURE_DEVOPS_TOKEN}
```

## Initial Setup and Configuration

### Database Initialization

#### Create Admin User
```bash
# Using management script
python scripts/create_admin.py \
  --email admin@example.com \
  --password secure_password \
  --first-name Admin \
  --last-name User

# Or using API
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "secure_password",
    "first_name": "Admin",
    "last_name": "User",
    "is_admin": true
  }'
```

#### Initialize Compliance Frameworks
```bash
# Load default compliance frameworks
python scripts/load_compliance_frameworks.py

# Or manually via API
curl -X POST http://localhost:8000/api/v1/compliance/frameworks \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d @compliance/owasp_top_10.json
```

### System Configuration

#### Configure System Settings
```bash
# Access the admin interface
open https://admin.secureops.example.com

# Or configure via API
curl -X PUT http://localhost:8000/api/v1/settings \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "security": {
      "mfa_enabled": true,
      "session_timeout": 30,
      "password_policy": "strong"
    },
    "notifications": {
      "email_enabled": true,
      "severity_threshold": "medium"
    },
    "scanning": {
      "auto_scan": true,
      "scan_schedule": "daily"
    }
  }'
```

### Health Checks

#### Verify Installation
```bash
#!/bin/bash
# scripts/health_check.sh

echo "Checking SecureOps installation..."

# Check API health
echo "Checking API health..."
curl -f http://localhost:8000/health || exit 1

# Check database connection
echo "Checking database connection..."
curl -f http://localhost:8000/health/db || exit 1

# Check Redis connection
echo "Checking Redis connection..."
curl -f http://localhost:8000/health/redis || exit 1

# Check worker status
echo "Checking worker status..."
celery -A src.tasks.celery_app inspect active

# Check frontend
echo "Checking frontend..."
curl -f http://localhost:3000 || exit 1

echo "All health checks passed!"
```

## Integration Setup

### CI/CD Platform Integration

#### GitHub Integration
```bash
# Create GitHub App
# Follow GitHub App creation guide in CI/CD Integration docs

# Configure webhook
curl -X POST https://api.github.com/repos/OWNER/REPO/hooks \
  -H "Authorization: token ${GITHUB_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "web",
    "active": true,
    "events": ["push", "pull_request", "workflow_run"],
    "config": {
      "url": "https://api.secureops.example.com/webhooks/github",
      "content_type": "json",
      "secret": "your_webhook_secret"
    }
  }'
```

#### GitLab Integration
```bash
# Add project webhook
curl -X POST https://gitlab.com/api/v4/projects/PROJECT_ID/hooks \
  -H "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.secureops.example.com/webhooks/gitlab",
    "push_events": true,
    "merge_requests_events": true,
    "pipeline_events": true,
    "token": "your_webhook_secret"
  }'
```

### Scanner Integration

#### Configure Trivy
```bash
# Test Trivy installation
trivy --version

# Scan a test image
trivy image --format json alpine:latest

# Configure in SecureOps
curl -X POST http://localhost:8000/api/v1/scanners/trivy/test \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Configure Safety
```bash
# Test Safety installation
safety --version

# Test with requirements file
safety check --file requirements.txt --json

# Configure in SecureOps
curl -X POST http://localhost:8000/api/v1/scanners/safety/test \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Notification Setup

#### Slack Integration
```bash
# Create Slack webhook URL
# https://api.slack.com/messaging/webhooks

# Test notification
curl -X POST YOUR_SLACK_WEBHOOK_URL \
  -H "Content-Type: application/json" \
  -d '{
    "text": "SecureOps test notification",
    "channel": "#security",
    "username": "SecureOps Bot"
  }'

# Configure in SecureOps
curl -X PUT http://localhost:8000/api/v1/settings \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "notifications": {
      "slack": {
        "enabled": true,
        "webhook_url": "YOUR_SLACK_WEBHOOK_URL",
        "channel": "#security"
      }
    }
  }'
```

## Monitoring and Logging

### Prometheus Configuration

#### prometheus.yml
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'secureops-api'
    static_configs:
      - targets: ['api:8000']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'secureops-workers'
    static_configs:
      - targets: ['worker:9540']
    metrics_path: /metrics
    scrape_interval: 15s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
```

### Grafana Dashboards

#### Import Default Dashboards
```bash
# Import SecureOps dashboard
curl -X POST http://admin:password@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @monitoring/dashboards/secureops-overview.json

# Import infrastructure dashboard
curl -X POST http://admin:password@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @monitoring/dashboards/infrastructure.json
```

### Logging Configuration

#### Application Logging
```python
# logging_config.py
import logging.config

LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '{asctime} {levelname} {name} {process:d} {thread:d} {message}',
            'style': '{'
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{'
        },
        'json': {
            'format': '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'simple',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': '/app/logs/secureops.log',
            'maxBytes': 100000000,  # 100MB
            'backupCount': 5
        },
        'security': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'WARNING',
            'formatter': 'json',
            'filename': '/app/logs/security.log',
            'maxBytes': 100000000,
            'backupCount': 10
        }
    },
    'loggers': {
        'secureops': {
            'level': 'DEBUG',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'secureops.security': {
            'level': 'WARNING',
            'handlers': ['security'],
            'propagate': False
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console']
    }
}

logging.config.dictConfig(LOGGING_CONFIG)
```

## Security Hardening

### SSL/TLS Configuration

#### Generate Certificates
```bash
# Using Let's Encrypt
sudo certbot certonly --standalone \
  -d secureops.example.com \
  -d api.secureops.example.com \
  --email admin@example.com \
  --agree-tos \
  --non-interactive

# Using custom CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem
openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=secureops.example.com" -sha256 -new -key server-key.pem -out server.csr
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem
```

### Firewall Configuration

#### iptables Rules
```bash
#!/bin/bash
# scripts/configure_firewall.sh

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (limit to specific IPs)
iptables -A INPUT -p tcp --dport 22 -s YOUR_ADMIN_IP -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow monitoring (from specific IPs)
iptables -A INPUT -p tcp --dport 9090 -s YOUR_MONITORING_IP -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -s YOUR_MONITORING_IP -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Security Scanning

#### Container Security Scanning
```bash
# Scan Docker images before deployment
trivy image secureops/api:latest --severity HIGH,CRITICAL
trivy image secureops/frontend:latest --severity HIGH,CRITICAL

# Scan for secrets
docker run --rm -v "$(pwd):/src" trufflesecurity/trufflehog:latest filesystem /src

# Scan infrastructure
checkov --framework docker --check CKV_DOCKER_2,CKV_DOCKER_3 .
```

## Backup and Recovery

### Database Backup

#### Automated Backup Script
```bash
#!/bin/bash
# scripts/backup_database.sh

BACKUP_DIR="/backups/$(date +%Y-%m-%d)"
DB_NAME="secureops"
DB_USER="secureops"
DB_HOST="localhost"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create database backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
  --format=custom \
  --compress=9 \
  --file="$BACKUP_DIR/secureops_$(date +%Y%m%d_%H%M%S).backup"

# Create schema-only backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
  --schema-only \
  --file="$BACKUP_DIR/secureops_schema_$(date +%Y%m%d_%H%M%S).sql"

# Compress and encrypt
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
gpg --trust-model always --encrypt \
  --recipient backup@example.com \
  --output "$BACKUP_DIR.tar.gz.gpg" \
  "$BACKUP_DIR.tar.gz"

# Upload to cloud storage
aws s3 cp "$BACKUP_DIR.tar.gz.gpg" s3://secureops-backups/

# Cleanup local files older than 7 days
find /backups -name "*.tar.gz*" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR.tar.gz.gpg"
```

#### Cron Job for Automated Backups
```bash
# Add to crontab
0 2 * * * /scripts/backup_database.sh >> /var/log/backup.log 2>&1
```

### Disaster Recovery

#### Recovery Procedure
```bash
#!/bin/bash
# scripts/restore_database.sh

BACKUP_FILE=$1
DB_NAME="secureops"
DB_USER="secureops"
DB_HOST="localhost"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Stop services
docker-compose stop api worker scheduler

# Drop and recreate database
dropdb -h $DB_HOST -U $DB_USER $DB_NAME
createdb -h $DB_HOST -U $DB_USER $DB_NAME

# Restore database
pg_restore -h $DB_HOST -U $DB_USER -d $DB_NAME "$BACKUP_FILE"

# Run migrations
alembic upgrade head

# Start services
docker-compose start api worker scheduler

echo "Database restored from $BACKUP_FILE"
```

## Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check database status
docker-compose exec postgres pg_isready -U secureops

# Check database logs
docker-compose logs postgres

# Test connection from API container
docker-compose exec api python -c "
from src.api.database import get_db
try:
    db = next(get_db())
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
"
```

#### Redis Connection Issues
```bash
# Check Redis status
docker-compose exec redis redis-cli ping

# Check Redis logs
docker-compose logs redis

# Test connection from API container
docker-compose exec api python -c "
import redis
r = redis.Redis(host='redis', port=6379, db=0)
print(r.ping())
"
```

#### Worker Issues
```bash
# Check worker status
celery -A src.tasks.celery_app inspect active

# Check worker logs
docker-compose logs worker

# Restart workers
docker-compose restart worker

# Purge all tasks
celery -A src.tasks.celery_app purge
```

#### API Issues
```bash
# Check API logs
docker-compose logs api

# Test API endpoints
curl -f http://localhost:8000/health
curl -f http://localhost:8000/docs

# Check API metrics
curl http://localhost:8000/metrics
```

### Performance Issues

#### Database Performance
```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check database size
SELECT 
    pg_size_pretty(pg_database_size('secureops')) as db_size,
    pg_size_pretty(pg_total_relation_size('alerts')) as alerts_size,
    pg_size_pretty(pg_total_relation_size('vulnerabilities')) as vulns_size;

-- Check index usage
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan;
```

#### Redis Performance
```bash
# Check Redis memory usage
redis-cli info memory

# Check slow log
redis-cli slowlog get 10

# Monitor Redis operations
redis-cli monitor
```

### Log Analysis

#### API Logs
```bash
# Error patterns
grep -E "ERROR|CRITICAL" /app/logs/secureops.log | tail -20

# Performance issues
grep "slow query" /app/logs/secureops.log

# Security events
grep -E "authentication|authorization|security" /app/logs/security.log
```

#### System Logs
```bash
# Check system resources
top
htop
iostat -x 1
free -h
df -h

# Check Docker container stats
docker stats

# Check Kubernetes pod status
kubectl get pods -n secureops
kubectl describe pod <pod-name> -n secureops
kubectl logs <pod-name> -n secureops
```

## Maintenance

### Regular Maintenance Tasks

#### Daily Tasks
```bash
#!/bin/bash
# scripts/daily_maintenance.sh

# Check system health
./scripts/health_check.sh

# Clean up old logs
find /app/logs -name "*.log.*" -mtime +7 -delete

# Update vulnerability databases
trivy image --download-db-only

# Check disk space
df -h | awk '$5 > 80 {print "WARNING: " $0}'

# Check failed tasks
celery -A src.tasks.celery_app events

# Generate daily reports
python scripts/generate_daily_report.py
```

#### Weekly Tasks
```bash
#!/bin/bash
# scripts/weekly_maintenance.sh

# Update security scanner databases
trivy image --reset --download-db-only
safety update

# Clean up old scan results
python scripts/cleanup_old_data.py --days 30

# Database maintenance
docker-compose exec postgres psql -U secureops -d secureops -c "VACUUM ANALYZE;"

# Restart services for memory cleanup
docker-compose restart worker

# Generate weekly reports
python scripts/generate_weekly_report.py
```

#### Monthly Tasks
```bash
#!/bin/bash
# scripts/monthly_maintenance.sh

# Full system backup
./scripts/backup_database.sh
./scripts/backup_configs.sh

# Security audit
./scripts/security_audit.sh

# Performance analysis
./scripts/performance_analysis.sh

# Update dependencies
pip-review --auto
npm update

# Certificate renewal check
certbot renew --dry-run

# Generate monthly reports
python scripts/generate_monthly_report.py
```

### Update Procedures

#### Application Updates
```bash
#!/bin/bash
# scripts/update_application.sh

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

# Backup before update
./scripts/backup_database.sh

# Pull new images
docker pull secureops/api:$VERSION
docker pull secureops/frontend:$VERSION

# Update docker-compose.yml with new version
sed -i "s/secureops\/api:.*/secureops\/api:$VERSION/" docker-compose.yml
sed -i "s/secureops\/frontend:.*/secureops\/frontend:$VERSION/" docker-compose.yml

# Rolling update
docker-compose up -d --no-deps api
docker-compose up -d --no-deps frontend
docker-compose up -d --no-deps worker

# Run health checks
sleep 30
./scripts/health_check.sh

echo "Update to version $VERSION completed"
```

#### Database Migrations
```bash
#!/bin/bash
# scripts/run_migrations.sh

# Backup database before migration
./scripts/backup_database.sh

# Stop workers to prevent conflicts
docker-compose stop worker scheduler

# Run migrations
docker-compose exec api alembic upgrade head

# Start workers
docker-compose start worker scheduler

# Verify migration
docker-compose exec api alembic current

echo "Database migration completed"
```

<<<<<<< HEAD
## SIEM & External Log Forwarding

SecureOps supports forwarding logs to external SIEM and monitoring platforms (ELK/Elasticsearch, Datadog, syslog) for enterprise security and compliance.

- See [docs/siem_log_forwarding.md](./siem_log_forwarding.md) for setup, environment variables, and troubleshooting.
- Required Python packages: `cmreslogging`, `datadog` (see requirements section).
- Configure via environment variables or `.env` file.
- All critical logs (security, audit, performance) can be exported in real time.

**Example:**
```env
LOG_FORWARD_ELK_ENABLED=true
LOG_FORWARD_ELK_HOST=elk.example.com
LOG_FORWARD_ELK_PORT=9200
LOG_FORWARD_DATADOG_ENABLED=true
LOG_FORWARD_DATADOG_API_KEY=your_datadog_api_key
LOG_FORWARD_SYSLOG_ENABLED=true
LOG_FORWARD_SYSLOG_HOST=syslog.example.com
LOG_FORWARD_SYSLOG_PORT=514
```

If a handler fails to initialize, a warning will be logged. See the troubleshooting section in the SIEM guide.

---

### CI/CD Pipeline Examples for SIEM Log Forwarding

See `docs/ci_cd_siem_examples.md` for ready-to-use YAML snippets for:
- GitHub Actions
- GitLab CI
- Azure DevOps

Each example shows how to:
- Install SIEM log forwarding dependencies (`cmreslogging`, `datadog`)
- Set required environment variables for ELK, Datadog, and syslog
- Run tests or your application with log forwarding enabled

Copy and adapt these snippets for your own pipelines.

---

### Real-Time Monitoring

SecureOps supports real-time monitoring of security, compliance, and operational metrics using Prometheus and Grafana. You can also stream logs and security events to SIEM platforms (ELK, Datadog, syslog) for live threat detection and compliance dashboards.

**Key Features:**
- Live metrics from API, workers, database, and infrastructure (see Prometheus config)
- Real-time dashboards in Grafana (import provided dashboards for instant visibility)
- AI Threat Detection metrics and alerts visualized in the dashboard
- Log forwarding to SIEM for real-time security monitoring and alerting
- Custom alerting rules for incidents, compliance violations, and performance issues

**How to Enable:**
- Deploy Prometheus and Grafana using the provided configs
- Import SecureOps dashboards for instant visibility
- Enable SIEM log forwarding (see SIEM section) for real-time log aggregation and alerting
- Use Grafana/Prometheus alerting or your SIEM's alerting for real-time notifications

See also:
- [docs/siem_log_forwarding.md](./siem_log_forwarding.md)
- [docs/ci_cd_siem_examples.md](./ci_cd_siem_examples.md)
- AI Threats dashboard in the frontend for live threat intelligence

---
=======
This comprehensive setup guide provides everything needed to deploy, configure, and maintain SecureOps in any environment, from development to enterprise production deployments.
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
