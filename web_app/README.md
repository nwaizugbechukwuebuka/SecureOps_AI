# 🛡️ SecureOps AI - Enterprise Security Platform

> **A comprehensive, enterprise-grade security operations platform with advanced authentication, role-based access control, multi-factor authentication, and comprehensive audit logging.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](https://www.docker.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-61DAFB?style=flat&logo=react&logoColor=black)](https://reactjs.org/)
[![Security](https://img.shields.io/badge/Security-Enterprise_Grade-red)](https://security.com/)
[![MFA](https://img.shields.io/badge/MFA-TOTP_Enabled-green)](https://tools.ietf.org/html/rfc6238)

## 🔐 **Enterprise Security Features**

### �️ **Authentication & Authorization**
- **JWT Authentication** - Secure token-based authentication with automatic refresh
- **Multi-Factor Authentication (MFA)** - TOTP-based two-factor authentication with QR codes
- **Role-Based Access Control (RBAC)** - Three-tier access system (Admin/Analyst/Viewer)
- **Session Management** - Secure HTTP-only cookies with session tracking
- **Password Security** - Enterprise-grade password policy with strength validation

### 📋 **Audit & Compliance**
- **Comprehensive Audit Logging** - All security events tracked with risk levels
- **Security Event Monitoring** - Real-time detection of suspicious activities
- **Audit Trail Management** - Complete user activity tracking and reporting
- **Risk Level Classification** - Automatic risk assessment for security events
- **Compliance Reporting** - Export audit logs for compliance requirements

### 🔒 **Advanced Security Measures**
- **Rate Limiting** - IP-based brute force protection with automatic blocking
- **Security Headers** - Complete CSP, XSS, and clickjacking protection
- **Request Validation** - Input sanitization and validation at all endpoints
- **Encrypted Communications** - TLS/HTTPS enforcement with secure cookie policies
- **Intrusion Detection** - Automated detection and logging of security incidents

### 🎨 **Modern User Experience**
- **Secure Login Interface** - Beautiful, accessible login with MFA support
- **Role-Based UI** - Dynamic interface adaptation based on user permissions
- **Security Dashboard** - Real-time security metrics and audit log visualization
- **Notification System** - Security alerts and system notifications
- **Responsive Design** - Optimized for desktop, tablet, and mobile devices

### 🚀 **Enterprise Infrastructure**
- **Docker Containerization** - Complete containerized deployment with security hardening
- **High Availability** - Scalable architecture with load balancing support
- **Monitoring Integration** - Comprehensive logging and metrics collection
- **Database Security** - Encrypted data storage with secure connection pooling

## 🚀 **Quick Start with Enhanced Security**

### � **Prerequisites**
- **Docker & Docker Compose** (Recommended)
- **Python 3.11+** (for local development)
- **Node.js 18+** (for frontend development)

### 🐳 **Docker Setup (Recommended)**

1. **Clone and Start:**
```bash
git clone <repository-url>
cd secureops_ai/web_app
docker-compose up --build
```

2. **Access the Application:**
- 🌐 **Frontend:** http://localhost:3010
- 🔌 **Backend API:** http://localhost:8001
- 📚 **API Documentation:** http://localhost:8001/api/docs
- 🔒 **Security Status:** http://localhost:8001/security-status

3. **Default Admin Login:**
```
Username: admin
Password: SecureAdmin123!
```
*⚠️ Change password on first login*

### 💻 **Local Development Setup**

1. **Backend Setup:**
```bash
cd backend
pip install -r requirements.txt
python demo_security.py  # Demo security features
python main.py           # Start backend server
```

2. **Frontend Setup:**
```bash
# In new terminal
npm install
npm run dev
```

3. **Security Demo:**
```bash
cd backend
python demo_security.py
```

### 📱 **Application URLs**

| Service | URL | Description |
|---------|-----|-------------|
| 🌐 **Web App** | http://localhost:3010 | Secure Frontend Interface |
| � **Backend API** | http://localhost:8001 | FastAPI with Enhanced Security |
| 📚 **API Docs** | http://localhost:8001/api/docs | Interactive API Documentation |
| � **Security Status** | http://localhost:8001/security-status | Security Feature Overview |
| ❤️ **Health Check** | http://localhost:8001/health | Application Health Status |

### 🛠️ **Development Tools**

| Tool | URL | Purpose |
|------|-----|---------|
| 📧 **Mailhog** | http://localhost:8025 | Email Testing |
| 🗄️ **Redis Commander** | http://localhost:8081 | Redis Management |
| 🗃️ **Adminer** | http://localhost:8082 | Database Management |
| 📊 **Prometheus** | http://localhost:9090 | Metrics Collection |
| 📈 **Grafana** | http://localhost:3000 | Analytics Dashboards |

## 🏗️ Architecture Overview

### 🔧 **Technology Stack**

**Frontend:**
- ⚛️ **React 18** with TypeScript support
- ⚡ **Vite** for lightning-fast development
- 🎨 **Tailwind CSS** for modern styling
- 📊 **Chart.js / Recharts** for data visualization
- 🔔 **React Hot Toast** for notifications
- 🎯 **React Query** for API state management

**Backend:**
- 🐍 **FastAPI** with async/await support
- 🗄️ **SQLAlchemy** with Alembic migrations
- 🔐 **JWT Authentication** with refresh tokens
- 📨 **Celery** for background task processing
- 📊 **Prometheus** metrics integration
- 🔍 **Pydantic** for data validation

**Infrastructure:**
- 🐳 **Docker** with multi-stage builds
- 🗃️ **PostgreSQL** for production data
- 🚀 **Redis** for caching and message queuing
- 🌐 **Nginx** for reverse proxy and load balancing
- 📈 **Prometheus + Grafana** for monitoring

## 👥 Default Users & Credentials

| Role | Username | Password | Permissions |
|------|----------|----------|-------------|
| 👨‍💼 **Admin** | `admin` | `admin123` | Full system access |
| 👤 **Demo User** | `demo` | `demo123` | Limited read access |
| 📊 **Grafana** | `admin` | `admin123` | Dashboard access |

> ⚠️ **Security Notice:** Change all default passwords in production!

## 🔌 API Reference

### 🔐 **Authentication Endpoints**

```http
POST   /api/auth/login           # User login
POST   /api/auth/register        # User registration
POST   /api/auth/refresh         # Refresh JWT token
POST   /api/auth/logout          # User logout
GET    /api/auth/me              # Current user info
```

### 🚨 **Alert Management**

```http
GET    /api/alerts/              # List alerts (paginated)
POST   /api/alerts/              # Create new alert
GET    /api/alerts/{id}          # Get alert details
PUT    /api/alerts/{id}          # Update alert
DELETE /api/alerts/{id}          # Delete alert
POST   /api/alerts/{id}/acknowledge  # Acknowledge alert
```

### 👥 **User Management**

```http
GET    /api/users/               # List users (admin only)
POST   /api/users/               # Create user (admin only)
GET    /api/users/{id}           # Get user details
PUT    /api/users/{id}           # Update user
DELETE /api/users/{id}           # Delete user (admin only)
```

### 📊 **Dashboard & Analytics**

```http
GET    /api/dashboard/stats      # Dashboard statistics
GET    /api/dashboard/alerts     # Recent alerts
GET    /api/dashboard/metrics    # System metrics
GET    /api/analytics/threats    # Threat analysis
GET    /api/analytics/trends     # Security trends
```

### 📋 **Full API Documentation**

- 📚 **Swagger UI:** http://localhost:8000/docs
- 📖 **ReDoc:** http://localhost:8000/redoc
- 📄 **OpenAPI JSON:** http://localhost:8000/openapi.json

## 🔧 Development

### 🛠️ **Local Development Setup**

```bash
# Install dependencies
npm install                    # Frontend dependencies
pip install -r requirements.txt  # Backend dependencies

# Start development servers
npm run dev                    # Frontend (port 3010)
uvicorn main:app --reload     # Backend (port 8000)
```

### 🧪 **Running Tests**

```bash
# Frontend tests
npm run test
npm run test:coverage

# Backend tests
pytest
pytest --cov=backend tests/

# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### 🐛 **Debugging**

```bash
# View service logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Access container shell
docker-compose exec backend bash
docker-compose exec frontend sh

# Database access
docker-compose exec postgres psql -U secureops -d secureops_ai
```

## 📈 Monitoring & Observability

### 📊 **Prometheus Metrics**

Available metrics endpoints:
- `/metrics` - Application metrics
- `/metrics/alerts` - Alert-specific metrics  
- `/metrics/security` - Security event metrics

### 📈 **Grafana Dashboards**

Pre-configured dashboards:
- **SecureOps Overview** - System health and key metrics
- **Alert Management** - Alert trends and response times
- **Security Analytics** - Threat detection and patterns
- **System Performance** - Resource utilization and performance

### 🚨 **Alerting Rules**

Prometheus alerting rules for:
- High CPU/Memory usage
- Database connection issues
- Failed authentication attempts
- Critical security alerts
- Service downtime

## 🚀 Deployment

### 🏭 **Production Deployment**

1. **Prepare environment:**
   ```bash
   # Set production environment variables
   export ENVIRONMENT=production
   export DEBUG=false
   export DATABASE_URL=postgresql://...
   ```

2. **Deploy with SSL:**
   ```bash
   # Copy SSL certificates to ./ssl/
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. **Health checks:**
   ```bash
   curl -f http://localhost/health
   ```

## 🚀 **Production Deployment Setup**

### 🌐 **Full Stack Deployment (Frontend + Backend)**

This project is designed for seamless deployment with a **GitHub Pages frontend** communicating with a **cloud-hosted backend**.

#### **Architecture Overview**
```
Frontend (GitHub Pages) ←→ Backend API (Render/Railway/Vercel)
├── Static SPA (docs/)       ├── FastAPI + Security
├── Dynamic API calls        ├── PostgreSQL/SQLite  
├── Auto environment detect  ├── CORS enabled
└── Fallback demo mode       └── Health monitoring
```

### 📦 **Frontend Deployment (GitHub Pages)**

1. **Enable GitHub Pages:**
   ```bash
   # 1. Push your code to GitHub
   git add .
   git commit -m "Deploy SecureOps AI to production"
   git push origin main
   
   # 2. Go to GitHub repository Settings → Pages
   # 3. Set Source: "Deploy from a branch"
   # 4. Select branch: "main" and folder: "/docs"
   # 5. Save and wait ~2 minutes for deployment
   ```

2. **Frontend URL:** `https://nwaizugbechukwuebuka.github.io/SecureOps/`

### 🔧 **Backend Deployment (Choose One Platform)**

#### **Option 1: Render (Recommended)**
```bash
# 1. Go to https://dashboard.render.com
# 2. Click "New +" → "Web Service"
# 3. Connect your GitHub repository
# 4. Configure:
#    - Name: secureops-ai-backend
#    - Environment: Python
#    - Build Command: cd backend && pip install -r requirements.txt
#    - Start Command: cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT

# 5. Set Environment Variables:
SECRET_KEY=your-super-secure-secret-key-here
ENVIRONMENT=production
DEBUG=false
CORS_ORIGINS=https://nwaizugbechukwuebuka.github.io
DATABASE_URL=<render-postgres-url>  # If using PostgreSQL
```

#### **Option 2: Railway**
```bash
npm install -g @railway/cli
railway login
railway deploy

# Set environment variables in Railway dashboard
```

#### **Option 3: Vercel**
```bash
npm install -g vercel
vercel --prod

# Configure environment variables in Vercel dashboard
```

### 🔗 **Connect Frontend to Backend**

1. **Update API Configuration:**
   - The frontend automatically detects the environment
   - On GitHub Pages (HTTPS), it uses: `https://secureops-ai-backend.onrender.com`
   - Locally (HTTP), it uses: `http://localhost:8000`

2. **Update Backend URL (if needed):**
   ```javascript
   // In docs/config.js, update PRODUCTION_API:
   PRODUCTION_API: "https://your-backend-url.onrender.com"
   ```

3. **Verify CORS Settings:**
   ```python
   # In backend/config.py, ensure GitHub Pages is included:
   cors_origins: str = "https://nwaizugbechukwuebuka.github.io,https://*.github.io"
   ```

### ✅ **Deployment Verification**

1. **Test Frontend:** Visit `https://nwaizugbechukwuebuka.github.io/SecureOps/`
2. **Test Backend:** Visit `https://your-backend.onrender.com/health`
3. **Test Connection:** Click "Test Backend Connection" in the About page
4. **Check CORS:** Verify no console errors when frontend calls backend

### 🔍 **Troubleshooting Deployment**

**Frontend Issues:**
- ❌ **404 on GitHub Pages:** Check that `/docs` folder contains `index.html`
- ❌ **Blank page:** Check browser console for JavaScript errors
- ❌ **API calls fail:** Verify backend URL in `docs/config.js`

**Backend Issues:**
- ❌ **CORS errors:** Add your GitHub Pages URL to `cors_origins` in `config.py`
- ❌ **500 errors:** Check backend logs for Python exceptions
- ❌ **Database errors:** Verify `DATABASE_URL` environment variable

**Connection Issues:**
- ❌ **Mixed content:** Ensure backend uses HTTPS in production
- ❌ **Timeout:** Check backend health endpoint: `/health`

### 🎯 **Production Checklist**

- [ ] ✅ Frontend deployed to GitHub Pages and accessible
- [ ] ✅ Backend deployed to cloud platform (Render/Railway/Vercel)
- [ ] ✅ Environment variables set (SECRET_KEY, CORS_ORIGINS)
- [ ] ✅ HTTPS enabled on both frontend and backend
- [ ] ✅ Database connected (if using external database)
- [ ] ✅ Health check endpoint responding: `/health`
- [ ] ✅ CORS configured for GitHub Pages domain
- [ ] ✅ Frontend successfully calls backend APIs
- [ ] ✅ No console errors in browser developer tools
- [ ] ✅ Authentication and security features working

### 🔄 **Continuous Deployment**

**Auto-deploy setup:**
- **Frontend:** Automatically deploys on push to `main` branch
- **Backend:** Connect GitHub repository to Render/Railway/Vercel for auto-deploy
- **Monitoring:** Use platform dashboards to monitor deployment status

**Update workflow:**
```bash
# 1. Make changes locally
# 2. Test with docker-compose up
# 3. Commit and push
git add .
git commit -m "Update feature X"
git push origin main
# 4. Monitor deployment dashboards
# 5. Verify live sites are updated
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### 📋 **Development Workflow**

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Commit: `git commit -m 'Add amazing feature'`
5. Push: `git push origin feature/amazing-feature`
6. Submit a Pull Request

### 🐛 **Bug Reports**

Found a bug? Please create an issue with:
- Detailed description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Docker version, etc.)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙋‍♂️ Support

- 📧 **Email:** support@secureops.ai
- 💬 **Discord:** [Join our community](https://discord.gg/secureops)
- 📚 **Documentation:** [docs.secureops.ai](https://docs.secureops.ai)
- 🐛 **Issues:** [GitHub Issues](https://github.com/your-org/secureops-ai/issues)

---

<div align="center">

**Made with ❤️ by the SecureOps AI Team**

[⭐ Star us on GitHub](https://github.com/your-org/secureops-ai) | [🐦 Follow on Twitter](https://twitter.com/secureopsai) | [🌐 Visit Website](https://secureops.ai)

</div>