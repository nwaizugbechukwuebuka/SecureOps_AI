// API Configuration for SecureOps AI
// This file manages backend API URLs for different environments

const CONFIG = {
  // Production backend URL (update this with your deployed backend)
  PRODUCTION_API: "https://secureops-ai-backend.onrender.com",
  
  // Development backend URL
  DEVELOPMENT_API: "http://localhost:8000",
  
  // GitHub Pages domain for CORS
  GITHUB_PAGES_DOMAIN: "https://nwaizugbechukwuebuka.github.io",
  
  // Auto-detect environment
  get API_BASE_URL() {
    // If we're on GitHub Pages or any HTTPS domain, use production API
    if (window.location.protocol === 'https:' || window.location.hostname.includes('github.io')) {
      return this.PRODUCTION_API;
    }
    // Otherwise use development API
    return this.DEVELOPMENT_API;
  },
  
  // API endpoints
  ENDPOINTS: {
    AUTH: {
      LOGIN: '/auth/login',
      LOGOUT: '/auth/logout',
      VERIFY_MFA: '/auth/verify-mfa',
      SETUP_MFA: '/auth/setup-mfa'
    },
    DASHBOARD: {
      METRICS: '/dashboard/security-metrics',
      ALERTS: '/dashboard/security-alerts',
      SYSTEM_HEALTH: '/dashboard/system-health'
    },
    USERS: {
      LIST: '/users/',
      CREATE: '/users/',
      UPDATE: '/users',
      DELETE: '/users'
    },
    AUDIT: {
      LOGS: '/audit/logs',
      STATS: '/audit/stats'
    }
  }
};

// Helper function to build full API URLs
function getApiUrl(endpoint) {
  return `${CONFIG.API_BASE_URL}${endpoint}`;
}

// Export for use in other files
window.CONFIG = CONFIG;
window.getApiUrl = getApiUrl;