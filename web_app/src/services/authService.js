/**
 * Enhanced Authentication Service for SecureOps AI
 * Handles all authentication operations including JWT tokens and MFA
 */

import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8001';
const AUTH_BASE_URL = `${API_BASE_URL}/auth`;

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Important for HttpOnly cookies
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10 second timeout
});

// Request interceptor to add CSRF token if available
apiClient.interceptors.request.use(
  (config) => {
    // Add CSRF token from meta tag if available
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    if (csrfToken) {
      config.headers['X-CSRFToken'] = csrfToken;
    }
    
    // Add timestamp to prevent caching of sensitive requests
    if (config.url?.includes('/auth/')) {
      config.params = { ...config.params, _t: Date.now() };
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh and errors
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Handle 401 errors (unauthorized)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      // Try to refresh token
      try {
        await authService.refreshToken();
        return apiClient(originalRequest);
      } catch (refreshError) {
        // Refresh failed, redirect to login
        authService.handleAuthError();
        return Promise.reject(refreshError);
      }
    }
    
    // Handle rate limiting
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'];
      if (retryAfter) {
        error.retryAfter = parseInt(retryAfter);
      }
    }
    
    return Promise.reject(error);
  }
);

class AuthService {
  constructor() {
    this.currentUser = null;
    this.isAuthenticated = false;
    this.authChangeListeners = [];
  }

  // Authentication state management
  addAuthChangeListener(callback) {
    this.authChangeListeners.push(callback);
    return () => {
      this.authChangeListeners = this.authChangeListeners.filter(listener => listener !== callback);
    };
  }

  notifyAuthChange() {
    this.authChangeListeners.forEach(callback => callback(this.isAuthenticated, this.currentUser));
  }

  // Login with username/password and optional MFA
  async login(credentials) {
    try {
      const response = await apiClient.post('/auth/login', credentials);
      
      if (response.data.requires_mfa) {
        // MFA is required, don't set user yet
        return {
          requires_mfa: true,
          message: 'MFA verification required'
        };
      }
      
      // Successful login
      this.currentUser = response.data.user;
      this.isAuthenticated = true;
      this.notifyAuthChange();
      
      return {
        success: true,
        user: response.data.user,
        message: response.data.message
      };
    } catch (error) {
      console.error('Login error:', error);
      throw this.handleApiError(error);
    }
  }

  // Logout user
  async logout() {
    try {
      await apiClient.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
      // Continue with logout even if request fails
    } finally {
      this.currentUser = null;
      this.isAuthenticated = false;
      this.notifyAuthChange();
    }
  }

  // Get current user info
  async getCurrentUser() {
    try {
      const response = await apiClient.get('/auth/me');
      this.currentUser = response.data;
      this.isAuthenticated = true;
      return response.data;
    } catch (error) {
      console.error('Get current user error:', error);
      this.currentUser = null;
      this.isAuthenticated = false;
      return null;
    }
  }

  // Refresh authentication token
  async refreshToken() {
    try {
      const response = await apiClient.post('/auth/refresh');
      if (response.data.user) {
        this.currentUser = response.data.user;
        this.isAuthenticated = true;
        return response.data;
      }
      throw new Error('Token refresh failed');
    } catch (error) {
      console.error('Token refresh error:', error);
      this.handleAuthError();
      throw error;
    }
  }

  // Change password
  async changePassword(passwordData) {
    try {
      const response = await apiClient.post('/auth/change-password', passwordData);
      return response.data;
    } catch (error) {
      console.error('Change password error:', error);
      throw this.handleApiError(error);
    }
  }

  // Request password reset
  async requestPasswordReset(email) {
    try {
      const response = await apiClient.post('/auth/request-password-reset', { email });
      return response.data;
    } catch (error) {
      console.error('Request password reset error:', error);
      throw this.handleApiError(error);
    }
  }

  // Reset password with token
  async resetPassword(token, newPassword) {
    try {
      const response = await apiClient.post('/auth/reset-password', {
        token,
        new_password: newPassword
      });
      return response.data;
    } catch (error) {
      console.error('Reset password error:', error);
      throw this.handleApiError(error);
    }
  }

  // MFA Operations
  async setupMfa() {
    try {
      const response = await apiClient.post('/auth/setup-mfa');
      return response.data;
    } catch (error) {
      console.error('Setup MFA error:', error);
      throw this.handleApiError(error);
    }
  }

  async verifyMfaSetup(code) {
    try {
      const response = await apiClient.post('/auth/verify-mfa-setup', { code });
      return response.data;
    } catch (error) {
      console.error('Verify MFA setup error:', error);
      throw this.handleApiError(error);
    }
  }

  async disableMfa(code) {
    try {
      const response = await apiClient.post('/auth/disable-mfa', { code });
      return response.data;
    } catch (error) {
      console.error('Disable MFA error:', error);
      throw this.handleApiError(error);
    }
  }

  async generateBackupCodes() {
    try {
      const response = await apiClient.post('/auth/generate-backup-codes');
      return response.data;
    } catch (error) {
      console.error('Generate backup codes error:', error);
      throw this.handleApiError(error);
    }
  }

  // Profile management
  async updateProfile(profileData) {
    try {
      const response = await apiClient.put('/auth/profile', profileData);
      this.currentUser = response.data;
      return response.data;
    } catch (error) {
      console.error('Update profile error:', error);
      throw this.handleApiError(error);
    }
  }

  // Session management
  async getActiveSessions() {
    try {
      const response = await apiClient.get('/auth/sessions');
      return response.data;
    } catch (error) {
      console.error('Get sessions error:', error);
      throw this.handleApiError(error);
    }
  }

  async revokeSession(sessionId) {
    try {
      const response = await apiClient.delete(`/auth/sessions/${sessionId}`);
      return response.data;
    } catch (error) {
      console.error('Revoke session error:', error);
      throw this.handleApiError(error);
    }
  }

  async revokeAllSessions() {
    try {
      const response = await apiClient.delete('/auth/sessions');
      return response.data;
    } catch (error) {
      console.error('Revoke all sessions error:', error);
      throw this.handleApiError(error);
    }
  }

  // Utility methods
  async getStoredToken() {
    // Since we're using HttpOnly cookies, we can't access the token directly
    // Instead, we'll check if we have a valid session
    try {
      const user = await this.getCurrentUser();
      return user ? 'token_exists_in_cookie' : null;
    } catch {
      return null;
    }
  }

  handleAuthError() {
    this.currentUser = null;
    this.isAuthenticated = false;
    this.notifyAuthChange();
    
    // Redirect to login page
    const currentPath = window.location.pathname;
    if (currentPath !== '/login' && currentPath !== '/') {
      window.location.href = '/login';
    }
  }

  handleApiError(error) {
    if (error.response) {
      // Server responded with error
      const { status, data } = error.response;
      const message = data.detail || data.message || `HTTP ${status} Error`;
      
      const customError = new Error(message);
      customError.status = status;
      customError.code = data.code;
      customError.response = error.response;
      
      return customError;
    } else if (error.request) {
      // Network error
      const networkError = new Error('Network error. Please check your connection.');
      networkError.isNetworkError = true;
      return networkError;
    } else {
      // Other error
      return error;
    }
  }

  // Password strength validation
  validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    const hasNoSpaces = !/\s/.test(password);

    const errors = [];
    
    if (password.length < minLength) {
      errors.push(`Password must be at least ${minLength} characters long`);
    }
    if (!hasUpperCase) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (!hasLowerCase) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (!hasNumbers) {
      errors.push('Password must contain at least one number');
    }
    if (!hasSpecialChar) {
      errors.push('Password must contain at least one special character');
    }
    if (!hasNoSpaces) {
      errors.push('Password cannot contain spaces');
    }

    return {
      isValid: errors.length === 0,
      errors,
      strength: this.calculatePasswordStrength(password)
    };
  }

  calculatePasswordStrength(password) {
    let score = 0;
    
    // Length score
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    
    // Character variety score
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
    
    // Bonus for very long passwords
    if (password.length >= 20) score += 1;
    
    if (score <= 2) return 'weak';
    if (score <= 4) return 'medium';
    if (score <= 6) return 'strong';
    return 'very-strong';
  }

  // Check authentication status
  isUserAuthenticated() {
    return this.isAuthenticated && this.currentUser !== null;
  }

  getUserRole() {
    return this.currentUser?.role || null;
  }

  hasRole(requiredRole) {
    if (!this.currentUser) return false;
    
    const roleHierarchy = {
      'viewer': 1,
      'analyst': 2,
      'admin': 3
    };
    
    const userLevel = roleHierarchy[this.currentUser.role] || 0;
    const requiredLevel = roleHierarchy[requiredRole] || 0;
    
    return userLevel >= requiredLevel;
  }
}

// Create singleton instance
export const authService = new AuthService();

// Export API client for use in other services
export { apiClient };

export default authService;