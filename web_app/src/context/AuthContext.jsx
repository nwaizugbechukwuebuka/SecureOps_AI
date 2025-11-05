/**
 * Enhanced Authentication Context for SecureOps AI
 * Manages user authentication state, JWT tokens, and MFA flow
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authService } from '../services/authService';
import { useNotification } from './NotificationContext';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [requiresMfa, setRequiresMfa] = useState(false);
  const [tempCredentials, setTempCredentials] = useState(null);
  const { showNotification } = useNotification();

  // Check if user is authenticated on app load
  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      setLoading(true);
      
      // Check if we have a valid token in cookies
      const token = await authService.getStoredToken();
      if (token) {
        // Verify token and get user info
        const userInfo = await authService.getCurrentUser();
        if (userInfo) {
          setUser(userInfo);
          setIsAuthenticated(true);
        } else {
          // Token is invalid, clear it
          await authService.logout();
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      // Clear any invalid tokens
      await authService.logout();
    } finally {
      setLoading(false);
    }
  };

  const login = async (credentials) => {
    try {
      setLoading(true);
      const response = await authService.login(credentials);
      
      if (response.requires_mfa) {
        // MFA is required, store temp credentials
        setRequiresMfa(true);
        setTempCredentials(credentials);
        return { requiresMfa: true };
      } else {
        // Login successful
        setUser(response.user);
        setIsAuthenticated(true);
        setRequiresMfa(false);
        setTempCredentials(null);
        
        showNotification('Login successful!', 'success');
        return { success: true, user: response.user };
      }
    } catch (error) {
      const message = error.response?.data?.detail || 'Login failed';
      showNotification(message, 'error');
      
      // Handle specific error cases
      if (error.response?.status === 429) {
        throw new Error('Too many login attempts. Please try again later.');
      } else if (error.response?.status === 401) {
        throw new Error('Invalid username or password');
      }
      
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const verifyMfa = async (mfaCode) => {
    try {
      setLoading(true);
      
      if (!tempCredentials) {
        throw new Error('No pending MFA verification');
      }
      
      const credentialsWithMfa = {
        ...tempCredentials,
        mfa_code: mfaCode
      };
      
      const response = await authService.login(credentialsWithMfa);
      
      if (response.requires_mfa) {
        throw new Error('Invalid MFA code');
      }
      
      // MFA successful
      setUser(response.user);
      setIsAuthenticated(true);
      setRequiresMfa(false);
      setTempCredentials(null);
      
      showNotification('MFA verification successful!', 'success');
      return { success: true, user: response.user };
      
    } catch (error) {
      const message = error.response?.data?.detail || 'MFA verification failed';
      showNotification(message, 'error');
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      setLoading(true);
      await authService.logout();
      
      // Clear state
      setUser(null);
      setIsAuthenticated(false);
      setRequiresMfa(false);
      setTempCredentials(null);
      
      showNotification('Logged out successfully', 'info');
    } catch (error) {
      console.error('Logout error:', error);
      // Clear state even if logout request fails
      setUser(null);
      setIsAuthenticated(false);
      setRequiresMfa(false);
      setTempCredentials(null);
    } finally {
      setLoading(false);
    }
  };

  const changePassword = async (passwordData) => {
    try {
      await authService.changePassword(passwordData);
      showNotification('Password changed successfully', 'success');
      return true;
    } catch (error) {
      const message = error.response?.data?.detail || 'Password change failed';
      showNotification(message, 'error');
      throw error;
    }
  };

  const setupMfa = async () => {
    try {
      const response = await authService.setupMfa();
      return response;
    } catch (error) {
      const message = error.response?.data?.detail || 'MFA setup failed';
      showNotification(message, 'error');
      throw error;
    }
  };

  const verifyMfaSetup = async (code) => {
    try {
      await authService.verifyMfaSetup(code);
      
      // Update user state to reflect MFA is now enabled
      setUser(prev => prev ? { ...prev, mfa_enabled: true } : null);
      
      showNotification('MFA enabled successfully!', 'success');
      return true;
    } catch (error) {
      const message = error.response?.data?.detail || 'MFA verification failed';
      showNotification(message, 'error');
      throw error;
    }
  };

  const disableMfa = async (code) => {
    try {
      await authService.disableMfa(code);
      
      // Update user state to reflect MFA is now disabled
      setUser(prev => prev ? { ...prev, mfa_enabled: false } : null);
      
      showNotification('MFA disabled successfully', 'info');
      return true;
    } catch (error) {
      const message = error.response?.data?.detail || 'MFA disable failed';
      showNotification(message, 'error');
      throw error;
    }
  };

  const refreshToken = async () => {
    try {
      const response = await authService.refreshToken();
      if (response.user) {
        setUser(response.user);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Token refresh failed:', error);
      // If refresh fails, logout user
      await logout();
      return false;
    }
  };

  const updateProfile = async (profileData) => {
    try {
      const updatedUser = await authService.updateProfile(profileData);
      setUser(updatedUser);
      showNotification('Profile updated successfully', 'success');
      return updatedUser;
    } catch (error) {
      const message = error.response?.data?.detail || 'Profile update failed';
      showNotification(message, 'error');
      throw error;
    }
  };

  // Check if user has required role
  const hasRole = useCallback((requiredRole) => {
    if (!user) return false;
    
    const roleHierarchy = {
      'viewer': 1,
      'analyst': 2,
      'admin': 3
    };
    
    const userLevel = roleHierarchy[user.role] || 0;
    const requiredLevel = roleHierarchy[requiredRole] || 0;
    
    return userLevel >= requiredLevel;
  }, [user]);

  // Check if user has specific permission
  const hasPermission = useCallback((permission) => {
    if (!user) return false;
    
    // Define role-based permissions
    const permissions = {
      viewer: ['view_dashboard', 'view_alerts'],
      analyst: ['view_dashboard', 'view_alerts', 'manage_alerts', 'view_users', 'view_audit_logs'],
      admin: ['*'] // Admin has all permissions
    };
    
    const userPermissions = permissions[user.role] || [];
    return userPermissions.includes('*') || userPermissions.includes(permission);
  }, [user]);

  // Auto-refresh token before it expires
  useEffect(() => {
    let refreshInterval;
    
    if (isAuthenticated) {
      // Refresh token every 25 minutes (tokens expire in 30 minutes)
      refreshInterval = setInterval(() => {
        refreshToken();
      }, 25 * 60 * 1000);
    }
    
    return () => {
      if (refreshInterval) {
        clearInterval(refreshInterval);
      }
    };
  }, [isAuthenticated]);

  const value = {
    // State
    user,
    isAuthenticated,
    loading,
    requiresMfa,
    
    // Authentication methods
    login,
    logout,
    verifyMfa,
    refreshToken,
    
    // Profile management
    updateProfile,
    changePassword,
    
    // MFA methods
    setupMfa,
    verifyMfaSetup,
    disableMfa,
    
    // Authorization methods
    hasRole,
    hasPermission,
    
    // Utility methods
    checkAuthStatus
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;