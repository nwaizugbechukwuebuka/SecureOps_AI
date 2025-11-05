/**
 * Enhanced User Management Service
 * Handles user CRUD operations with RBAC support
 */

import { apiClient } from './authService';

class UserService {
  constructor() {
    this.baseURL = '/users';
  }

  // Get all users (Admin only)
  async getAllUsers(params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.page) queryParams.append('page', params.page);
      if (params.limit) queryParams.append('limit', params.limit);
      if (params.role) queryParams.append('role', params.role);
      if (params.search) queryParams.append('search', params.search);
      if (params.active !== undefined) queryParams.append('active', params.active);

      const response = await apiClient.get(`${this.baseURL}?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Get all users error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get user by ID
  async getUserById(userId) {
    try {
      const response = await apiClient.get(`${this.baseURL}/${userId}`);
      return response.data;
    } catch (error) {
      console.error('Get user by ID error:', error);
      throw this.handleApiError(error);
    }
  }

  // Create new user (Admin only)
  async createUser(userData) {
    try {
      const response = await apiClient.post(this.baseURL, userData);
      return response.data;
    } catch (error) {
      console.error('Create user error:', error);
      throw this.handleApiError(error);
    }
  }

  // Update user (Admin or own profile)
  async updateUser(userId, userData) {
    try {
      const response = await apiClient.put(`${this.baseURL}/${userId}`, userData);
      return response.data;
    } catch (error) {
      console.error('Update user error:', error);
      throw this.handleApiError(error);
    }
  }

  // Delete user (Admin only)
  async deleteUser(userId) {
    try {
      const response = await apiClient.delete(`${this.baseURL}/${userId}`);
      return response.data;
    } catch (error) {
      console.error('Delete user error:', error);
      throw this.handleApiError(error);
    }
  }

  // Bulk user operations (Admin only)
  async bulkUpdateUsers(userUpdates) {
    try {
      const response = await apiClient.put(`${this.baseURL}/bulk`, { users: userUpdates });
      return response.data;
    } catch (error) {
      console.error('Bulk update users error:', error);
      throw this.handleApiError(error);
    }
  }

  async bulkDeleteUsers(userIds) {
    try {
      const response = await apiClient.delete(`${this.baseURL}/bulk`, { 
        data: { user_ids: userIds } 
      });
      return response.data;
    } catch (error) {
      console.error('Bulk delete users error:', error);
      throw this.handleApiError(error);
    }
  }

  // User role management
  async updateUserRole(userId, newRole) {
    try {
      const response = await apiClient.put(`${this.baseURL}/${userId}/role`, { 
        role: newRole 
      });
      return response.data;
    } catch (error) {
      console.error('Update user role error:', error);
      throw this.handleApiError(error);
    }
  }

  // User account status management
  async activateUser(userId) {
    try {
      const response = await apiClient.put(`${this.baseURL}/${userId}/activate`);
      return response.data;
    } catch (error) {
      console.error('Activate user error:', error);
      throw this.handleApiError(error);
    }
  }

  async deactivateUser(userId, reason = '') {
    try {
      const response = await apiClient.put(`${this.baseURL}/${userId}/deactivate`, { 
        reason 
      });
      return response.data;
    } catch (error) {
      console.error('Deactivate user error:', error);
      throw this.handleApiError(error);
    }
  }

  async lockUser(userId, reason = '') {
    try {
      const response = await apiClient.put(`${this.baseURL}/${userId}/lock`, { 
        reason 
      });
      return response.data;
    } catch (error) {
      console.error('Lock user error:', error);
      throw this.handleApiError(error);
    }
  }

  async unlockUser(userId) {
    try {
      const response = await apiClient.put(`${this.baseURL}/${userId}/unlock`);
      return response.data;
    } catch (error) {
      console.error('Unlock user error:', error);
      throw this.handleApiError(error);
    }
  }

  // User session management
  async getUserSessions(userId) {
    try {
      const response = await apiClient.get(`${this.baseURL}/${userId}/sessions`);
      return response.data;
    } catch (error) {
      console.error('Get user sessions error:', error);
      throw this.handleApiError(error);
    }
  }

  async revokeUserSession(userId, sessionId) {
    try {
      const response = await apiClient.delete(`${this.baseURL}/${userId}/sessions/${sessionId}`);
      return response.data;
    } catch (error) {
      console.error('Revoke user session error:', error);
      throw this.handleApiError(error);
    }
  }

  async revokeAllUserSessions(userId) {
    try {
      const response = await apiClient.delete(`${this.baseURL}/${userId}/sessions`);
      return response.data;
    } catch (error) {
      console.error('Revoke all user sessions error:', error);
      throw this.handleApiError(error);
    }
  }

  // User statistics and analytics
  async getUserStats() {
    try {
      const response = await apiClient.get(`${this.baseURL}/stats`);
      return response.data;
    } catch (error) {
      console.error('Get user stats error:', error);
      throw this.handleApiError(error);
    }
  }

  async getUserActivity(userId, params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.limit) queryParams.append('limit', params.limit);

      const response = await apiClient.get(
        `${this.baseURL}/${userId}/activity?${queryParams}`
      );
      return response.data;
    } catch (error) {
      console.error('Get user activity error:', error);
      throw this.handleApiError(error);
    }
  }

  // User permissions and roles
  async getAvailableRoles() {
    try {
      const response = await apiClient.get(`${this.baseURL}/roles`);
      return response.data;
    } catch (error) {
      console.error('Get available roles error:', error);
      throw this.handleApiError(error);
    }
  }

  async getUserPermissions(userId) {
    try {
      const response = await apiClient.get(`${this.baseURL}/${userId}/permissions`);
      return response.data;
    } catch (error) {
      console.error('Get user permissions error:', error);
      throw this.handleApiError(error);
    }
  }

  // Password management
  async resetUserPassword(userId, sendEmail = true) {
    try {
      const response = await apiClient.post(`${this.baseURL}/${userId}/reset-password`, {
        send_email: sendEmail
      });
      return response.data;
    } catch (error) {
      console.error('Reset user password error:', error);
      throw this.handleApiError(error);
    }
  }

  async forcePasswordChange(userId) {
    try {
      const response = await apiClient.put(`${this.baseURL}/${userId}/force-password-change`);
      return response.data;
    } catch (error) {
      console.error('Force password change error:', error);
      throw this.handleApiError(error);
    }
  }

  // MFA management for users
  async getUserMfaStatus(userId) {
    try {
      const response = await apiClient.get(`${this.baseURL}/${userId}/mfa-status`);
      return response.data;
    } catch (error) {
      console.error('Get user MFA status error:', error);
      throw this.handleApiError(error);
    }
  }

  async disableUserMfa(userId, adminCode) {
    try {
      const response = await apiClient.delete(`${this.baseURL}/${userId}/mfa`, {
        data: { admin_code: adminCode }
      });
      return response.data;
    } catch (error) {
      console.error('Disable user MFA error:', error);
      throw this.handleApiError(error);
    }
  }

  // User search and filtering
  async searchUsers(query, filters = {}) {
    try {
      const queryParams = new URLSearchParams();
      queryParams.append('q', query);
      
      if (filters.role) queryParams.append('role', filters.role);
      if (filters.active !== undefined) queryParams.append('active', filters.active);
      if (filters.mfa_enabled !== undefined) queryParams.append('mfa_enabled', filters.mfa_enabled);

      const response = await apiClient.get(`${this.baseURL}/search?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Search users error:', error);
      throw this.handleApiError(error);
    }
  }

  // User export (Admin only)
  async exportUsers(format = 'csv', filters = {}) {
    try {
      const queryParams = new URLSearchParams();
      queryParams.append('format', format);
      
      if (filters.role) queryParams.append('role', filters.role);
      if (filters.active !== undefined) queryParams.append('active', filters.active);

      const response = await apiClient.get(`${this.baseURL}/export?${queryParams}`, {
        responseType: 'blob'
      });
      
      return response.data;
    } catch (error) {
      console.error('Export users error:', error);
      throw this.handleApiError(error);
    }
  }

  // User import (Admin only)
  async importUsers(file, options = {}) {
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      if (options.update_existing) {
        formData.append('update_existing', options.update_existing);
      }
      if (options.send_invitations) {
        formData.append('send_invitations', options.send_invitations);
      }

      const response = await apiClient.post(`${this.baseURL}/import`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      return response.data;
    } catch (error) {
      console.error('Import users error:', error);
      throw this.handleApiError(error);
    }
  }

  // User validation helpers
  validateUserData(userData, isUpdate = false) {
    const errors = [];

    if (!isUpdate && !userData.username) {
      errors.push('Username is required');
    }

    if (userData.username && !this.isValidUsername(userData.username)) {
      errors.push('Username must be 3-50 characters and contain only letters, numbers, and underscores');
    }

    if (!isUpdate && !userData.email) {
      errors.push('Email is required');
    }

    if (userData.email && !this.isValidEmail(userData.email)) {
      errors.push('Please enter a valid email address');
    }

    if (!isUpdate && !userData.password) {
      errors.push('Password is required');
    }

    if (userData.role && !this.isValidRole(userData.role)) {
      errors.push('Invalid role specified');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  isValidUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_]{3,50}$/;
    return usernameRegex.test(username);
  }

  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  isValidRole(role) {
    const validRoles = ['admin', 'analyst', 'viewer'];
    return validRoles.includes(role);
  }

  // Error handling
  handleApiError(error) {
    if (error.response) {
      const { status, data } = error.response;
      const message = data.detail || data.message || `HTTP ${status} Error`;
      
      const customError = new Error(message);
      customError.status = status;
      customError.code = data.code;
      customError.response = error.response;
      
      return customError;
    } else if (error.request) {
      const networkError = new Error('Network error. Please check your connection.');
      networkError.isNetworkError = true;
      return networkError;
    } else {
      return error;
    }
  }

  // Helper method to download exported data
  downloadFile(blob, filename) {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }
}

// Create singleton instance
export const userService = new UserService();

export default userService;