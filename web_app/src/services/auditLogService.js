/**
 * Audit Log Service for SecureOps AI
 * Handles audit log retrieval and security event monitoring
 */

import { apiClient } from './authService';

class AuditLogService {
  constructor() {
    this.baseURL = '/dashboard/audit-logs';
  }

  // Get audit logs with filtering and pagination
  async getAuditLogs(params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      // Pagination
      if (params.page) queryParams.append('page', params.page);
      if (params.limit) queryParams.append('limit', params.limit);
      
      // Filtering
      if (params.user_id) queryParams.append('user_id', params.user_id);
      if (params.event_type) queryParams.append('event_type', params.event_type);
      if (params.risk_level) queryParams.append('risk_level', params.risk_level);
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.ip_address) queryParams.append('ip_address', params.ip_address);
      if (params.search) queryParams.append('search', params.search);

      const response = await apiClient.get(`${this.baseURL}?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Get audit logs error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get audit log by ID
  async getAuditLogById(logId) {
    try {
      const response = await apiClient.get(`${this.baseURL}/${logId}`);
      return response.data;
    } catch (error) {
      console.error('Get audit log by ID error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get audit log statistics
  async getAuditLogStats(params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.group_by) queryParams.append('group_by', params.group_by);

      const response = await apiClient.get(`${this.baseURL}/stats?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Get audit log stats error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get security events summary
  async getSecurityEventsSummary(timeRange = '24h') {
    try {
      const response = await apiClient.get(`/dashboard/security-events?time_range=${timeRange}`);
      return response.data;
    } catch (error) {
      console.error('Get security events summary error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get login activity analysis
  async getLoginActivity(params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.user_id) queryParams.append('user_id', params.user_id);

      const response = await apiClient.get(`/dashboard/login-activity?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Get login activity error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get user activity analysis
  async getUserActivity(params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.limit) queryParams.append('limit', params.limit);

      const response = await apiClient.get(`/dashboard/user-activity?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Get user activity error:', error);
      throw this.handleApiError(error);
    }
  }

  // Export audit logs
  async exportAuditLogs(params = {}, format = 'csv') {
    try {
      const queryParams = new URLSearchParams();
      queryParams.append('format', format);
      
      // Add filtering parameters
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.event_type) queryParams.append('event_type', params.event_type);
      if (params.risk_level) queryParams.append('risk_level', params.risk_level);
      if (params.user_id) queryParams.append('user_id', params.user_id);

      const response = await apiClient.get(`${this.baseURL}/export?${queryParams}`, {
        responseType: 'blob'
      });
      
      return response.data;
    } catch (error) {
      console.error('Export audit logs error:', error);
      throw this.handleApiError(error);
    }
  }

  // Real-time audit log streaming (if supported)
  async streamAuditLogs(params = {}, callback) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.event_types) {
        params.event_types.forEach(type => queryParams.append('event_type', type));
      }
      if (params.risk_levels) {
        params.risk_levels.forEach(level => queryParams.append('risk_level', level));
      }

      // Note: This would typically use WebSocket or Server-Sent Events
      // For now, we'll simulate with polling
      const pollInterval = setInterval(async () => {
        try {
          const recentLogs = await this.getAuditLogs({
            limit: 10,
            start_date: new Date(Date.now() - 60000).toISOString(), // Last minute
            ...params
          });
          
          if (recentLogs.logs && recentLogs.logs.length > 0) {
            callback(recentLogs.logs);
          }
        } catch (error) {
          console.error('Polling error:', error);
        }
      }, 5000); // Poll every 5 seconds

      return () => clearInterval(pollInterval);
    } catch (error) {
      console.error('Stream audit logs error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get event type statistics
  async getEventTypeStats(timeRange = '7d') {
    try {
      const response = await apiClient.get(`${this.baseURL}/event-types/stats?time_range=${timeRange}`);
      return response.data;
    } catch (error) {
      console.error('Get event type stats error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get risk level distribution
  async getRiskLevelDistribution(timeRange = '7d') {
    try {
      const response = await apiClient.get(`${this.baseURL}/risk-levels/stats?time_range=${timeRange}`);
      return response.data;
    } catch (error) {
      console.error('Get risk level distribution error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get top users by activity
  async getTopUsersByActivity(params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.limit) queryParams.append('limit', params.limit || 10);

      const response = await apiClient.get(`${this.baseURL}/top-users?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Get top users by activity error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get suspicious activity patterns
  async getSuspiciousActivity(params = {}) {
    try {
      const queryParams = new URLSearchParams();
      
      if (params.start_date) queryParams.append('start_date', params.start_date);
      if (params.end_date) queryParams.append('end_date', params.end_date);
      if (params.threshold) queryParams.append('threshold', params.threshold);

      const response = await apiClient.get(`/dashboard/suspicious-activity?${queryParams}`);
      return response.data;
    } catch (error) {
      console.error('Get suspicious activity error:', error);
      throw this.handleApiError(error);
    }
  }

  // Search audit logs with advanced criteria
  async searchAuditLogs(searchCriteria) {
    try {
      const response = await apiClient.post(`${this.baseURL}/search`, searchCriteria);
      return response.data;
    } catch (error) {
      console.error('Search audit logs error:', error);
      throw this.handleApiError(error);
    }
  }

  // Get audit log retention info
  async getRetentionInfo() {
    try {
      const response = await apiClient.get(`${this.baseURL}/retention-info`);
      return response.data;
    } catch (error) {
      console.error('Get retention info error:', error);
      throw this.handleApiError(error);
    }
  }

  // Archive old audit logs (Admin only)
  async archiveOldLogs(beforeDate) {
    try {
      const response = await apiClient.post(`${this.baseURL}/archive`, {
        before_date: beforeDate
      });
      return response.data;
    } catch (error) {
      console.error('Archive old logs error:', error);
      throw this.handleApiError(error);
    }
  }

  // Utility methods for formatting and filtering
  formatEventType(eventType) {
    const eventTypeMap = {
      'user_login': 'User Login',
      'user_logout': 'User Logout',
      'user_created': 'User Created',
      'user_updated': 'User Updated',
      'user_deleted': 'User Deleted',
      'password_changed': 'Password Changed',
      'mfa_enabled': 'MFA Enabled',
      'mfa_disabled': 'MFA Disabled',
      'role_changed': 'Role Changed',
      'security_alert': 'Security Alert',
      'suspicious_activity': 'Suspicious Activity',
      'data_access': 'Data Access',
      'config_change': 'Configuration Change',
      'api_access': 'API Access'
    };
    
    return eventTypeMap[eventType] || eventType.replace('_', ' ').toUpperCase();
  }

  formatRiskLevel(riskLevel) {
    const riskLevelMap = {
      'low': 'Low',
      'medium': 'Medium',
      'high': 'High',
      'critical': 'Critical'
    };
    
    return riskLevelMap[riskLevel] || riskLevel.toUpperCase();
  }

  getRiskLevelColor(riskLevel) {
    const colorMap = {
      'low': '#48bb78',     // Green
      'medium': '#ed8936',  // Orange
      'high': '#f56565',    // Red
      'critical': '#c53030' // Dark Red
    };
    
    return colorMap[riskLevel] || '#718096';
  }

  formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (seconds < 60) {
      return 'Just now';
    } else if (minutes < 60) {
      return `${minutes}m ago`;
    } else if (hours < 24) {
      return `${hours}h ago`;
    } else if (days < 7) {
      return `${days}d ago`;
    } else {
      return date.toLocaleDateString();
    }
  }

  // Create filter presets for common use cases
  getFilterPresets() {
    return {
      securityEvents: {
        event_types: ['security_alert', 'suspicious_activity', 'user_login', 'mfa_disabled'],
        risk_levels: ['high', 'critical']
      },
      userManagement: {
        event_types: ['user_created', 'user_updated', 'user_deleted', 'role_changed'],
        risk_levels: ['medium', 'high', 'critical']
      },
      authenticationEvents: {
        event_types: ['user_login', 'user_logout', 'password_changed', 'mfa_enabled', 'mfa_disabled']
      },
      highRiskEvents: {
        risk_levels: ['high', 'critical']
      },
      recentActivity: {
        start_date: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Last 24h
        limit: 50
      }
    };
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
export const auditLogService = new AuditLogService();

export default auditLogService;