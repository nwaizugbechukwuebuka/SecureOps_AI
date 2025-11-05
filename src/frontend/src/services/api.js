import axios from 'axios';

// Base configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';
const WS_BASE_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';

// Create axios instance with base configuration
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Token management
const getToken = () => {
  return localStorage.getItem('access_token');
};

const setToken = (token) => {
  localStorage.setItem('access_token', token);
};

const removeToken = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
};

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle auth errors and token refresh
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken,
          });

          const { access_token } = response.data;
          setToken(access_token);

          // Retry the original request with new token
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return apiClient(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        removeToken();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    // Handle other error responses
    if (error.response?.status === 403) {
      console.error('Access forbidden:', error.response.data);
    } else if (error.response?.status >= 500) {
      console.error('Server error:', error.response.data);
    }

    return Promise.reject(error);
  }
);

// WebSocket connection management
class WebSocketManager {
  constructor() {
    this.connections = new Map();
    this.reconnectAttempts = new Map();
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
  }

  connect(endpoint, callbacks = {}) {
    const url = `${WS_BASE_URL}/${endpoint}`;
    const token = getToken();
    
    if (!token) {
      console.error('No auth token available for WebSocket connection');
      return null;
    }

    const wsUrl = `${url}?token=${token}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log(`WebSocket connected: ${endpoint}`);
      this.reconnectAttempts.set(endpoint, 0);
      if (callbacks.onOpen) callbacks.onOpen();
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (callbacks.onMessage) callbacks.onMessage(data);
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    ws.onclose = (event) => {
      console.log(`WebSocket closed: ${endpoint}`, event);
      this.connections.delete(endpoint);
      
      if (!event.wasClean) {
        this.handleReconnect(endpoint, callbacks);
      }
      
      if (callbacks.onClose) callbacks.onClose(event);
    };

    ws.onerror = (error) => {
      console.error(`WebSocket error: ${endpoint}`, error);
      if (callbacks.onError) callbacks.onError(error);
    };

    this.connections.set(endpoint, ws);
    return ws;
  }

  handleReconnect(endpoint, callbacks) {
    const attempts = this.reconnectAttempts.get(endpoint) || 0;
    
    if (attempts < this.maxReconnectAttempts) {
      const delay = this.reconnectDelay * Math.pow(2, attempts);
      
      setTimeout(() => {
        console.log(`Attempting to reconnect WebSocket: ${endpoint} (attempt ${attempts + 1})`);
        this.reconnectAttempts.set(endpoint, attempts + 1);
        this.connect(endpoint, callbacks);
      }, delay);
    } else {
      console.error(`Max reconnection attempts reached for: ${endpoint}`);
      this.reconnectAttempts.delete(endpoint);
    }
  }

  disconnect(endpoint) {
    const ws = this.connections.get(endpoint);
    if (ws) {
      ws.close(1000, 'Client disconnecting');
      this.connections.delete(endpoint);
      this.reconnectAttempts.delete(endpoint);
    }
  }

  disconnectAll() {
    for (const endpoint of this.connections.keys()) {
      this.disconnect(endpoint);
    }
  }

  send(endpoint, data) {
    const ws = this.connections.get(endpoint);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
      return true;
    }
    return false;
  }
}

const wsManager = new WebSocketManager();

// API service methods
export const api = {
  // HTTP methods
  get: (url, config = {}) => apiClient.get(url, config),
  post: (url, data = {}, config = {}) => apiClient.post(url, data, config),
  put: (url, data = {}, config = {}) => apiClient.put(url, data, config),
  patch: (url, data = {}, config = {}) => apiClient.patch(url, data, config),
  delete: (url, config = {}) => apiClient.delete(url, config),

  // Authentication
  auth: {
    login: async (credentials) => {
      const response = await apiClient.post('/auth/login', credentials);
      const { access_token, refresh_token, user } = response.data;
      
      setToken(access_token);
      localStorage.setItem('refresh_token', refresh_token);
      localStorage.setItem('user', JSON.stringify(user));
      
      return response.data;
    },

    logout: async () => {
      try {
        await apiClient.post('/auth/logout');
      } catch (error) {
        console.error('Logout error:', error);
      } finally {
        removeToken();
        wsManager.disconnectAll();
      }
    },

    register: (userData) => apiClient.post('/auth/register', userData),
    
    refreshToken: async () => {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) throw new Error('No refresh token available');
      
      const response = await apiClient.post('/auth/refresh', {
        refresh_token: refreshToken,
      });
      
      const { access_token } = response.data;
      setToken(access_token);
      
      return response.data;
    },

    resetPassword: (email) => apiClient.post('/auth/reset-password', { email }),
    
    changePassword: (data) => apiClient.post('/auth/change-password', data),
    
    verifyEmail: (token) => apiClient.post('/auth/verify-email', { token }),
  },

  // Users
  users: {
    getProfile: () => apiClient.get('/users/me'),
    updateProfile: (data) => apiClient.patch('/users/me', data),
    getUsers: (params = {}) => apiClient.get('/users', { params }),
    createUser: (data) => apiClient.post('/users', data),
    updateUser: (id, data) => apiClient.patch(`/users/${id}`, data),
    deleteUser: (id) => apiClient.delete(`/users/${id}`),
  },

  // Pipelines
  pipelines: {
    getAll: (params = {}) => apiClient.get('/pipelines', { params }),
    getById: (id) => apiClient.get(`/pipelines/${id}`),
    create: (data) => apiClient.post('/pipelines', data),
    update: (id, data) => apiClient.patch(`/pipelines/${id}`, data),
    delete: (id) => apiClient.delete(`/pipelines/${id}`),
    trigger: (id) => apiClient.post(`/pipelines/${id}/trigger`),
    getStats: () => apiClient.get('/pipelines/stats'),
    getLogs: (id, params = {}) => apiClient.get(`/pipelines/${id}/logs`, { params }),
  },

  // Alerts
  alerts: {
    getAll: (params = {}) => apiClient.get('/alerts', { params }),
    getById: (id) => apiClient.get(`/alerts/${id}`),
    create: (data) => apiClient.post('/alerts', data),
    update: (id, data) => apiClient.patch(`/alerts/${id}`, data),
    delete: (id) => apiClient.delete(`/alerts/${id}`),
    acknowledge: (id) => apiClient.post(`/alerts/${id}/acknowledge`),
    resolve: (id) => apiClient.post(`/alerts/${id}/resolve`),
    getStats: () => apiClient.get('/alerts/stats'),
    bulkAction: (data) => apiClient.post('/alerts/bulk-action', data),
  },

  // Vulnerabilities
  vulnerabilities: {
    getAll: (params = {}) => apiClient.get('/vulnerabilities', { params }),
    getById: (id) => apiClient.get(`/vulnerabilities/${id}`),
    update: (id, data) => apiClient.patch(`/vulnerabilities/${id}`, data),
    getStats: () => apiClient.get('/vulnerabilities/stats'),
    export: (params = {}) => apiClient.get('/vulnerabilities/export', { 
      params, 
      responseType: 'blob' 
    }),
  },

  // Compliance
  compliance: {
    getFrameworks: () => apiClient.get('/compliance/frameworks'),
    getCompliance: (params = {}) => apiClient.get('/compliance', { params }),
    getReport: (params = {}) => apiClient.get('/compliance/report', { 
      params, 
      responseType: 'blob' 
    }),
    updateControl: (id, data) => apiClient.patch(`/compliance/controls/${id}`, data),
  },

  // Reports
  reports: {
    generate: (data) => apiClient.post('/reports/generate', data),
    getAll: (params = {}) => apiClient.get('/reports', { params }),
    getById: (id) => apiClient.get(`/reports/${id}`),
    download: (id) => apiClient.get(`/reports/${id}/download`, { 
      responseType: 'blob' 
    }),
    delete: (id) => apiClient.delete(`/reports/${id}`),
  },

  // Settings
  settings: {
    getAll: () => apiClient.get('/settings'),
    update: (data) => apiClient.put('/settings', data),
    test: (service, config) => apiClient.post(`/settings/test/${service}`, config),
  },

  // Integrations
  integrations: {
    getAll: () => apiClient.get('/integrations'),
    create: (data) => apiClient.post('/integrations', data),
    update: (id, data) => apiClient.patch(`/integrations/${id}`, data),
    delete: (id) => apiClient.delete(`/integrations/${id}`),
    test: (id) => apiClient.post(`/integrations/${id}/test`),
    sync: (id) => apiClient.post(`/integrations/${id}/sync`),
  },

  // Scanning
  scanning: {
    trigger: (data) => apiClient.post('/scanning/trigger', data),
    getResults: (params = {}) => apiClient.get('/scanning/results', { params }),
    getResultById: (id) => apiClient.get(`/scanning/results/${id}`),
    getScanners: () => apiClient.get('/scanning/scanners'),
    getStats: () => apiClient.get('/scanning/stats'),
  },

  // Dashboard
  dashboard: {
    getOverview: () => apiClient.get('/dashboard/overview'),
    getMetrics: (params = {}) => apiClient.get('/dashboard/metrics', { params }),
    getActivity: (params = {}) => apiClient.get('/dashboard/activity', { params }),
  },

  // WebSocket connections
  ws: {
    connect: (endpoint, callbacks) => wsManager.connect(endpoint, callbacks),
    disconnect: (endpoint) => wsManager.disconnect(endpoint),
    disconnectAll: () => wsManager.disconnectAll(),
    send: (endpoint, data) => wsManager.send(endpoint, data),
  },
};

// Error handling utility
export const handleApiError = (error, defaultMessage = 'An error occurred') => {
  if (error.response) {
    // Server responded with error status
    const { status, data } = error.response;
    
    if (status === 400) {
      return data.detail || data.message || 'Invalid request';
    } else if (status === 401) {
      return 'Authentication required';
    } else if (status === 403) {
      return 'Access forbidden';
    } else if (status === 404) {
      return 'Resource not found';
    } else if (status === 422) {
      // Validation errors
      if (data.detail && Array.isArray(data.detail)) {
        return data.detail.map(err => err.msg).join(', ');
      }
      return data.detail || 'Validation error';
    } else if (status >= 500) {
      return 'Server error occurred';
    }
    
    return data.detail || data.message || defaultMessage;
  } else if (error.request) {
    // Network error
    return 'Network error - please check your connection';
  } else {
    // Other error
    return error.message || defaultMessage;
  }
};

// Request cancellation
export const createCancelToken = () => {
  return axios.CancelToken.source();
};

// File upload utility
export const uploadFile = async (file, endpoint, onProgress = null) => {
  const formData = new FormData();
  formData.append('file', file);

  const config = {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  };

  if (onProgress) {
    config.onUploadProgress = (progressEvent) => {
      const percentCompleted = Math.round(
        (progressEvent.loaded * 100) / progressEvent.total
      );
      onProgress(percentCompleted);
    };
  }

  return apiClient.post(endpoint, formData, config);
};

<<<<<<< HEAD

// Utility to get WebSocket URL for a given endpoint
export function getWebSocketUrl(endpoint = "") {
  // Remove leading slash if present
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint.slice(1) : endpoint;
  return `${WS_BASE_URL}/${cleanEndpoint}`;
}

=======
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
// Default export
export default api;
