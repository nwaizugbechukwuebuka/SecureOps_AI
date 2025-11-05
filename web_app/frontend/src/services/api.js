import axios from 'axios';
import toast from 'react-hot-toast';

// API configuration
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

// Create axios instance
export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    
    const errorMessage = error.response?.data?.detail || error.message || 'An error occurred';
    toast.error(errorMessage);
    
    return Promise.reject(error);
  }
);

// API Service Class
class APIService {
  // Authentication endpoints
  async login(credentials) {
    const response = await api.post('/auth/login', credentials);
    return response.data;
  }

  async register(userData) {
    const response = await api.post('/auth/register', userData);
    return response.data;
  }

  async logout() {
    const response = await api.post('/auth/logout');
    return response.data;
  }

  async refreshToken() {
    const response = await api.post('/auth/refresh');
    return response.data;
  }

  // User management endpoints
  async getCurrentUser() {
    const response = await api.get('/users/me');
    return response.data;
  }

  async updateProfile(userData) {
    const response = await api.put('/users/me', userData);
    return response.data;
  }

  async getUsers(params = {}) {
    const response = await api.get('/users/', { params });
    return response.data;
  }

  async createUser(userData) {
    const response = await api.post('/users/', userData);
    return response.data;
  }

  async updateUser(userId, userData) {
    const response = await api.put(`/users/${userId}`, userData);
    return response.data;
  }

  async deleteUser(userId) {
    const response = await api.delete(`/users/${userId}`);
    return response.data;
  }

  // Dashboard and analytics endpoints
  async getDashboardStats() {
    const response = await api.get('/dashboard/stats');
    return response.data;
  }

  async getSecurityMetrics() {
    const response = await api.get('/dashboard/security-metrics');
    return response.data;
  }

  async getSystemHealth() {
    const response = await api.get('/dashboard/system-health');
    return response.data;
  }

  async getThreatAnalytics(timeRange = '24h') {
    const response = await api.get(`/dashboard/threat-analytics?range=${timeRange}`);
    return response.data;
  }

  // Alerts and notifications endpoints
  async getAlerts(params = {}) {
    const response = await api.get('/alerts/', { params });
    return response.data;
  }

  async createAlert(alertData) {
    const response = await api.post('/alerts/', alertData);
    return response.data;
  }

  async updateAlert(alertId, alertData) {
    const response = await api.put(`/alerts/${alertId}`, alertData);
    return response.data;
  }

  async deleteAlert(alertId) {
    const response = await api.delete(`/alerts/${alertId}`);
    return response.data;
  }

  async acknowledgeAlert(alertId) {
    const response = await api.post(`/alerts/${alertId}/acknowledge`);
    return response.data;
  }

  // AI Advisor endpoints
  async getAIThreatAnalysis(data) {
    const response = await api.post('/ai-advisor/analyze', data);
    return response.data;
  }

  async getAIRecommendations() {
    const response = await api.get('/ai-advisor/recommendations');
    return response.data;
  }

  async generateReport(reportType, params = {}) {
    const response = await api.post(`/ai-advisor/report/${reportType}`, params);
    return response.data;
  }

  // System monitoring endpoints
  async getSystemMetrics() {
    const response = await api.get('/monitoring/metrics');
    return response.data;
  }

  async getLogs(params = {}) {
    const response = await api.get('/monitoring/logs', { params });
    return response.data;
  }

  async getUptime() {
    const response = await api.get('/monitoring/uptime');
    return response.data;
  }

  // WebSocket connection for real-time updates
  createWebSocket(path) {
    const wsUrl = API_BASE_URL.replace('http', 'ws') + path;
    const token = localStorage.getItem('token');
    
    const ws = new WebSocket(`${wsUrl}?token=${token}`);
    return ws;
  }
}

// Create and export API service instance
export const apiService = new APIService();
export default apiService;

// Export individual functions for backward compatibility
export const login = (credentials) => apiService.login(credentials);
export const logout = () => apiService.logout();
export const register = (userData) => apiService.register(userData);
export const fetchCurrentUser = () => apiService.getCurrentUser();
export const fetchUserProfile = () => apiService.getCurrentUser();
export const updateUserProfile = (userData) => apiService.updateUser(userData);

export const fetchDashboardData = () => apiService.getDashboardStats();
export const fetchAlerts = (params) => apiService.getAlerts(params);
export const createAlert = (alertData) => apiService.createAlert(alertData);
export const updateAlert = (id, alertData) => apiService.updateAlert(id, alertData);
export const deleteAlert = (id) => apiService.deleteAlert(id);

export const fetchUsers = (params) => apiService.getUsers(params);
export const createUser = (userData) => apiService.createUser(userData);
export const updateUser = (id, userData) => apiService.updateUser(userData);
export const deleteUser = (id) => apiService.deleteUser(id);

export const fetchSystemMetrics = () => apiService.getSystemMetrics();
export const fetchAIRecommendations = () => apiService.getAIRecommendations();
export const generateAIReport = (reportType, params) => apiService.generateReport(reportType, params);