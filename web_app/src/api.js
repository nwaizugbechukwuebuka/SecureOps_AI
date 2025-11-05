// API utility for REST and WebSocket
import { getAuthToken } from './auth';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8010';
const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8010';

export async function apiFetch(path, options = {}) {
  const token = getAuthToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: 'include',
    headers
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(errorText || `HTTP ${res.status}`);
  }

  return res.json();
}

export function createWebSocket(path, token = null) {
  const wsToken = token || getAuthToken();
  const url = `${WS_BASE_URL}${path}`;
  return new WebSocket(wsToken ? `${url}?token=${wsToken}` : url);
}

// API helper functions for common operations
export const api = {
  // Authentication
  auth: {
    login: (credentials) => apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    }),
    me: () => apiFetch('/api/auth/me')
  },

  // Users
  users: {
    list: () => apiFetch('/api/users'),
    create: (userData) => apiFetch('/api/users', {
      method: 'POST',
      body: JSON.stringify(userData)
    }),
    update: (id, userData) => apiFetch(`/api/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(userData)
    }),
    delete: (id) => apiFetch(`/api/users/${id}`, {
      method: 'DELETE'
    })
  },

  // Security Analytics
  security: {
    analytics: () => apiFetch('/api/analytics/security'),
    events: () => apiFetch('/api/security-events'),
    createEvent: (eventData) => apiFetch('/api/security-events', {
      method: 'POST',
      body: JSON.stringify(eventData)
    })
  },

  // System Health
  system: {
    health: () => apiFetch('/api/system/health'),
    metrics: () => apiFetch('/api/system/metrics'),
    createMetric: (metricData) => apiFetch('/api/system/metrics', {
      method: 'POST',
      body: JSON.stringify(metricData)
    })
  },

  // Automation
  automation: {
    tasks: () => apiFetch('/api/automation/tasks'),
    createTask: (taskData) => apiFetch('/api/automation/tasks', {
      method: 'POST',
      body: JSON.stringify(taskData)
    }),
    runTask: (taskId) => apiFetch(`/api/automation/tasks/${taskId}/run`, {
      method: 'PUT'
    })
  },

  // Notifications
  notifications: {
    list: () => apiFetch('/api/notifications'),
    create: (notificationData) => apiFetch('/api/notifications', {
      method: 'POST',
      body: JSON.stringify(notificationData)
    }),
    markRead: (notificationId) => apiFetch(`/api/notifications/${notificationId}/read`, {
      method: 'PUT'
    })
  },

  // Logs
  logs: {
    list: () => apiFetch('/api/logs')
  },

  // Celery
  celery: {
    status: () => apiFetch('/api/celery/status')
  },

  // Redis
  redis: {
    data: () => apiFetch('/api/redis/data')
  },

  // Prometheus
  prometheus: {
    metrics: () => apiFetch('/api/prometheus/metrics')
  }
};
