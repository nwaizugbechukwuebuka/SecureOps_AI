// Authentication utility for SecureOps AI
import { apiFetch } from './api';

export function getAuthToken() {
  return localStorage.getItem('auth_token');
}

export function setAuthToken(token) {
  localStorage.setItem('auth_token', token);
}

export function clearAuthToken() {
  localStorage.removeItem('auth_token');
}

export function isAuthenticated() {
  return !!getAuthToken();
}

export async function login(username, password) {
  try {
    const response = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    
    setAuthToken(response.access_token);
    return response;
  } catch (error) {
    throw new Error('Login failed: ' + error.message);
  }
}

export async function logout() {
  clearAuthToken();
  // Optional: call logout endpoint if backend supports it
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch (error) {
    // Ignore logout endpoint errors
  }
}

export async function getCurrentUser() {
  if (!isAuthenticated()) {
    throw new Error('Not authenticated');
  }
  
  try {
    return await apiFetch('/api/auth/me', {
      headers: {
        'Authorization': `Bearer ${getAuthToken()}`
      }
    });
  } catch (error) {
    clearAuthToken(); // Clear invalid token
    throw error;
  }
}
