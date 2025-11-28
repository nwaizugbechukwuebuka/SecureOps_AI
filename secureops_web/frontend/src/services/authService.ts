import { apiRequest } from './apiClient';

export async function login(username: string, password: string) {
  return apiRequest('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
}

export async function getCurrentUser() {
  return apiRequest('/me');
}
