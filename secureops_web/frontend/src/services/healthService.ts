import { apiRequest } from './apiClient';

export async function healthCheck() {
  return apiRequest('/health');
}
