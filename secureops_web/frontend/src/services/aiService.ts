import { apiRequest } from './apiClient';

export async function analyzeAI(data: string) {
  return apiRequest('/ai/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data })
  });
}
