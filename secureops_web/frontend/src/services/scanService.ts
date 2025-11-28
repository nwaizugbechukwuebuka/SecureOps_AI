import { apiRequest } from './apiClient';

export async function runScan(target: string, scanType: string) {
  return apiRequest('/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, scan_type: scanType })
  });
}
