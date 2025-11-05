// Utility to get environment variables for API URLs
export function getApiUrl() {
  return import.meta.env.VITE_API_URL || 'http://localhost:8002';
}
