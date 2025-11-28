export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function apiRequest<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${endpoint}`, options);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
