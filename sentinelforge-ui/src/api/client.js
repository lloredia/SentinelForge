const DEFAULT_BASE = 'http://127.0.0.1:8080';

export function apiBase() {
  const configured = import.meta.env.VITE_API_BASE || DEFAULT_BASE;
  return configured.replace(/\/$/, '');
}

export function apiHeaders(extra = {}) {
  const headers = { Accept: 'application/json', ...extra };
  const key = import.meta.env.VITE_API_KEY;
  if (key) {
    headers['X-API-Key'] = key;
  }
  return headers;
}

export async function apiRequest(path, options = {}) {
  const response = await fetch(`${apiBase()}${path}`, {
    ...options,
    headers: apiHeaders(options.headers),
  });
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { error: 'unexpected response' };
    }
  }
  if (!response.ok) {
    const message =
      body && typeof body === 'object' && body.error
        ? body.error
        : `request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

export function getStats() {
  return apiRequest('/api/v1/stats');
}

export function listIndicators() {
  return apiRequest('/api/v1/indicators');
}

export function getIndicator(id) {
  return apiRequest(`/api/v1/indicators/${encodeURIComponent(id)}`);
}

export function createIndicator(payload) {
  return apiRequest('/api/v1/indicators', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}
