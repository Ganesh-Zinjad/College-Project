// ============================================================================
// API client — every network call in the app goes through `apiRequest()`.
// Centralizes the base URL, auth header, JSON parsing, and the 401 ->
// refresh-token -> retry-once flow so individual pages never touch fetch()
// directly or duplicate that logic.
// ============================================================================

export const API_BASE = (() => {
  // Allows the same static frontend to point at a different backend without
  // a rebuild: set window.__API_BASE__ before this module loads, or fall
  // back to same-origin /api/v1 in production, or localhost in dev.
  if (window.__API_BASE__) return window.__API_BASE__;
  if (location.port === "5500" || location.port === "5501" || location.protocol === "file:") {
    return "http://127.0.0.1:8000/api/v1";
  }
  return "/api/v1";
})();

const ACCESS_TOKEN_KEY = "scp_access_token";
const REFRESH_TOKEN_KEY = "scp_refresh_token";

export class ApiError extends Error {
  constructor(message, status, type) {
    super(message);
    this.status = status;
    this.type = type;
  }
}

export function getAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens({ access_token, refresh_token }) {
  if (access_token) localStorage.setItem(ACCESS_TOKEN_KEY, access_token);
  if (refresh_token) localStorage.setItem(REFRESH_TOKEN_KEY, refresh_token);
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

export function isAuthenticated() {
  return Boolean(getAccessToken());
}

let refreshPromise = null;

async function refreshAccessToken() {
  if (refreshPromise) return refreshPromise; // de-dupe concurrent refreshes

  refreshPromise = (async () => {
    const refreshToken = getRefreshToken();
    if (!refreshToken) throw new ApiError("No refresh token", 401, "NoRefreshToken");

    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) throw new ApiError("Session expired", 401, "RefreshFailed");
    const data = await res.json();
    setTokens(data);
    return data.access_token;
  })();

  try {
    return await refreshPromise;
  } finally {
    refreshPromise = null;
  }
}

/**
 * @param {string} path - e.g. "/auth/login" (relative to API_BASE)
 * @param {object} options - { method, body, isForm, skipAuth, retry }
 */
export async function apiRequest(path, options = {}) {
  const { method = "GET", body, isForm = false, skipAuth = false, _isRetry = false } = options;

  const headers = {};
  if (!isForm && body !== undefined) headers["Content-Type"] = "application/json";
  if (!skipAuth) {
    const token = getAccessToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
    });
  } catch (networkErr) {
    throw new ApiError("Could not reach the server. Check your connection.", 0, "NetworkError");
  }

  if (res.status === 401 && !skipAuth && !_isRetry && getRefreshToken()) {
    try {
      await refreshAccessToken();
      return apiRequest(path, { ...options, _isRetry: true });
    } catch {
      clearTokens();
      if (!location.pathname.endsWith("index.html") && location.pathname !== "/") {
        window.location.href = "index.html?session_expired=1";
      }
      throw new ApiError("Your session has expired. Please sign in again.", 401, "SessionExpired");
    }
  }

  if (res.status === 204) return null;

  let payload = null;
  const text = await res.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!res.ok) {
    const message = payload?.error?.message || payload?.detail?.[0]?.msg || payload?.detail || "Something went wrong";
    throw new ApiError(message, res.status, payload?.error?.type || "ApiError");
  }

  return payload;
}

export const api = {
  get: (path) => apiRequest(path),
  post: (path, body) => apiRequest(path, { method: "POST", body }),
  put: (path, body) => apiRequest(path, { method: "PUT", body }),
  patch: (path, body) => apiRequest(path, { method: "PATCH", body }),
  delete: (path) => apiRequest(path, { method: "DELETE" }),
  postForm: (path, formData) => apiRequest(path, { method: "POST", body: formData, isForm: true }),
};

/** Builds an absolute download URL (for <a href> export links / report downloads) including the bearer token as a fetch-then-blob flow. */
export async function downloadFile(path, suggestedFilename) {
  const token = getAccessToken();
  const res = await fetch(`${API_BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new ApiError("Download failed", res.status, "DownloadFailed");

  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : suggestedFilename;

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
