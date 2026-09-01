// ============================================================================
// Auth module — wraps the /auth endpoints and provides route guards used at
// the top of every protected page.
// ============================================================================
import { api, clearTokens, isAuthenticated, setTokens } from "./api.js";

let cachedUser = null;

export async function login(email, password, rememberMe = false) {
  const tokens = await api.post("/auth/login", { email, password, remember_me: rememberMe });
  setTokens(tokens);
  cachedUser = null;
  return tokens;
}

export async function register({ fullName, email, password, confirmPassword }) {
  return api.post("/auth/register", {
    full_name: fullName,
    email,
    password,
    confirm_password: confirmPassword,
  });
}

export async function logout() {
  try {
    await api.post("/auth/logout");
  } catch {
    /* token may already be invalid — clear locally regardless */
  }
  clearTokens();
  cachedUser = null;
  window.location.href = "index.html";
}

export async function getCurrentUser({ force = false } = {}) {
  if (cachedUser && !force) return cachedUser;
  cachedUser = await api.get("/auth/me");
  return cachedUser;
}

export function forgotPassword(email) {
  return api.post("/auth/forgot-password", { email });
}

export function resetPassword(token, newPassword, confirmPassword) {
  return api.post("/auth/reset-password", { token, new_password: newPassword, confirm_password: confirmPassword });
}

export function verifyEmail(token) {
  return api.post("/auth/verify-email", { token });
}

export function resendVerification(email) {
  return api.post("/auth/resend-verification", { email });
}

/** Call at the top of any protected page. Redirects to login if not authenticated. */
export function requireAuth() {
  if (!isAuthenticated()) {
    window.location.href = "index.html";
    return false;
  }
  return true;
}

/** Call at the top of admin.html — redirects non-admins back to the dashboard. */
export async function requireAdmin() {
  if (!requireAuth()) return false;
  try {
    const user = await getCurrentUser();
    if (user.role !== "admin") {
      window.location.href = "dashboard.html";
      return false;
    }
    return true;
  } catch {
    window.location.href = "index.html";
    return false;
  }
}

/** Call at the top of login/register pages — bounces already-authenticated users straight to the dashboard. */
export function redirectIfAuthenticated() {
  if (isAuthenticated()) {
    window.location.href = "dashboard.html";
  }
}

export function passwordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password) && /\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password) && password.length >= 10) score++;
  if (score <= 1) return "weak";
  if (score <= 3) return "medium";
  return "strong";
}
