// ============================================================================
// Shared formatting / DOM utility helpers used across pages.
// ============================================================================

export function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function formatDate(isoString, { withTime = true } = {}) {
  if (!isoString) return "—";
  const d = new Date(isoString.endsWith("Z") || isoString.includes("+") ? isoString : isoString + "Z");
  const dateStr = d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  if (!withTime) return dateStr;
  const timeStr = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return `${dateStr}, ${timeStr}`;
}

export function timeAgo(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString.endsWith("Z") || isoString.includes("+") ? isoString : isoString + "Z");
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  const steps = [
    [60, "second"], [60, "minute"], [24, "hour"], [7, "day"], [4.345, "week"], [12, "month"], [Infinity, "year"],
  ];
  let value = seconds;
  let unit = "second";
  for (const [factor, name] of steps) {
    if (value < factor) { unit = name; break; }
    value = Math.floor(value / factor);
    unit = name;
  }
  if (value <= 0) return "just now";
  return `${value} ${unit}${value !== 1 ? "s" : ""} ago`;
}

export function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function debounce(fn, delay = 300) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

export function qs(name, fallback = null) {
  return new URLSearchParams(window.location.search).get(name) ?? fallback;
}

export function setQs(params) {
  const url = new URL(window.location.href);
  Object.entries(params).forEach(([k, v]) => {
    if (v === null || v === undefined || v === "") url.searchParams.delete(k);
    else url.searchParams.set(k, v);
  });
  window.history.replaceState({}, "", url);
}

export function initials(name) {
  if (!name) return "?";
  const parts = name.trim().split(/\s+/);
  return ((parts[0]?.[0] || "") + (parts[1]?.[0] || "")).toUpperCase();
}

export const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export function severityWeight(sev) {
  const idx = SEVERITY_ORDER.indexOf(sev);
  return idx === -1 ? 99 : idx;
}

/** Renders a tiny inline spinner + label, used inside buttons during async actions. */
export function setButtonLoading(buttonEl, isLoading, loadingLabel = "Please wait…") {
  if (isLoading) {
    buttonEl.dataset.originalContent = buttonEl.innerHTML;
    buttonEl.innerHTML = `<span class="spinner"></span> ${escapeHtml(loadingLabel)}`;
    buttonEl.disabled = true;
  } else {
    if (buttonEl.dataset.originalContent) buttonEl.innerHTML = buttonEl.dataset.originalContent;
    buttonEl.disabled = false;
  }
}

export function copyToClipboard(text) {
  return navigator.clipboard?.writeText(text) ?? Promise.reject(new Error("Clipboard API unavailable"));
}
