// ============================================================================
// Toast notifications. Call `toast.success("Saved")` etc. from any page.
// Lazily creates a single `.toast-stack` container on first use.
// ============================================================================

const ICONS = {
  success: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6 9 17l-5-5"/></svg>`,
  error: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>`,
  warning: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><path d="M12 9v4M12 17h.01"/></svg>`,
  info: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>`,
};

const COLORS = { success: "var(--verdict-secure)", error: "var(--verdict-vulnerable)", warning: "var(--verdict-pending)", info: "var(--accent)" };

function getStack() {
  let stack = document.querySelector(".toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.className = "toast-stack";
    stack.setAttribute("role", "status");
    stack.setAttribute("aria-live", "polite");
    document.body.appendChild(stack);
  }
  return stack;
}

function show(type, title, message = "", duration = 4500) {
  const stack = getStack();
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `
    <span class="toast-icon" style="color:${COLORS[type]}">${ICONS[type]}</span>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      ${message ? `<div class="toast-message">${message}</div>` : ""}
    </div>
    <button class="toast-close" aria-label="Dismiss">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
    </button>`;

  const dismiss = () => {
    el.classList.add("closing");
    setTimeout(() => el.remove(), 150);
  };
  el.querySelector(".toast-close").addEventListener("click", dismiss);

  stack.appendChild(el);
  if (duration > 0) setTimeout(dismiss, duration);
  return el;
}

export const toast = {
  success: (title, message) => show("success", title, message),
  error: (title, message) => show("error", title, message),
  warning: (title, message) => show("warning", title, message),
  info: (title, message) => show("info", title, message),
};
