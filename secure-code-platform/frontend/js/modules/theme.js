// ============================================================================
// Theme module — dark mode is the default; persists the choice and applies
// it before first paint (see the inline snippet in each page's <head>) to
// avoid a flash of the wrong theme.
// ============================================================================

const STORAGE_KEY = "scp_theme";

export function getTheme() {
  return localStorage.getItem(STORAGE_KEY) || "dark";
}

export function applyTheme(theme) {
  if (theme === "light") {
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  localStorage.setItem(STORAGE_KEY, theme);
}

export function toggleTheme() {
  const next = getTheme() === "dark" ? "light" : "dark";
  applyTheme(next);
  return next;
}

/** Wires a `.theme-toggle` button (icon swap included) — call once per page after the shell renders. */
export function initThemeToggle(buttonEl) {
  if (!buttonEl) return;
  const render = () => {
    const isDark = getTheme() === "dark";
    buttonEl.innerHTML = isDark
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>`;
    buttonEl.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
  };
  render();
  buttonEl.addEventListener("click", () => {
    toggleTheme();
    render();
  });
}
