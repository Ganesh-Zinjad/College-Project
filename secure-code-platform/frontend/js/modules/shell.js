// ============================================================================
// App shell — renders the sidebar + topbar into a page's `#app-shell-root`
// and wires up theme toggle, mobile nav, user menu, and logout. Every
// protected page calls `renderShell({ active: 'dashboard', breadcrumb: [...] })`
// once on load instead of hand-writing the same nav markup eight times.
// ============================================================================
import { getCurrentUser, logout } from "./auth.js";
import { initThemeToggle } from "./theme.js";
import { initials } from "./utils.js";

const NAV_SECTIONS = [
  {
    title: "Overview",
    items: [
      { id: "dashboard", href: "dashboard.html", label: "Dashboard", icon: "grid" },
    ],
  },
  {
    title: "Scanning",
    items: [
      { id: "upload", href: "upload.html", label: "New Scan", icon: "upload" },
      { id: "scan-progress", href: "scan-progress.html", label: "Scan Progress", icon: "activity", hidden: true },
      { id: "results", href: "results.html", label: "Results", icon: "shield-check", hidden: true },
      { id: "history", href: "history.html", label: "History", icon: "clock" },
    ],
  },
  {
    title: "Account",
    items: [
      { id: "profile", href: "profile.html", label: "Profile", icon: "user" },
    ],
  },
];

const ADMIN_SECTION = {
  title: "Administration",
  items: [{ id: "admin", href: "admin.html", label: "Admin Panel", icon: "settings-shield" }],
};

const ICONS = {
  grid: `<path d="M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z"/>`,
  upload: `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>`,
  activity: `<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>`,
  "shield-check": `<path d="M12 2 4 5v6c0 5.5 3.8 9.7 8 11 4.2-1.3 8-5.5 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/>`,
  clock: `<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>`,
  user: `<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>`,
  "settings-shield": `<path d="M12 2 4 5v6c0 5.5 3.8 9.7 8 11 4.2-1.3 8-5.5 8-11V5l-8-3Z"/><circle cx="12" cy="11" r="2.5"/>`,
  menu: `<path d="M3 12h18M3 6h18M3 18h18"/>`,
  search: `<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>`,
  "chevron-down": `<path d="m6 9 6 6 6-6"/>`,
  "log-out": `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>`,
  bell: `<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>`,
};

function icon(name, size = 18) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ""}</svg>`;
}

function brandSvg() {
  // The "Triple Judge" mark: three small hexagonal seals orbiting a central shield.
  return `<svg width="34" height="34" viewBox="0 0 34 34" fill="none" class="brand-mark">
    <path d="M17 3 27 8v9c0 8-6.5 12.5-10 14-3.5-1.5-10-6-10-14V8l10-5Z" fill="var(--accent-dim)" stroke="var(--accent)" stroke-width="1.6"/>
    <circle cx="17" cy="14" r="3" fill="var(--accent)"/>
    <circle cx="11" cy="20" r="2" fill="var(--engine-codeql)"/>
    <circle cx="23" cy="20" r="2" fill="var(--engine-ml)"/>
  </svg>`;
}

export async function renderShell({ active, breadcrumb = [] }) {
  const root = document.getElementById("app-shell-root");
  if (!root) return null;

  let user;
  try {
    user = await getCurrentUser();
  } catch {
    window.location.href = "index.html";
    return null;
  }

  const sections = [...NAV_SECTIONS];
  if (user.role === "admin") sections.push(ADMIN_SECTION);

  const navHtml = sections
    .map(
      (section) => `
      <div class="nav-section">
        <div class="nav-section-title">${section.title}</div>
        ${section.items
          .filter((item) => !item.hidden || item.id === active)
          .map(
            (item) => `
            <a class="nav-item ${item.id === active ? "active" : ""}" href="${item.href}">
              ${icon(item.icon)}<span class="nav-label">${item.label}</span>
            </a>`
          )
          .join("")}
      </div>`
    )
    .join("");

  const crumbHtml = breadcrumb
    .map(
      (c, i) =>
        `${i > 0 ? '<span class="crumb-sep">/</span>' : ""}${
          i === breadcrumb.length - 1
            ? `<span class="crumb-current">${c.label}</span>`
            : `<a href="${c.href}">${c.label}</a>`
        }`
    )
    .join("");

  root.innerHTML = `
    <div class="sidebar-scrim"></div>
    <aside class="sidebar">
      <div class="sidebar-brand">
        ${brandSvg()}
        <div class="brand-text">SecureCode<small>TRIPLE JUDGE ENGINE</small></div>
      </div>
      <nav>${navHtml}</nav>
      <div class="sidebar-footer">
        <button class="nav-item" id="shell-logout-btn" style="width:100%;">
          ${icon("log-out")}<span class="nav-label">Log out</span>
        </button>
      </div>
    </aside>
    <div class="shell-main">
      <header class="topbar">
        <div class="topbar-left">
          <button class="mobile-menu-btn btn btn-icon btn-ghost" id="mobile-menu-btn">${icon("menu")}</button>
          <div class="breadcrumbs">${crumbHtml}</div>
        </div>
        <div class="topbar-right">
          <label class="search-box" style="display:none;" id="global-search-box">
            ${icon("search", 16)}
            <input type="search" placeholder="Search scans, vulnerabilities…" id="global-search-input" />
          </label>
          <button class="theme-toggle" id="theme-toggle-btn"></button>
          <div style="position:relative;">
            <button class="flex items-center gap-2" id="user-menu-btn" style="padding:4px 8px 4px 4px; border-radius:var(--radius-pill); border:1px solid var(--border-hairline);">
              <span class="avatar" style="background:${user.avatar_color};width:30px;height:30px;font-size:12px;">${initials(user.full_name)}</span>
              ${icon("chevron-down", 14)}
            </button>
            <div id="user-menu-dropdown" class="card" style="display:none; position:absolute; right:0; top:calc(100% + 8px); width:220px; padding:8px; z-index:40;">
              <div style="padding:8px 10px;">
                <div style="font-weight:600; font-size:var(--fs-sm);">${user.full_name}</div>
                <div style="font-size:var(--fs-xs); color:var(--text-muted);">${user.email}</div>
              </div>
              <hr class="divider" style="margin:4px 0;">
              <a href="profile.html" class="nav-item" style="padding:8px 10px;">${icon("user", 16)} Profile</a>
              <button class="nav-item" id="user-menu-logout" style="width:100%; padding:8px 10px;">${icon("log-out", 16)} Log out</button>
            </div>
          </div>
        </div>
      </header>
      <main class="content" id="page-content"></main>
    </div>`;

  initThemeToggle(document.getElementById("theme-toggle-btn"));

  document.getElementById("shell-logout-btn").addEventListener("click", logout);
  document.getElementById("user-menu-logout").addEventListener("click", logout);

  const menuBtn = document.getElementById("user-menu-btn");
  const dropdown = document.getElementById("user-menu-dropdown");
  menuBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    dropdown.style.display = dropdown.style.display === "none" ? "block" : "none";
  });
  document.addEventListener("click", () => (dropdown.style.display = "none"));

  const appShell = document.querySelector(".app-shell");
  document.getElementById("mobile-menu-btn")?.addEventListener("click", () => {
    appShell.classList.toggle("sidebar-open");
  });
  document.querySelector(".sidebar-scrim")?.addEventListener("click", () => {
    appShell.classList.remove("sidebar-open");
  });

  return user;
}
