// ============================================================================
// Lightweight SVG chart renderers — no charting library, per the vanilla-JS
// constraint. Each function returns an SVG string ready to drop into
// `el.innerHTML`. Charts read CSS custom properties via a `getComputedStyle`
// lookup so they automatically match the active theme.
// ============================================================================

function cssVar(name, fallback) {
  const val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return val || fallback;
}

const SEVERITY_COLOR_VAR = { critical: "--sev-critical", high: "--sev-high", medium: "--sev-medium", low: "--sev-low" };

/** Donut chart — used for severity distribution and secure/vulnerable split. */
export function donutChart(data, { size = 160, thickness = 22, centerLabel = "", centerSub = "" } = {}) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const cx = size / 2;
  const cy = size / 2;

  let offset = 0;
  const segments = data
    .filter((d) => d.value > 0)
    .map((d) => {
      const fraction = total > 0 ? d.value / total : 0;
      const dash = fraction * circumference;
      const seg = `<circle cx="${cx}" cy="${cy}" r="${radius}" fill="none" stroke="${d.color}"
        stroke-width="${thickness}" stroke-dasharray="${dash} ${circumference - dash}"
        stroke-dashoffset="${-offset}" stroke-linecap="butt" transform="rotate(-90 ${cx} ${cy})">
        <title>${d.label}: ${d.value}</title>
      </circle>`;
      offset += dash;
      return seg;
    })
    .join("");

  const emptyRing = total === 0
    ? `<circle cx="${cx}" cy="${cy}" r="${radius}" fill="none" stroke="${cssVar("--border-hairline", "#1e2733")}" stroke-width="${thickness}"/>`
    : "";

  return `
    <svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="${centerLabel} ${centerSub}">
      ${emptyRing}${segments}
      <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-family="${cssVar("--font-display", "sans-serif")}"
        font-size="${size * 0.16}" font-weight="700" fill="${cssVar("--text-primary", "#fff")}">${centerLabel}</text>
      <text x="${cx}" y="${cy + 16}" text-anchor="middle" font-family="${cssVar("--font-body", "sans-serif")}"
        font-size="${size * 0.07}" fill="${cssVar("--text-muted", "#888")}">${centerSub}</text>
    </svg>`;
}

export function severityDonut(breakdown, { size = 160 } = {}) {
  const data = Object.entries(breakdown).map(([severity, value]) => ({
    label: severity,
    value,
    color: cssVar(SEVERITY_COLOR_VAR[severity] || "--text-muted", "#888"),
  }));
  const total = Object.values(breakdown).reduce((a, b) => a + b, 0);
  return donutChart(data, { size, centerLabel: String(total), centerSub: "findings" });
}

/** Vertical bar chart — used for the scans trend and engine usage. */
export function barChart(series, { width = 560, height = 200, barColor, valueKey = "total", labelKey = "date" } = {}) {
  const color = barColor || cssVar("--accent", "#00d4b8");
  const padding = { top: 16, right: 12, bottom: 28, left: 12 };
  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;
  const max = Math.max(1, ...series.map((d) => d[valueKey]));
  const barW = innerW / series.length;
  const gap = Math.min(10, barW * 0.3);

  const bars = series
    .map((d, i) => {
      const barHeight = (d[valueKey] / max) * innerH;
      const x = padding.left + i * barW + gap / 2;
      const y = padding.top + (innerH - barHeight);
      const w = Math.max(2, barW - gap);
      const label = String(d[labelKey]).slice(5); // "MM-DD" from an ISO date
      return `
        <rect x="${x}" y="${y}" width="${w}" height="${Math.max(2, barHeight)}" rx="3" fill="${color}" opacity="0.9">
          <title>${d[labelKey]}: ${d[valueKey]}</title>
        </rect>
        <text x="${x + w / 2}" y="${height - 8}" text-anchor="middle" font-size="9"
          fill="${cssVar("--text-muted", "#888")}" font-family="${cssVar("--font-body", "sans-serif")}">${label}</text>`;
    })
    .join("");

  return `<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" preserveAspectRatio="xMidYMid meet">${bars}</svg>`;
}

/** Stacked bar chart for secure vs vulnerable trend. */
export function stackedTrendChart(series, { width = 560, height = 200 } = {}) {
  const secureColor = cssVar("--verdict-secure", "#00d4b8");
  const vulnColor = cssVar("--verdict-vulnerable", "#ff5470");
  const padding = { top: 16, right: 12, bottom: 28, left: 12 };
  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;
  const max = Math.max(1, ...series.map((d) => d.total));
  const barW = innerW / Math.max(series.length, 1);
  const gap = Math.min(10, barW * 0.3);

  const bars = series
    .map((d, i) => {
      const x = padding.left + i * barW + gap / 2;
      const w = Math.max(2, barW - gap);
      const secureH = (d.secure / max) * innerH;
      const vulnH = (d.vulnerable / max) * innerH;
      const yBase = padding.top + innerH;
      const label = String(d.date).slice(5);
      return `
        <rect x="${x}" y="${yBase - secureH}" width="${w}" height="${Math.max(0, secureH)}" fill="${secureColor}" rx="2">
          <title>${d.date} secure: ${d.secure}</title>
        </rect>
        <rect x="${x}" y="${yBase - secureH - vulnH}" width="${w}" height="${Math.max(0, vulnH)}" fill="${vulnColor}" rx="2">
          <title>${d.date} vulnerable: ${d.vulnerable}</title>
        </rect>
        <text x="${x + w / 2}" y="${height - 8}" text-anchor="middle" font-size="9"
          fill="${cssVar("--text-muted", "#888")}">${label}</text>`;
    })
    .join("");

  if (series.length === 0) {
    return `<div class="empty-state" style="padding:32px 0;"><p>No scan data yet — run your first scan to see trends here.</p></div>`;
  }

  return `<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" preserveAspectRatio="xMidYMid meet">${bars}</svg>`;
}

/** Circular gauge — used for the Security Score stat card. */
export function gaugeChart(value, { size = 120, max = 100, thickness = 12 } = {}) {
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius * 0.75; // 270° arc
  const fraction = Math.max(0, Math.min(1, value / max));
  const color = value >= 80 ? cssVar("--verdict-secure", "#00d4b8") : value >= 50 ? cssVar("--verdict-pending", "#ffb454") : cssVar("--verdict-vulnerable", "#ff5470");
  const cx = size / 2;
  const cy = size / 2;

  return `
    <svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
      <circle cx="${cx}" cy="${cy}" r="${radius}" fill="none" stroke="${cssVar("--border-hairline", "#1e2733")}"
        stroke-width="${thickness}" stroke-dasharray="${circumference} ${2 * Math.PI * radius}"
        stroke-linecap="round" transform="rotate(135 ${cx} ${cy})"/>
      <circle cx="${cx}" cy="${cy}" r="${radius}" fill="none" stroke="${color}"
        stroke-width="${thickness}" stroke-dasharray="${circumference * fraction} ${2 * Math.PI * radius}"
        stroke-linecap="round" transform="rotate(135 ${cx} ${cy})"/>
      <text x="${cx}" y="${cy + 8}" text-anchor="middle" font-family="${cssVar("--font-display", "sans-serif")}"
        font-size="${size * 0.22}" font-weight="700" fill="${cssVar("--text-primary", "#fff")}">${Math.round(value)}</text>
    </svg>`;
}
