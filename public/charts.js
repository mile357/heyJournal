/**
 * HeyJournal — Native Theme-Aware SVG Time-Series Chart Renderer
 * Zero external charting libraries. Uses HeyJournal / Metro semantic CSS tokens
 * so charts automatically harmonize across all 20 themes (dark & light modes).
 */

import { findSeverityBand } from "./quiz-engine.js?v=4";

const RANGE_DAYS_MAP = {
  "30d": 30,
  "90d": 90,
  "1y": 365,
  all: null,
};

export function filterPointsByRange(points, rangeKey = "all", nowMs = Date.now()) {
  const sorted = [...(points || [])]
    .filter((p) => p && typeof p.value === "number" && Number.isFinite(p.value) && Number.isFinite(p.tsMs))
    .sort((a, b) => a.tsMs - b.tsMs);

  const days = RANGE_DAYS_MAP[rangeKey] ?? null;
  if (!days) return sorted;
  const cutoff = nowMs - days * 24 * 60 * 60 * 1000;
  return sorted.filter((p) => p.tsMs >= cutoff);
}

export function computeSeriesStats(points) {
  if (!Array.isArray(points) || points.length === 0) {
    return null;
  }
  const vals = points.map((p) => p.value);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
  const first = vals[0];
  const latest = vals[vals.length - 1];
  const prev = vals.length >= 2 ? vals[vals.length - 2] : latest;
  return {
    count: points.length,
    min,
    max,
    avg,
    first,
    latest,
    deltaPrev: latest - prev,
    deltaPeriod: latest - first,
  };
}

function formatNum(v) {
  if (!Number.isFinite(v)) return "—";
  if (Math.abs(v) >= 100 || Number.isInteger(v)) return String(Math.round(v * 10) / 10);
  return (Math.round(v * 100) / 100).toString();
}

function formatShortDate(tsMs) {
  const d = new Date(tsMs);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function formatFullDateTime(tsMs) {
  const d = new Date(tsMs);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function bandLevelColorVar(level) {
  switch (level) {
    case "low":
      return "var(--success-color)";
    case "mild":
      return "var(--info-color)";
    case "moderate":
      return "var(--warning-color)";
    case "high":
      return "var(--warning-color)";
    case "severe":
      return "var(--danger-color)";
    default:
      return "var(--accent)";
  }
}

function escapeXml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Renders an interactive SVG line/area chart inside `containerEl`.
 * Options:
 * - points: [{ tsMs, value, label?, bandLabel?, entryId? }] (requires >= 3 points to graph)
 * - unit: string
 * - minBound?: number (e.g. 0 for clinical quizzes)
 * - maxBound?: number (e.g. 27 for PHQ-9)
 * - severityBands?: [{ min, max, label, level }]
 * - higherIsWorse?: boolean
 * - accentColor?: string
 */
export function renderMetricChart(containerEl, options) {
  const {
    points = [],
    unit = "",
    minBound = null,
    maxBound = null,
    severityBands = null,
    accentColor = "var(--accent)",
  } = options || {};

  containerEl.innerHTML = "";

  if (points.length < 3) {
    const empty = document.createElement("div");
    empty.className = "chart-insufficient";
    empty.textContent = `Needs ${Math.max(1, 3 - points.length)} more data ${3 - points.length === 1 ? "point" : "points"} in this time range to display a trend graph.`;
    containerEl.appendChild(empty);
    return;
  }

  const width = 640;
  const height = 220;
  const pad = { top: 18, right: 18, bottom: 30, left: 46 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  const vals = points.map((p) => p.value);
  const rawMin = Math.min(...vals);
  const rawMax = Math.max(...vals);

  let yMin = typeof minBound === "number" ? Math.min(minBound, rawMin) : rawMin;
  let yMax = typeof maxBound === "number" ? Math.max(maxBound, rawMax) : rawMax;

  if (yMin === yMax) {
    const padSpan = yMin === 0 ? 1 : Math.abs(yMin) * 0.15;
    yMin -= padSpan;
    yMax += padSpan;
  } else if (typeof minBound !== "number" && typeof maxBound !== "number") {
    const span = yMax - yMin;
    yMin -= span * 0.12;
    yMax += span * 0.12;
  }

  const xMin = points[0].tsMs;
  const xMax = points[points.length - 1].tsMs;
  const xSpan = xMax - xMin;

  const mapX = (tsMs, idx) => {
    if (xSpan <= 0) {
      return pad.left + (points.length > 1 ? (idx / (points.length - 1)) * plotW : plotW / 2);
    }
    return pad.left + ((tsMs - xMin) / xSpan) * plotW;
  };

  const mapY = (val) => {
    const t = (val - yMin) / (yMax - yMin);
    return pad.top + plotH - Math.max(0, Math.min(1, t)) * plotH;
  };

  // Severity bands (if clinical quiz)
  let bandsSvg = "";
  if (Array.isArray(severityBands) && severityBands.length > 0) {
    bandsSvg = severityBands
      .map((b) => {
        const clampedMin = Math.max(yMin, b.min);
        const clampedMax = Math.min(yMax, b.max);
        if (clampedMax <= clampedMin) return "";
        const yTop = mapY(clampedMax);
        const yBot = mapY(clampedMin);
        const bandH = Math.max(1, yBot - yTop);
        const color = bandLevelColorVar(b.level);
        const showLabel = bandH >= 14;
        return `
          <rect x="${pad.left}" y="${yTop.toFixed(1)}" width="${plotW}" height="${bandH.toFixed(1)}"
                fill="${color}" fill-opacity="0.075" />
          <line x1="${pad.left}" y1="${yTop.toFixed(1)}" x2="${pad.left + plotW}" y2="${yTop.toFixed(1)}"
                stroke="${color}" stroke-opacity="0.22" stroke-dasharray="3 3" stroke-width="1" />
          ${
            showLabel
              ? `<text x="${pad.left + plotW - 4}" y="${(yTop + 11).toFixed(1)}"
                       text-anchor="end" class="chart-band-label" fill="${color}">${escapeXml(b.label)}</text>`
              : ""
          }
        `;
      })
      .join("");
  }

  // Horizontal Y grid ticks (4 ticks)
  const yTickCount = 4;
  let yGridSvg = "";
  for (let i = 0; i <= yTickCount; i++) {
    const val = yMin + ((yMax - yMin) * i) / yTickCount;
    const y = mapY(val);
    yGridSvg += `
      <line x1="${pad.left}" y1="${y.toFixed(1)}" x2="${pad.left + plotW}" y2="${y.toFixed(1)}"
            class="chart-grid-line" />
      <text x="${pad.left - 8}" y="${(y + 3.5).toFixed(1)}" text-anchor="end" class="chart-axis-label">
        ${escapeXml(formatNum(val))}
      </text>
    `;
  }

  // X-axis date ticks (up to 4 evenly spaced non-overlapping labels)
  const xTickIndices = new Set([0, points.length - 1]);
  if (points.length >= 4) {
    xTickIndices.add(Math.floor(points.length / 3));
    xTickIndices.add(Math.floor((2 * points.length) / 3));
  } else if (points.length === 3) {
    xTickIndices.add(1);
  }
  const sameDaySpan = xSpan > 0 && xSpan < 24 * 60 * 60 * 1000;
  const formatXTick = (tsMs) => {
    if (!sameDaySpan) return formatShortDate(tsMs);
    return new Date(tsMs).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  };
  let lastTickX = -Infinity;
  const xTicksSvg = Array.from(xTickIndices)
    .sort((a, b) => a - b)
    .map((idx, pos, arr) => {
      const pt = points[idx];
      const x = mapX(pt.tsMs, idx);
      const isLast = pos === arr.length - 1;
      if (!isLast && x - lastTickX < 52) return "";
      if (isLast && pos > 0 && x - lastTickX < 44) return "";
      lastTickX = x;
      const anchor = idx === 0 ? "start" : idx === points.length - 1 ? "end" : "middle";
      return `<text x="${x.toFixed(1)}" y="${height - 8}" text-anchor="${anchor}" class="chart-axis-label">${escapeXml(
        formatXTick(pt.tsMs)
      )}</text>`;
    })
    .join("");

  // Line & Area path
  const coords = points.map((pt, idx) => ({
    x: mapX(pt.tsMs, idx),
    y: mapY(pt.value),
    pt,
    idx,
  }));

  const linePath = coords
    .map((c, i) => `${i === 0 ? "M" : "L"}${c.x.toFixed(1)},${c.y.toFixed(1)}`)
    .join(" ");

  const areaPath = `${linePath} L${coords[coords.length - 1].x.toFixed(1)},${(pad.top + plotH).toFixed(
    1
  )} L${coords[0].x.toFixed(1)},${(pad.top + plotH).toFixed(1)} Z`;

  const gradId = `cg-${Math.random().toString(36).slice(2, 9)}`;
  const safeAccent = escapeXml(accentColor);
  const chartSummary = `${points.length} data points from ${formatShortDate(xMin)} to ${formatShortDate(xMax)}`;

  const pointsSvg = coords
    .map(
      (c) => `
      <circle cx="${c.x.toFixed(1)}" cy="${c.y.toFixed(1)}" r="4"
              class="chart-dot" style="--dot-accent:${safeAccent};" data-idx="${c.idx}" />
      <circle cx="${c.x.toFixed(1)}" cy="${c.y.toFixed(1)}" r="14"
              fill="transparent" class="chart-hit" data-idx="${c.idx}" tabindex="0"
              role="button" aria-label="${escapeXml(formatShortDate(c.pt.tsMs))}: ${escapeXml(formatNum(c.pt.value))} ${escapeXml(unit)}" />
    `
    )
    .join("");

  const wrap = document.createElement("div");
  wrap.className = "chart-svg-wrap";
  wrap.innerHTML = `
    <svg class="chart-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="${escapeXml(chartSummary)}">
      <defs>
        <linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="${safeAccent}" stop-opacity="0.28" />
          <stop offset="100%" stop-color="${safeAccent}" stop-opacity="0.01" />
        </linearGradient>
      </defs>
      ${bandsSvg}
      ${yGridSvg}
      <path d="${areaPath}" fill="url(#${gradId})" />
      <path d="${linePath}" fill="none" stroke="${safeAccent}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" />
      <line class="chart-crosshair" x1="0" y1="${pad.top}" x2="0" y2="${pad.top + plotH}" style="display:none;" />
      ${pointsSvg}
      ${xTicksSvg}
    </svg>
    <div class="chart-tooltip" style="display:none;"></div>
  `;

  const svg = wrap.querySelector("svg");
  const tooltip = wrap.querySelector(".chart-tooltip");
  const crosshair = wrap.querySelector(".chart-crosshair");

  const showPoint = (idx) => {
    const c = coords[idx];
    if (!c) return;
    crosshair.setAttribute("x1", c.x.toFixed(1));
    crosshair.setAttribute("x2", c.x.toFixed(1));
    crosshair.style.display = "block";

    svg.querySelectorAll(".chart-dot").forEach((d) => d.classList.remove("active"));
    const dot = svg.querySelector(`.chart-dot[data-idx="${idx}"]`);
    if (dot) dot.classList.add("active");

    const band =
      c.pt.bandLabel ||
      (Array.isArray(severityBands) ? findSeverityBand(c.pt.value, severityBands)?.label : "");
    const unitSuffix = unit === "%" ? "%" : unit ? ` ${unit}` : "";

    tooltip.innerHTML = `
      <div class="chart-tooltip-val">${escapeXml(formatNum(c.pt.value))}${escapeXml(unitSuffix)}${
        band ? ` <span class="chart-tooltip-band">· ${escapeXml(band)}</span>` : ""
      }</div>
      <div class="chart-tooltip-date">${escapeXml(formatFullDateTime(c.pt.tsMs))}</div>
    `;
    tooltip.style.display = "block";

    const pctX = (c.x / width) * 100;
    const pctY = (c.y / height) * 100;
    tooltip.style.left = `${Math.max(12, Math.min(88, pctX))}%`;
    tooltip.style.top = `${Math.max(8, pctY - 12)}%`;
  };

  const hidePoint = () => {
    crosshair.style.display = "none";
    tooltip.style.display = "none";
    svg.querySelectorAll(".chart-dot.active").forEach((d) => d.classList.remove("active"));
  };

  svg.querySelectorAll(".chart-hit").forEach((hit) => {
    const idx = Number(hit.getAttribute("data-idx"));
    hit.addEventListener("mouseenter", () => showPoint(idx));
    hit.addEventListener("focus", () => showPoint(idx));
    hit.addEventListener("click", (e) => {
      e.stopPropagation();
      showPoint(idx);
    });
  });

  wrap.addEventListener("mouseleave", hidePoint);
  wrap.addEventListener("focusout", (e) => {
    if (!wrap.contains(e.relatedTarget)) hidePoint();
  });
  containerEl.appendChild(wrap);
}
