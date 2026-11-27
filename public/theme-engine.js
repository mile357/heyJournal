/**
 * heyJo — 20-Theme Engine & WCAG Contrast Contract
 * Directly compatible with FamilyCoordination's `public/themes/<id>/` format.
 */

export const ASSET_VERSION = "8";
export const THEME_CACHE_KEY = "heyjournal_active_theme_cache_v1";

export const METRO_ACCENTS = [
  { name: "Teal", hex: "#00ABA9" },
  { name: "Cobalt", hex: "#1BA1E2" },
  { name: "Crimson", hex: "#A20025" },
  { name: "Lime", hex: "#60A917" },
  { name: "Orange", hex: "#FA6800" },
  { name: "Magenta", hex: "#D80073" },
  { name: "Violet", hex: "#6A00FF" },
  { name: "Amber", hex: "#F0A30A" },
];

export const FALLBACK_THEMES = [
  {
    id: "metro",
    name: "Metro",
    description: "Classic Windows Phone 8 / Metro typography with sharp edges and pitch-black OLED dark mode.",
    order: 1,
    modes: ["dark", "light"],
    defaultMode: "dark",
    defaultAccent: "#00ABA9",
    accents: METRO_ACCENTS,
    metaThemeColor: { dark: "#000000", light: "#FFFFFF" },
    preview: {
      dark: { canvas: "#000000", tile: "#111111", accent: "#00ABA9" },
      light: { canvas: "#FFFFFF", tile: "#F3F3F3", accent: "#00ABA9" },
    },
    stylesheetUrl: "/themes/metro/theme.css",
  },
];

export const ThemeRegistry = new Map();

export function sanitizeColor(val, fallback = "#00ABA9") {
  const str = String(val || "").trim();
  return /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(str) ? str : fallback;
}

export function parseHexColor(hexColor, fallback = "#00ABA9") {
  const clean = sanitizeColor(hexColor, fallback).slice(1);
  const full =
    clean.length === 3
      ? clean
          .split("")
          .map((c) => c + c)
          .join("")
      : clean;
  const r = parseInt(full.slice(0, 2), 16);
  const g = parseInt(full.slice(2, 4), 16);
  const b = parseInt(full.slice(4, 6), 16);
  return { r, g, b, hex: `#${full.toUpperCase()}` };
}

export function parseCssColorToHex(rawColor, fallback = "#000000") {
  const str = String(rawColor || "").trim();
  if (/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(str)) {
    return parseHexColor(str, fallback).hex;
  }
  const match = str.match(/^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)/i);
  if (match) {
    const toHex = (n) =>
      Math.max(0, Math.min(255, Math.round(Number(n))))
        .toString(16)
        .padStart(2, "0");
    return `#${toHex(match[1])}${toHex(match[2])}${toHex(match[3])}`.toUpperCase();
  }
  return parseHexColor(fallback, "#000000").hex;
}

function relativeLuminance(hexColor) {
  const { r, g, b } = parseHexColor(hexColor, "#00ABA9");
  const toLin = (c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * toLin(r) + 0.7152 * toLin(g) + 0.0722 * toLin(b);
}

export function contrastRatio(hexA, hexB) {
  const lumA = relativeLuminance(hexA);
  const lumB = relativeLuminance(hexB);
  const lighter = Math.max(lumA, lumB);
  const darker = Math.min(lumA, lumB);
  return (lighter + 0.05) / (darker + 0.05);
}

function mixHexColors(hexA, hexB, amount) {
  const a = parseHexColor(hexA, "#000000");
  const b = parseHexColor(hexB, "#FFFFFF");
  const t = Math.max(0, Math.min(1, Number(amount) || 0));
  const ch = (x, y) => Math.round(x + (y - x) * t).toString(16).padStart(2, "0");
  return `#${ch(a.r, b.r)}${ch(a.g, b.g)}${ch(a.b, b.b)}`.toUpperCase();
}

export function getContrastColor(hexColor) {
  const { r, g, b, hex } = parseHexColor(hexColor, "#00ABA9");
  const yiq = (r * 299 + g * 587 + b * 114) / 1000;
  const whiteContrast = contrastRatio(hex, "#FFFFFF");
  return whiteContrast >= 2.8 && yiq < 155 ? "#FFFFFF" : "#000000";
}

export function ensureReadableOnSurface(fgHex, bgHex, minRatio = 4.5) {
  const fg = parseHexColor(fgHex, "#00ABA9").hex;
  const bg = parseHexColor(bgHex, "#000000").hex;
  if (contrastRatio(fg, bg) >= minRatio) return fg;
  const target = contrastRatio("#FFFFFF", bg) >= contrastRatio("#000000", bg) ? "#FFFFFF" : "#000000";
  let low = 0;
  let high = 1;
  let best = target;
  for (let i = 0; i < 12; i++) {
    const mid = (low + high) / 2;
    const candidate = mixHexColors(fg, target, mid);
    if (contrastRatio(candidate, bg) >= minRatio) {
      best = candidate;
      high = mid;
    } else {
      low = mid;
    }
  }
  return best;
}

export async function discoverAndLoadThemes() {
  let themes = null;
  try {
    const res = await fetch("/api/themes", { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data && Array.isArray(data.themes) && data.themes.length > 0) {
        themes = data.themes;
      }
    }
  } catch (e) {
    // Offline fallback
  }
  if (!themes) themes = FALLBACK_THEMES;
  ThemeRegistry.clear();
  for (const def of themes) {
    if (def && def.id) ThemeRegistry.set(def.id, def);
  }
  if (!ThemeRegistry.has("metro")) {
    ThemeRegistry.set("metro", FALLBACK_THEMES[0]);
  }
  return Array.from(ThemeRegistry.values());
}

export function getActiveThemeDef(settings) {
  const id = (settings && settings.themeId) || "metro";
  return ThemeRegistry.get(id) || ThemeRegistry.get("metro") || FALLBACK_THEMES[0];
}

export function getEffectiveThemeMode(settings, themeDef = getActiveThemeDef(settings)) {
  const allowed = Array.isArray(themeDef.modes) && themeDef.modes.length > 0 ? themeDef.modes : ["dark", "light"];
  const current = settings && settings.theme;
  if (allowed.includes(current)) return current;
  return themeDef.defaultMode && allowed.includes(themeDef.defaultMode) ? themeDef.defaultMode : allowed[0];
}

export function getThemeAccents(themeDef) {
  return Array.isArray(themeDef.accents) && themeDef.accents.length > 0 ? themeDef.accents : METRO_ACCENTS;
}

export function getEffectiveThemeAccent(settings, themeDef = getActiveThemeDef(settings)) {
  const raw = settings && settings.accentColor;
  return sanitizeColor(raw, sanitizeColor(themeDef.defaultAccent, "#00ABA9"));
}

function getEffectiveSurfaceHex(themeDef, mode) {
  const previewSurface =
    (themeDef.preview && themeDef.preview[mode] && (themeDef.preview[mode].tile || themeDef.preview[mode].canvas)) ||
    null;
  const activeLink = document.getElementById("activeThemeStylesheet");
  const expectedPrefix = themeDef.stylesheetUrl || "";
  const linkMatches =
    !expectedPrefix ||
    (activeLink && String(activeLink.getAttribute("href") || "").startsWith(expectedPrefix));
  if (linkMatches && typeof getComputedStyle === "function") {
    const cs = getComputedStyle(document.documentElement);
    const tileVar = cs.getPropertyValue("--bg-tile").trim() || cs.getPropertyValue("--bg-canvas").trim();
    if (tileVar && !tileVar.startsWith("color-mix")) {
      return parseCssColorToHex(tileVar, previewSurface || (mode === "light" ? "#FFFFFF" : "#000000"));
    }
  }
  return sanitizeColor(previewSurface, mode === "light" ? "#FFFFFF" : "#000000");
}

export function updateAccentContrastTokens(settings) {
  const themeDef = getActiveThemeDef(settings);
  const mode = getEffectiveThemeMode(settings, themeDef);
  const accentHex = getEffectiveThemeAccent(settings, themeDef);
  const surfaceHex = getEffectiveSurfaceHex(themeDef, mode);
  document.documentElement.style.setProperty("--accent-text", ensureReadableOnSurface(accentHex, surfaceHex));
  document.documentElement.style.setProperty("--slot-accent", accentHex);
  document.documentElement.style.setProperty("--slot-accent-fg", getContrastColor(accentHex));
  document.documentElement.style.setProperty("--slot-accent-text", ensureReadableOnSurface(accentHex, surfaceHex));
}

export function applyThemeAndAccent(settings) {
  const themeDef = getActiveThemeDef(settings);
  const mode = getEffectiveThemeMode(settings, themeDef);
  const accentHex = getEffectiveThemeAccent(settings, themeDef);
  const surfaceHex = getEffectiveSurfaceHex(themeDef, mode);

  document.documentElement.setAttribute("data-theme-id", themeDef.id);
  document.documentElement.setAttribute("data-theme", mode);
  document.documentElement.style.setProperty("--accent", accentHex);
  document.documentElement.style.setProperty("--accent-fg", getContrastColor(accentHex));
  document.documentElement.style.setProperty("--accent-text", ensureReadableOnSurface(accentHex, surfaceHex));
  document.documentElement.style.setProperty("--slot-accent", accentHex);
  document.documentElement.style.setProperty("--slot-accent-fg", getContrastColor(accentHex));
  document.documentElement.style.setProperty("--slot-accent-text", ensureReadableOnSurface(accentHex, surfaceHex));

  const targetHref = themeDef.stylesheetUrl ? `${themeDef.stylesheetUrl}?v=${ASSET_VERSION}` : "";
  let link = document.getElementById("activeThemeStylesheet");
  if (
    targetHref &&
    /^\/themes\/[a-zA-Z0-9._\/-]+\.css\?v=/.test(targetHref) &&
    !targetHref.includes("..")
  ) {
    if (!link) {
      link = document.createElement("link");
      link.id = "activeThemeStylesheet";
      link.rel = "stylesheet";
      document.head.appendChild(link);
    }
    if (link.getAttribute("href") !== targetHref) {
      link.onload = () => updateAccentContrastTokens(settings);
      link.setAttribute("href", targetHref);
    }
  } else if (link) {
    link.remove();
  }

  const metaColor =
    (themeDef.metaThemeColor && themeDef.metaThemeColor[mode]) ||
    (mode === "light" ? "#FFFFFF" : "#000000");
  const metaTheme = document.querySelector('meta[name="theme-color"]');
  if (metaTheme) metaTheme.setAttribute("content", metaColor);

  try {
    localStorage.setItem(
      THEME_CACHE_KEY,
      JSON.stringify({
        themeId: themeDef.id,
        mode,
        accent: accentHex,
        stylesheetUrl: themeDef.stylesheetUrl || "",
        metaColor,
      })
    );
  } catch (e) {}
}
