/**
 * HeyJournal — Zero-Knowledge Encrypted Journal & Clinical Metric Tracker
 * Native ES Modules, zero external dependencies, 20-theme Family Hub parity.
 */

import {
  DEFAULT_KDF_ITERATIONS,
  RECOVERY_KDF_ITERATIONS,
  base64ToBytes,
  bytesToBase64,
  decryptJson,
  deriveAuthAndKek,
  encryptJson,
  generateDek,
  generateRecoveryKey,
  generateSaltB64,
  getCryptoBackendLabel,
  isNativeWebCryptoAvailable,
  normalizeRecoveryKey,
  unwrapDek,
  wrapDek,
} from "./crypto.js?v=4";

import { findSeverityBand, formatScoreValue, getQuestionOptions, scoreQuiz } from "./quiz-engine.js?v=4";
import { computeSeriesStats, filterPointsByRange, renderMetricChart } from "./charts.js?v=4";
import {
  ASSET_VERSION,
  ThemeRegistry,
  applyThemeAndAccent,
  discoverAndLoadThemes,
  getActiveThemeDef,
  getEffectiveThemeAccent,
  getEffectiveThemeMode,
  getThemeAccents,
  sanitizeColor,
} from "./theme-engine.js?v=4";
import {
  downloadDecryptedCsv,
  downloadDecryptedJson,
  openPrintableClinicianSummary,
  openPrintableRecoverySheet,
} from "./export.js?v=4";

const SESSION_DEK_KEY = "heyjournal_session_dek_v1";
const STAY_UNLOCKED_PREF_KEY = "heyjournal_stay_unlocked_pref_v1";

const DEFAULT_VAULT_META = {
  settings: {
    journalName: "heyjournal",
    themeId: "metro",
    theme: "dark",
    accentColor: "#00ABA9",
    themeAccents: {},
    autoLockMinutes: 60, // 0 = off; 15 / 30 / 60 minutes
  },
  metrics: [], // [{ id, kind: "number", name, unit, pinned, createdAt }]
  pinnedQuizIds: [], // ["phq-9", "gad-7"]
};

const QUICK_METRIC_SUGGESTIONS = [
  { name: "Weight", unit: "lbs" },
  { name: "Sleep", unit: "hrs" },
  { name: "Energy", unit: "1-10" },
  { name: "Mood", unit: "1-10" },
  { name: "Steps", unit: "steps" },
];

// ============================================================================
// APPLICATION STATE
// ============================================================================
const state = {
  authStatus: { authenticated: false, userCount: 0, allowSignups: true, user: null },
  dekBytes: null, // In-memory 32-byte AES-256 vault key (NEVER sent to server)
  stayUnlocked: false,
  vaultMeta: structuredCloneSafe(DEFAULT_VAULT_META),
  lastSyncedVaultMeta: structuredCloneSafe(DEFAULT_VAULT_META),
  vaultMetaUpdatedAt: "",
  entries: [], // [{ id, createdAt, updatedAt, data: { timestamp, text, numericMetrics, quizResults } }]
  quizzes: [], // Auto-discovered from GET /api/quizzes
  quizById: new Map(),

  // UI state
  activeTab: "input",
  authMode: "login", // "login" | "register" | "unlock" | "recover"
  authUsernameDraft: "",
  authError: "",
  autoLockReason: "",
  authBusy: false,
  savingEntry: false,
  syncingVault: false,
  lastVaultSyncMs: 0,
  lastActivityMs: Date.now(),

  // Input draft state (preserved across tab switches)
  draft: createFreshDraft(),

  // Metrics tab UI
  quizCategoryFilter: "All",
  quizSearch: "",
  editingMetricId: null,

  // Review tab UI
  reviewSearch: "",
  reviewMetricFilter: "all",
  openEntryMenuId: null,

  // Report tab UI
  reportRange: "90d",
  activeSubscaleByQuiz: {},

  // Flyout & Modal UI
  flyoutOpen: false,
  flyoutTab: "appearance",
  adminData: null,
  adminLoadError: "",
  modalState: null, // { type: "quiz-runner" | "quiz-breakdown", ... }
};

function structuredCloneSafe(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function createFreshDraft() {
  return {
    editingEntryId: null,
    editingUpdatedAt: "",
    conflictNotice: "",
    timestampLocal: toLocalDateTimeInputValue(new Date()),
    timestampManuallyEdited: false,
    showTimestampEditor: false,
    text: "",
    numericValues: {}, // { [metricId]: string }
    extraNumerics: [], // [{ metricId, name, unit, value }] for unpinned or ad-hoc metrics
    quizResults: [], // array of scoreQuiz() outputs attached to this entry
    showPicker: false,
  };
}

function hasUnsavedDraft(d = state.draft) {
  if (!d) return false;
  if ((d.text || "").trim().length > 0) return true;
  if (d.extraNumerics && d.extraNumerics.length > 0) return true;
  if (d.quizResults && d.quizResults.length > 0) return true;
  return Object.values(d.numericValues || {}).some((v) => String(v ?? "").trim() !== "");
}

function safeExternalUrl(rawUrl) {
  const s = String(rawUrl || "").trim();
  return /^https?:\/\/\S+$/i.test(s) ? s : "";
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function generateClientId(prefix = "id") {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `${prefix}-${crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function toLocalDateTimeInputValue(date) {
  const d = date instanceof Date && !Number.isNaN(date.getTime()) ? date : new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function parseLocalDateTimeToIso(localStr) {
  const d = new Date(localStr);
  if (Number.isNaN(d.getTime())) return new Date().toISOString();
  return d.toISOString();
}

function localDateKeyFromIso(isoStr) {
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return "unknown";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function formatDayHeading(dateKey) {
  const parts = dateKey.split("-").map(Number);
  if (parts.length !== 3) return { label: dateKey, relative: "" };
  const d = new Date(parts[0], parts[1] - 1, parts[2]);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const diffDays = Math.round((today - d) / 86400000);
  let relative = "";
  if (diffDays === 0) relative = "today";
  else if (diffDays === 1) relative = "yesterday";
  else if (diffDays > 1 && diffDays < 7) relative = `${diffDays} days ago`;

  const label = d.toLocaleDateString(undefined, {
    weekday: "long",
    month: "short",
    day: "numeric",
    year: d.getFullYear() !== now.getFullYear() ? "numeric" : undefined,
  });
  return { label, relative };
}

function formatEntryTime(isoStr) {
  const d = new Date(isoStr);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

function formatTimestampPill(localStr) {
  const d = new Date(localStr);
  if (Number.isNaN(d.getTime())) return "now";
  const now = new Date();
  const isToday =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  const timePart = d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  if (isToday) return `today · ${timePart}`;
  const datePart = d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  return `${datePart} · ${timePart}`;
}

let toastTimer = null;
function showToast(msg, durationMs = 2800) {
  const el = document.getElementById("toastBanner");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("visible");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.remove("visible");
  }, durationMs);
}

// ============================================================================
// API CLIENT
// ============================================================================
async function apiFetch(url, options = {}) {
  const opts = {
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  };
  if (opts.body && typeof opts.body !== "string") {
    opts.body = JSON.stringify(opts.body);
  }
  try {
    const res = await fetch(url, opts);
    let data = null;
    try {
      data = await res.json();
    } catch (e) {}
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      networkError: true,
      data: { error: "Unable to reach server. Check your network connection." },
    };
  }
}

// ============================================================================
// SESSION DEK HELPERS (OPTIONAL "STAY UNLOCKED IN THIS SESSION")
// ============================================================================
function persistSessionDekIfEnabled() {
  try {
    if (state.stayUnlocked && state.dekBytes && state.authStatus.user) {
      sessionStorage.setItem(
        SESSION_DEK_KEY,
        JSON.stringify({
          userId: state.authStatus.user.id,
          dekB64: bytesToBase64(state.dekBytes),
        })
      );
    } else {
      sessionStorage.removeItem(SESSION_DEK_KEY);
    }
  } catch (e) {}
}

function tryRestoreSessionDek(userId) {
  try {
    const raw = sessionStorage.getItem(SESSION_DEK_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.userId !== userId || !parsed.dekB64) return null;
    const bytes = base64ToBytes(parsed.dekB64);
    return bytes.length === 32 ? bytes : null;
  } catch (e) {
    return null;
  }
}

function clearSessionDek() {
  if (state.dekBytes instanceof Uint8Array) {
    state.dekBytes.fill(0);
  }
  state.dekBytes = null;
  try {
    sessionStorage.removeItem(SESSION_DEK_KEY);
  } catch (e) {}
}

function loadStayUnlockedPref() {
  try {
    return localStorage.getItem(STAY_UNLOCKED_PREF_KEY) === "1";
  } catch (e) {
    return false;
  }
}

function saveStayUnlockedPref(val) {
  state.stayUnlocked = Boolean(val);
  try {
    localStorage.setItem(STAY_UNLOCKED_PREF_KEY, state.stayUnlocked ? "1" : "0");
  } catch (e) {}
  persistSessionDekIfEnabled();
}

// ============================================================================
// VAULT NORMALIZATION, LOADING & ENCRYPTED PERSISTENCE
// ============================================================================
function normalizeVaultMeta(raw) {
  const base = structuredCloneSafe(DEFAULT_VAULT_META);
  if (!raw || typeof raw !== "object") return base;
  if (raw.settings && typeof raw.settings === "object") {
    base.settings = {
      ...base.settings,
      ...raw.settings,
      themeAccents:
        raw.settings.themeAccents && typeof raw.settings.themeAccents === "object"
          ? { ...raw.settings.themeAccents }
          : {},
    };
  }
  if (Array.isArray(raw.metrics)) {
    base.metrics = raw.metrics.filter((m) => m && typeof m.id === "string" && typeof m.name === "string");
  }
  if (Array.isArray(raw.pinnedQuizIds)) {
    base.pinnedQuizIds = raw.pinnedQuizIds.filter((id) => typeof id === "string");
  }
  return base;
}

async function loadAndDecryptVault() {
  if (!state.dekBytes) return false;
  const res = await apiFetch("/api/vault");
  if (!res.ok) {
    if (res.status === 401) {
      clearSessionDek();
      state.authStatus.authenticated = false;
      state.authStatus.user = null;
      renderShell();
    }
    return false;
  }

  state.authStatus.user = res.data.user;
  state.vaultMetaUpdatedAt = res.data.vaultMetaUpdatedAt || "";

  let metaFailed = false;
  if (res.data.vaultMeta) {
    try {
      const decryptedMeta = await decryptJson(res.data.vaultMeta, state.dekBytes, "heyjournal:meta:v1");
      state.vaultMeta = normalizeVaultMeta(decryptedMeta);
    } catch (e) {
      console.error("Failed to decrypt vault metadata:", e);
      state.vaultMeta = structuredCloneSafe(DEFAULT_VAULT_META);
      metaFailed = true;
    }
  } else {
    state.vaultMeta = structuredCloneSafe(DEFAULT_VAULT_META);
  }
  state.lastSyncedVaultMeta = structuredCloneSafe(state.vaultMeta);

  const decryptedEntries = [];
  let failedEntries = 0;
  for (const row of res.data.entries || []) {
    try {
      const data = await decryptJson(row.ciphertext, state.dekBytes, `heyjournal:entry:${row.id}`);
      decryptedEntries.push({
        id: row.id,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
        data: normalizeEntryData(data, row.createdAt),
      });
    } catch (e) {
      failedEntries++;
      console.error(`Failed to decrypt entry ${row.id}:`, e);
    }
  }

  decryptedEntries.sort(
    (a, b) => new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime()
  );
  state.entries = decryptedEntries;
  state.lastVaultSyncMs = Date.now();

  applyUserThemeAndTitle();
  if (metaFailed || failedEntries > 0) {
    const parts = [];
    if (metaFailed) parts.push("settings");
    if (failedEntries > 0) parts.push(`${failedEntries} ${failedEntries === 1 ? "entry" : "entries"}`);
    showToast(`Warning: could not decrypt ${parts.join(" and ")}.`, 5000);
  }
  return true;
}

function normalizeEntryData(raw, fallbackIso) {
  const rawTs = raw && typeof raw.timestamp === "string" ? raw.timestamp : "";
  const hasValidTs = rawTs && !Number.isNaN(Date.parse(rawTs));
  const fallback =
    fallbackIso && !Number.isNaN(Date.parse(fallbackIso)) ? fallbackIso : new Date().toISOString();
  return {
    timestamp: hasValidTs ? rawTs : fallback,
    text: raw && typeof raw.text === "string" ? raw.text : "",
    numericMetrics: Array.isArray(raw && raw.numericMetrics) ? raw.numericMetrics : [],
    quizResults: Array.isArray(raw && raw.quizResults) ? raw.quizResults : [],
  };
}

/**
 * 3-way merges local vault metadata edits onto fresher remote metadata so
 * concurrent metric/pin/theme changes on two devices do not clobber each other.
 */
function mergeVaultMetaThreeWay(base, local, remote) {
  const merged = structuredCloneSafe(remote);

  // Merge top-level settings keys that actually changed locally
  for (const key of ["journalName", "themeId", "theme", "accentColor", "autoLockMinutes"]) {
    if (local.settings[key] !== base.settings[key]) {
      merged.settings[key] = local.settings[key];
    }
  }
  merged.settings.themeAccents = {
    ...(remote.settings.themeAccents || {}),
    ...(local.settings.themeAccents || {}),
  };

  // Merge numeric metrics: preserve remote additions, apply local additions/edits/removals
  const baseById = new Map((base.metrics || []).map((m) => [m.id, m]));
  const localById = new Map((local.metrics || []).map((m) => [m.id, m]));
  const mergedMetrics = [];
  const seenIds = new Set();

  for (const rm of remote.metrics || []) {
    const bm = baseById.get(rm.id);
    const lm = localById.get(rm.id);
    if (bm && !lm) continue; // Explicitly deleted locally
    if (lm && (!bm || JSON.stringify(lm) !== JSON.stringify(bm))) {
      mergedMetrics.push(structuredCloneSafe(lm));
    } else {
      mergedMetrics.push(structuredCloneSafe(rm));
    }
    seenIds.add(rm.id);
  }
  for (const lm of local.metrics || []) {
    if (!seenIds.has(lm.id)) {
      mergedMetrics.push(structuredCloneSafe(lm));
    }
  }
  merged.metrics = mergedMetrics;

  // Merge pinned quiz IDs as a 3-way set diff
  const basePinned = new Set(base.pinnedQuizIds || []);
  const localPinned = new Set(local.pinnedQuizIds || []);
  const mergedPinned = (remote.pinnedQuizIds || []).filter((id) => !(basePinned.has(id) && !localPinned.has(id)));
  for (const id of local.pinnedQuizIds || []) {
    if (!mergedPinned.includes(id)) mergedPinned.push(id);
  }
  merged.pinnedQuizIds = mergedPinned;

  return normalizeVaultMeta(merged);
}

async function saveVaultMeta(toastMsg = "") {
  if (!state.dekBytes) return false;
  const encrypted = await encryptJson(state.vaultMeta, state.dekBytes, "heyjournal:meta:v1");
  const res = await apiFetch("/api/vault/meta", {
    method: "PUT",
    body: {
      vaultMeta: encrypted,
      expectedUpdatedAt: state.vaultMetaUpdatedAt ?? "",
    },
  });
  if (res.status === 409 && res.data && res.data.vaultMetaUpdatedAt) {
    // Decrypt remote metadata and 3-way merge before retrying once
    state.vaultMetaUpdatedAt = res.data.vaultMetaUpdatedAt;
    if (res.data.vaultMeta) {
      try {
        const remoteMeta = normalizeVaultMeta(
          await decryptJson(res.data.vaultMeta, state.dekBytes, "heyjournal:meta:v1")
        );
        state.vaultMeta = mergeVaultMetaThreeWay(state.lastSyncedVaultMeta, state.vaultMeta, remoteMeta);
      } catch (e) {
        console.error("Failed to merge remote vault metadata:", e);
      }
    }
    const mergedEncrypted = await encryptJson(state.vaultMeta, state.dekBytes, "heyjournal:meta:v1");
    const retry = await apiFetch("/api/vault/meta", {
      method: "PUT",
      body: {
        vaultMeta: mergedEncrypted,
        expectedUpdatedAt: state.vaultMetaUpdatedAt,
      },
    });
    if (retry.ok) {
      state.vaultMetaUpdatedAt = retry.data.vaultMetaUpdatedAt || state.vaultMetaUpdatedAt;
      state.lastSyncedVaultMeta = structuredCloneSafe(state.vaultMeta);
      if (toastMsg) showToast(toastMsg);
      return true;
    }
    showToast("Could not save settings — please reload.");
    return false;
  }
  if (res.ok) {
    state.vaultMetaUpdatedAt = res.data.vaultMetaUpdatedAt || state.vaultMetaUpdatedAt;
    state.lastSyncedVaultMeta = structuredCloneSafe(state.vaultMeta);
    if (toastMsg) showToast(toastMsg);
    return true;
  }
  showToast((res.data && res.data.error) || "Failed to save settings");
  return false;
}

function applyUserThemeAndTitle() {
  applyThemeAndAccent(state.vaultMeta.settings);
  const titleEl = document.getElementById("appTitle");
  const name = (state.vaultMeta.settings && state.vaultMeta.settings.journalName) || "heyjournal";
  if (titleEl) titleEl.textContent = name;
  document.title = name;
}

// ============================================================================
// HEADER & SHELL RENDERING
// ============================================================================
function renderShell() {
  const isUnlocked = Boolean(state.authStatus.authenticated && state.dekBytes);
  const authScreen = document.getElementById("authScreen");
  const appShell = document.getElementById("appShell");
  const userPill = document.getElementById("headerUserPill");
  const syncBtn = document.getElementById("btnSyncVault");
  const lockBtn = document.getElementById("btnLockVault");
  const subtitle = document.getElementById("headerSubtitle");

  if (isUnlocked) {
    authScreen.classList.add("hidden");
    appShell.classList.remove("hidden");
    userPill.classList.remove("hidden");
    userPill.textContent = state.authStatus.user.username + (state.authStatus.user.isAdmin ? " · admin" : "");
    syncBtn?.classList.remove("hidden");
    lockBtn.classList.remove("hidden");
    if (subtitle) {
      const cnt = state.entries.length;
      subtitle.textContent = `${cnt} ${cnt === 1 ? "entry" : "entries"} · encrypted`;
    }
    document.querySelectorAll("#primaryPivotNav .pivot-tab").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === state.activeTab);
    });
    renderActiveTab();
  } else {
    authScreen.classList.remove("hidden");
    appShell.classList.add("hidden");
    userPill.classList.add("hidden");
    syncBtn?.classList.add("hidden");
    lockBtn.classList.add("hidden");
    if (subtitle) {
      subtitle.textContent = "zero-knowledge encrypted journal";
    }
    renderAuthCard();
  }

  if (state.flyoutOpen) {
    renderFlyout();
  }
}

// ============================================================================
// AUTH / UNLOCK / RECOVERY SCREEN
// ============================================================================
function renderAuthCard() {
  const card = document.getElementById("authCard");
  if (!card) return;

  const isFirstUser = state.authStatus.userCount === 0;
  const hasSessionPendingUnlock = Boolean(state.authStatus.authenticated && state.authStatus.user && !state.dekBytes);

  if (hasSessionPendingUnlock && state.authMode !== "recover") {
    state.authMode = "unlock";
  } else if (isFirstUser) {
    state.authMode = "register";
  } else if (!state.authStatus.allowSignups && state.authMode === "register") {
    state.authMode = "login";
  }

  const httpWarning = !isNativeWebCryptoAvailable()
    ? `<div class="auth-notice">
         <strong>LAN HTTP Mode:</strong> Native Web Crypto requires HTTPS, so HeyJournal is using its built-in pure-JS AES-256-GCM engine. For best transport security, serving over HTTPS (Tailscale or Cloudflare Tunnel) is recommended.
       </div>`
    : "";

  const errHtml = state.authError ? `<div class="auth-error">${escapeHtml(state.authError)}</div>` : "";
  const autoLockHtml = state.autoLockReason
    ? `<div class="auth-notice">${escapeHtml(state.autoLockReason)}</div>`
    : "";

  if (state.authMode === "unlock") {
    const uname = state.authStatus.user.username;
    card.innerHTML = `
      <div class="slot-header">
        <div class="slot-title-group"><h2 class="slot-title">unlock vault</h2></div>
      </div>
      <div class="slot-body">
        <p class="auth-lead">
          Welcome back, <strong>${escapeHtml(uname)}</strong>. Enter your password to decrypt your journal locally on this device.
        </p>
        ${autoLockHtml}
        ${httpWarning}
        ${errHtml}
        <form id="authForm">
          <div class="field-group">
            <label class="field-label" for="authPassword">password</label>
            <input class="metro-input" id="authPassword" type="password" autocomplete="current-password" required autofocus />
          </div>
          <label class="checkbox-row">
            <input type="checkbox" id="chkStayUnlocked" ${state.stayUnlocked ? "checked" : ""} />
            <span>Stay unlocked in this browser tab until closed</span>
          </label>
          <div class="auth-actions">
            <button class="metro-btn accent" type="submit" ${state.authBusy ? "disabled" : ""}>
              ${state.authBusy ? "decrypting..." : "unlock"}
            </button>
            <button class="metro-btn subtle" type="button" id="btnSwitchAccount">switch account</button>
          </div>
          ${
            state.authStatus.user.hasRecoveryKey
              ? `<div style="margin-top:12px; font-size:12px; color:var(--text-secondary);">
                   Forgot your password? <button type="button" class="link-btn" id="btnGoRecover">use recovery key</button>
                 </div>`
              : ""
          }
        </form>
      </div>
    `;

    card.querySelector("#btnSwitchAccount").addEventListener("click", handleLockOrLogout);
    card.querySelector("#btnGoRecover")?.addEventListener("click", () => {
      state.authError = "";
      state.authUsernameDraft = uname;
      state.authMode = "recover";
      renderAuthCard();
    });
    card.querySelector("#authForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const pw = card.querySelector("#authPassword").value;
      const stay = card.querySelector("#chkStayUnlocked").checked;
      await handleUnlockExistingSession(pw, stay);
    });
    return;
  }

  if (state.authMode === "recover") {
    card.innerHTML = `
      <div class="slot-header">
        <div class="slot-title-group"><h2 class="slot-title">recover vault</h2></div>
      </div>
      <div class="slot-body">
        <p class="auth-lead">
          Enter your username and 32-character emergency recovery key to decrypt your vault locally and set a new password.
        </p>
        ${httpWarning}
        ${errHtml}
        <form id="recoverForm">
          <div class="field-group">
            <label class="field-label" for="recUsername">username</label>
            <input class="metro-input" id="recUsername" type="text" autocomplete="username" required
                   value="${escapeHtml(state.authUsernameDraft)}" autofocus />
          </div>
          <div class="field-group">
            <label class="field-label" for="recKey">emergency recovery key</label>
            <input class="metro-input" id="recKey" type="text" autocomplete="off" spellcheck="false" required
                   placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" style="font-family:var(--font-mono);" />
          </div>
          <div class="field-group">
            <label class="field-label" for="recNewPassword">new password</label>
            <input class="metro-input" id="recNewPassword" type="password" autocomplete="new-password" required
                   placeholder="at least 8 characters" />
          </div>
          <div class="field-group">
            <label class="field-label" for="recConfirmPassword">confirm new password</label>
            <input class="metro-input" id="recConfirmPassword" type="password" autocomplete="new-password" required />
          </div>
          <label class="checkbox-row">
            <input type="checkbox" id="chkStayUnlocked" ${state.stayUnlocked ? "checked" : ""} />
            <span>Stay unlocked in this browser tab until closed</span>
          </label>
          <div class="auth-actions">
            <button class="metro-btn accent" type="submit" ${state.authBusy ? "disabled" : ""}>
              ${state.authBusy ? "recovering vault..." : "reset password & unlock"}
            </button>
            <button class="metro-btn subtle" type="button" id="btnBackToLogin">back</button>
          </div>
        </form>
      </div>
    `;

    card.querySelector("#btnBackToLogin").addEventListener("click", () => {
      state.authError = "";
      state.authMode = hasSessionPendingUnlock ? "unlock" : "login";
      renderAuthCard();
    });
    card.querySelector("#recoverForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = card.querySelector("#recUsername").value.trim();
      state.authUsernameDraft = username;
      const recKey = card.querySelector("#recKey").value;
      const newPw = card.querySelector("#recNewPassword").value;
      const confirmPw = card.querySelector("#recConfirmPassword").value;
      const stay = card.querySelector("#chkStayUnlocked").checked;
      await handleRecoverPassword(username, recKey, newPw, confirmPw, stay);
    });
    return;
  }

  const showModeTabs = !isFirstUser && state.authStatus.allowSignups;
  const isReg = state.authMode === "register";

  card.innerHTML = `
    <div class="slot-header">
      <div class="slot-title-group"><h2 class="slot-title">${isFirstUser ? "create admin vault" : isReg ? "create vault" : "sign in"}</h2></div>
    </div>
    <div class="slot-body">
      ${
        showModeTabs
          ? `
            <div class="sub-pivots" style="margin-bottom:8px;">
              <button type="button" class="pivot-tab ${!isReg ? "active" : ""}" data-auth-mode="login">sign in</button>
              <button type="button" class="pivot-tab ${isReg ? "active" : ""}" data-auth-mode="register">create account</button>
            </div>
          `
          : ""
      }
      ${
        isFirstUser
          ? `<div class="auth-notice">
               <strong>First-time setup:</strong> The first account created becomes the server <strong>Admin</strong> (can manage accounts &amp; backups, but can never read other users' encrypted journals).
             </div>`
          : ""
      }
      <p class="auth-lead">
        ${
          isReg
            ? "Your password derives your encryption key directly in this browser. The server only stores ciphertext — if you lose your password, your entries cannot be recovered."
            : "Sign in to decrypt your journal locally in your browser."
        }
      </p>
      ${httpWarning}
      ${errHtml}
      <form id="authForm">
        <div class="field-group">
          <label class="field-label" for="authUsername">username</label>
          <input class="metro-input" id="authUsername" type="text" autocomplete="username" required
                 placeholder="e.g. josh" value="${escapeHtml(state.authUsernameDraft)}" autofocus />
        </div>
        <div class="field-group">
          <label class="field-label" for="authPassword">password</label>
          <input class="metro-input" id="authPassword" type="password"
                 autocomplete="${isReg ? "new-password" : "current-password"}" required
                 placeholder="${isReg ? "at least 8 characters" : ""}" />
        </div>
        ${
          isReg
            ? `
              <div class="field-group">
                <label class="field-label" for="authPasswordConfirm">confirm password</label>
                <input class="metro-input" id="authPasswordConfirm" type="password" autocomplete="new-password" required />
              </div>
            `
            : ""
        }
        <label class="checkbox-row">
          <input type="checkbox" id="chkStayUnlocked" ${state.stayUnlocked ? "checked" : ""} />
          <span>Stay unlocked in this browser tab until closed</span>
        </label>
        <div class="auth-actions">
          <button class="metro-btn accent" type="submit" ${state.authBusy ? "disabled" : ""}>
            ${state.authBusy ? (isReg ? "creating encrypted vault..." : "unlocking...") : isReg ? "create encrypted vault" : "sign in"}
          </button>
        </div>
        ${
          !isReg && !isFirstUser
            ? `<div style="margin-top:12px; font-size:12px; color:var(--text-secondary);">
                 Forgot your password? <button type="button" class="link-btn" id="btnGoRecoverLogin">use recovery key</button>
               </div>`
            : ""
        }
      </form>
    </div>
  `;

  card.querySelectorAll("[data-auth-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.authError = "";
      state.authMode = btn.getAttribute("data-auth-mode");
      renderAuthCard();
    });
  });

  card.querySelector("#btnGoRecoverLogin")?.addEventListener("click", () => {
    state.authError = "";
    const curUser = card.querySelector("#authUsername")?.value.trim();
    if (curUser) state.authUsernameDraft = curUser;
    state.authMode = "recover";
    renderAuthCard();
  });

  card.querySelector("#authForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = card.querySelector("#authUsername").value.trim();
    state.authUsernameDraft = username;
    const password = card.querySelector("#authPassword").value;
    const stay = card.querySelector("#chkStayUnlocked").checked;
    if (isReg) {
      const confirmPw = card.querySelector("#authPasswordConfirm").value;
      await handleRegister(username, password, confirmPw, stay);
    } else {
      await handleLogin(username, password, stay);
    }
  });
}

async function handleRegister(username, password, confirmPw, stayUnlocked) {
  state.authError = "";
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$/.test(username)) {
    state.authError = "Username must be 2–32 characters (letters, numbers, ., _, -) and start with a letter or number.";
    renderAuthCard();
    return;
  }
  if (password.length < 8) {
    state.authError = "Please choose a password of at least 8 characters.";
    renderAuthCard();
    return;
  }
  if (password !== confirmPw) {
    state.authError = "Passwords do not match.";
    renderAuthCard();
    return;
  }

  state.authBusy = true;
  renderAuthCard();

  let kekBytes = null;
  let dekBytes = null;
  try {
    const kdfSalt = generateSaltB64();
    const kdfIterations = DEFAULT_KDF_ITERATIONS;
    const derived = await deriveAuthAndKek(password, kdfSalt, kdfIterations);
    kekBytes = derived.kekBytes;
    dekBytes = generateDek();
    const wrappedDek = await wrapDek(dekBytes, kekBytes);
    kekBytes.fill(0);
    kekBytes = null;

    // Carry over only the visual theme/mode/accent picked on the login screen
    const initialMeta = structuredCloneSafe(DEFAULT_VAULT_META);
    initialMeta.settings.themeId = state.vaultMeta.settings.themeId || "metro";
    initialMeta.settings.theme = state.vaultMeta.settings.theme || "dark";
    initialMeta.settings.accentColor = state.vaultMeta.settings.accentColor || "#00ABA9";
    const encryptedMeta = await encryptJson(initialMeta, dekBytes, "heyjournal:meta:v1");

    const res = await apiFetch("/api/auth/register", {
      method: "POST",
      body: {
        username,
        authKey: derived.authKeyB64,
        kdfSalt,
        kdfIterations,
        wrappedDek,
        vaultMeta: encryptedMeta,
      },
    });

    if (!res.ok) {
      state.authError = (res.data && res.data.error) || "Registration failed.";
      state.authBusy = false;
      renderAuthCard();
      return;
    }

    state.authStatus.authenticated = true;
    state.authStatus.user = res.data.user;
    state.authStatus.userCount = Math.max(1, state.authStatus.userCount + 1);
    state.authUsernameDraft = "";
    state.dekBytes = dekBytes;
    dekBytes = null; // Ownership transferred to state.dekBytes
    state.autoLockReason = "";
    state.lastActivityMs = Date.now();
    saveStayUnlockedPref(stayUnlocked);
    state.authBusy = false;
    const loaded = await loadAndDecryptVault();
    state.draft = createFreshDraft();
    renderShell();
    if (loaded) {
      showToast(res.data.user.isAdmin ? "Encrypted admin vault created" : "Encrypted vault created");
      // Offer optional zero-knowledge printable recovery key setup once after signup
      state.modalState = { type: "recovery-prompt" };
      renderModal();
    } else {
      showToast("Vault created, but could not load data — please reload.");
    }
  } catch (err) {
    console.error(err);
    state.authError = err.message || "Encryption error during registration.";
    state.authBusy = false;
    renderAuthCard();
  } finally {
    if (kekBytes) kekBytes.fill(0);
    if (dekBytes) dekBytes.fill(0);
  }
}

async function handleLogin(username, password, stayUnlocked) {
  state.authError = "";
  if (!username || !password) {
    state.authError = "Username and password are required.";
    renderAuthCard();
    return;
  }

  state.authBusy = true;
  renderAuthCard();

  let kekBytes = null;
  let dekBytes = null;
  try {
    const chal = await apiFetch("/api/auth/challenge", {
      method: "POST",
      body: { username },
    });
    if (!chal.ok) {
      state.authError = (chal.data && chal.data.error) || "Unable to reach server.";
      state.authBusy = false;
      renderAuthCard();
      return;
    }

    const { kdfSalt, kdfIterations } = chal.data;
    const derived = await deriveAuthAndKek(password, kdfSalt, kdfIterations);
    kekBytes = derived.kekBytes;

    const res = await apiFetch("/api/auth/login", {
      method: "POST",
      body: { username, authKey: derived.authKeyB64 },
    });
    if (!res.ok) {
      state.authError = (res.data && res.data.error) || "Invalid username or password.";
      state.authBusy = false;
      renderAuthCard();
      return;
    }

    dekBytes = await unwrapDek(res.data.user.wrappedDek, kekBytes);
    state.authStatus.authenticated = true;
    state.authStatus.user = res.data.user;
    state.authUsernameDraft = "";
    state.dekBytes = dekBytes;
    dekBytes = null;
    state.autoLockReason = "";
    state.lastActivityMs = Date.now();
    saveStayUnlockedPref(stayUnlocked);
    state.authBusy = false;
    const loaded = await loadAndDecryptVault();
    state.draft = createFreshDraft();
    renderShell();
    if (loaded) {
      showToast("Vault unlocked");
    } else {
      showToast("Signed in, but could not load vault — please retry.");
    }
  } catch (err) {
    console.error(err);
    state.authError = "Incorrect password or unable to decrypt vault key.";
    state.authBusy = false;
    renderAuthCard();
  } finally {
    if (kekBytes) kekBytes.fill(0);
    if (dekBytes) dekBytes.fill(0);
  }
}

async function handleUnlockExistingSession(password, stayUnlocked) {
  state.authError = "";
  const user = state.authStatus.user;
  if (!user || !password) {
    state.authError = "Password is required.";
    renderAuthCard();
    return;
  }

  state.authBusy = true;
  renderAuthCard();

  let kekBytes = null;
  let dekBytes = null;
  try {
    const derived = await deriveAuthAndKek(password, user.kdfSalt, user.kdfIterations);
    kekBytes = derived.kekBytes;
    dekBytes = await unwrapDek(user.wrappedDek, kekBytes);
    state.dekBytes = dekBytes;
    dekBytes = null;
    state.autoLockReason = "";
    state.lastActivityMs = Date.now();
    saveStayUnlockedPref(stayUnlocked);
    state.authBusy = false;
    const loaded = await loadAndDecryptVault();
    state.draft = createFreshDraft();
    renderShell();
    if (loaded) {
      showToast("Vault unlocked");
    } else if (state.authStatus.authenticated) {
      showToast("Unlocked key, but could not load vault from server.");
    }
  } catch (err) {
    state.authError = "Incorrect password.";
    state.authBusy = false;
    renderAuthCard();
  } finally {
    if (kekBytes) kekBytes.fill(0);
    if (dekBytes) dekBytes.fill(0);
  }
}

async function handleRecoverPassword(username, rawRecoveryKey, newPassword, confirmPw, stayUnlocked) {
  state.authError = "";
  const normalizedKey = normalizeRecoveryKey(rawRecoveryKey);
  if (!username || !normalizedKey) {
    state.authError = "Enter your username and a valid 32-character recovery key.";
    renderAuthCard();
    return;
  }
  if (newPassword.length < 8) {
    state.authError = "Please choose a new password of at least 8 characters.";
    renderAuthCard();
    return;
  }
  if (newPassword !== confirmPw) {
    state.authError = "New passwords do not match.";
    renderAuthCard();
    return;
  }

  state.authBusy = true;
  renderAuthCard();

  let recKekBytes = null;
  let newKekBytes = null;
  let dekBytes = null;
  try {
    const chal = await apiFetch("/api/auth/recovery-challenge", {
      method: "POST",
      body: { username },
    });
    if (!chal.ok) {
      state.authError = (chal.data && chal.data.error) || "Unable to reach server.";
      state.authBusy = false;
      renderAuthCard();
      return;
    }

    const recDerived = await deriveAuthAndKek(
      normalizedKey,
      chal.data.recoveryKdfSalt,
      chal.data.recoveryKdfIterations
    );
    recKekBytes = recDerived.kekBytes;

    const ver = await apiFetch("/api/auth/recovery-verify", {
      method: "POST",
      body: { username, recoveryAuthKey: recDerived.authKeyB64 },
    });
    if (!ver.ok) {
      state.authError = (ver.data && ver.data.error) || "Invalid username or recovery key.";
      state.authBusy = false;
      renderAuthCard();
      return;
    }

    dekBytes = await unwrapDek(
      ver.data.recoveryWrappedDek,
      recKekBytes,
      "heyjournal:recovery-dek:v1"
    );
    recKekBytes.fill(0);
    recKekBytes = null;

    const newSalt = generateSaltB64();
    const newDerived = await deriveAuthAndKek(newPassword, newSalt, DEFAULT_KDF_ITERATIONS);
    newKekBytes = newDerived.kekBytes;
    const newWrappedDek = await wrapDek(dekBytes, newKekBytes);
    newKekBytes.fill(0);
    newKekBytes = null;

    const res = await apiFetch("/api/auth/recover", {
      method: "POST",
      body: {
        username,
        recoveryAuthKey: recDerived.authKeyB64,
        newAuthKey: newDerived.authKeyB64,
        newKdfSalt: newSalt,
        newKdfIterations: DEFAULT_KDF_ITERATIONS,
        newWrappedDek,
      },
    });
    if (!res.ok) {
      state.authError = (res.data && res.data.error) || "Could not complete password reset.";
      state.authBusy = false;
      renderAuthCard();
      return;
    }

    state.authStatus.authenticated = true;
    state.authStatus.user = res.data.user;
    state.authUsernameDraft = "";
    state.autoLockReason = "";
    state.lastActivityMs = Date.now();
    state.dekBytes = dekBytes;
    dekBytes = null;
    saveStayUnlockedPref(stayUnlocked);
    state.authBusy = false;
    const loaded = await loadAndDecryptVault();
    state.draft = createFreshDraft();
    renderShell();
    if (loaded) {
      showToast("Password reset & vault unlocked", 4000);
    } else {
      showToast("Password reset, but could not load vault — please reload.");
    }
  } catch (err) {
    console.error(err);
    state.authError = "Invalid recovery key or unable to decrypt vault.";
    state.authBusy = false;
    renderAuthCard();
  } finally {
    if (recKekBytes) recKekBytes.fill(0);
    if (newKekBytes) newKekBytes.fill(0);
    if (dekBytes) dekBytes.fill(0);
  }
}

function _wipeDecryptedMemoryState() {
  clearSessionDek();
  const preservedTheme = {
    themeId: state.vaultMeta.settings.themeId || "metro",
    theme: state.vaultMeta.settings.theme || "dark",
    accentColor: state.vaultMeta.settings.accentColor || "#00ABA9",
  };
  state.vaultMeta = structuredCloneSafe(DEFAULT_VAULT_META);
  state.vaultMeta.settings.themeId = preservedTheme.themeId;
  state.vaultMeta.settings.theme = preservedTheme.theme;
  state.vaultMeta.settings.accentColor = preservedTheme.accentColor;
  state.lastSyncedVaultMeta = structuredCloneSafe(state.vaultMeta);
  state.vaultMetaUpdatedAt = "";
  state.entries = [];
  state.draft = createFreshDraft();
  state.activeTab = "input";
  state.quizCategoryFilter = "All";
  state.reviewSearch = "";
  state.reviewMetricFilter = "all";
  state.reportRange = "90d";
  state.activeSubscaleByQuiz = {};
  state.lastVaultSyncMs = 0;
  state.quizSearch = "";
  state.editingMetricId = null;
  state.openEntryMenuId = null;
  state.adminData = null;
  state.adminLoadError = "";
  closeModal();
  closeFlyout();
  applyUserThemeAndTitle();
}

function lockVaultLocally(reason = "") {
  if (!state.dekBytes) return;
  _wipeDecryptedMemoryState();
  state.autoLockReason = reason;
  state.authMode = "unlock";
  state.authError = "";
  renderShell();
}

async function handleLockOrLogout() {
  _wipeDecryptedMemoryState();
  state.authUsernameDraft = "";
  state.autoLockReason = "";

  await apiFetch("/api/auth/logout", { method: "POST" });
  const statusRes = await apiFetch("/api/auth/status");
  if (statusRes.ok) {
    state.authStatus = statusRes.data;
  } else {
    state.authStatus.authenticated = false;
    state.authStatus.user = null;
  }
  state.authMode = state.authStatus.userCount === 0 ? "register" : "login";
  state.authError = "";
  renderShell();
  showToast("Vault locked");
}

function checkAutoLock() {
  if (!state.authStatus.authenticated || !state.dekBytes) return;
  const mins = Number(state.vaultMeta.settings?.autoLockMinutes ?? 60);
  if (!Number.isFinite(mins) || mins <= 0) return;
  const elapsedMs = Date.now() - state.lastActivityMs;
  if (elapsedMs >= mins * 60 * 1000) {
    lockVaultLocally(`Auto-locked after ${mins} minutes of inactivity.`);
  }
}

async function syncVaultInBackground({ manual = false } = {}) {
  if (!state.authStatus.authenticated || !state.dekBytes || state.syncingVault || state.savingEntry) {
    return;
  }
  state.syncingVault = true;
  const syncBtn = document.getElementById("btnSyncVault");
  if (syncBtn) syncBtn.disabled = true;
  try {
    const ok = await loadAndDecryptVault();
    if (ok) {
      const subtitle = document.getElementById("headerSubtitle");
      if (subtitle) {
        const cnt = state.entries.length;
        subtitle.textContent = `${cnt} ${cnt === 1 ? "entry" : "entries"} · encrypted`;
      }
      // Preserve active Input draft uninterrupted; refresh Input only if untouched, and always refresh Review/Report/Metrics
      if (
        state.activeTab !== "input" ||
        (manual && !hasUnsavedDraft(state.draft) && !state.draft.showPicker && !state.draft.showTimestampEditor)
      ) {
        renderActiveTab();
      }
      if (manual) showToast("Vault synced");
    } else if (manual) {
      showToast("Could not sync with server");
    }
  } finally {
    state.syncingVault = false;
    if (syncBtn) syncBtn.disabled = false;
  }
}

async function handleGenerateRecoveryKey() {
  if (!state.dekBytes || !state.authStatus.user) return false;
  let recKekBytes = null;
  try {
    const recoveryKey = generateRecoveryKey();
    const normalized = normalizeRecoveryKey(recoveryKey);
    const recSalt = generateSaltB64();
    const recDerived = await deriveAuthAndKek(normalized, recSalt, RECOVERY_KDF_ITERATIONS);
    recKekBytes = recDerived.kekBytes;
    const recWrappedDek = await wrapDek(state.dekBytes, recKekBytes, "heyjournal:recovery-dek:v1");
    recKekBytes.fill(0);
    recKekBytes = null;

    const res = await apiFetch("/api/auth/recovery-key", {
      method: "POST",
      body: {
        recoveryAuthKey: recDerived.authKeyB64,
        recoveryKdfSalt: recSalt,
        recoveryKdfIterations: RECOVERY_KDF_ITERATIONS,
        recoveryWrappedDek: recWrappedDek,
      },
    });
    if (!res.ok) {
      showToast((res.data && res.data.error) || "Could not save recovery key");
      return false;
    }
    state.authStatus.user = res.data.user;
    if (state.flyoutOpen) renderFlyout();
    state.modalState = {
      type: "recovery-key",
      recoveryKey,
      username: state.authStatus.user.username,
    };
    renderModal();
    return true;
  } catch (err) {
    console.error(err);
    showToast("Encryption error generating recovery key");
    return false;
  } finally {
    if (recKekBytes) recKekBytes.fill(0);
  }
}

// ============================================================================
// PRIMARY TAB NAVIGATION
// ============================================================================
function setActiveTab(tabId) {
  state.activeTab = tabId;
  state.openEntryMenuId = null;
  document.querySelectorAll("#primaryPivotNav .pivot-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
  });
  renderActiveTab();
}

function renderActiveTab() {
  const stage = document.getElementById("mainStage");
  if (!stage) return;

  if (state.activeTab === "input") renderInputTab(stage);
  else if (state.activeTab === "metrics") renderMetricsTab(stage);
  else if (state.activeTab === "review") renderReviewTab(stage);
  else if (state.activeTab === "report") renderReportTab(stage);
}

// ============================================================================
// TAB 1: INPUT (JOURNAL + PINNED METRICS + AD-HOC METRIC/QUIZ ATTACHMENT)
// ============================================================================
function renderInputTab(stage) {
  const d = state.draft;
  if (!d.editingEntryId && !d.timestampManuallyEdited) {
    d.timestampLocal = toLocalDateTimeInputValue(new Date());
  }

  const pinnedNumerics = state.vaultMeta.metrics.filter((m) => m.pinned);
  const pinnedQuizzes = state.vaultMeta.pinnedQuizIds
    .map((id) => state.quizById.get(id))
    .filter(Boolean);

  const attachedQuizById = new Map(d.quizResults.map((qr) => [qr.quizId, qr]));

  const pinnedSectionHtml =
    pinnedNumerics.length > 0 || pinnedQuizzes.length > 0
      ? `
        <div class="pinned-strip">
          <div class="section-label">pinned quick metrics</div>
          <div class="pinned-grid">
            ${pinnedNumerics
              .map(
                (m) => `
                <div class="quick-metric-card">
                  <div class="quick-metric-head">
                    <span class="quick-metric-name">${escapeHtml(m.name)}</span>
                    ${m.unit ? `<span class="quick-metric-unit">${escapeHtml(m.unit)}</span>` : ""}
                  </div>
                  <input class="metro-input quick-metric-input" type="number" step="any" inputmode="decimal"
                         data-pinned-num="${escapeHtml(m.id)}"
                         value="${escapeHtml(d.numericValues[m.id] ?? "")}"
                         placeholder="—" aria-label="${escapeHtml(m.name)}" />
                </div>
              `
              )
              .join("")}
            ${pinnedQuizzes
              .map((q) => {
                const done = attachedQuizById.get(q.id);
                return `
                  <div class="quick-metric-card">
                    <div class="quick-metric-head">
                      <span class="quick-metric-name">${escapeHtml(q.name)}</span>
                      <span class="quick-metric-unit">${q.questions.length}q · ${escapeHtml(String(q.estimatedMinutes || 2))}m</span>
                    </div>
                    ${
                      done
                        ? `<button type="button" class="metro-btn accent compact" data-launch-quiz="${escapeHtml(q.id)}">
                             ${escapeHtml(formatScoreValue(done.score, done.unit))}${done.band ? ` · ${escapeHtml(done.band.label)}` : ""}
                           </button>`
                        : `<button type="button" class="metro-btn subtle compact" data-launch-quiz="${escapeHtml(q.id)}">
                             take ${escapeHtml(q.name)}
                           </button>`
                    }
                  </div>
                `;
              })
              .join("")}
          </div>
        </div>
      `
      : "";

  const attachedChips = [
    ...d.extraNumerics.map(
      (item, idx) => `
        <span class="metric-chip">
          <span><strong>${escapeHtml(item.name)}</strong> · ${escapeHtml(String(item.value))}${item.unit ? ` ${escapeHtml(item.unit)}` : ""}</span>
          <button type="button" class="chip-remove-btn" data-remove-extra-num="${idx}" title="Remove" aria-label="Remove ${escapeHtml(item.name)}">×</button>
        </span>
      `
    ),
    ...d.quizResults.map(
      (qr, idx) => `
        <span class="metric-chip clickable" data-inspect-draft-quiz="${idx}" title="Inspect quiz score">
          <span><strong>${escapeHtml(qr.quizName)}</strong> · ${escapeHtml(formatScoreValue(qr.score, qr.unit))}${
        qr.band ? ` · ${escapeHtml(qr.band.label)}` : ""
      }</span>
          <button type="button" class="chip-remove-btn" data-remove-quiz="${idx}" title="Detach quiz" aria-label="Detach ${escapeHtml(qr.quizName)}">×</button>
        </span>
      `
    ),
  ];

  const unpinnedNumerics = state.vaultMeta.metrics.filter((m) => !m.pinned);

  const pickerHtml = d.showPicker
    ? `
      <div class="inline-picker" id="inlineMetricPicker">
        <div class="section-label" style="margin-bottom:0;">attach a metric or clinical quiz to this entry</div>
        <div class="picker-row">
          <select class="metro-select" id="pickerMetricSelect" aria-label="Choose metric or quiz">
            <option value="">choose a metric or quiz...</option>
            ${
              unpinnedNumerics.length > 0
                ? `<optgroup label="Your Numeric Metrics">
                     ${unpinnedNumerics
                       .map(
                         (m) =>
                           `<option value="num:${escapeHtml(m.id)}">${escapeHtml(m.name)}${
                             m.unit ? ` (${escapeHtml(m.unit)})` : ""
                           }</option>`
                       )
                       .join("")}
                   </optgroup>`
                : ""
            }
            <optgroup label="Clinical Self-Assessment Quizzes">
              ${state.quizzes
                .map(
                  (q) =>
                    `<option value="quiz:${escapeHtml(q.id)}">${escapeHtml(q.name)} — ${escapeHtml(q.fullName)}</option>`
                )
                .join("")}
            </optgroup>
            <option value="__new_numeric__">+ create new numeric metric...</option>
          </select>
          <input class="metro-input hidden" id="pickerNumValue" type="number" step="any" inputmode="decimal" placeholder="value..." style="max-width:140px;" />
          <button type="button" class="metro-btn accent compact" id="btnPickerApply">add</button>
          <button type="button" class="metro-btn subtle compact" id="btnPickerClose">close</button>
        </div>
        <div class="picker-row hidden" id="pickerNewMetricRow">
          <input class="metro-input" id="pickerNewName" type="text" placeholder="metric name (e.g. Weight)" />
          <input class="metro-input" id="pickerNewUnit" type="text" placeholder="unit (e.g. lbs)" style="max-width:130px;" />
          <input class="metro-input" id="pickerNewVal" type="number" step="any" inputmode="decimal" placeholder="today's value" style="max-width:140px;" />
        </div>
      </div>
    `
    : "";

  stage.innerHTML = `
    <div class="metro-slot">
      <div class="slot-header">
        <div class="slot-title-group">
          <h2 class="slot-title">${d.editingEntryId ? "edit entry" : "new entry"}</h2>
        </div>
        <button type="button" class="metro-btn subtle compact" id="btnTogglePicker">
          ${d.showPicker ? "hide metric picker" : "+ add metric / quiz"}
        </button>
      </div>
      <div class="slot-body">
        ${
          d.editingEntryId
            ? `
              <div class="edit-banner">
                <span>Editing entry from <strong>${escapeHtml(formatTimestampPill(d.timestampLocal))}</strong></span>
                <button type="button" class="metro-btn subtle compact" id="btnCancelEdit">cancel edit</button>
              </div>
            `
            : ""
        }
        ${
          d.conflictNotice
            ? `
              <div class="auth-error" style="display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; margin-bottom:4px;">
                <span>${escapeHtml(d.conflictNotice)}</span>
                <button type="button" class="metro-btn subtle compact" id="btnReloadConflict">load latest</button>
              </div>
            `
            : ""
        }

        <div class="timestamp-bar" style="margin-bottom:0;">
          ${
            d.showTimestampEditor
              ? `
                <div class="timestamp-editor">
                  <input class="metro-input" id="entryTimestampInput" type="datetime-local" value="${escapeHtml(d.timestampLocal)}" />
                  <button type="button" class="metro-btn subtle compact" id="btnTimestampNow">now</button>
                  <button type="button" class="metro-btn subtle compact" id="btnTimestampDone">done</button>
                </div>
              `
              : `
                <button type="button" class="timestamp-trigger" id="btnEditTimestamp" title="Click to adjust date & time">
                  <span>${escapeHtml(formatTimestampPill(d.timestampLocal))}</span>
                  <span style="opacity:0.65; font-size:12px;">edit time</span>
                </button>
              `
          }
        </div>

        <textarea class="metro-textarea" id="entryTextInput" placeholder="what's on your mind?">${escapeHtml(d.text)}</textarea>

        ${
          !d.editingEntryId &&
          state.entries.length === 0 &&
          state.vaultMeta.metrics.length === 0 &&
          state.vaultMeta.pinnedQuizIds.length === 0
            ? `
              <div class="onboarding-cue">
                <span>Tip: Pin daily numbers (like Sleep or Mood) or clinical check-ins from <strong>metrics</strong> to appear right here for one-tap logging.</span>
                <button type="button" class="metro-btn subtle compact" id="btnOnboardingMetrics">browse metrics →</button>
              </div>
            `
            : ""
        }

        ${pinnedSectionHtml}

        ${
          attachedChips.length > 0
            ? `<div class="attached-bar" style="margin-top:4px;">${attachedChips.join("")}</div>`
            : ""
        }

        ${pickerHtml}

        <div class="input-footer" style="margin-top:6px;">
          <span style="font-size:12px; color:var(--text-muted);">
            Encrypted locally with AES-256-GCM before saving
          </span>
          <div style="display:flex; gap:10px; align-items:center;">
            ${
              d.editingEntryId
                ? `<button type="button" class="metro-btn subtle" id="btnCancelEditFooter">cancel</button>`
                : ""
            }
            <button type="button" class="metro-btn accent" id="btnSaveEntry">
              ${d.editingEntryId ? "update entry" : "save entry"}
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

  // Bindings
  const textArea = stage.querySelector("#entryTextInput");
  textArea.addEventListener("input", () => {
    state.draft.text = textArea.value;
  });

  stage.querySelector("#btnEditTimestamp")?.addEventListener("click", () => {
    state.draft.showTimestampEditor = true;
    renderInputTab(stage);
  });

  const syncTimestampInput = (e) => {
    if (e.target.value) {
      state.draft.timestampLocal = e.target.value;
      state.draft.timestampManuallyEdited = true;
    }
  };
  const tsInput = stage.querySelector("#entryTimestampInput");
  tsInput?.addEventListener("input", syncTimestampInput);
  tsInput?.addEventListener("change", syncTimestampInput);

  stage.querySelector("#btnTimestampNow")?.addEventListener("click", () => {
    state.draft.timestampLocal = toLocalDateTimeInputValue(new Date());
    state.draft.timestampManuallyEdited = false;
    renderInputTab(stage);
  });

  stage.querySelector("#btnTimestampDone")?.addEventListener("click", () => {
    state.draft.showTimestampEditor = false;
    renderInputTab(stage);
  });

  stage.querySelector("#btnTogglePicker")?.addEventListener("click", () => {
    state.draft.showPicker = !state.draft.showPicker;
    renderInputTab(stage);
  });

  stage.querySelector("#btnOnboardingMetrics")?.addEventListener("click", () => {
    setActiveTab("metrics");
  });

  stage.querySelectorAll("[data-pinned-num]").forEach((inp) => {
    inp.addEventListener("input", () => {
      state.draft.numericValues[inp.getAttribute("data-pinned-num")] = inp.value;
    });
  });

  stage.querySelectorAll("[data-launch-quiz]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const qid = btn.getAttribute("data-launch-quiz");
      const existing = state.draft.quizResults.find((r) => r.quizId === qid);
      openQuizRunnerModal(qid, existing ? existing.answers : null);
    });
  });

  stage.querySelectorAll("[data-remove-extra-num]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const idx = Number(btn.getAttribute("data-remove-extra-num"));
      state.draft.extraNumerics.splice(idx, 1);
      renderInputTab(stage);
    });
  });

  stage.querySelectorAll("[data-remove-quiz]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const idx = Number(btn.getAttribute("data-remove-quiz"));
      state.draft.quizResults.splice(idx, 1);
      renderInputTab(stage);
    });
  });

  stage.querySelectorAll("[data-inspect-draft-quiz]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const idx = Number(chip.getAttribute("data-inspect-draft-quiz"));
      const qr = state.draft.quizResults[idx];
      if (qr) openQuizBreakdownModal(qr, state.draft.timestampLocal);
    });
  });

  // Inline metric / quiz picker bindings
  const selectEl = stage.querySelector("#pickerMetricSelect");
  const numValEl = stage.querySelector("#pickerNumValue");
  const newRowEl = stage.querySelector("#pickerNewMetricRow");

  selectEl?.addEventListener("change", () => {
    const val = selectEl.value;
    numValEl.classList.toggle("hidden", !val.startsWith("num:"));
    newRowEl.classList.toggle("hidden", val !== "__new_numeric__");
    if (val.startsWith("num:")) numValEl.focus();
    if (val === "__new_numeric__") stage.querySelector("#pickerNewName")?.focus();
  });

  stage.querySelector("#btnPickerClose")?.addEventListener("click", () => {
    state.draft.showPicker = false;
    renderInputTab(stage);
  });

  const applyPickerBtn = stage.querySelector("#btnPickerApply");
  const handlePickerEnter = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      applyPickerBtn?.click();
    }
  };
  numValEl?.addEventListener("keydown", handlePickerEnter);
  stage.querySelector("#pickerNewVal")?.addEventListener("keydown", handlePickerEnter);

  applyPickerBtn?.addEventListener("click", async () => {
    const val = selectEl.value;
    if (!val) return;
    if (val.startsWith("quiz:")) {
      const qid = val.slice(5);
      state.draft.showPicker = false;
      const existing = state.draft.quizResults.find((r) => r.quizId === qid);
      openQuizRunnerModal(qid, existing ? existing.answers : null);
      return;
    }
    if (val.startsWith("num:")) {
      const mid = val.slice(4);
      const metric = state.vaultMeta.metrics.find((m) => m.id === mid);
      const rawNum = String(numValEl.value ?? "").trim();
      const num = rawNum === "" ? NaN : Number(rawNum);
      if (!metric || !Number.isFinite(num)) {
        showToast("Enter a numeric value first");
        return;
      }
      const existingIdx = state.draft.extraNumerics.findIndex((x) => x.metricId === mid);
      const item = { metricId: metric.id, name: metric.name, unit: metric.unit || "", value: num };
      if (existingIdx >= 0) state.draft.extraNumerics[existingIdx] = item;
      else state.draft.extraNumerics.push(item);
      state.draft.showPicker = false;
      renderInputTab(stage);
      return;
    }
    if (val === "__new_numeric__") {
      const name = stage.querySelector("#pickerNewName").value.trim();
      const unit = stage.querySelector("#pickerNewUnit").value.trim();
      const rawVal = String(stage.querySelector("#pickerNewVal").value ?? "").trim();
      const parsedNewVal = rawVal === "" ? NaN : Number(rawVal);
      if (!name) {
        showToast("Enter a metric name");
        return;
      }
      const existingMetric = state.vaultMeta.metrics.find(
        (m) => m.name.toLowerCase() === name.toLowerCase()
      );
      if (existingMetric) {
        if (Number.isFinite(parsedNewVal)) {
          if (existingMetric.pinned) {
            state.draft.numericValues[existingMetric.id] = rawVal;
          } else {
            const idx = state.draft.extraNumerics.findIndex((x) => x.metricId === existingMetric.id);
            const item = { metricId: existingMetric.id, name: existingMetric.name, unit: existingMetric.unit || "", value: parsedNewVal };
            if (idx >= 0) state.draft.extraNumerics[idx] = item;
            else state.draft.extraNumerics.push(item);
          }
        }
        state.draft.showPicker = false;
        renderInputTab(stage);
        showToast(`Using existing "${existingMetric.name}" metric`);
        return;
      }
      const newMetric = {
        id: generateClientId("metric"),
        kind: "number",
        name,
        unit,
        pinned: true,
        createdAt: new Date().toISOString(),
      };
      state.vaultMeta.metrics.push(newMetric);
      const saved = await saveVaultMeta();
      if (Number.isFinite(parsedNewVal)) {
        state.draft.numericValues[newMetric.id] = rawVal;
      }
      state.draft.showPicker = false;
      renderInputTab(stage);
      if (saved) showToast(`Added "${name}" to your metrics`);
    }
  });

  const cancelEdit = () => {
    state.draft = createFreshDraft();
    renderInputTab(stage);
  };
  stage.querySelector("#btnCancelEdit")?.addEventListener("click", cancelEdit);
  stage.querySelector("#btnCancelEditFooter")?.addEventListener("click", cancelEdit);
  stage.querySelector("#btnReloadConflict")?.addEventListener("click", () => {
    if (state.draft.editingEntryId) {
      const id = state.draft.editingEntryId;
      state.draft = createFreshDraft();
      startEditingEntry(id);
      showToast("Loaded latest version from server");
    }
  });

  stage.querySelector("#btnSaveEntry")?.addEventListener("click", handleSaveDraftEntry);
}

async function handleSaveDraftEntry() {
  if (state.savingEntry) return;
  const d = state.draft;
  const text = (d.text || "").trim();

  // Gather extra numeric metrics first, then pinned numeric inputs so live pinned values win
  const numericMap = new Map();
  for (const extra of d.extraNumerics) {
    if (Number.isFinite(Number(extra.value))) {
      numericMap.set(extra.metricId, {
        metricId: extra.metricId,
        name: extra.name,
        unit: extra.unit || "",
        value: Number(extra.value),
      });
    }
  }
  for (const m of state.vaultMeta.metrics) {
    if (!m.pinned) continue;
    const raw = d.numericValues[m.id];
    if (raw !== undefined && raw !== null && String(raw).trim() !== "") {
      const val = Number(String(raw).trim());
      if (Number.isFinite(val)) {
        numericMap.set(m.id, { metricId: m.id, name: m.name, unit: m.unit || "", value: val });
      }
    }
  }
  const numericMetrics = Array.from(numericMap.values());
  const quizResults = [...d.quizResults];

  if (!text && numericMetrics.length === 0 && quizResults.length === 0) {
    showToast("Add some text, a metric, or a quiz score before saving");
    return;
  }

  const timestampIso =
    !d.editingEntryId && !d.timestampManuallyEdited
      ? new Date().toISOString()
      : parseLocalDateTimeToIso(d.timestampLocal);

  const payload = {
    timestamp: timestampIso,
    text,
    numericMetrics,
    quizResults,
  };

  state.savingEntry = true;
  const saveBtn = document.getElementById("btnSaveEntry");
  if (saveBtn) saveBtn.disabled = true;

  try {
    if (d.editingEntryId) {
      const entryId = d.editingEntryId;
      const ciphertext = await encryptJson(payload, state.dekBytes, `heyjournal:entry:${entryId}`);
      const res = await apiFetch(`/api/entries/${encodeURIComponent(entryId)}`, {
        method: "PUT",
        body: { ciphertext, expectedUpdatedAt: d.editingUpdatedAt || undefined },
      });
      if (!res.ok) {
        if (res.status === 409 && res.data && res.data.entry) {
          // Sync latest remote entry locally and refresh expectedUpdatedAt so user can resolve cleanly
          const remoteRow = res.data.entry;
          try {
            const remoteData = await decryptJson(remoteRow.ciphertext, state.dekBytes, `heyjournal:entry:${remoteRow.id}`);
            const idx = state.entries.findIndex((e) => e.id === remoteRow.id);
            const refreshed = {
              id: remoteRow.id,
              createdAt: remoteRow.createdAt,
              updatedAt: remoteRow.updatedAt,
              data: normalizeEntryData(remoteData, remoteRow.createdAt),
            };
            if (idx >= 0) state.entries[idx] = refreshed;
            else state.entries.unshift(refreshed);
          } catch (e) {
            console.error("Failed to decrypt conflicting entry:", e);
          }
          d.editingUpdatedAt = remoteRow.updatedAt || "";
          d.conflictNotice = "This entry was updated on another device. Click 'update entry' again to keep your edits, or load the latest version.";
          renderActiveTab();
          showToast("Sync conflict detected — choose how to resolve", 4000);
          return;
        }
        showToast((res.data && res.data.error) || "Could not update entry");
        return;
      }
      const idx = state.entries.findIndex((e) => e.id === entryId);
      const updated = {
        id: res.data.entry.id,
        createdAt: res.data.entry.createdAt,
        updatedAt: res.data.entry.updatedAt,
        data: payload,
      };
      if (idx >= 0) state.entries[idx] = updated;
      else state.entries.unshift(updated);
      state.entries.sort((a, b) => new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime());
      state.draft = createFreshDraft();
      renderShell();
      showToast("Entry updated");
    } else {
      const entryId = generateClientId("entry");
      const ciphertext = await encryptJson(payload, state.dekBytes, `heyjournal:entry:${entryId}`);
      const res = await apiFetch("/api/entries", {
        method: "POST",
        body: { id: entryId, ciphertext },
      });
      if (!res.ok) {
        showToast((res.data && res.data.error) || "Could not save entry");
        return;
      }
      state.entries.unshift({
        id: res.data.entry.id,
        createdAt: res.data.entry.createdAt,
        updatedAt: res.data.entry.updatedAt,
        data: payload,
      });
      state.entries.sort((a, b) => new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime());
      state.draft = createFreshDraft();
      renderShell();
      showToast("Entry encrypted & saved");
    }
  } catch (err) {
    console.error(err);
    showToast("Encryption error while saving entry");
  } finally {
    state.savingEntry = false;
    const btn = document.getElementById("btnSaveEntry");
    if (btn) btn.disabled = false;
  }
}

// ============================================================================
// TAB 2: METRICS LIBRARY (CUSTOM NUMERIC METRICS + CLINICAL QUIZ CATALOG)
// ============================================================================
function countMetricOccurrences() {
  const numCounts = new Map();
  const quizCounts = new Map();
  for (const e of state.entries) {
    for (const m of e.data.numericMetrics || []) {
      const key = m.metricId || m.name;
      numCounts.set(key, (numCounts.get(key) || 0) + 1);
    }
    for (const q of e.data.quizResults || []) {
      quizCounts.set(q.quizId, (quizCounts.get(q.quizId) || 0) + 1);
    }
  }
  return { numCounts, quizCounts };
}

function renderMetricsTab(stage) {
  const { numCounts, quizCounts } = countMetricOccurrences();
  const categories = ["All", ...Array.from(new Set(state.quizzes.map((q) => q.category || "General"))).sort()];

  const existingNamesLower = new Set(state.vaultMeta.metrics.map((m) => m.name.toLowerCase()));
  const availableSuggestions = QUICK_METRIC_SUGGESTIONS.filter((s) => !existingNamesLower.has(s.name.toLowerCase()));

  stage.innerHTML = `
    <!-- CUSTOM NUMERIC METRICS -->
    <div class="metro-slot">
      <div class="slot-header">
        <div class="slot-title-group"><h2 class="slot-title">numeric metrics</h2></div>
        <span style="font-size:13px; color:var(--text-secondary);">${state.vaultMeta.metrics.length} tracked</span>
      </div>
      <div class="slot-body">

      <form id="newMetricForm" class="picker-row" style="margin-bottom:4px;">
        <input class="metro-input" id="newMetricName" type="text" placeholder="metric name (e.g. Weight)" required />
        <input class="metro-input" id="newMetricUnit" type="text" placeholder="unit (e.g. lbs, hrs)" style="max-width:170px;" />
        <button class="metro-btn accent" type="submit">+ add metric</button>
      </form>

      ${
        availableSuggestions.length > 0
          ? `
            <div style="display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin-bottom:16px;">
              <span style="font-size:12px; color:var(--text-muted);">quick add:</span>
              ${availableSuggestions
                .map(
                  (s) =>
                    `<button type="button" class="filter-pill" data-suggest-name="${escapeHtml(s.name)}" data-suggest-unit="${escapeHtml(s.unit)}">+ ${escapeHtml(s.name)} (${escapeHtml(s.unit)})</button>`
                )
                .join("")}
            </div>
          `
          : ""
      }

      ${
        state.vaultMeta.metrics.length === 0
          ? `<div class="empty-state" style="padding:18px 8px;">No custom numeric metrics yet. Add one above (like Weight or Sleep) and pin it to appear right on your Input tab.</div>`
          : `
            <div class="library-grid">
              ${state.vaultMeta.metrics
                .map((m) => {
                  const cnt = numCounts.get(m.id) || 0;
                  const isEditing = state.editingMetricId === m.id;
                  if (isEditing) {
                    return `
                      <form class="library-card" data-edit-metric-form="${escapeHtml(m.id)}">
                        <div style="display:flex; flex-direction:column; gap:8px;">
                          <div class="section-label" style="margin-bottom:0;">edit metric</div>
                          <input class="metro-input" data-edit-metric-name type="text" value="${escapeHtml(m.name)}" placeholder="metric name" required />
                          <input class="metro-input" data-edit-metric-unit type="text" value="${escapeHtml(m.unit || "")}" placeholder="unit (optional)" />
                        </div>
                        <div class="library-card-actions">
                          <button type="submit" class="metro-btn accent compact">save</button>
                          <button type="button" class="metro-btn subtle compact" data-cancel-edit-metric>cancel</button>
                        </div>
                      </form>
                    `;
                  }
                  return `
                    <div class="library-card">
                      <div>
                        <div class="library-card-head">
                          <div>
                            <div class="library-card-title">${escapeHtml(m.name)}</div>
                            ${m.unit ? `<div class="library-card-sub">unit: ${escapeHtml(m.unit)}</div>` : ""}
                          </div>
                          <span class="category-badge">${cnt} ${cnt === 1 ? "entry" : "entries"}</span>
                        </div>
                      </div>
                      <div class="library-card-actions">
                        <button type="button" class="metro-btn ${m.pinned ? "accent" : "subtle"} compact" data-pin-metric="${escapeHtml(m.id)}">
                          ${m.pinned ? "pinned to input" : "pin to input"}
                        </button>
                        <button type="button" class="metro-btn subtle compact" data-edit-metric="${escapeHtml(m.id)}">edit</button>
                        <button type="button" class="metro-btn subtle compact" data-delete-metric="${escapeHtml(m.id)}">remove</button>
                      </div>
                    </div>
                  `;
                })
                .join("")}
            </div>
          `
      }
      </div>
    </div>

    <!-- CLINICAL & SELF-ASSESSMENT QUIZ CATALOG -->
    <div class="metro-slot">
      <div class="slot-header">
        <div class="slot-title-group"><h2 class="slot-title">clinical quizzes</h2></div>
        <span style="font-size:13px; color:var(--text-secondary);">${state.quizzes.length} validated scales</span>
      </div>
      <div class="slot-body">

      <p style="font-size:13px; color:var(--text-secondary); margin-bottom:14px; line-height:1.45;">
        Each assessment lives in its own standardized file under <code>quizzes/</code> so new scales can be dropped in anytime.
        Self-assessments support longitudinal reflection and clinician conversations — they are not a medical diagnosis.
      </p>

      <div class="review-toolbar" style="margin-bottom:12px;">
        <input class="metro-input" id="quizSearchInput" type="search" placeholder="search quizzes (e.g. PHQ-9, anxiety, OCD, sleep)..." value="${escapeHtml(state.quizSearch)}" />
      </div>

      <div class="filter-pills">
        ${categories
          .map(
            (cat) =>
              `<button type="button" class="filter-pill ${state.quizCategoryFilter === cat ? "active" : ""}" data-quiz-cat="${escapeHtml(cat)}">${escapeHtml(cat)}</button>`
          )
          .join("")}
      </div>

      <div class="library-grid" id="quizCatalogGrid"></div>
      </div>
    </div>
  `;

  const renderQuizCatalogGrid = () => {
    const grid = stage.querySelector("#quizCatalogGrid");
    if (!grid) return;
    const filtered = state.quizzes.filter((q) => {
      if (state.quizCategoryFilter !== "All" && (q.category || "General") !== state.quizCategoryFilter) {
        return false;
      }
      if (state.quizSearch.trim()) {
        const needle = state.quizSearch.trim().toLowerCase();
        const hay = `${q.name} ${q.fullName || ""} ${q.shortDescription || ""} ${q.category || ""}`.toLowerCase();
        return hay.includes(needle);
      }
      return true;
    });

    if (filtered.length === 0) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1 / -1; padding:18px 8px;">No clinical quizzes match your filter.</div>`;
      return;
    }

    grid.innerHTML = filtered
      .map((q) => {
        const isPinned = state.vaultMeta.pinnedQuizIds.includes(q.id);
        const cnt = quizCounts.get(q.id) || 0;
        const scoring = q.scoring || {};
        const safeUrl = safeExternalUrl(q.resourceUrl);
        return `
          <div class="library-card">
            <div>
              <div class="library-card-head">
                <div>
                  <div class="library-card-title">${escapeHtml(q.name)}</div>
                  <div class="library-card-sub">${escapeHtml(q.fullName || "")}</div>
                </div>
                <span class="category-badge">${escapeHtml(q.category || "Clinical")}</span>
              </div>
              <p class="library-card-desc" style="margin-top:8px;">${escapeHtml(q.shortDescription || "")}</p>
              <div class="library-card-meta" style="margin-top:8px;">
                <span>${q.questions.length} items</span>
                <span>~${escapeHtml(String(q.estimatedMinutes || 2))} min</span>
                <span>range ${escapeHtml(String(scoring.min ?? 0))}–${escapeHtml(String(scoring.max ?? "?"))} ${escapeHtml(scoring.unit || "")}</span>
                ${cnt > 0 ? `<span><strong>${cnt} logged</strong></span>` : ""}
              </div>
            </div>
            <div class="library-card-actions">
              <button type="button" class="metro-btn accent compact" data-take-quiz-now="${escapeHtml(q.id)}">take now</button>
              <button type="button" class="metro-btn ${isPinned ? "accent" : "subtle"} compact" data-pin-quiz="${escapeHtml(q.id)}">
                ${isPinned ? "pinned" : "pin to input"}
              </button>
              ${
                safeUrl
                  ? `<a class="metro-btn subtle compact" href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer">info ↗</a>`
                  : ""
              }
            </div>
          </div>
        `;
      })
      .join("");

    grid.querySelectorAll("[data-pin-quiz]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const qid = btn.getAttribute("data-pin-quiz");
        const idx = state.vaultMeta.pinnedQuizIds.indexOf(qid);
        const q = state.quizById.get(qid);
        if (idx >= 0) {
          state.vaultMeta.pinnedQuizIds.splice(idx, 1);
          await saveVaultMeta(`Unpinned ${q?.name || qid}`);
        } else {
          state.vaultMeta.pinnedQuizIds.push(qid);
          await saveVaultMeta(`Pinned ${q?.name || qid} to Input`);
        }
        renderQuizCatalogGrid();
      });
    });

    grid.querySelectorAll("[data-take-quiz-now]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const qid = btn.getAttribute("data-take-quiz-now");
        setActiveTab("input");
        const existing = state.draft.quizResults.find((r) => r.quizId === qid);
        openQuizRunnerModal(qid, existing ? existing.answers : null);
      });
    });
  };

  renderQuizCatalogGrid();

  // Bindings
  stage.querySelector("#newMetricForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = stage.querySelector("#newMetricName").value.trim();
    const unit = stage.querySelector("#newMetricUnit").value.trim();
    if (!name) return;
    if (state.vaultMeta.metrics.some((m) => m.name.toLowerCase() === name.toLowerCase())) {
      showToast(`"${name}" is already in your metrics`);
      return;
    }
    state.vaultMeta.metrics.push({
      id: generateClientId("metric"),
      kind: "number",
      name,
      unit,
      pinned: true,
      createdAt: new Date().toISOString(),
    });
    await saveVaultMeta(`Added "${name}"`);
    renderMetricsTab(stage);
  });

  stage.querySelectorAll("[data-suggest-name]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const name = btn.getAttribute("data-suggest-name");
      const unit = btn.getAttribute("data-suggest-unit");
      if (state.vaultMeta.metrics.some((m) => m.name.toLowerCase() === name.toLowerCase())) {
        return;
      }
      btn.disabled = true;
      state.vaultMeta.metrics.push({
        id: generateClientId("metric"),
        kind: "number",
        name,
        unit,
        pinned: true,
        createdAt: new Date().toISOString(),
      });
      await saveVaultMeta(`Added "${name}"`);
      renderMetricsTab(stage);
    });
  });

  stage.querySelectorAll("[data-pin-metric]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-pin-metric");
      const m = state.vaultMeta.metrics.find((x) => x.id === id);
      if (!m) return;
      m.pinned = !m.pinned;
      await saveVaultMeta(m.pinned ? `Pinned ${m.name} to Input` : `Unpinned ${m.name}`);
      renderMetricsTab(stage);
    });
  });

  stage.querySelectorAll("[data-edit-metric]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.editingMetricId = btn.getAttribute("data-edit-metric");
      renderMetricsTab(stage);
      stage.querySelector("[data-edit-metric-name]")?.focus();
    });
  });

  stage.querySelectorAll("[data-cancel-edit-metric]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.editingMetricId = null;
      renderMetricsTab(stage);
    });
  });

  stage.querySelectorAll("[data-edit-metric-form]").forEach((form) => {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const id = form.getAttribute("data-edit-metric-form");
      const m = state.vaultMeta.metrics.find((x) => x.id === id);
      if (!m) return;
      const newName = form.querySelector("[data-edit-metric-name]").value.trim();
      const newUnit = form.querySelector("[data-edit-metric-unit]").value.trim();
      if (!newName) {
        showToast("Metric name cannot be empty");
        return;
      }
      if (state.vaultMeta.metrics.some((x) => x.id !== id && x.name.toLowerCase() === newName.toLowerCase())) {
        showToast(`"${newName}" is already in your metrics`);
        return;
      }
      m.name = newName;
      m.unit = newUnit;
      state.editingMetricId = null;
      await saveVaultMeta(`Updated "${newName}"`);
      renderMetricsTab(stage);
    });
  });

  stage.querySelectorAll("[data-delete-metric]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-delete-metric");
      const m = state.vaultMeta.metrics.find((x) => x.id === id);
      if (!m) return;
      if (!confirm(`Remove "${m.name}" from your metrics library? Past entries will keep their recorded values.`)) return;
      state.vaultMeta.metrics = state.vaultMeta.metrics.filter((x) => x.id !== id);
      await saveVaultMeta(`Removed "${m.name}"`);
      renderMetricsTab(stage);
    });
  });

  stage.querySelector("#quizSearchInput").addEventListener("input", (e) => {
    state.quizSearch = e.target.value;
    renderQuizCatalogGrid();
  });

  stage.querySelectorAll("[data-quiz-cat]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.quizCategoryFilter = btn.getAttribute("data-quiz-cat");
      stage.querySelectorAll("[data-quiz-cat]").forEach((el) => {
        el.classList.toggle("active", el.getAttribute("data-quiz-cat") === state.quizCategoryFilter);
      });
      renderQuizCatalogGrid();
    });
  });
}

// ============================================================================
// TAB 3: REVIEW (REVERSE CHRONOLOGICAL DAY CARDS)
// ============================================================================
function renderReviewTab(stage) {
  // Build metric filter options from all recorded entries
  const filterOptions = new Map();
  for (const e of state.entries) {
    for (const m of e.data.numericMetrics || []) {
      filterOptions.set(`num:${m.name.toLowerCase()}`, m.name);
    }
    for (const q of e.data.quizResults || []) {
      filterOptions.set(`quiz:${q.quizId}`, q.quizName || q.quizId);
    }
  }

  stage.innerHTML = `
    <div class="review-toolbar">
      <input class="metro-input" id="reviewSearchInput" type="search"
             placeholder="search journal text, metrics, or quizzes..."
             value="${escapeHtml(state.reviewSearch)}" />
      <select class="metro-select" id="reviewMetricFilter" aria-label="Filter by metric">
        <option value="all">all entries (${state.entries.length})</option>
        ${Array.from(filterOptions.entries())
          .sort((a, b) => a[1].localeCompare(b[1]))
          .map(
            ([val, label]) =>
              `<option value="${escapeHtml(val)}" ${state.reviewMetricFilter === val ? "selected" : ""}>${escapeHtml(label)}</option>`
          )
          .join("")}
      </select>
    </div>
    <div id="reviewEntriesList"></div>
  `;

  const renderReviewEntriesList = () => {
    const listEl = stage.querySelector("#reviewEntriesList");
    if (!listEl) return;

    const needle = state.reviewSearch.trim().toLowerCase();
    const metricFilter = state.reviewMetricFilter;

    const filtered = state.entries.filter((e) => {
      if (metricFilter !== "all") {
        if (metricFilter.startsWith("num:")) {
          const target = metricFilter.slice(4);
          if (!(e.data.numericMetrics || []).some((m) => m.name.toLowerCase() === target)) return false;
        } else if (metricFilter.startsWith("quiz:")) {
          const target = metricFilter.slice(5);
          if (!(e.data.quizResults || []).some((q) => q.quizId === target)) return false;
        }
      }
      if (needle) {
        const textHit = (e.data.text || "").toLowerCase().includes(needle);
        const numHit = (e.data.numericMetrics || []).some((m) => m.name.toLowerCase().includes(needle));
        const quizHit = (e.data.quizResults || []).some((q) =>
          `${q.quizName || ""} ${q.quizId || ""} ${q.band?.label || ""}`.toLowerCase().includes(needle)
        );
        return textHit || numHit || quizHit;
      }
      return true;
    });

    // Group into Day Cards in reverse chronological order
    const dayMap = new Map();
    for (const e of filtered) {
      const key = localDateKeyFromIso(e.data.timestamp);
      if (!dayMap.has(key)) dayMap.set(key, []);
      dayMap.get(key).push(e);
    }
    const dayKeys = Array.from(dayMap.keys()).sort((a, b) => b.localeCompare(a));

    listEl.innerHTML =
      dayKeys.length === 0
        ? `
          <div class="metro-slot">
            <div class="slot-body">
              <div class="empty-state">
                ${
                  state.entries.length === 0
                    ? `Your journal is empty. Head to <strong>input</strong> to write your first encrypted entry.`
                    : `No entries match your current search or filter.`
                }
              </div>
            </div>
          </div>
        `
        : dayKeys
            .map((dateKey) => {
              const { label, relative } = formatDayHeading(dateKey);
              const dayEntries = dayMap.get(dateKey);
              return `
                <article class="metro-slot">
                  <div class="slot-header">
                    <div class="slot-title-group">
                      <h2 class="slot-title">${escapeHtml(label)}</h2>
                    </div>
                    ${relative ? `<span class="day-card-rel">${escapeHtml(relative)}</span>` : ""}
                  </div>
                  <div class="slot-body">
                  ${dayEntries
                    .map((entry) => {
                      const menuOpen = state.openEntryMenuId === entry.id;
                      const numPills = (entry.data.numericMetrics || []).map(
                        (m) => `
                          <span class="metric-chip">
                            <strong>${escapeHtml(m.name)}</strong> · ${escapeHtml(String(m.value))}${m.unit ? ` ${escapeHtml(m.unit)}` : ""}
                          </span>
                        `
                      );
                      const quizPills = (entry.data.quizResults || []).map(
                        (q, qIdx) => `
                          <button type="button" class="metric-chip clickable"
                                  data-inspect-entry="${escapeHtml(entry.id)}" data-quiz-idx="${qIdx}"
                                  title="Inspect full quiz responses">
                            <strong>${escapeHtml(q.quizName || q.quizId)}</strong>
                            · ${escapeHtml(formatScoreValue(q.score, q.unit))}
                            ${
                              q.band
                                ? `<span class="severity-badge level-${escapeHtml(q.band.level || "low")}">${escapeHtml(q.band.label)}</span>`
                                : ""
                            }
                          </button>
                        `
                      );
                      return `
                        <div class="day-entry">
                          <div class="day-entry-head">
                            <span class="day-entry-time">${escapeHtml(formatEntryTime(entry.data.timestamp))}</span>
                            <div class="entry-menu-wrap">
                              <button type="button" class="metro-ellipsis-btn" data-entry-menu="${escapeHtml(entry.id)}" aria-label="Entry options" aria-expanded="${menuOpen}">
                                <svg class="ellipsis-dots-svg" viewBox="0 0 18 4" aria-hidden="true">
                                  <circle cx="2" cy="2" r="1.75" fill="currentColor" />
                                  <circle cx="9" cy="2" r="1.75" fill="currentColor" />
                                  <circle cx="16" cy="2" r="1.75" fill="currentColor" />
                                </svg>
                              </button>
                              ${
                                menuOpen
                                  ? `
                                    <div class="entry-menu-popover">
                                      <button type="button" class="entry-menu-item" data-edit-entry="${escapeHtml(entry.id)}">edit entry</button>
                                      <button type="button" class="entry-menu-item danger" data-delete-entry="${escapeHtml(entry.id)}">delete entry</button>
                                    </div>
                                  `
                                  : ""
                              }
                            </div>
                          </div>
                          ${
                            entry.data.text
                              ? `<div class="day-entry-text">${escapeHtml(entry.data.text)}</div>`
                              : ""
                          }
                          ${
                            numPills.length > 0 || quizPills.length > 0
                              ? `<div class="day-entry-metrics">${numPills.join("")}${quizPills.join("")}</div>`
                              : ""
                          }
                        </div>
                      `;
                    })
                    .join("")}
                  </div>
                </article>
              `;
            })
            .join("");

    listEl.querySelectorAll("[data-entry-menu]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const id = btn.getAttribute("data-entry-menu");
        state.openEntryMenuId = state.openEntryMenuId === id ? null : id;
        renderReviewEntriesList();
      });
    });

    listEl.querySelectorAll("[data-edit-entry]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-edit-entry");
        startEditingEntry(id);
      });
    });

    listEl.querySelectorAll("[data-delete-entry]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-delete-entry");
        await handleDeleteEntry(id);
      });
    });

    listEl.querySelectorAll("[data-inspect-entry]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const entryId = btn.getAttribute("data-inspect-entry");
        const qIdx = Number(btn.getAttribute("data-quiz-idx"));
        const entry = state.entries.find((x) => x.id === entryId);
        if (entry && entry.data.quizResults && entry.data.quizResults[qIdx]) {
          openQuizBreakdownModal(entry.data.quizResults[qIdx], entry.data.timestamp);
        }
      });
    });
  };

  renderReviewEntriesList();

  stage.querySelector("#reviewSearchInput").addEventListener("input", (e) => {
    state.reviewSearch = e.target.value;
    renderReviewEntriesList();
  });

  stage.querySelector("#reviewMetricFilter").addEventListener("change", (e) => {
    state.reviewMetricFilter = e.target.value;
    renderReviewEntriesList();
  });
}

function startEditingEntry(entryId) {
  const entry = state.entries.find((e) => e.id === entryId);
  if (!entry) return;
  if (state.draft.editingEntryId !== entryId && hasUnsavedDraft(state.draft)) {
    if (!confirm("Discard your current unsaved draft on the Input tab and edit this entry?")) {
      return;
    }
  }

  const draft = createFreshDraft();
  draft.editingEntryId = entry.id;
  draft.editingUpdatedAt = entry.updatedAt || "";
  draft.timestampLocal = toLocalDateTimeInputValue(new Date(entry.data.timestamp));
  draft.timestampManuallyEdited = true;
  draft.text = entry.data.text || "";
  draft.quizResults = structuredCloneSafe(entry.data.quizResults || []);

  const pinnedIds = new Set(state.vaultMeta.metrics.filter((m) => m.pinned).map((m) => m.id));
  for (const m of entry.data.numericMetrics || []) {
    if (pinnedIds.has(m.metricId)) {
      draft.numericValues[m.metricId] = String(m.value);
    } else {
      draft.extraNumerics.push({ ...m });
    }
  }

  state.draft = draft;
  state.openEntryMenuId = null;
  setActiveTab("input");
}

async function handleDeleteEntry(entryId) {
  if (!confirm("Permanently delete this encrypted entry? This cannot be undone.")) return;
  const res = await apiFetch(`/api/entries/${encodeURIComponent(entryId)}`, { method: "DELETE" });
  if (!res.ok) {
    showToast((res.data && res.data.error) || "Could not delete entry");
    return;
  }
  state.entries = state.entries.filter((e) => e.id !== entryId);
  if (state.draft.editingEntryId === entryId) {
    state.draft = createFreshDraft();
  }
  state.openEntryMenuId = null;
  renderShell();
  showToast("Entry deleted");
}

// ============================================================================
// TAB 4: REPORT (GRAPHS FOR ALL METRICS WITH >= 3 DATA POINTS + SEVERITY BANDS)
// ============================================================================
function collectMetricSeries() {
  const numericGroups = new Map();
  const quizGroups = new Map();
  const metricDefById = new Map((state.vaultMeta.metrics || []).map((m) => [m.id, m]));

  for (const e of state.entries) {
    const tsMs = new Date(e.data.timestamp).getTime();
    if (!Number.isFinite(tsMs)) continue;

    for (const m of e.data.numericMetrics || []) {
      const val = Number(m.value);
      if (!Number.isFinite(val)) continue;
      const key = m.metricId || `name:${m.name.toLowerCase()}`;
      const liveDef = m.metricId ? metricDefById.get(m.metricId) : null;
      if (!numericGroups.has(key)) {
        numericGroups.set(key, {
          key: `num:${key}`,
          kind: "number",
          name: (liveDef && liveDef.name) || m.name,
          unit: liveDef ? liveDef.unit || "" : m.unit || "",
          higherIsWorse: null,
          points: [],
        });
      }
      numericGroups.get(key).points.push({ tsMs, value: val, entryId: e.id });
    }

    for (const q of e.data.quizResults || []) {
      const val = Number(q.score);
      if (!Number.isFinite(val)) continue;
      const def = state.quizById.get(q.quizId);
      if (!quizGroups.has(q.quizId)) {
        quizGroups.set(q.quizId, {
          key: `quiz:${q.quizId}`,
          kind: "quiz",
          quizId: q.quizId,
          quizDef: def || null,
          name: (def && def.name) || q.quizName || q.quizId,
          fullName: (def && def.fullName) || "",
          unit: (def && def.scoring?.unit) || q.unit || "pts",
          minBound: def?.scoring?.min ?? q.minScore ?? 0,
          maxBound: def?.scoring?.max ?? q.maxScore ?? null,
          higherIsWorse: def?.scoring?.higherIsWorse ?? q.higherIsWorse ?? true,
          severityBands: def?.scoring?.severityBands || null,
          subscaleDefs: def?.scoring?.subscales || [],
          points: [],
        });
      }
      quizGroups.get(q.quizId).points.push({
        tsMs,
        value: val,
        bandLabel: q.band?.label || "",
        subscales: q.subscales || [],
        entryId: e.id,
      });
    }
  }

  return [...quizGroups.values(), ...numericGroups.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function renderReportTab(stage) {
  const allSeries = collectMetricSeries();
  const readySeries = allSeries.filter((s) => s.points.length >= 3);
  const buildingSeries = allSeries.filter((s) => s.points.length > 0 && s.points.length < 3);

  const ranges = [
    { key: "30d", label: "30d" },
    { key: "90d", label: "90d" },
    { key: "1y", label: "1y" },
    { key: "all", label: "all" },
  ];

  stage.innerHTML = `
    <div class="report-toolbar">
      <div class="filter-pills" style="margin-bottom:0;">
        ${ranges
          .map(
            (r) =>
              `<button type="button" class="filter-pill ${state.reportRange === r.key ? "active" : ""}" data-report-range="${r.key}">${r.label}</button>`
          )
          .join("")}
      </div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button type="button" class="metro-btn subtle compact" id="btnPrintSummary">clinician summary</button>
        <button type="button" class="metro-btn subtle compact" id="btnExportCsv">export csv</button>
      </div>
    </div>

    ${
      readySeries.length === 0
        ? `
          <div class="metro-slot">
            <div class="slot-body">
              <div class="empty-state">
                Trend graphs appear automatically once any tracked metric or clinical quiz has at least <strong>3 data points</strong>.
                ${
                  buildingSeries.length > 0
                    ? `<br/>You're already collecting data for ${buildingSeries.length} ${buildingSeries.length === 1 ? "metric" : "metrics"} below!`
                    : `<br/>Log metrics or take a quiz on the <strong>input</strong> tab to get started.`
                }
              </div>
            </div>
          </div>
        `
        : `<div id="reportChartsContainer"></div>`
    }

    ${
      buildingSeries.length > 0
        ? `
          <div class="metro-slot">
            <div class="slot-header">
              <div class="slot-title-group"><h2 class="slot-title">building baseline</h2></div>
              <span class="category-badge">needs 3 points</span>
            </div>
            <div class="slot-body">
              <div class="baseline-list">
                ${buildingSeries
                  .map(
                    (s) =>
                      `<span class="metric-chip"><strong>${escapeHtml(s.name)}</strong> · ${s.points.length} / 3 entries</span>`
                  )
                  .join("")}
              </div>
            </div>
          </div>
        `
        : ""
    }
  `;

  // Render each chart card with >= 3 total points
  const container = stage.querySelector("#reportChartsContainer");
  if (container) {
    for (const s of readySeries) {
      const activeSubId = state.activeSubscaleByQuiz[s.key] || "__total__";
      const subDef =
        s.kind === "quiz" && activeSubId !== "__total__"
          ? (s.subscaleDefs || []).find((sd) => sd.id === activeSubId)
          : null;

      let rawPoints = s.points;
      let chartUnit = s.unit;
      let minBound = s.minBound ?? null;
      let maxBound = s.maxBound ?? null;
      let severityBands = s.severityBands || null;

      if (subDef) {
        rawPoints = s.points
          .map((pt) => {
            const match = (pt.subscales || []).find((x) => x.id === subDef.id);
            if (!match || !Number.isFinite(Number(match.score))) return null;
            return {
              tsMs: pt.tsMs,
              value: Number(match.score),
              bandLabel: match.band?.label || "",
            };
          })
          .filter(Boolean);
        chartUnit = subDef.unit || "pts";
        minBound = typeof subDef.min === "number" ? subDef.min : 0;
        maxBound = typeof subDef.max === "number" ? subDef.max : null;
        severityBands = subDef.severityBands || null;
      }

      const rangedPoints = filterPointsByRange(rawPoints, state.reportRange);
      const stats = computeSeriesStats(rangedPoints);

      const latestBand =
        stats && Array.isArray(severityBands)
          ? findSeverityBand(stats.latest, severityBands)
          : null;

      let deltaHtml = "";
      if (stats && stats.count >= 2) {
        const diff = Math.round(stats.deltaPeriod * 10) / 10;
        const sign = diff > 0 ? "+" : "";
        let cls = "";
        if (s.higherIsWorse === true && diff !== 0) {
          cls = diff < 0 ? "improved" : "worsened";
        } else if (s.higherIsWorse === false && diff !== 0) {
          cls = diff > 0 ? "improved" : "worsened";
        }
        const unitSuffix = chartUnit === "%" ? "%" : chartUnit ? ` ${chartUnit}` : "";
        deltaHtml = `<span class="stat-meta stat-delta ${cls}">${sign}${diff}${escapeHtml(unitSuffix)} over period</span>`;
      }

      const card = document.createElement("section");
      card.className = "metro-slot";
      const unitSuffix = chartUnit === "%" ? "%" : chartUnit ? ` ${chartUnit}` : "";

      card.innerHTML = `
        <div class="slot-header">
          <div class="slot-title-group">
            <h2 class="slot-title">${escapeHtml(s.name)}${subDef ? ` · ${escapeHtml(subDef.name)}` : ""}</h2>
          </div>
          ${
            latestBand
              ? `<span class="severity-badge level-${escapeHtml(latestBand.level)}">${escapeHtml(latestBand.label)}</span>`
              : `<span class="category-badge">${rangedPoints.length} ${rangedPoints.length === 1 ? "entry" : "entries"}</span>`
          }
        </div>
        <div class="slot-body">
        ${s.fullName ? `<div style="font-size:12px; color:var(--text-muted); margin-top:-4px;">${escapeHtml(s.fullName)}</div>` : ""}

        ${
          s.kind === "quiz" && Array.isArray(s.subscaleDefs) && s.subscaleDefs.length > 0
            ? `
              <div class="filter-pills" style="margin-bottom:4px;">
                <button type="button" class="filter-pill ${activeSubId === "__total__" ? "active" : ""}" data-sub-key="${escapeHtml(s.key)}" data-sub-id="__total__">total</button>
                ${s.subscaleDefs
                  .map(
                    (sd) =>
                      `<button type="button" class="filter-pill ${activeSubId === sd.id ? "active" : ""}" data-sub-key="${escapeHtml(s.key)}" data-sub-id="${escapeHtml(sd.id)}">${escapeHtml(sd.name)}</button>`
                  )
                  .join("")}
              </div>
            `
            : ""
        }

        ${
          stats
            ? `
              <div class="chart-card-stats" style="margin-bottom:2px;">
                <span class="stat-primary">${escapeHtml(String(Math.round(stats.latest * 10) / 10))}${escapeHtml(unitSuffix)}</span>
                ${deltaHtml}
                <span class="stat-meta">avg ${escapeHtml(String(Math.round(stats.avg * 10) / 10))} · range ${escapeHtml(String(Math.round(stats.min * 10) / 10))}–${escapeHtml(String(Math.round(stats.max * 10) / 10))}</span>
              </div>
            `
            : ""
        }

        <div class="chart-mount"></div>
        </div>
      `;

      renderMetricChart(card.querySelector(".chart-mount"), {
        points: rangedPoints,
        unit: chartUnit,
        minBound,
        maxBound,
        severityBands,
      });

      card.querySelectorAll("[data-sub-key]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.activeSubscaleByQuiz[btn.getAttribute("data-sub-key")] = btn.getAttribute("data-sub-id");
          renderReportTab(stage);
        });
      });

      container.appendChild(card);
    }
  }

  // Range & Export bindings
  stage.querySelectorAll("[data-report-range]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.reportRange = btn.getAttribute("data-report-range");
      renderReportTab(stage);
    });
  });

  stage.querySelector("#btnPrintSummary")?.addEventListener("click", () => {
    openPrintableClinicianSummary({
      entries: state.entries,
      seriesList: allSeries,
      rangeKey: state.reportRange,
      username: state.authStatus.user?.username || "",
    });
  });

  stage.querySelector("#btnExportCsv")?.addEventListener("click", () => {
    downloadDecryptedCsv(state.entries);
    showToast("Decrypted CSV downloaded");
  });
}

// ============================================================================
// GUIDED QUIZ RUNNER & QUIZ BREAKDOWN MODALS
// ============================================================================
function openQuizRunnerModal(quizId, existingAnswers = null) {
  const quiz = state.quizById.get(quizId);
  if (!quiz) return;
  state.modalState = {
    type: "quiz-runner",
    quiz,
    answers: existingAnswers ? { ...existingAnswers } : {},
    stepIndex: 0,
    viewMode: "step", // "step" | "all" | "summary"
  };
  renderModal();
}

function openQuizBreakdownModal(quizResult, timestampStr) {
  state.modalState = {
    type: "quiz-breakdown",
    quizResult,
    quizDef: state.quizById.get(quizResult.quizId) || null,
    timestampStr,
  };
  renderModal();
}

function closeModal() {
  state.modalState = null;
  const backdrop = document.getElementById("modalBackdrop");
  if (backdrop) {
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
  }
}

function renderModal() {
  const backdrop = document.getElementById("modalBackdrop");
  const panel = document.getElementById("modalPanel");
  if (!backdrop || !panel || !state.modalState) return;
  backdrop.classList.add("open");
  backdrop.setAttribute("aria-hidden", "false");

  if (state.modalState.type === "quiz-runner") {
    renderQuizRunnerPanel(panel);
  } else if (state.modalState.type === "quiz-breakdown") {
    renderQuizBreakdownPanel(panel);
  } else if (state.modalState.type === "recovery-prompt") {
    renderRecoveryPromptPanel(panel);
  } else if (state.modalState.type === "recovery-key") {
    renderRecoveryKeyPanel(panel);
  }
}

function renderRecoveryPromptPanel(panel) {
  panel.innerHTML = `
    <div class="flyout-head">
      <div>
        <h2 class="slot-title">save a recovery key?</h2>
        <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">optional · zero-knowledge protection</div>
      </div>
      <button type="button" class="metro-btn subtle compact" id="btnCloseModal">skip</button>
    </div>
    <p style="font-size:14px; color:var(--text-secondary); line-height:1.5;">
      Because HeyJournal is zero-knowledge encrypted, the server cannot reset a forgotten password.
      You can generate an optional <strong>printable Emergency Recovery Key</strong> now (or anytime later in Settings → Security &amp; Export) to store safely offline.
    </p>
    <div class="auth-actions">
      <button type="button" class="metro-btn accent" id="btnPromptGenRecovery">generate recovery key</button>
      <button type="button" class="metro-btn subtle" id="btnPromptSkip">skip for now</button>
    </div>
  `;
  panel.querySelector("#btnCloseModal").addEventListener("click", closeModal);
  panel.querySelector("#btnPromptSkip").addEventListener("click", closeModal);
  panel.querySelector("#btnPromptGenRecovery").addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = "generating...";
    const ok = await handleGenerateRecoveryKey();
    if (!ok && btn.isConnected) {
      btn.disabled = false;
      btn.textContent = "generate recovery key";
    }
  });
}

function renderRecoveryKeyPanel(panel) {
  const { recoveryKey, username } = state.modalState;
  panel.innerHTML = `
    <div class="flyout-head">
      <div>
        <h2 class="slot-title">emergency recovery key</h2>
        <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">shown once · store safely offline</div>
      </div>
      <button type="button" class="metro-btn subtle compact" id="btnCloseModal">done</button>
    </div>
    <div class="recovery-key-display">${escapeHtml(recoveryKey)}</div>
    <div class="auth-notice" style="margin-bottom:0;">
      <strong>Important:</strong> The server never stores this key and cannot show it again.
      Print it or save it in a password manager. Anyone with your username and this key can reset your password and decrypt your journal.
    </div>
    <div class="auth-actions">
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button type="button" class="metro-btn subtle compact" id="btnCopyRecoveryKey">copy key</button>
        <button type="button" class="metro-btn accent compact" id="btnPrintRecoveryKey">print / save sheet</button>
      </div>
      <button type="button" class="metro-btn subtle compact" id="btnRecoverySaved">i've saved it</button>
    </div>
  `;
  panel.querySelector("#btnCloseModal").addEventListener("click", closeModal);
  panel.querySelector("#btnRecoverySaved").addEventListener("click", closeModal);
  panel.querySelector("#btnCopyRecoveryKey").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(recoveryKey);
      showToast("Recovery key copied to clipboard");
    } catch (e) {
      showToast("Select the key above to copy it");
    }
  });
  panel.querySelector("#btnPrintRecoveryKey").addEventListener("click", () => {
    openPrintableRecoverySheet({
      username,
      recoveryKey,
      serverUrl: typeof window !== "undefined" ? window.location.origin : "",
    });
  });
}

function renderQuizRunnerPanel(panel) {
  const ms = state.modalState;
  const quiz = ms.quiz;
  const questions = quiz.questions || [];
  const answeredCount = questions.filter((q) => ms.answers[q.id] !== undefined).length;
  const pct = questions.length > 0 ? Math.round((answeredCount / questions.length) * 100) : 0;

  if (ms.viewMode === "summary") {
    const result = scoreQuiz(quiz, ms.answers);
    panel.innerHTML = `
      <div class="flyout-head">
        <div>
          <h2 class="slot-title">${escapeHtml(quiz.name)} result</h2>
          <div style="font-size:13px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(quiz.fullName || "")}</div>
        </div>
        <button type="button" class="metro-btn subtle compact" id="btnCloseModal">close</button>
      </div>

      ${
        result.safetyFlags.length > 0
          ? result.safetyFlags
              .map((f) => `<div class="safety-callout"><strong>Support Resource:</strong> ${escapeHtml(f.message)}</div>`)
              .join("")
          : ""
      }

      <div style="display:flex; align-items:baseline; gap:14px; flex-wrap:wrap;">
        <span class="quiz-summary-score">${escapeHtml(formatScoreValue(result.score, result.unit))}</span>
        <span style="font-size:14px; color:var(--text-muted);">of ${escapeHtml(String(result.maxScore))}</span>
        ${
          result.band
            ? `<span class="severity-badge level-${escapeHtml(result.band.level)}">${escapeHtml(result.band.label)}</span>`
            : ""
        }
      </div>

      ${
        result.subscales.length > 0
          ? `
            <div>
              <div class="section-label">subscales</div>
              <div class="subscale-grid">
                ${result.subscales
                  .map(
                    (sub) => `
                    <div class="subscale-card">
                      <div style="font-size:12px; color:var(--text-secondary);">${escapeHtml(sub.name)}</div>
                      <div style="font-size:20px; font-weight:500; margin-top:2px;">
                        ${escapeHtml(String(sub.score))}${sub.max ? `<span style="font-size:12px; color:var(--text-muted);"> / ${escapeHtml(String(sub.max))}</span>` : ""}
                      </div>
                      ${sub.band ? `<div style="font-size:11px; color:var(--accent-text); margin-top:2px;">${escapeHtml(sub.band.label)}</div>` : ""}
                    </div>
                  `
                  )
                  .join("")}
              </div>
            </div>
          `
          : ""
      }

      <p style="font-size:12px; color:var(--text-secondary); line-height:1.45;">
        ${escapeHtml(quiz.scoring?.formulaDescription || "")}
        ${
          safeExternalUrl(quiz.resourceUrl)
            ? ` <a href="${escapeHtml(safeExternalUrl(quiz.resourceUrl))}" target="_blank" rel="noopener noreferrer">${escapeHtml(quiz.resourceLabel || "Learn more")} ↗</a>`
            : ""
        }
      </p>

      <div class="auth-actions">
        <button type="button" class="metro-btn accent" id="btnAttachQuizResult">attach score to entry</button>
        <button type="button" class="metro-btn subtle" id="btnReviewQuizAnswers">review answers</button>
      </div>
    `;

    panel.querySelector("#btnCloseModal").addEventListener("click", closeModal);
    panel.querySelector("#btnReviewQuizAnswers").addEventListener("click", () => {
      ms.viewMode = "all";
      renderQuizRunnerPanel(panel);
    });
    panel.querySelector("#btnAttachQuizResult").addEventListener("click", () => {
      const idx = state.draft.quizResults.findIndex((r) => r.quizId === quiz.id);
      if (idx >= 0) state.draft.quizResults[idx] = result;
      else state.draft.quizResults.push(result);
      closeModal();
      if (state.activeTab === "input") renderActiveTab();
      showToast(`Attached ${quiz.name} (${formatScoreValue(result.score, result.unit)})`);
    });
    return;
  }

  if (ms.viewMode === "all") {
    panel.innerHTML = `
      <div class="flyout-head">
        <div>
          <h2 class="slot-title">${escapeHtml(quiz.name)}</h2>
          <div style="font-size:12px; color:var(--text-secondary);">${answeredCount} of ${questions.length} answered</div>
        </div>
        <div style="display:flex; gap:8px;">
          <button type="button" class="metro-btn subtle compact" id="btnSwitchToStep">step view</button>
          <button type="button" class="metro-btn subtle compact" id="btnCloseModal">cancel</button>
        </div>
      </div>
      <div class="quiz-progress-track"><div class="quiz-progress-fill" style="width:${pct}%;"></div></div>
      <p style="font-size:14px; color:var(--text-secondary);">${escapeHtml(quiz.timeframe || "")}</p>

      <div style="display:flex; flex-direction:column; gap:16px;">
        ${questions
          .map((q, idx) => {
            const opts = getQuestionOptions(quiz, q);
            const cur = ms.answers[q.id];
            return `
              <div style="padding-bottom:12px; border-bottom:1px solid var(--border-color);">
                <div style="font-size:15px; margin-bottom:8px;">
                  <span style="color:var(--text-muted); margin-right:6px;">${idx + 1}.</span>${escapeHtml(q.text)}
                </div>
                <div class="filter-pills" style="margin-bottom:0;">
                  ${opts
                    .map(
                      (o) =>
                        `<button type="button" class="filter-pill ${cur !== undefined && Number(cur) === Number(o.value) ? "active" : ""}"
                                 data-all-q="${escapeHtml(q.id)}" data-all-val="${escapeHtml(String(o.value))}">${escapeHtml(o.label)}</button>`
                    )
                    .join("")}
                </div>
              </div>
            `;
          })
          .join("")}
      </div>

      <div class="auth-actions">
        <button type="button" class="metro-btn accent" id="btnFinishQuiz" ${answeredCount < questions.length ? "disabled" : ""}>
          ${answeredCount < questions.length ? `answer ${questions.length - answeredCount} remaining` : "calculate score"}
        </button>
      </div>
    `;

    panel.querySelector("#btnCloseModal").addEventListener("click", closeModal);
    panel.querySelector("#btnSwitchToStep").addEventListener("click", () => {
      ms.viewMode = "step";
      renderQuizRunnerPanel(panel);
    });
    panel.querySelectorAll("[data-all-q]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const prevScroll = panel.scrollTop;
        ms.answers[btn.getAttribute("data-all-q")] = Number(btn.getAttribute("data-all-val"));
        renderQuizRunnerPanel(panel);
        panel.scrollTop = prevScroll;
      });
    });
    panel.querySelector("#btnFinishQuiz").addEventListener("click", () => {
      if (answeredCount === questions.length) {
        ms.viewMode = "summary";
        renderQuizRunnerPanel(panel);
      }
    });
    return;
  }

  // Default Step-by-Step Guided Mode
  const q = questions[ms.stepIndex] || questions[0];
  const opts = getQuestionOptions(quiz, q);
  const currentVal = ms.answers[q.id];

  panel.innerHTML = `
    <div class="flyout-head">
      <div>
        <h2 class="slot-title">${escapeHtml(quiz.name)}</h2>
        <div style="font-size:12px; color:var(--text-secondary);">
          question ${ms.stepIndex + 1} of ${questions.length}
          ${
            safeExternalUrl(quiz.resourceUrl)
              ? ` · <a href="${escapeHtml(safeExternalUrl(quiz.resourceUrl))}" target="_blank" rel="noopener noreferrer">${escapeHtml(quiz.resourceLabel || "about")} ↗</a>`
              : ""
          }
        </div>
      </div>
      <div style="display:flex; gap:8px;">
        <button type="button" class="metro-btn subtle compact" id="btnSwitchToAll">all items</button>
        <button type="button" class="metro-btn subtle compact" id="btnCloseModal">cancel</button>
      </div>
    </div>

    <div class="quiz-progress-track">
      <div class="quiz-progress-fill" style="width:${Math.round(((ms.stepIndex + 1) / questions.length) * 100)}%;"></div>
    </div>

    ${quiz.timeframe ? `<div style="font-size:13px; color:var(--text-secondary);">${escapeHtml(quiz.timeframe)}</div>` : ""}

    <div class="quiz-question-text">${escapeHtml(q.text)}</div>

    <div class="quiz-options-list">
      ${opts
        .map(
          (o, oIdx) => `
          <button type="button" class="quiz-option-btn ${
            currentVal !== undefined && Number(currentVal) === Number(o.value) ? "selected" : ""
          }" data-step-val="${escapeHtml(String(o.value))}">
            <span>${escapeHtml(o.label)}</span>
            <span class="quiz-option-key">${oIdx + 1}</span>
          </button>
        `
        )
        .join("")}
    </div>

    <div class="auth-actions">
      <button type="button" class="metro-btn subtle compact" id="btnStepPrev" ${ms.stepIndex === 0 ? "disabled" : ""}>← back</button>
      ${
        answeredCount === questions.length
          ? `<button type="button" class="metro-btn accent compact" id="btnJumpSummary">view score →</button>`
          : `<button type="button" class="metro-btn subtle compact" id="btnStepNext" ${
              ms.stepIndex >= questions.length - 1 ? "disabled" : ""
            }>skip →</button>`
      }
    </div>
  `;

  panel.querySelector("#btnCloseModal").addEventListener("click", closeModal);
  panel.querySelector("#btnSwitchToAll").addEventListener("click", () => {
    ms.viewMode = "all";
    renderQuizRunnerPanel(panel);
  });
  panel.querySelector("#btnStepPrev")?.addEventListener("click", () => {
    if (ms.stepIndex > 0) {
      ms.stepIndex--;
      renderQuizRunnerPanel(panel);
    }
  });
  panel.querySelector("#btnStepNext")?.addEventListener("click", () => {
    if (ms.stepIndex < questions.length - 1) {
      ms.stepIndex++;
      renderQuizRunnerPanel(panel);
    }
  });
  panel.querySelector("#btnJumpSummary")?.addEventListener("click", () => {
    ms.viewMode = "summary";
    renderQuizRunnerPanel(panel);
  });

  panel.querySelectorAll("[data-step-val]").forEach((btn) => {
    btn.addEventListener("click", () => {
      ms.answers[q.id] = Number(btn.getAttribute("data-step-val"));
      if (ms.stepIndex < questions.length - 1) {
        ms.stepIndex++;
      } else {
        const firstMissing = questions.findIndex((item) => ms.answers[item.id] === undefined);
        if (firstMissing >= 0) {
          ms.stepIndex = firstMissing;
          showToast("Please answer the remaining question");
        } else {
          ms.viewMode = "summary";
        }
      }
      renderQuizRunnerPanel(panel);
    });
  });
}

function renderQuizBreakdownPanel(panel) {
  const { quizResult: qr, quizDef, timestampStr } = state.modalState;
  const details = Array.isArray(qr.answerDetails) ? qr.answerDetails : [];
  panel.innerHTML = `
    <div class="flyout-head">
      <div>
        <h2 class="slot-title">${escapeHtml(qr.quizName || qr.quizId)}</h2>
        <div style="font-size:12px; color:var(--text-secondary);">
          ${escapeHtml(new Date(timestampStr).toLocaleString())}
          ${
            safeExternalUrl(quizDef?.resourceUrl)
              ? ` · <a href="${escapeHtml(safeExternalUrl(quizDef.resourceUrl))}" target="_blank" rel="noopener noreferrer">${escapeHtml(quizDef.resourceLabel || "reference")} ↗</a>`
              : ""
          }
        </div>
      </div>
      <button type="button" class="metro-btn subtle compact" id="btnCloseModal">close</button>
    </div>

    <div style="display:flex; align-items:baseline; gap:14px; flex-wrap:wrap;">
      <span class="quiz-summary-score">${escapeHtml(formatScoreValue(qr.score, qr.unit))}</span>
      ${qr.maxScore ? `<span style="font-size:14px; color:var(--text-muted);">of ${escapeHtml(String(qr.maxScore))}</span>` : ""}
      ${
        qr.band
          ? `<span class="severity-badge level-${escapeHtml(qr.band.level || "low")}">${escapeHtml(qr.band.label)}</span>`
          : ""
      }
    </div>

    ${
      Array.isArray(qr.subscales) && qr.subscales.length > 0
        ? `
          <div>
            <div class="section-label">subscales</div>
            <div class="subscale-grid">
              ${qr.subscales
                .map(
                  (sub) => `
                  <div class="subscale-card">
                    <div style="font-size:12px; color:var(--text-secondary);">${escapeHtml(sub.name)}</div>
                    <div style="font-size:18px; font-weight:500; margin-top:2px;">
                      ${escapeHtml(String(sub.score))}${sub.max ? `<span style="font-size:12px; color:var(--text-muted);"> / ${escapeHtml(String(sub.max))}</span>` : ""}
                    </div>
                    ${sub.band ? `<div style="font-size:11px; color:var(--accent-text);">${escapeHtml(sub.band.label)}</div>` : ""}
                  </div>
                `
                )
                .join("")}
            </div>
          </div>
        `
        : ""
    }

    ${
      details.length > 0
        ? `
          <div>
            <div class="section-label">recorded responses (encrypted at rest)</div>
            <div style="display:flex; flex-direction:column; gap:10px;">
              ${details
                .map(
                  (item, idx) => `
                  <div style="padding-bottom:8px; border-bottom:1px solid var(--border-color); font-size:13px;">
                    <div style="color:var(--text-primary); margin-bottom:3px;">${idx + 1}. ${escapeHtml(item.text)}</div>
                    <div style="color:var(--accent-text); font-weight:500;">
                      ${escapeHtml(item.label || String(item.value ?? "—"))}
                      <span style="color:var(--text-muted); font-weight:400;">(${escapeHtml(String(item.value ?? "—"))})</span>
                    </div>
                  </div>
                `
                )
                .join("")}
            </div>
          </div>
        `
        : `<p style="font-size:13px; color:var(--text-secondary);">Individual item answers were not stored for this entry.</p>`
    }
  `;

  panel.querySelector("#btnCloseModal").addEventListener("click", closeModal);
}

// ============================================================================
// SETTINGS, APPEARANCE (20 THEMES), SECURITY/EXPORT & ADMIN FLYOUT DRAWER
// ============================================================================
function openFlyout(tab = "appearance") {
  state.flyoutOpen = true;
  state.flyoutTab = tab;
  const backdrop = document.getElementById("flyoutBackdrop");
  if (backdrop) {
    backdrop.classList.add("open");
    backdrop.setAttribute("aria-hidden", "false");
  }
  renderFlyout();
  if (tab === "admin" && state.authStatus.user?.isAdmin) {
    refreshAdminData();
  }
}

function closeFlyout() {
  state.flyoutOpen = false;
  const backdrop = document.getElementById("flyoutBackdrop");
  if (backdrop) {
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
  }
}

async function refreshAdminData() {
  state.adminLoadError = "";
  const res = await apiFetch("/api/admin/users");
  if (res.ok) {
    state.adminData = res.data;
  } else {
    state.adminLoadError = (res.data && res.data.error) || "Could not load admin status.";
  }
  if (state.flyoutOpen && state.flyoutTab === "admin") {
    renderFlyout();
  }
}

function renderFlyout() {
  const panel = document.getElementById("flyoutPanel");
  if (!panel) return;

  const isUnlocked = Boolean(state.authStatus.authenticated && state.dekBytes);
  const isAdmin = Boolean(isUnlocked && state.authStatus.user?.isAdmin);

  if (!isUnlocked && state.flyoutTab !== "appearance") {
    state.flyoutTab = "appearance";
  }
  if (!isAdmin && state.flyoutTab === "admin") {
    state.flyoutTab = "appearance";
  }

  const sameTab = panel.getAttribute("data-rendered-tab") === state.flyoutTab;
  const prevScroll = sameTab ? panel.scrollTop : 0;
  panel.setAttribute("data-rendered-tab", state.flyoutTab);

  panel.innerHTML = `
    <div class="flyout-head">
      <h2 class="flyout-title">settings</h2>
      <button type="button" class="metro-btn subtle compact" id="btnCloseFlyout">close</button>
    </div>

    <div class="sub-pivots">
      <button type="button" class="pivot-tab ${state.flyoutTab === "appearance" ? "active" : ""}" data-flyout-tab="appearance">appearance</button>
      ${
        isUnlocked
          ? `<button type="button" class="pivot-tab ${state.flyoutTab === "security" ? "active" : ""}" data-flyout-tab="security">security &amp; export</button>`
          : ""
      }
      ${
        isAdmin
          ? `<button type="button" class="pivot-tab ${state.flyoutTab === "admin" ? "active" : ""}" data-flyout-tab="admin">admin</button>`
          : ""
      }
    </div>

    <div id="flyoutTabBody" style="display:flex; flex-direction:column; gap:20px;"></div>
  `;

  panel.querySelector("#btnCloseFlyout").addEventListener("click", closeFlyout);
  panel.querySelectorAll("[data-flyout-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const nextTab = btn.getAttribute("data-flyout-tab");
      state.flyoutTab = nextTab;
      renderFlyout();
      if (nextTab === "admin") refreshAdminData();
    });
  });

  const body = panel.querySelector("#flyoutTabBody");
  if (state.flyoutTab === "appearance") {
    renderAppearanceFlyoutTab(body, isUnlocked);
  } else if (state.flyoutTab === "security") {
    renderSecurityFlyoutTab(body);
  } else if (state.flyoutTab === "admin") {
    renderAdminFlyoutTab(body);
  }
  panel.scrollTop = prevScroll;
}

function renderAppearanceFlyoutTab(body, isUnlocked) {
  const settings = state.vaultMeta.settings;
  const activeTheme = getActiveThemeDef(settings);
  const effectiveMode = getEffectiveThemeMode(settings, activeTheme);
  const isDark = effectiveMode === "dark";
  const supportsMultipleModes = Array.isArray(activeTheme.modes) && activeTheme.modes.length > 1;
  const themeAccents = getThemeAccents(activeTheme);
  const currentAccentHex = getEffectiveThemeAccent(settings, activeTheme).toLowerCase();

  body.innerHTML = `
    <div class="flyout-section">
      <div class="flyout-section-title">theme (${ThemeRegistry.size} available)</div>
      <p style="font-size:12px; color:var(--text-secondary);">
        Drop-in visual themes loaded from <code>public/themes/</code>.
      </p>
      <div class="theme-picker-grid" id="themePickerGrid"></div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">color mode</div>
      ${
        supportsMultipleModes
          ? `
            <div class="extension-card">
              <div>
                <div class="card-title">dark mode</div>
                <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">
                  Switch ${escapeHtml(activeTheme.name)} between dark and light palettes.
                </div>
              </div>
              <div class="metro-toggle ${isDark ? "on" : ""}" id="toggleThemeMode" role="switch" aria-checked="${isDark}" tabindex="0"></div>
            </div>
          `
          : `
            <div class="extension-card">
              <div>
                <div class="card-title">fixed palette mode</div>
                <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">
                  ${escapeHtml(activeTheme.name)} is designed specifically as a ${escapeHtml(effectiveMode)}-mode theme.
                </div>
              </div>
              <span class="category-badge">${escapeHtml(effectiveMode)} only</span>
            </div>
          `
      }
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">${escapeHtml(activeTheme.name)} accent color</div>
      <div class="swatch-grid" id="swatchGrid"></div>
    </div>

    ${
      isUnlocked
        ? `
          <div class="flyout-section">
            <div class="flyout-section-title">journal title</div>
            <div class="picker-row">
              <input class="metro-input" id="journalNameInput" value="${escapeHtml(settings.journalName || "heyjournal")}" />
              <button type="button" class="metro-btn accent compact" id="btnSaveJournalName">rename</button>
            </div>
          </div>
        `
        : ""
    }
  `;

  const pickerGrid = body.querySelector("#themePickerGrid");
  Array.from(ThemeRegistry.values()).forEach((tDef) => {
    const tModes = Array.isArray(tDef.modes) && tDef.modes.length > 0 ? tDef.modes : ["dark", "light"];
    const previewMode = tModes.includes(effectiveMode) ? effectiveMode : tDef.defaultMode || tModes[0];
    const p =
      (tDef.preview && (tDef.preview[previewMode] || tDef.preview.dark || tDef.preview.light)) || {
        canvas: "#000000",
        tile: "#111111",
        accent: tDef.defaultAccent || "#00ABA9",
      };
    const dotColors = Object.values(tDef.extensionAccents || {}).slice(0, 3);
    const modeBadge = tModes.length > 1 ? "Dark · Light" : tModes[0] === "dark" ? "Dark Only" : "Light Only";

    const card = document.createElement("button");
    card.type = "button";
    card.className = `theme-card ${tDef.id === activeTheme.id ? "selected" : ""}`;
    card.setAttribute("aria-pressed", String(tDef.id === activeTheme.id));
    card.innerHTML = `
      <div class="theme-preview-strip" style="background:${sanitizeColor(p.canvas, "#000000")};">
        <div class="theme-preview-tile" style="background:${sanitizeColor(p.tile, "#111111")};">
          <span class="theme-preview-accent" style="background:${sanitizeColor(p.accent, "#00ABA9")};"></span>
          ${dotColors.map((c) => `<span class="theme-preview-dot" style="background:${sanitizeColor(c, "#00ABA9")};"></span>`).join("")}
        </div>
      </div>
      <div class="theme-card-head">
        <span class="theme-card-name">${escapeHtml(tDef.name)}</span>
        <span class="theme-mode-badge">${escapeHtml(modeBadge)}</span>
      </div>
      <div class="theme-card-desc">${escapeHtml(tDef.description || "")}</div>
    `;
    card.addEventListener("click", async () => {
      const prevId = settings.themeId || "metro";
      if (!settings.themeAccents || typeof settings.themeAccents !== "object") settings.themeAccents = {};
      if (settings.accentColor) settings.themeAccents[prevId] = sanitizeColor(settings.accentColor);
      settings.themeId = tDef.id;
      if (!tModes.includes(settings.theme)) {
        settings.theme = tDef.defaultMode && tModes.includes(tDef.defaultMode) ? tDef.defaultMode : tModes[0];
      }
      settings.accentColor = sanitizeColor(settings.themeAccents[tDef.id], sanitizeColor(tDef.defaultAccent, "#00ABA9"));
      applyUserThemeAndTitle();
      renderFlyout();
      if (isUnlocked) await saveVaultMeta(`Theme: ${tDef.name}`);
      else showToast(`Theme: ${tDef.name}`);
    });
    pickerGrid.appendChild(card);
  });

  const modeToggle = body.querySelector("#toggleThemeMode");
  if (modeToggle) {
    const flipMode = async () => {
      settings.theme = isDark ? "light" : "dark";
      applyUserThemeAndTitle();
      renderFlyout();
      if (isUnlocked) await saveVaultMeta(`${activeTheme.name} ${settings.theme} mode`);
    };
    modeToggle.addEventListener("click", flipMode);
    modeToggle.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        flipMode();
      }
    });
  }

  const swatchGrid = body.querySelector("#swatchGrid");
  themeAccents.forEach((sw) => {
    const isSelected = currentAccentHex === sw.hex.toLowerCase();
    const el = document.createElement("button");
    el.type = "button";
    el.className = `color-swatch ${isSelected ? "selected" : ""}`;
    el.style.backgroundColor = sw.hex;
    el.title = sw.name;
    el.setAttribute("aria-label", `${sw.name} (${sw.hex})`);
    el.addEventListener("click", async () => {
      settings.accentColor = sw.hex;
      if (!settings.themeAccents || typeof settings.themeAccents !== "object") settings.themeAccents = {};
      settings.themeAccents[activeTheme.id] = sw.hex;
      applyUserThemeAndTitle();
      renderFlyout();
      if (isUnlocked) await saveVaultMeta(`Accent: ${sw.name}`);
    });
    swatchGrid.appendChild(el);
  });

  body.querySelector("#btnSaveJournalName")?.addEventListener("click", async () => {
    const val = body.querySelector("#journalNameInput").value.trim() || "heyjournal";
    settings.journalName = val;
    applyUserThemeAndTitle();
    await saveVaultMeta(`Renamed to ${val}`);
  });
}

function renderSecurityFlyoutTab(body) {
  const backendLabel = getCryptoBackendLabel();
  const isNative = isNativeWebCryptoAvailable();
  const user = state.authStatus.user || {};
  const autoLockMinutes = Number(state.vaultMeta.settings?.autoLockMinutes ?? 60);
  const kdfIters = Number(user.kdfIterations || DEFAULT_KDF_ITERATIONS);

  body.innerHTML = `
    <div class="flyout-section">
      <div class="flyout-section-title">zero-knowledge encryption</div>
      <div class="extension-card">
        <div>
          <div class="card-title">AES-256-GCM active</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">
            Engine: ${escapeHtml(backendLabel)} · PBKDF2 ${kdfIters.toLocaleString()} iterations<br/>
            Keys stay strictly on your device. Plaintext never reaches the server.
          </div>
        </div>
        <span class="category-badge">${isNative ? "HTTPS" : "HTTP"}</span>
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">session &amp; auto-lock</div>
      <div class="extension-card">
        <div>
          <div class="card-title">stay unlocked in this tab</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
            Keeps your key in browser <code>sessionStorage</code> until you close this tab or click Lock.
          </div>
        </div>
        <div class="metro-toggle ${state.stayUnlocked ? "on" : ""}" id="toggleStayUnlocked" role="switch" aria-checked="${state.stayUnlocked}" tabindex="0"></div>
      </div>
      <div class="extension-card">
        <div>
          <div class="card-title">auto-lock on inactivity</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
            Clears your vault key from memory after idle time (great for shared household devices).
          </div>
        </div>
        <select class="metro-select" id="selectAutoLock" aria-label="Auto-lock timeout" style="width:auto; min-width:120px;">
          <option value="0" ${autoLockMinutes === 0 ? "selected" : ""}>Off</option>
          <option value="15" ${autoLockMinutes === 15 ? "selected" : ""}>15 min</option>
          <option value="30" ${autoLockMinutes === 30 ? "selected" : ""}>30 min</option>
          <option value="60" ${autoLockMinutes === 60 ? "selected" : ""}>1 hour</option>
        </select>
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">emergency recovery key</div>
      <div class="extension-card">
        <div>
          <div class="card-title">${user.hasRecoveryKey ? "recovery key active" : "not configured"}</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
            ${
              user.hasRecoveryKey
                ? `Created ${escapeHtml(user.recoveryCreatedAt ? new Date(user.recoveryCreatedAt).toLocaleDateString() : "previously")}. Lets you reset a forgotten password locally without exposing plaintext to the server.`
                : "Generate a printable offline key so you can recover your encrypted vault if you ever forget your password."
            }
          </div>
        </div>
        <span class="category-badge">${user.hasRecoveryKey ? "ready" : "off"}</span>
      </div>
      <div style="display:flex; flex-wrap:wrap; gap:8px;">
        <button type="button" class="metro-btn subtle compact" id="btnGenRecoveryKey">
          ${user.hasRecoveryKey ? "regenerate key" : "generate recovery key"}
        </button>
        ${
          user.hasRecoveryKey
            ? `<button type="button" class="metro-btn danger compact" id="btnRemoveRecoveryKey">remove key</button>`
            : ""
        }
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">client-side export &amp; import</div>
      <p style="font-size:12px; color:var(--text-secondary);">
        Exports are decrypted locally on your device — store them securely. Importing re-encrypts entries locally before uploading.
      </p>
      <div style="display:flex; flex-wrap:wrap; gap:8px;">
        <button type="button" class="metro-btn subtle compact" id="btnFlyoutExportJson">download json</button>
        <button type="button" class="metro-btn subtle compact" id="btnFlyoutExportCsv">download csv</button>
        <button type="button" class="metro-btn subtle compact" id="btnFlyoutClinician">clinician summary</button>
        <button type="button" class="metro-btn subtle compact" id="btnFlyoutImportJson">import json</button>
        <input type="file" id="importJsonFileInput" accept="application/json,.json" class="hidden" />
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">change password</div>
      <p style="font-size:12px; color:var(--text-secondary);">
        Re-wraps your vault key locally with your new password (${DEFAULT_KDF_ITERATIONS.toLocaleString()} PBKDF2 iterations) without altering historical entries.
      </p>
      <form id="changePasswordForm" style="display:flex; flex-direction:column; gap:10px;">
        <input class="metro-input" id="curPwInput" type="password" placeholder="current password" required autocomplete="current-password" />
        <input class="metro-input" id="newPwInput" type="password" placeholder="new password (min 8 chars)" required autocomplete="new-password" />
        <input class="metro-input" id="newPwConfirmInput" type="password" placeholder="confirm new password" required autocomplete="new-password" />
        <div>
          <button type="submit" class="metro-btn accent compact" id="btnChangePw">update password</button>
        </div>
      </form>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">vault session &amp; account</div>
      <div style="display:flex; flex-wrap:wrap; gap:10px; align-items:center;">
        <button type="button" class="metro-btn danger" id="btnFlyoutLogout">lock &amp; sign out</button>
        <button type="button" class="metro-btn subtle compact" id="btnToggleDeleteSelf">delete my account...</button>
      </div>
      <form id="deleteSelfForm" class="hidden" style="display:flex; flex-direction:column; gap:10px; margin-top:8px; padding:12px; background:var(--bg-tile); border-left:3px solid var(--danger-color);">
        <p style="font-size:12px; color:var(--text-secondary);">
          Permanently deletes your account and all encrypted entries on this server. Export your JSON first if you want a copy.
        </p>
        <input class="metro-input" id="delSelfPwInput" type="password" placeholder="confirm current password" required autocomplete="current-password" />
        <div style="display:flex; gap:8px;">
          <button type="submit" class="metro-btn danger compact" id="btnConfirmDeleteSelf">permanently delete account</button>
          <button type="button" class="metro-btn subtle compact" id="btnCancelDeleteSelf">cancel</button>
        </div>
      </form>
    </div>
  `;

  const toggleEl = body.querySelector("#toggleStayUnlocked");
  const flipStay = () => {
    saveStayUnlockedPref(!state.stayUnlocked);
    renderFlyout();
    showToast(state.stayUnlocked ? "Will stay unlocked until tab closes" : "Session key cleared on reload");
  };
  toggleEl.addEventListener("click", flipStay);
  toggleEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      flipStay();
    }
  });

  body.querySelector("#selectAutoLock").addEventListener("change", async (e) => {
    const mins = Math.max(0, parseInt(e.target.value, 10) || 0);
    state.vaultMeta.settings.autoLockMinutes = mins;
    state.lastActivityMs = Date.now();
    await saveVaultMeta(mins > 0 ? `Auto-lock set to ${mins} min` : "Auto-lock disabled");
  });

  body.querySelector("#btnGenRecoveryKey").addEventListener("click", async (e) => {
    if (user.hasRecoveryKey && !confirm("Generate a new recovery key? Your previous recovery key will stop working.")) {
      return;
    }
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = "generating...";
    await handleGenerateRecoveryKey();
    btn.disabled = false;
    btn.textContent = state.authStatus.user?.hasRecoveryKey ? "regenerate key" : "generate recovery key";
  });

  body.querySelector("#btnRemoveRecoveryKey")?.addEventListener("click", async () => {
    if (!confirm("Remove your emergency recovery key? Without it, a forgotten password cannot be recovered.")) return;
    const res = await apiFetch("/api/auth/recovery-key", { method: "DELETE" });
    if (res.ok) {
      state.authStatus.user = res.data.user;
      renderFlyout();
      showToast("Recovery key removed");
    } else {
      showToast((res.data && res.data.error) || "Could not remove recovery key");
    }
  });

  body.querySelector("#btnFlyoutExportJson").addEventListener("click", () => {
    downloadDecryptedJson(state.entries, state.vaultMeta, state.authStatus.user?.username || "user");
    showToast("Decrypted JSON downloaded");
  });
  body.querySelector("#btnFlyoutExportCsv").addEventListener("click", () => {
    downloadDecryptedCsv(state.entries);
    showToast("Decrypted CSV downloaded");
  });
  body.querySelector("#btnFlyoutClinician").addEventListener("click", () => {
    openPrintableClinicianSummary({
      entries: state.entries,
      seriesList: collectMetricSeries(),
      rangeKey: state.reportRange,
      username: state.authStatus.user?.username || "",
    });
  });

  const fileInput = body.querySelector("#importJsonFileInput");
  body.querySelector("#btnFlyoutImportJson").addEventListener("click", () => {
    fileInput.value = "";
    fileInput.click();
  });
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) return;
    await handleImportJsonFile(file);
  });

  body.querySelector("#btnFlyoutLogout").addEventListener("click", handleLockOrLogout);

  const delForm = body.querySelector("#deleteSelfForm");
  body.querySelector("#btnToggleDeleteSelf").addEventListener("click", () => {
    delForm.classList.toggle("hidden");
    if (!delForm.classList.contains("hidden")) {
      body.querySelector("#delSelfPwInput")?.focus();
    }
  });
  body.querySelector("#btnCancelDeleteSelf").addEventListener("click", () => {
    delForm.reset();
    delForm.classList.add("hidden");
  });
  delForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = body.querySelector("#delSelfPwInput").value;
    if (!pw) return;
    if (!confirm("Final confirmation: permanently delete your account and all encrypted journal entries?")) return;
    const btn = body.querySelector("#btnConfirmDeleteSelf");
    btn.disabled = true;
    btn.textContent = "deleting...";
    try {
      const curUser = state.authStatus.user;
      const derived = await deriveAuthAndKek(pw, curUser.kdfSalt, curUser.kdfIterations);
      derived.kekBytes.fill(0);
      const res = await apiFetch("/api/auth/account", {
        method: "DELETE",
        body: { currentAuthKey: derived.authKeyB64 },
      });
      if (!res.ok) {
        showToast((res.data && res.data.error) || "Could not delete account", 4500);
        btn.disabled = false;
        btn.textContent = "permanently delete account";
        return;
      }
      _wipeDecryptedMemoryState();
      state.authUsernameDraft = "";
      state.autoLockReason = "";
      const statusRes = await apiFetch("/api/auth/status");
      if (statusRes.ok) {
        state.authStatus = statusRes.data;
      } else {
        state.authStatus.authenticated = false;
        state.authStatus.user = null;
      }
      state.authMode = state.authStatus.userCount === 0 ? "register" : "login";
      state.authError = "";
      renderShell();
      showToast("Account permanently deleted");
    } catch (err) {
      showToast("Error verifying password");
      btn.disabled = false;
      btn.textContent = "permanently delete account";
    }
  });

  body.querySelector("#changePasswordForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const curPw = body.querySelector("#curPwInput").value;
    const newPw = body.querySelector("#newPwInput").value;
    const confirmPw = body.querySelector("#newPwConfirmInput").value;
    if (newPw.length < 8) {
      showToast("New password must be at least 8 characters");
      return;
    }
    if (newPw !== confirmPw) {
      showToast("New passwords do not match");
      return;
    }
    const btn = body.querySelector("#btnChangePw");
    btn.disabled = true;
    btn.textContent = "updating...";
    try {
      const user = state.authStatus.user;
      const curDerived = await deriveAuthAndKek(curPw, user.kdfSalt, user.kdfIterations);
      // Verify locally that current password actually unwraps the DEK
      const verifiedDek = await unwrapDek(user.wrappedDek, curDerived.kekBytes);
      curDerived.kekBytes.fill(0);
      const newSalt = generateSaltB64();
      const newDerived = await deriveAuthAndKek(newPw, newSalt, DEFAULT_KDF_ITERATIONS);
      const newWrappedDek = await wrapDek(verifiedDek, newDerived.kekBytes);
      verifiedDek.fill(0);
      newDerived.kekBytes.fill(0);

      const res = await apiFetch("/api/auth/change-password", {
        method: "POST",
        body: {
          currentAuthKey: curDerived.authKeyB64,
          newAuthKey: newDerived.authKeyB64,
          newKdfSalt: newSalt,
          newKdfIterations: DEFAULT_KDF_ITERATIONS,
          newWrappedDek,
        },
      });
      if (!res.ok) {
        showToast((res.data && res.data.error) || "Password change failed");
        btn.disabled = false;
        btn.textContent = "update password";
        return;
      }
      state.authStatus.user = res.data.user;
      persistSessionDekIfEnabled();
      body.querySelector("#changePasswordForm").reset();
      btn.disabled = false;
      btn.textContent = "update password";
      showToast("Password updated & other sessions revoked");
    } catch (err) {
      showToast("Current password is incorrect");
      btn.disabled = false;
      btn.textContent = "update password";
    }
  });
}

async function handleImportJsonFile(file) {
  if (!state.dekBytes) return;
  let parsed = null;
  try {
    const text = await file.text();
    parsed = JSON.parse(text);
  } catch (e) {
    showToast("Could not read JSON file — invalid syntax");
    return;
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.entries)) {
    showToast("Unsupported file format (expected HeyJournal JSON export)");
    return;
  }

  const incomingEntries = parsed.entries;
  const incomingMetrics = Array.isArray(parsed.metrics) ? parsed.metrics : [];
  if (incomingEntries.length === 0 && incomingMetrics.length === 0) {
    showToast("This export file contains no entries or metrics");
    return;
  }

  const msg = `Import up to ${incomingEntries.length} ${incomingEntries.length === 1 ? "entry" : "entries"} and ${incomingMetrics.length} ${incomingMetrics.length === 1 ? "metric" : "metrics"} from "${file.name}"? Existing entries with matching IDs will be kept untouched.`;
  if (!confirm(msg)) return;

  showToast("Encrypting & importing entries locally...", 4000);

  // Merge new custom numeric metrics (avoid duplicate IDs or names)
  let metricsAdded = 0;
  for (const m of incomingMetrics) {
    if (!m || typeof m.name !== "string" || !m.name.trim()) continue;
    const exists = state.vaultMeta.metrics.some(
      (x) => (m.id && x.id === m.id) || x.name.toLowerCase() === m.name.trim().toLowerCase()
    );
    if (!exists) {
      state.vaultMeta.metrics.push({
        id: typeof m.id === "string" && /^[a-zA-Z0-9_-]{8,64}$/.test(m.id) ? m.id : generateClientId("metric"),
        kind: "number",
        name: m.name.trim(),
        unit: typeof m.unit === "string" ? m.unit.trim() : "",
        pinned: Boolean(m.pinned),
        createdAt: typeof m.createdAt === "string" ? m.createdAt : new Date().toISOString(),
      });
      metricsAdded++;
    }
  }
  if (metricsAdded > 0) {
    await saveVaultMeta();
  }

  // Encrypt non-duplicate entries locally and upload in chunks of 200
  const existingIds = new Set(state.entries.map((e) => e.id));
  const prepared = [];
  let localSkipped = 0;
  for (const raw of incomingEntries) {
    if (!raw || typeof raw !== "object") continue;
    const rawId = typeof raw.id === "string" ? raw.id.trim() : "";
    const entryId = /^[a-zA-Z0-9_-]{8,64}$/.test(rawId) ? rawId : generateClientId("entry");
    if (existingIds.has(entryId)) {
      localSkipped++;
      continue;
    }
    const payload = normalizeEntryData(raw, raw.createdAt || new Date().toISOString());
    if (!payload.text && payload.numericMetrics.length === 0 && payload.quizResults.length === 0) {
      continue;
    }
    const ciphertext = await encryptJson(payload, state.dekBytes, `heyjournal:entry:${entryId}`);
    prepared.push({ id: entryId, ciphertext, payload });
    existingIds.add(entryId);
  }

  let totalImported = 0;
  let serverSkipped = 0;
  const MAX_CHUNK_COUNT = 200;
  const MAX_CHUNK_BYTES = 4 * 1024 * 1024;
  let cursor = 0;
  while (cursor < prepared.length) {
    const chunk = [];
    let chunkBytes = 0;
    while (cursor < prepared.length && chunk.length < MAX_CHUNK_COUNT) {
      const nextItem = prepared[cursor];
      const estBytes = nextItem.ciphertext.length + nextItem.id.length + 32;
      if (chunk.length > 0 && chunkBytes + estBytes > MAX_CHUNK_BYTES) {
        break;
      }
      chunk.push(nextItem);
      chunkBytes += estBytes;
      cursor++;
    }
    const res = await apiFetch("/api/entries/batch", {
      method: "POST",
      body: {
        entries: chunk.map((c) => ({ id: c.id, ciphertext: c.ciphertext })),
      },
    });
    if (!res.ok) {
      showToast((res.data && res.data.error) || "Import interrupted by server error", 4500);
      break;
    }
    totalImported += Number(res.data.importedCount || 0);
    serverSkipped += Number(res.data.skippedCount || 0);
    const payloadById = new Map(chunk.map((c) => [c.id, c.payload]));
    for (const row of res.data.imported || []) {
      const data = payloadById.get(row.id);
      if (data) {
        state.entries.push({
          id: row.id,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
          data,
        });
      }
    }
  }

  state.entries.sort((a, b) => new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime());
  renderShell();
  const totalSkipped = localSkipped + serverSkipped;
  const summaryParts = [`Imported ${totalImported} ${totalImported === 1 ? "entry" : "entries"}`];
  if (metricsAdded > 0) summaryParts.push(`${metricsAdded} ${metricsAdded === 1 ? "metric" : "metrics"}`);
  if (totalSkipped > 0) summaryParts.push(`${totalSkipped} skipped as duplicates`);
  showToast(summaryParts.join(" · "), 4500);
}

function renderAdminFlyoutTab(body) {
  if (!state.adminData) {
    if (state.adminLoadError) {
      body.innerHTML = `
        <div class="empty-state">
          <p style="margin-bottom:12px;">${escapeHtml(state.adminLoadError)}</p>
          <button type="button" class="metro-btn subtle compact" id="btnRetryAdminLoad">retry</button>
        </div>
      `;
      body.querySelector("#btnRetryAdminLoad")?.addEventListener("click", () => {
        state.adminLoadError = "";
        renderFlyout();
        refreshAdminData();
      });
      return;
    }
    body.innerHTML = `<div class="empty-state">Loading server accounts &amp; backup status...</div>`;
    return;
  }

  const { allowSignups, users = [], backups = [] } = state.adminData;
  const selfId = state.authStatus.user?.id;

  body.innerHTML = `
    <div class="flyout-section">
      <div class="flyout-section-title">registration policy</div>
      <div class="extension-card">
        <div>
          <div class="card-title">allow new accounts</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
            When enabled, others on your server can register their own isolated encrypted vaults.
          </div>
        </div>
        <div class="metro-toggle ${allowSignups ? "on" : ""}" id="toggleAllowSignups" role="switch" aria-checked="${allowSignups}" tabindex="0"></div>
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">registered accounts (${users.length})</div>
      <p style="font-size:12px; color:var(--text-secondary);">
        As admin, you can remove accounts, but all journal entries remain zero-knowledge encrypted and unreadable to you.
      </p>
      <div style="display:flex; flex-direction:column; gap:8px;">
        ${users
          .map(
            (u) => `
            <div class="extension-card">
              <div>
                <div class="card-title" style="text-transform:none;">${escapeHtml(u.username)} ${
              u.isAdmin ? '<span class="category-badge" style="margin-left:6px;">admin</span>' : ""
            }</div>
                <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
                  ${u.entryCount} encrypted ${u.entryCount === 1 ? "entry" : "entries"} · joined ${escapeHtml(
              new Date(u.createdAt).toLocaleDateString()
            )}
                </div>
              </div>
              ${
                u.id === selfId
                  ? `<span class="category-badge">you</span>`
                  : `<div style="display:flex; gap:6px; flex-wrap:wrap;">
                       <button type="button" class="metro-btn subtle compact" data-admin-role-user="${escapeHtml(u.id)}" data-admin-role-next="${u.isAdmin ? "0" : "1"}" data-admin-role-name="${escapeHtml(u.username)}">
                         ${u.isAdmin ? "remove admin" : "make admin"}
                       </button>
                       <button type="button" class="metro-btn danger compact" data-admin-del-user="${escapeHtml(u.id)}" data-admin-del-name="${escapeHtml(u.username)}">delete</button>
                     </div>`
              }
            </div>
          `
          )
          .join("")}
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">encrypted sqlite backups (3:00 am daily)</div>
      <div style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
        <span style="font-size:12px; color:var(--text-secondary);">Stored in <code>data/backups/</code> (encrypted at rest)</span>
        <button type="button" class="metro-btn subtle compact" id="btnTriggerBackup">backup now</button>
      </div>
      ${
        backups.length === 0
          ? `<div style="font-size:12px; color:var(--text-muted);">No backups created yet. Next automatic run is at 3:00 AM server time.</div>`
          : `
            <div style="display:flex; flex-direction:column; gap:6px;">
              ${backups
                .slice(0, 7)
                .map(
                  (b) => `
                  <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; font-size:12px; color:var(--text-secondary); padding:6px 10px; background:var(--bg-tile);">
                    <span style="font-family:var(--font-mono); overflow:hidden; text-overflow:ellipsis;">${escapeHtml(b.name)}</span>
                    <div style="display:flex; align-items:center; gap:10px; flex-shrink:0;">
                      <span>${Math.max(1, Math.round(b.sizeBytes / 1024))} KB</span>
                      <a class="metro-btn subtle compact" style="min-height:26px; padding:2px 8px; font-size:11px;" href="/api/admin/backups/${encodeURIComponent(b.name)}" download="${escapeHtml(b.name)}">download</a>
                    </div>
                  </div>
                `
                )
                .join("")}
              ${
                backups.length > 7
                  ? `<div style="font-size:11px; color:var(--text-muted); padding:2px 4px;">Showing latest 7 of ${backups.length} backups in <code>data/backups/</code>.</div>`
                  : ""
              }
            </div>
          `
      }
    </div>
  `;

  const toggleEl = body.querySelector("#toggleAllowSignups");
  const flipSignups = async () => {
    const res = await apiFetch("/api/admin/settings", {
      method: "PUT",
      body: { allowSignups: !allowSignups },
    });
    if (res.ok) {
      state.adminData.allowSignups = res.data.allowSignups;
      state.authStatus.allowSignups = res.data.allowSignups;
      renderFlyout();
      showToast(res.data.allowSignups ? "Open registration enabled" : "New registrations disabled");
    } else {
      showToast((res.data && res.data.error) || "Could not update registration policy");
    }
  };
  toggleEl.addEventListener("click", flipSignups);
  toggleEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      flipSignups();
    }
  });

  body.querySelectorAll("[data-admin-role-user]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const uid = btn.getAttribute("data-admin-role-user");
      const uname = btn.getAttribute("data-admin-role-name");
      const nextAdmin = btn.getAttribute("data-admin-role-next") === "1";
      const verb = nextAdmin ? `Grant admin privileges to "${uname}"?` : `Remove admin privileges from "${uname}"?`;
      if (!confirm(verb)) return;
      const res = await apiFetch(`/api/admin/users/${encodeURIComponent(uid)}/role`, {
        method: "PUT",
        body: { isAdmin: nextAdmin },
      });
      if (res.ok) {
        showToast(nextAdmin ? `"${uname}" is now an admin` : `Removed admin role from "${uname}"`);
        await refreshAdminData();
      } else {
        showToast((res.data && res.data.error) || "Could not update role");
      }
    });
  });

  body.querySelectorAll("[data-admin-del-user]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const uid = btn.getAttribute("data-admin-del-user");
      const uname = btn.getAttribute("data-admin-del-name");
      if (!confirm(`Permanently delete account "${uname}" and all of its encrypted entries?`)) return;
      const res = await apiFetch(`/api/admin/users/${encodeURIComponent(uid)}`, { method: "DELETE" });
      if (res.ok) {
        showToast(`Deleted account "${uname}"`);
        await refreshAdminData();
      } else {
        showToast((res.data && res.data.error) || "Could not delete account");
      }
    });
  });

  const backupBtn = body.querySelector("#btnTriggerBackup");
  backupBtn.addEventListener("click", async () => {
    backupBtn.disabled = true;
    backupBtn.textContent = "backing up...";
    const res = await apiFetch("/api/admin/backup", { method: "POST" });
    if (res.ok) {
      state.adminData.backups = res.data.backups || [];
      renderFlyout();
      showToast(`Backup saved: ${res.data.backupName}`);
    } else {
      backupBtn.disabled = false;
      backupBtn.textContent = "backup now";
      showToast((res.data && res.data.error) || "Backup failed");
    }
  });
}

// ============================================================================
// GLOBAL EVENTS & BOOTSTRAP
// ============================================================================
function wireGlobalEvents() {
  document.getElementById("btnSettings")?.addEventListener("click", () => openFlyout("appearance"));
  document.getElementById("btnSyncVault")?.addEventListener("click", () => syncVaultInBackground({ manual: true }));
  document.getElementById("btnLockVault")?.addEventListener("click", () => {
    lockVaultLocally();
    showToast("Vault locked");
  });

  // Track user activity (throttled) for configurable auto-lock inactivity timer
  const markActivity = () => {
    const now = Date.now();
    if (now - state.lastActivityMs > 5000) {
      state.lastActivityMs = now;
    }
  };
  for (const evt of ["pointerdown", "keydown", "touchstart", "scroll"]) {
    document.addEventListener(evt, markActivity, { passive: true });
  }
  setInterval(checkAutoLock, 15000);

  // On tab wake / return: enforce auto-lock immediately, or quietly sync newer entries from other devices
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") return;
    checkAutoLock();
    if (state.authStatus.authenticated && state.dekBytes && Date.now() - state.lastVaultSyncMs >= 60000) {
      syncVaultInBackground({ manual: false });
    }
  });

  // Warn before accidentally closing/reloading a tab with unsaved journal text or metrics
  window.addEventListener("beforeunload", (e) => {
    if (state.authStatus.authenticated && state.dekBytes && hasUnsavedDraft(state.draft)) {
      e.preventDefault();
      e.returnValue = "";
    }
  });

  document.getElementById("flyoutBackdrop")?.addEventListener("click", (e) => {
    if (e.target.id === "flyoutBackdrop") closeFlyout();
  });

  document.getElementById("modalBackdrop")?.addEventListener("click", (e) => {
    if (e.target.id === "modalBackdrop") closeModal();
  });

  document.querySelectorAll("#primaryPivotNav .pivot-tab").forEach((btn) => {
    btn.addEventListener("click", () => setActiveTab(btn.getAttribute("data-tab")));
  });

  // Close open entry menus on outside click
  document.addEventListener("click", () => {
    if (state.openEntryMenuId) {
      state.openEntryMenuId = null;
      if (state.activeTab === "review") renderActiveTab();
    }
  });

  // Keyboard shortcuts: Esc closes modal/flyout/menu; number keys 1-9 answer step-by-step quiz
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (state.modalState) closeModal();
      else if (state.flyoutOpen) closeFlyout();
      else if (state.openEntryMenuId) {
        state.openEntryMenuId = null;
        if (state.activeTab === "review") renderActiveTab();
      }
      return;
    }
    if (
      !e.ctrlKey &&
      !e.metaKey &&
      !e.altKey &&
      state.modalState &&
      state.modalState.type === "quiz-runner" &&
      state.modalState.viewMode === "step"
    ) {
      const idx = parseInt(e.key, 10) - 1;
      if (idx >= 0 && idx <= 8) {
        const btns = document.querySelectorAll("#modalPanel [data-step-val]");
        if (btns[idx]) {
          e.preventDefault();
          btns[idx].click();
        }
      }
    }
  });
}

async function boot() {
  state.stayUnlocked = loadStayUnlockedPref();
  wireGlobalEvents();

  // Load cached theme preferences early if present
  try {
    const cachedRaw = localStorage.getItem("heyjournal_active_theme_cache_v1");
    if (cachedRaw) {
      const cached = JSON.parse(cachedRaw);
      if (cached.themeId) state.vaultMeta.settings.themeId = cached.themeId;
      if (cached.mode) state.vaultMeta.settings.theme = cached.mode;
      if (cached.accent) state.vaultMeta.settings.accentColor = cached.accent;
    }
  } catch (e) {}

  await Promise.all([
    discoverAndLoadThemes(),
    (async () => {
      const qRes = await apiFetch("/api/quizzes");
      if (qRes.ok && Array.isArray(qRes.data.quizzes)) {
        state.quizzes = qRes.data.quizzes;
        state.quizById.clear();
        for (const q of state.quizzes) state.quizById.set(q.id, q);
      }
    })(),
    (async () => {
      const aRes = await apiFetch("/api/auth/status");
      if (aRes.ok) state.authStatus = aRes.data;
    })(),
  ]);

  applyUserThemeAndTitle();

  // If browser cookie is active AND user opted to stay unlocked in this tab, restore DEK from sessionStorage
  if (state.authStatus.authenticated && state.authStatus.user) {
    const restored = tryRestoreSessionDek(state.authStatus.user.id);
    if (restored) {
      state.dekBytes = restored;
      await loadAndDecryptVault();
    }
  }

  renderShell();

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register(`/sw.js?v=${ASSET_VERSION}`).catch(() => {});
  }
}

boot();
