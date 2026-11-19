/**
 * HeyJournal — Zero-Knowledge Encrypted Journal & Clinical Metric Tracker
 * Native ES Modules, zero external dependencies, 20-theme Family Hub parity.
 */

import {
  DEFAULT_KDF_ITERATIONS,
  base64ToBytes,
  bytesToBase64,
  decryptJson,
  deriveAuthAndKek,
  encryptJson,
  generateDek,
  generateSaltB64,
  getCryptoBackendLabel,
  isNativeWebCryptoAvailable,
  unwrapDek,
  wrapDek,
} from "./crypto.js?v=1";

import { findSeverityBand, formatScoreValue, getQuestionOptions, scoreQuiz } from "./quiz-engine.js?v=1";
import { computeSeriesStats, filterPointsByRange, renderMetricChart } from "./charts.js?v=1";
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
} from "./theme-engine.js?v=1";
import { downloadDecryptedCsv, downloadDecryptedJson, openPrintableClinicianSummary } from "./export.js?v=1";

const SESSION_DEK_KEY = "heyjournal_session_dek_v1";
const STAY_UNLOCKED_PREF_KEY = "heyjournal_stay_unlocked_pref_v1";

const DEFAULT_VAULT_META = {
  settings: {
    journalName: "heyjournal",
    themeId: "metro",
    theme: "dark",
    accentColor: "#00ABA9",
    themeAccents: {},
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
  vaultMetaUpdatedAt: "",
  entries: [], // [{ id, createdAt, updatedAt, data: { timestamp, text, numericMetrics, quizResults } }]
  quizzes: [], // Auto-discovered from GET /api/quizzes
  quizById: new Map(),

  // UI state
  activeTab: "input",
  authMode: "login", // "login" | "register" | "unlock"
  authError: "",
  authBusy: false,

  // Input draft state (preserved across tab switches)
  draft: createFreshDraft(),

  // Metrics tab UI
  quizCategoryFilter: "All",
  quizSearch: "",

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
  modalState: null, // { type: "quiz-runner" | "quiz-breakdown", ... }
};

function structuredCloneSafe(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function createFreshDraft() {
  return {
    editingEntryId: null,
    editingUpdatedAt: "",
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
  const res = await fetch(url, opts);
  let data = null;
  try {
    data = await res.json();
  } catch (e) {}
  return { ok: res.ok, status: res.status, data };
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

  if (res.data.vaultMeta) {
    try {
      const decryptedMeta = await decryptJson(res.data.vaultMeta, state.dekBytes, "heyjournal:meta:v1");
      state.vaultMeta = normalizeVaultMeta(decryptedMeta);
    } catch (e) {
      console.error("Failed to decrypt vault metadata:", e);
      state.vaultMeta = structuredCloneSafe(DEFAULT_VAULT_META);
    }
  } else {
    state.vaultMeta = structuredCloneSafe(DEFAULT_VAULT_META);
  }

  const decryptedEntries = [];
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
      console.error(`Failed to decrypt entry ${row.id}:`, e);
    }
  }

  decryptedEntries.sort(
    (a, b) => new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime()
  );
  state.entries = decryptedEntries;

  applyUserThemeAndTitle();
  return true;
}

function normalizeEntryData(raw, fallbackIso) {
  return {
    timestamp: raw && typeof raw.timestamp === "string" ? raw.timestamp : fallbackIso || new Date().toISOString(),
    text: raw && typeof raw.text === "string" ? raw.text : "",
    numericMetrics: Array.isArray(raw && raw.numericMetrics) ? raw.numericMetrics : [],
    quizResults: Array.isArray(raw && raw.quizResults) ? raw.quizResults : [],
  };
}

async function saveVaultMeta(toastMsg = "") {
  if (!state.dekBytes) return false;
  const encrypted = await encryptJson(state.vaultMeta, state.dekBytes, "heyjournal:meta:v1");
  const res = await apiFetch("/api/vault/meta", {
    method: "PUT",
    body: {
      vaultMeta: encrypted,
      expectedUpdatedAt: state.vaultMetaUpdatedAt || undefined,
    },
  });
  if (res.status === 409 && res.data && res.data.vaultMetaUpdatedAt) {
    // Re-sync updatedAt and retry once
    state.vaultMetaUpdatedAt = res.data.vaultMetaUpdatedAt;
    const retry = await apiFetch("/api/vault/meta", {
      method: "PUT",
      body: {
        vaultMeta: encrypted,
        expectedUpdatedAt: state.vaultMetaUpdatedAt,
      },
    });
    if (retry.ok) {
      state.vaultMetaUpdatedAt = retry.data.vaultMetaUpdatedAt || state.vaultMetaUpdatedAt;
      if (toastMsg) showToast(toastMsg);
      return true;
    }
    showToast("Could not save settings — please reload.");
    return false;
  }
  if (res.ok) {
    state.vaultMetaUpdatedAt = res.data.vaultMetaUpdatedAt || state.vaultMetaUpdatedAt;
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
  const lockBtn = document.getElementById("btnLockVault");
  const subtitle = document.getElementById("headerSubtitle");

  if (isUnlocked) {
    authScreen.classList.add("hidden");
    appShell.classList.remove("hidden");
    userPill.classList.remove("hidden");
    userPill.textContent = state.authStatus.user.username + (state.authStatus.user.isAdmin ? " · admin" : "");
    lockBtn.classList.remove("hidden");
    if (subtitle) {
      const cnt = state.entries.length;
      subtitle.textContent = `${cnt} ${cnt === 1 ? "entry" : "entries"} · encrypted`;
    }
    renderActiveTab();
  } else {
    authScreen.classList.remove("hidden");
    appShell.classList.add("hidden");
    userPill.classList.add("hidden");
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
// AUTH / UNLOCK SCREEN
// ============================================================================
function renderAuthCard() {
  const card = document.getElementById("authCard");
  if (!card) return;

  const isFirstUser = state.authStatus.userCount === 0;
  const hasSessionPendingUnlock = Boolean(state.authStatus.authenticated && state.authStatus.user && !state.dekBytes);

  if (hasSessionPendingUnlock) {
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
        </form>
      </div>
    `;

    card.querySelector("#btnSwitchAccount").addEventListener("click", handleLockOrLogout);
    card.querySelector("#authForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const pw = card.querySelector("#authPassword").value;
      const stay = card.querySelector("#chkStayUnlocked").checked;
      await handleUnlockExistingSession(pw, stay);
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
                 placeholder="e.g. josh" autofocus />
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

  card.querySelector("#authForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = card.querySelector("#authUsername").value.trim();
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

  try {
    const kdfSalt = generateSaltB64();
    const kdfIterations = DEFAULT_KDF_ITERATIONS;
    const { authKeyB64, kekBytes } = await deriveAuthAndKek(password, kdfSalt, kdfIterations);
    const dekBytes = generateDek();
    const wrappedDek = await wrapDek(dekBytes, kekBytes);

    // Carry over any theme picked on the login screen into the new encrypted vault!
    const initialMeta = structuredCloneSafe(DEFAULT_VAULT_META);
    initialMeta.settings = { ...state.vaultMeta.settings };
    const encryptedMeta = await encryptJson(initialMeta, dekBytes, "heyjournal:meta:v1");

    const res = await apiFetch("/api/auth/register", {
      method: "POST",
      body: {
        username,
        authKey: authKeyB64,
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
    state.dekBytes = dekBytes;
    saveStayUnlockedPref(stayUnlocked);
    state.authBusy = false;
    await loadAndDecryptVault();
    state.draft = createFreshDraft();
    renderShell();
    showToast(res.data.user.isAdmin ? "Encrypted admin vault created" : "Encrypted vault created");
  } catch (err) {
    console.error(err);
    state.authError = err.message || "Encryption error during registration.";
    state.authBusy = false;
    renderAuthCard();
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
    const { authKeyB64, kekBytes } = await deriveAuthAndKek(password, kdfSalt, kdfIterations);

    const res = await apiFetch("/api/auth/login", {
      method: "POST",
      body: { username, authKey: authKeyB64 },
    });
    if (!res.ok) {
      state.authError = (res.data && res.data.error) || "Invalid username or password.";
      state.authBusy = false;
      renderAuthCard();
      return;
    }

    const dekBytes = await unwrapDek(res.data.user.wrappedDek, kekBytes);
    state.authStatus.authenticated = true;
    state.authStatus.user = res.data.user;
    state.dekBytes = dekBytes;
    saveStayUnlockedPref(stayUnlocked);
    state.authBusy = false;
    await loadAndDecryptVault();
    state.draft = createFreshDraft();
    renderShell();
    showToast("Vault unlocked");
  } catch (err) {
    console.error(err);
    state.authError = "Incorrect password or unable to decrypt vault key.";
    state.authBusy = false;
    renderAuthCard();
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

  try {
    const { kekBytes } = await deriveAuthAndKek(password, user.kdfSalt, user.kdfIterations);
    const dekBytes = await unwrapDek(user.wrappedDek, kekBytes);
    state.dekBytes = dekBytes;
    saveStayUnlockedPref(stayUnlocked);
    state.authBusy = false;
    await loadAndDecryptVault();
    state.draft = createFreshDraft();
    renderShell();
    showToast("Vault unlocked");
  } catch (err) {
    state.authError = "Incorrect password.";
    state.authBusy = false;
    renderAuthCard();
  }
}

async function handleLockOrLogout() {
  clearSessionDek();
  state.entries = [];
  state.draft = createFreshDraft();
  state.adminData = null;
  state.flyoutOpen = false;
  document.getElementById("flyoutBackdrop")?.classList.remove("open");
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
                      <span class="quick-metric-unit">${q.questions.length}q · ${q.estimatedMinutes || 2}m</span>
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

  stage.querySelector("#entryTimestampInput")?.addEventListener("change", (e) => {
    if (e.target.value) {
      state.draft.timestampLocal = e.target.value;
      state.draft.timestampManuallyEdited = true;
    }
  });

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

  stage.querySelector("#btnPickerApply")?.addEventListener("click", async () => {
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
      const num = parseFloat(numValEl.value);
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
      const rawVal = stage.querySelector("#pickerNewVal").value;
      if (!name) {
        showToast("Enter a metric name");
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
      await saveVaultMeta();
      if (rawVal !== "" && Number.isFinite(parseFloat(rawVal))) {
        state.draft.numericValues[newMetric.id] = rawVal;
      }
      state.draft.showPicker = false;
      renderInputTab(stage);
      showToast(`Added "${name}" to your metrics`);
    }
  });

  const cancelEdit = () => {
    state.draft = createFreshDraft();
    renderInputTab(stage);
  };
  stage.querySelector("#btnCancelEdit")?.addEventListener("click", cancelEdit);
  stage.querySelector("#btnCancelEditFooter")?.addEventListener("click", cancelEdit);

  stage.querySelector("#btnSaveEntry")?.addEventListener("click", handleSaveDraftEntry);
}

async function handleSaveDraftEntry() {
  const d = state.draft;
  const text = (d.text || "").trim();

  // Gather pinned numeric metrics + extra numeric metrics
  const numericMap = new Map();
  for (const m of state.vaultMeta.metrics) {
    if (!m.pinned) continue;
    const raw = d.numericValues[m.id];
    if (raw !== undefined && raw !== null && String(raw).trim() !== "") {
      const val = parseFloat(raw);
      if (Number.isFinite(val)) {
        numericMap.set(m.id, { metricId: m.id, name: m.name, unit: m.unit || "", value: val });
      }
    }
  }
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
        showToast((res.data && res.data.error) || "Could not update entry");
        if (saveBtn) saveBtn.disabled = false;
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
        if (saveBtn) saveBtn.disabled = false;
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
    if (saveBtn) saveBtn.disabled = false;
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

  const filteredQuizzes = state.quizzes.filter((q) => {
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

      <div class="library-grid">
        ${filteredQuizzes
          .map((q) => {
            const isPinned = state.vaultMeta.pinnedQuizIds.includes(q.id);
            const cnt = quizCounts.get(q.id) || 0;
            const scoring = q.scoring || {};
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
                    <span>~${q.estimatedMinutes || 2} min</span>
                    <span>range ${scoring.min ?? 0}–${scoring.max ?? "?"} ${escapeHtml(scoring.unit || "")}</span>
                    ${cnt > 0 ? `<span><strong>${cnt} logged</strong></span>` : ""}
                  </div>
                </div>
                <div class="library-card-actions">
                  <button type="button" class="metro-btn accent compact" data-take-quiz-now="${escapeHtml(q.id)}">take now</button>
                  <button type="button" class="metro-btn ${isPinned ? "accent" : "subtle"} compact" data-pin-quiz="${escapeHtml(q.id)}">
                    ${isPinned ? "pinned" : "pin to input"}
                  </button>
                  ${
                    q.resourceUrl
                      ? `<a class="metro-btn subtle compact" href="${escapeHtml(q.resourceUrl)}" target="_blank" rel="noopener noreferrer">info ↗</a>`
                      : ""
                  }
                </div>
              </div>
            `;
          })
          .join("")}
      </div>
      </div>
    </div>
  `;

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
    renderMetricsTab(stage);
    const inp = stage.querySelector("#quizSearchInput");
    if (inp) {
      inp.focus();
      inp.setSelectionRange(inp.value.length, inp.value.length);
    }
  });

  stage.querySelectorAll("[data-quiz-cat]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.quizCategoryFilter = btn.getAttribute("data-quiz-cat");
      renderMetricsTab(stage);
    });
  });

  stage.querySelectorAll("[data-pin-quiz]").forEach((btn) => {
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
      renderMetricsTab(stage);
    });
  });

  stage.querySelectorAll("[data-take-quiz-now]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const qid = btn.getAttribute("data-take-quiz-now");
      setActiveTab("input");
      const existing = state.draft.quizResults.find((r) => r.quizId === qid);
      openQuizRunnerModal(qid, existing ? existing.answers : null);
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
              `<option value="${escapeHtml(val)}" ${metricFilter === val ? "selected" : ""}>${escapeHtml(label)}</option>`
          )
          .join("")}
      </select>
    </div>

    ${
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
                              <button type="button" class="metro-ellipsis-btn" data-entry-menu="${escapeHtml(entry.id)}" aria-label="Entry options">
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
            .join("")
    }
  `;

  stage.querySelector("#reviewSearchInput").addEventListener("input", (e) => {
    state.reviewSearch = e.target.value;
    renderReviewTab(stage);
    const inp = stage.querySelector("#reviewSearchInput");
    if (inp) {
      inp.focus();
      inp.setSelectionRange(inp.value.length, inp.value.length);
    }
  });

  stage.querySelector("#reviewMetricFilter").addEventListener("change", (e) => {
    state.reviewMetricFilter = e.target.value;
    renderReviewTab(stage);
  });

  stage.querySelectorAll("[data-entry-menu]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const id = btn.getAttribute("data-entry-menu");
      state.openEntryMenuId = state.openEntryMenuId === id ? null : id;
      renderReviewTab(stage);
    });
  });

  stage.querySelectorAll("[data-edit-entry]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-edit-entry");
      startEditingEntry(id);
    });
  });

  stage.querySelectorAll("[data-delete-entry]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-delete-entry");
      await handleDeleteEntry(id);
    });
  });

  stage.querySelectorAll("[data-inspect-entry]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const entryId = btn.getAttribute("data-inspect-entry");
      const qIdx = Number(btn.getAttribute("data-quiz-idx"));
      const entry = state.entries.find((x) => x.id === entryId);
      if (entry && entry.data.quizResults && entry.data.quizResults[qIdx]) {
        openQuizBreakdownModal(entry.data.quizResults[qIdx], entry.data.timestamp);
      }
    });
  });
}

function startEditingEntry(entryId) {
  const entry = state.entries.find((e) => e.id === entryId);
  if (!entry) return;

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

  for (const e of state.entries) {
    const tsMs = new Date(e.data.timestamp).getTime();
    if (!Number.isFinite(tsMs)) continue;

    for (const m of e.data.numericMetrics || []) {
      const val = Number(m.value);
      if (!Number.isFinite(val)) continue;
      const key = m.metricId || `name:${m.name.toLowerCase()}`;
      if (!numericGroups.has(key)) {
        numericGroups.set(key, {
          key: `num:${key}`,
          kind: "number",
          name: m.name,
          unit: m.unit || "",
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
        chartUnit = "pts";
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
              : `<span class="category-badge">${rangedPoints.length} pts</span>`
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
  document.getElementById("modalBackdrop")?.classList.remove("open");
}

function renderModal() {
  const backdrop = document.getElementById("modalBackdrop");
  const panel = document.getElementById("modalPanel");
  if (!backdrop || !panel || !state.modalState) return;
  backdrop.classList.add("open");

  if (state.modalState.type === "quiz-runner") {
    renderQuizRunnerPanel(panel);
  } else if (state.modalState.type === "quiz-breakdown") {
    renderQuizBreakdownPanel(panel);
  }
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
                        ${escapeHtml(String(sub.score))}${sub.max ? `<span style="font-size:12px; color:var(--text-muted);"> / ${sub.max}</span>` : ""}
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
          quiz.resourceUrl
            ? ` <a href="${escapeHtml(quiz.resourceUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(quiz.resourceLabel || "Learn more")} ↗</a>`
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
        ms.answers[btn.getAttribute("data-all-q")] = Number(btn.getAttribute("data-all-val"));
        renderQuizRunnerPanel(panel);
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
            quiz.resourceUrl
              ? ` · <a href="${escapeHtml(quiz.resourceUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(quiz.resourceLabel || "about")} ↗</a>`
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
            quizDef?.resourceUrl
              ? ` · <a href="${escapeHtml(quizDef.resourceUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(quizDef.resourceLabel || "reference")} ↗</a>`
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
                      ${escapeHtml(String(sub.score))}${sub.max ? `<span style="font-size:12px; color:var(--text-muted);"> / ${sub.max}</span>` : ""}
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
  document.getElementById("flyoutBackdrop")?.classList.add("open");
  renderFlyout();
  if (tab === "admin" && state.authStatus.user?.isAdmin) {
    refreshAdminData();
  }
}

function closeFlyout() {
  state.flyoutOpen = false;
  document.getElementById("flyoutBackdrop")?.classList.remove("open");
}

async function refreshAdminData() {
  const res = await apiFetch("/api/admin/users");
  if (res.ok) {
    state.adminData = res.data;
    if (state.flyoutOpen && state.flyoutTab === "admin") {
      renderFlyout();
    }
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
        Uses the exact drop-in theme engine from Family Hub (<code>public/themes/</code>).
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
      <div class="theme-preview-strip" style="background:${escapeHtml(p.canvas)};">
        <div class="theme-preview-tile" style="background:${escapeHtml(p.tile)};">
          <span class="theme-preview-accent" style="background:${escapeHtml(p.accent)};"></span>
          ${dotColors.map((c) => `<span class="theme-preview-dot" style="background:${escapeHtml(c)};"></span>`).join("")}
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

  body.innerHTML = `
    <div class="flyout-section">
      <div class="flyout-section-title">zero-knowledge encryption</div>
      <div class="extension-card">
        <div>
          <div class="card-title">AES-256-GCM active</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">
            Engine: ${escapeHtml(backendLabel)}<br/>
            Keys stay strictly on your device. Plaintext never reaches the server.
          </div>
        </div>
        <span class="category-badge">${isNative ? "HTTPS" : "HTTP"}</span>
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">session lock</div>
      <div class="extension-card">
        <div>
          <div class="card-title">stay unlocked in this tab</div>
          <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
            Keeps your key in browser <code>sessionStorage</code> until you close this tab or click Lock.
          </div>
        </div>
        <div class="metro-toggle ${state.stayUnlocked ? "on" : ""}" id="toggleStayUnlocked" role="switch" aria-checked="${state.stayUnlocked}" tabindex="0"></div>
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">client-side decrypted export</div>
      <p style="font-size:12px; color:var(--text-secondary);">
        Exported files are decrypted locally on your device — store them securely.
      </p>
      <div style="display:flex; flex-wrap:wrap; gap:8px;">
        <button type="button" class="metro-btn subtle compact" id="btnFlyoutExportJson">download json</button>
        <button type="button" class="metro-btn subtle compact" id="btnFlyoutExportCsv">download csv</button>
        <button type="button" class="metro-btn subtle compact" id="btnFlyoutClinician">clinician summary</button>
      </div>
    </div>

    <div class="flyout-section">
      <div class="flyout-section-title">change password</div>
      <p style="font-size:12px; color:var(--text-secondary);">
        Re-wraps your vault key locally with your new password without altering historical entries.
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
      <div class="flyout-section-title">vault session</div>
      <div>
        <button type="button" class="metro-btn danger" id="btnFlyoutLogout">lock &amp; sign out</button>
      </div>
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
  body.querySelector("#btnFlyoutLogout").addEventListener("click", handleLockOrLogout);

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
      const newSalt = generateSaltB64();
      const newDerived = await deriveAuthAndKek(newPw, newSalt, DEFAULT_KDF_ITERATIONS);
      const newWrappedDek = await wrapDek(verifiedDek, newDerived.kekBytes);

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

function renderAdminFlyoutTab(body) {
  if (!state.adminData) {
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
                  : `<button type="button" class="metro-btn danger compact" data-admin-del-user="${escapeHtml(u.id)}" data-admin-del-name="${escapeHtml(u.username)}">delete</button>`
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
                  <div style="display:flex; justify-content:space-between; font-size:12px; color:var(--text-secondary); padding:6px 10px; background:var(--bg-tile);">
                    <span style="font-family:var(--font-mono);">${escapeHtml(b.name)}</span>
                    <span>${Math.max(1, Math.round(b.sizeBytes / 1024))} KB</span>
                  </div>
                `
                )
                .join("")}
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
    }
  };
  toggleEl.addEventListener("click", flipSignups);
  toggleEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      flipSignups();
    }
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

  body.querySelector("#btnTriggerBackup").addEventListener("click", async () => {
    const res = await apiFetch("/api/admin/backup", { method: "POST" });
    if (res.ok) {
      state.adminData.backups = res.data.backups || [];
      renderFlyout();
      showToast(`Backup saved: ${res.data.backupName}`);
    } else {
      showToast("Backup failed");
    }
  });
}

// ============================================================================
// GLOBAL EVENTS & BOOTSTRAP
// ============================================================================
function wireGlobalEvents() {
  document.getElementById("btnSettings")?.addEventListener("click", () => openFlyout("appearance"));
  document.getElementById("btnLockVault")?.addEventListener("click", handleLockOrLogout);

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

  // Keyboard shortcuts: Esc closes modal/flyout; number keys 1-6 answer step-by-step quiz
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (state.modalState) closeModal();
      else if (state.flyoutOpen) closeFlyout();
      return;
    }
    if (state.modalState && state.modalState.type === "quiz-runner" && state.modalState.viewMode === "step") {
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
