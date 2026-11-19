# HeyJournal

**A calm, self-hosted, zero-knowledge encrypted journal and clinical metric tracker.**

Built with the exact minimalist **"Content, Not Chrome"** philosophy, zero-dependency Python + SQLite stack, and **20 swappable visual themes** of [Metro Family Hub](https://github.com/mile357/FamilyCoordination).

```bash
# Run locally in seconds (Python 3 standard library only — zero pip installs or build steps)
python3 server.py
```

Open **`http://localhost:8080`**.

---

## Core Capabilities

### 1. True Zero-Knowledge Client-Side Encryption
- **Single-step Username + Password**: Your browser runs `PBKDF2-HMAC-SHA256` (150,000 iterations) to split your password into two independent 256-bit keys:
  1. An **Auth Key** verified by the server (re-hashed server-side with PBKDF2 + per-user salt).
  2. A **Key Encryption Key (KEK)** that **never leaves your device** and wraps/unwraps a random 256-bit Data Encryption Key (DEK).
- **Encrypted at Rest & in Transit**: Journal text, timestamps, custom metrics, pinned layout, and per-question quiz responses are all encrypted locally with **AES-256-GCM** before leaving the browser.
- **Password Rotation Without Re-Encryption**: Changing your password simply re-wraps your DEK locally and revokes other active sessions.
- **Works on Both HTTPS and Plain LAN HTTP**: Automatically uses native browser **Web Crypto API** on `https://`/`localhost`, and seamlessly falls back to an audited, NIST SP 800-38D verified pure-JS **AES-256-GCM + PBKDF2-SHA256** engine on plain LAN HTTP (like `sslip.io`) with 100% identical ciphertext format.
- **Optional Session Unlock**: Toggle **"Stay unlocked in this browser tab"** (`sessionStorage`) or lock instantly with one tap.

### 2. Multi-User Vaults & First-User Admin
- Open multi-user registration out of the box (each user gets an isolated encrypted vault).
- The **first registered account** automatically becomes **Admin**, with an **Admin** tab in Settings (`•••`) to view registered usernames/entry counts, delete other accounts, toggle registration on/off, and inspect/trigger encrypted SQLite backups — with **zero ability to read other users' encrypted data**.

### 3. Two Metric Types: Custom Numbers + 13 Clinical Self-Assessment Quizzes
- **Simple Numeric Metrics**: Add anything you want (`Weight (lbs)`, `Sleep (hrs)`, `Energy (1–10)`, etc.), pin favorites directly onto the **Input** tab for 1-tap daily logging, and track trends over time.
- **Drop-In Clinical Quizzes (`quizzes/*.json`)**: One standardized JSON file per quiz (auto-discovered via `GET /api/quizzes`). Includes 13 widely accepted, validated self-report scales out of the box:
  - **Mood & Depression**: `PHQ-9` (with Q9 crisis support callout), `WHO-5`, `MDQ`
  - **Anxiety & Stress**: `GAD-7`, `PSS-10`, `DASS-21` (with Depression / Anxiety / Stress subscales)
  - **OCD & Compulsions**: `OCI-R` (6 symptom subscales)
  - **Functioning & Disability**: `WHODAS 2.0 (12-Item)` (6 WHO domains)
  - **Sleep**: `ISI` (Insomnia Severity Index), `ESS` (Epworth Sleepiness Scale)
  - **Trauma & Focus**: `PCL-5` (DSM-5 PTSD clusters), `ASRS-v1.1` (Adult ADHD)
  - **Substance & Habits**: `AUDIT` (WHO Alcohol Use, incl. AUDIT-C subscale)
- See **[`quizzes/README.md`](quizzes/README.md)** to drop in your own custom JSON quizzes without editing any code.

### 4. Four Focused Metro Pivot Tabs
- **`input`**: Auto-filled editable timestamp, distraction-free journal box, pinned quick numeric inputs & quiz launchers, inline metric/quiz picker, and guided step-by-step (or all-items) quiz runner.
- **`metrics`**: Create & pin custom numeric metrics; browse, search, filter, pin, learn about (`↗`), or immediately launch any clinical quiz.
- **`review`**: Reverse-chronological **Day Cards** grouping same-day entries, instant client-side search & metric filtering, contextual `•••` edit/delete menus, and clickable quiz pills to inspect full encrypted Q&A breakdowns.
- **`report`**: Theme-aware native SVG trend graphs for every tracked metric & quiz with **at least 3 data points**, clinical severity threshold bands, subscale switchers, `30d / 90d / 1y / all` range filters, and client-side decrypted **JSON**, **CSV**, and **Printable Clinician Summary** exports.

### 5. All 20 Swappable Themes from Family Hub
Switch live inside **Settings (`•••`) → `appearance`** between **Metro**, **LCARS**, **Nothing OS**, **Apple HIG**, **Material You**, **Braun Hardware**, **E-Ink Paper**, **Wabi-Sabi**, **Mid-Century Modern**, **Bauhaus**, **Art Deco**, **Macintosh 1984**, **NeXTSTEP**, **BeOS**, **Game Boy**, **Apollo DSKY**, **Blade Runner 2049**, **Matrix**, **Starfield**, and **Skyrim**.

---

## Testing & Deployment

```bash
# Run full zero-dependency backend, crypto (NIST vectors), quiz schema & frontend test suite
python3 -m unittest discover -s tests -p "test_*.py" -v
```

- **Docker Compose**: `docker compose up -d`
- **Coolify Home Server**: Follow **[`COOLIFY_SETUP.md`](COOLIFY_SETUP.md)**.
