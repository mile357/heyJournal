# HeyJournal

**A calm, self-hosted, zero-knowledge encrypted journal and clinical metric tracker.**

No cloud account. No build step. No external dependencies. Your thoughts, metrics, and self-assessments are encrypted in your browser before they ever touch the server — and the entire stack runs on Python 3's standard library, SQLite, and vanilla web primitives.

> **Status: Public Beta** — Feature-complete and ready for daily personal or household use. Expect refinements as real-world usage surfaces edge cases; bug reports, custom quizzes, and themes are welcome.

```bash
git clone https://github.com/mile357/heyJournal.git
cd heyJournal
python3 server.py
```

Open **`http://localhost:8080`** and create your vault. That's it — no `pip install`, no `npm`, no database container.

---

## Why HeyJournal?

Most personal tracking tools force an awkward compromise: cloud journaling apps that can read your most private writing (or lock it behind a subscription), or plain local text files that can't graph sleep, symptoms, or clinical scales over time.

HeyJournal sits cleanly in the middle:

- **True zero-knowledge encryption — even on a home LAN.** Every journal entry, timestamp, custom metric, pinned layout, and quiz answer is encrypted client-side with **AES-256-GCM** using a key derived from your password (`PBKDF2-HMAC-SHA256`, `600,000` iterations). The server never sees plaintext or your encryption key. Unlike browser crypto apps that break over plain LAN HTTP (such as `sslip.io`), HeyJournal automatically falls back from native Web Crypto API to a NIST SP 800-38D–verified pure-JS engine producing **bit-for-bit identical ciphertext** — so you can start on a local network today and move to HTTPS later with zero migration.
- **Freeform journaling + structured clinical tracking in one place.** Write a quick daily note, log custom numbers (`Sleep`, `Energy`, `Weight`, `Pain`), or step through **13 validated clinical self-assessments** (`PHQ-9`, `GAD-7`, `DASS-21`, `PCL-5`, `ASRS-v1.1`, `OCI-R`, `ISI`, `ESS`, `WHO-5`, `AUDIT`, `MDQ`, `PSS-10`, `WHODAS 2.0`). Once any metric or quiz reaches 3 data points, native SVG trend charts with clinical severity bands appear automatically.
- **Built to leave the app when you need it.** Export your decrypted history as **JSON**, **CSV**, or a clean **Printable Clinician Summary** to bring to therapy or doctor appointments — and re-import HeyJournal JSON exports into any account with automatic client-side re-encryption.
- **Zero-ceremony modularity & 20 swappable themes.** Drop a single `.json` file into [`quizzes/`](quizzes/README.md) to add a new assessment, or drop a folder into [`public/themes/`](public/themes/README.md) to add a theme. Switch live between **20 built-in themes** — from *Metro*, *E-Ink Paper*, *Braun Hardware*, and *Wabi-Sabi* to *LCARS*, *Macintosh 1984*, *Game Boy*, and *Blade Runner 2049*.
- **"Content, Not Chrome."** Four focused tabs for daily use (`input`, `metrics`, `review`, `report`). Settings, themes, exports, and admin controls stay tucked behind a single `•••` drawer instead of cluttering the screen.

---

## A Quick Tour

| Tab | What you do there |
| :--- | :--- |
| **`input`** | Jot down a note with an editable timestamp, tap pinned numeric metrics or favorite quizzes, or launch any assessment in guided one-question-at-a-time (or all-items) mode. |
| **`metrics`** | Create and pin custom numeric metrics; search, filter, learn about (`↗`), pin, or immediately take any of the 13 built-in clinical scales. |
| **`review`** | Browse reverse-chronological **Day Cards** grouping same-day entries, filter or search entirely client-side, edit/delete entries, and open clickable quiz pills for full question-by-question breakdowns. |
| **`report`** | Explore theme-aware SVG trend charts (auto-enabled at 3+ data points) with clinical severity bands, subscale switchers, `30d / 90d / 1y / all` windows, and one-click JSON, CSV, or Printable Clinician Summary exports. |

<details>
<summary><strong>Included Clinical Self-Assessments (13 scales)</strong></summary>

| Category | Scales |
| :--- | :--- |
| **Mood & Depression** | `PHQ-9` *(with Q9 crisis support callout)*, `WHO-5`, `MDQ` |
| **Anxiety & Stress** | `GAD-7`, `PSS-10`, `DASS-21` *(Depression / Anxiety / Stress subscales)* |
| **OCD & Compulsions** | `OCI-R` *(6 symptom subscales)* |
| **Functioning & Disability** | `WHODAS 2.0` *(12-item, 6 WHO domains)* |
| **Sleep** | `ISI` *(Insomnia Severity Index)*, `ESS` *(Epworth Sleepiness Scale)* |
| **Trauma & Focus** | `PCL-5` *(DSM-5 PTSD clusters)*, `ASRS-v1.1` *(Adult ADHD)* |
| **Substance & Habits** | `AUDIT` *(WHO Alcohol Use, incl. AUDIT-C subscale)* |

> *Disclaimer: Self-assessment quizzes in HeyJournal are intended for personal tracking and reflection over time, not professional medical or psychological diagnosis.*

</details>

<details>
<summary><strong>Included Visual Themes (20 swappable themes)</strong></summary>

Switch live inside **Settings (`•••`) → `appearance`**:

*Metro* · *LCARS* · *Nothing OS* · *Apple HIG* · *Material You* · *Braun Hardware* · *E-Ink Paper* · *Wabi-Sabi* · *Mid-Century Modern* · *Bauhaus* · *Art Deco* · *Macintosh 1984* · *NeXTSTEP* · *BeOS* · *Game Boy* · *Apollo DSKY* · *Blade Runner 2049* · *Matrix* · *Starfield* · *Skyrim*

Themes share 100% CSS token compatibility with [Metro Family Hub](https://github.com/mile357/FamilyCoordination). See [`public/themes/README.md`](public/themes/README.md) to author your own.

</details>

---

## Ways to Use It

- **Private personal journal & health log** — Run locally on your laptop or self-host on a home server, and install it to your phone or tablet home screen as a PWA for fast daily check-ins that auto-sync across devices when you return to the tab.
- **Therapy & clinician visit prep** — Track validated clinical scales alongside narrative context over weeks or months, then generate a clean, browser-printed **Clinician Summary** without ever handing raw notes to a third-party cloud service.
- **Shared household server** — Open multi-user registration gives every household member an isolated encrypted vault. The **first registered account** becomes **Admin** (able to manage signups, promote/demote admins, and download encrypted SQLite backups — with **zero ability** to read anyone else's data). Shared devices can enable an automatic inactivity lock (`15m / 30m / 1h`) or lock instantly with one tap.
- **Custom tracking workbench** — Drop your own standardized `.json` questionnaires into `quizzes/` (or mount a host folder in Docker) to track physical therapy, medication side effects, habits, or coaching check-ins without modifying a line of app code.

---

## Deployment Options

HeyJournal has zero external runtime dependencies and runs identically on macOS, Linux, Raspberry Pi, NAS boxes, and small VPS instances.

### 1. Local / Bare Metal (Fastest)
```bash
python3 server.py
# Runs on http://localhost:8080 (override with PORT=9000 python3 server.py)
```
Encrypted data is stored in `./data/journal.db` (SQLite WAL mode), with automatic nightly encrypted snapshots at 3:00 AM local time in `./data/backups/`.

### 2. Docker Compose (Home Server / NAS / VPS)
```bash
mkdir -p data
docker compose up -d
```
The container runs as a non-root user (`UID 1000`) on `python:3.12-alpine` with a built-in `/api/health` healthcheck. On Linux, ensure `./data` is writable by `UID 1000` (`sudo chown -R 1000:1000 data`) or use a named Docker volume. You can also uncomment the `./quizzes:/app/quizzes:ro` bind mount in [`docker-compose.yml`](docker-compose.yml) to hot-add custom quizzes without rebuilding.

### 3. Coolify (Home Server One-Repo Deploy)
Point Coolify at this repository using the included `Dockerfile`, expose port `8080`, and attach a persistent volume at `/app/data`. Full step-by-step instructions — including LAN `sslip.io` vs. HTTPS (Tailscale Serve, Cloudflare Tunnel, or Let's Encrypt) and backup restore — are in **[`COOLIFY_SETUP.md`](COOLIFY_SETUP.md)**.

### 4. Mobile / Tablet PWA
Open your deployed HeyJournal URL in Safari or Chrome and choose **Add to Home Screen**. The service worker caches only the static app shell (never `/api/` responses), giving you a full-screen mobile app with automatic multi-device vault sync and 3-way metadata conflict merging.

<details>
<summary><strong>Environment Variables, Backups & Admin CLI Recovery</strong></summary>

#### Environment Variables
| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `8080` | HTTP listen port |
| `TZ` | `UTC` | Local timezone for 3:00 AM nightly backups |
| `BACKUP_RETENTION_DAYS` | `14` | Number of nightly encrypted SQLite backups to retain |
| `ALLOW_SIGNUPS` | `1` | Initial first-boot registration default (toggleable live in Admin UI) |
| `SESSION_TTL_DAYS` | `14` | Session cookie lifetime in days |
| `AUTH_RATE_LIMIT` | `30` | Max auth attempts per IP per 60 seconds |
| `TRUST_PROXY` | `auto` | Trust `X-Forwarded-For`/`X-Forwarded-Proto` from local/private proxies (`auto`, `1`, or `0`) |

#### Backups & Restore
Atomic SQLite snapshots run nightly at **3:00 AM** local time into `data/backups/` and can also be triggered or downloaded from **Settings (`•••`) → `admin`**. All journal data inside backups remains zero-knowledge encrypted. To restore: stop the server, copy a backup file over `data/journal.db`, delete any `journal.db-wal` / `journal.db-shm` files, and restart.

#### Admin CLI Recovery
If the original admin ever loses access, manage accounts directly from the host or container:
```bash
python3 server.py --list-users
python3 server.py --promote-admin <username>
python3 server.py --delete-user <username>
```

</details>

---

## Security Model (Honest Threat Boundaries)

HeyJournal is designed so you don't have to trust your host, backups, or server admin with plaintext data:

- **How keys work:** On sign-in, your browser runs `PBKDF2-HMAC-SHA256` (`600,000` iterations) to split your password into two independent 256-bit keys: an **Auth Key** (re-hashed server-side with PBKDF2 + per-user salt) and a **Key Encryption Key (KEK)** that never leaves your device and wraps/unwraps a random 256-bit **Data Encryption Key (DEK)**.
- **Recovery & rotation without compromise:** Optionally generate an offline, printable **160-bit recovery key** that wraps the same DEK in a separate zero-knowledge slot. Changing your password or recovering your vault simply re-wraps the DEK locally and revokes other active sessions — no mass re-encryption required.
- **Protected on both HTTP and HTTPS:** Stolen SQLite databases (`data/journal.db`), nightly backups, disk snapshots, cloud backup mirrors, host shell access, and server administrators see only AES-256-GCM ciphertext. Compromising one user account never exposes another household vault.
- **What HTTPS adds (recommended):** Over plain LAN HTTP, an active attacker on the same Wi-Fi network could theoretically tamper with served JavaScript in transit or intercept the `hj_session` cookie. Putting HeyJournal behind HTTPS (via Tailscale Serve, Cloudflare Tunnel, or Let's Encrypt) protects JS integrity in transit, marks session cookies `Secure`, and activates hardware-accelerated native Web Crypto.
- **Defense in depth:** Strict Content Security Policy (`default-src 'self'; script-src 'self'`), zero third-party CDNs or analytics, `Cache-Control: no-store` on all API/auth responses, and per-IP auth rate limiting.

---

## How It Was Built

HeyJournal grew out of [Metro Family Hub](https://github.com/mile357/FamilyCoordination), carrying over its *"Content, Not Chrome"* design philosophy, zero-dependency Python + SQLite resilience, and 20-theme token engine into a dedicated personal vault.

It was developed through deliberate human–AI pair-architecting — designing invariants and failure modes up front before writing code — paired with lightweight **Compound Engineering**:

- Design and architecture standards live openly in [`AGENTS.md`](AGENTS.md) and [`WORKING_WITH_JOSH.md`](WORKING_WITH_JOSH.md).
- Non-obvious engineering invariants (dual-engine crypto parity, CSP-safe `blob:` exports, lock-free PBKDF2, 3-way multi-device metadata merging, and asset cache-busting) are documented in [`docs/solutions/`](docs/solutions/README.md) so regressions don't creep back in.
- Everything is verified by a zero-dependency `unittest` suite covering official NIST SP 800-38D AES-GCM / PBKDF2 test vectors, backend auth/concurrency/backup flows, quiz schema validation, and frontend contracts.

---

## Testing & Extending

Run the full zero-dependency test suite:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Want to customize or contribute?
- **Add a clinical or custom quiz:** Drop a JSON file into `quizzes/` following [`quizzes/README.md`](quizzes/README.md).
- **Create a visual theme:** Drop a folder into `public/themes/` following [`public/themes/README.md`](public/themes/README.md).
- **Found a bug during beta?** Open an issue with your browser, deployment method (local / Docker / Coolify), and whether you're running over HTTP or HTTPS.
