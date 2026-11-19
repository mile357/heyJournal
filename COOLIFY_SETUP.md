# Coolify Home Server Deployment Guide — HeyJournal

Deploy **HeyJournal** onto your Coolify server (Ubuntu Mini PC / Raspberry Pi / NAS) alongside Family Hub with zero external dependencies and persistent encrypted SQLite storage.

---

## 1. Connect Repository & Build Settings

1. In Coolify, open your Project &rarr; **+ Add Resource** &rarr; **Public Repository** (or **Private Repository** with Deploy Key / GitHub App).
2. Set:
   - **Branch**: `main`
   - **Build Pack**: **Dockerfile** (auto-detected from `Dockerfile`).
   - **Port Exposes**: `8080`
3. **Domain**:
   - **Local LAN (`sslip.io`)**: e.g. `http://journal.192.168.1.150.sslip.io`
   - **Recommended HTTPS** (via Tailscale Serve, Cloudflare Tunnel, or Coolify Let's Encrypt): e.g. `https://journal.yourdomain.com`

> [!TIP]
> **HTTPS vs. Plain LAN HTTP (Web Crypto API)**:
> Browsers restrict native `window.crypto.subtle` to `https://` and `localhost`. HeyJournal automatically detects this and falls back to its NIST-verified pure-JS AES-256-GCM + PBKDF2-SHA256 engine when opened over plain `http://` on your home LAN — and both engines produce bit-for-bit identical ciphertext so you can switch to HTTPS anytime without migrating data. Still, HTTPS is recommended whenever possible so login traffic is TLS-encrypted on Wi-Fi.

---

## 2. Environment Variables

Open the **Environment Variables** tab in Coolify and configure:

```text
TZ=America/Los_Angeles
BACKUP_RETENTION_DAYS=14
```

- `TZ`: Ensures automatic 3:00 AM nightly backups run at 3:00 AM local time.
- `ALLOW_SIGNUPS`: Optional (`1` default; the Admin account can also toggle signups live inside **Settings (`•••`) → `admin`**).

---

## 3. Persistent Storage (Required for SQLite)

Open the **Storages** tab in Coolify and add a **Persistent Volume** *(use Volume Mount, not Host Directory Mount, so Docker preserves `UID 1000` write permissions)*:

- **Name**: `heyjournal-data`
- **Destination Path**: `/app/data`

This persists both `data/journal.db` (WAL SQLite database) and `data/backups/` (nightly encrypted SQLite snapshots) across rebuilds and container updates.

---

## 4. First-Boot Admin Setup

1. Click **Deploy** in Coolify.
2. Open your HeyJournal URL.
3. Because the database has 0 accounts, HeyJournal opens directly to **Create Admin Vault**.
4. The **first user created** automatically becomes the server **Admin**:
   - Can open **Settings (`•••`) → `admin`** to view registered accounts (usernames & entry counts only), delete other accounts, toggle open registration, and trigger/inspect encrypted SQLite backups.
   - **Cannot** view or decrypt any other user's entries — all entries, metrics, and quiz answers are zero-knowledge encrypted with each user's own password-derived key.
