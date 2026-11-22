# CSP-Safe Blob Exports, PBKDF2 Lock Contention & 3-Way Metadata Sync

- **Area**: Security / Concurrency / Export / Multi-Device Sync
- **Key Files**: `server.py`, `public/export.js`, `public/print-summary.js`, `public/app.js`

## Symptom / Problem
1. **Clinician summary double-download & broken Print button**: `window.open(blobUrl, "_blank", "noopener,noreferrer")` always returns `null` by spec (triggering the popup-blocked download fallback on every click), and `blob:` documents inherit the opener's strict `script-src 'self'` CSP, silently blocking inline `onclick="window.print()"`.
2. **Global server stalls during login/password change**: Running 100,000-iteration PBKDF2 inside `with DB_LOCK:` blocked all other users' API requests on the server.
3. **Multi-device metadata clobbering on 409**: Blindly re-sending the stale local `vaultMeta` after updating `vaultMetaUpdatedAt` overwrote metrics/pins added on another device.

## Root Cause / Invariant
- To detect popup blockers safely while keeping `noopener`, call `window.open(url, "_blank")`, check truthiness, then immediately set `win.opener = null` and schedule `URL.revokeObjectURL(url)`. Attach print handlers via an external same-origin script (`/print-summary.js?v=N`) rather than inline `onclick`.
- Keep `DB_LOCK` strictly around short SQLite transactions — always run `_derive_server_auth_hash()` outside the lock and re-verify row state before writing.
- Track `state.lastSyncedVaultMeta` in `app.js` and 3-way merge remote vs. local changes on HTTP `409 Conflict` before re-encrypting and retrying `PUT /api/vault/meta`.

## Fix / Pattern to Follow
- Never use inline event handlers in generated HTML blobs; load a versioned helper script from `window.location.origin`.
- Keep PBKDF2 and other CPU-heavy crypto strictly outside `DB_LOCK`.
- Any multi-device mutable state should resolve `409` via explicit merge or user-visible conflict choice rather than silent overwrite.
