# Zero-Knowledge Dual-Engine Cryptography (Web Crypto + Pure-JS Fallback)

- **Area**: Crypto / Auth / LAN HTTP Deployment
- **Key Files**: `public/crypto.js`, `server.py`, `tests/test_crypto.py`

## Symptom / Problem
Browsers disable `window.crypto.subtle` (Web Crypto API) on non-HTTPS LAN origins such as `http://journal.192.168.1.150.sslip.io`. A zero-knowledge app that depends solely on `crypto.subtle` breaks completely on plain-HTTP Coolify LAN deployments.

## Root Cause / Invariant
- `crypto.getRandomValues` remains available on plain HTTP in modern browsers, while `crypto.subtle` is restricted to secure contexts (`https://`, `localhost`, `127.0.0.1`).
- Both engines MUST share the exact same wire format (`{"v":1,"alg":"A256GCM","iv":"<b64>","ct":"<b64 ct||tag>"}`) and AAD strings (`heyjournal:dek:v1`, `heyjournal:recovery-dek:v1`, `heyjournal:meta:v1`, `heyjournal:entry:<id>`) so vaults created on HTTP decrypt seamlessly on HTTPS and vice versa.
- Never send the raw password, recovery key, `kekBytes`, or `dekBytes` to the server. Only the first 32 bytes of `PBKDF2-HMAC-SHA256(secret, kdfSalt, iterations, 64)` (`authKey` / `recoveryAuthKey`, default `600,000` iterations for passwords and `150,000` for 160-bit Crockford Base32 recovery keys) are transmitted for authentication, and the server re-hashes them with its own random salt.

## Fix / Pattern to Follow
- Always call the high-level helpers in `public/crypto.js` (`deriveAuthAndKek`, `wrapDek`, `unwrapDek`, `encryptJson`, `decryptJson`).
- Verify any changes to `public/crypto.js` by running `python3 -m unittest tests/test_crypto.py -v`, which validates SHA-256, PBKDF2-HMAC-SHA256, and AES-256-GCM against official NIST SP 800-38D test vectors.
