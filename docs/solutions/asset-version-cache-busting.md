# Asset Version & Service Worker Cache-Busting

- **Area**: PWA / Browser Caching / CSP
- **Key Files**: `public/sw.js`, `public/index.html`, `public/theme-boot.js`, `public/theme-engine.js`, `public/app.js`, `public/manifest.json`

## Symptom / Problem
Editing frontend ES modules, stylesheets, or theme CSS without bumping `?v=N` across all entry points can leave browsers or installed PWAs running mismatched cached modules.

## Root Cause / Invariant
HeyJournal uses a zero-bundler manual integer version token (`v=1`) across:
1. `public/sw.js`: `CACHE_NAME = "heyjournal-v1"` and `SHELL_ASSETS` query strings (`/api/` is strictly excluded from `CacheStorage`).
2. `public/theme-engine.js`: `export const ASSET_VERSION = "1";`.
3. `public/index.html`: `?v=1` on `/manifest.json`, `/icon.svg`, `/styles.css`, `/theme-boot.js`, `/app.js`.
4. `public/theme-boot.js`: `"?v=1"` appended to cached theme stylesheets (kept in an external `.js` file so CSP stays strict `script-src 'self'` with zero `'unsafe-inline'`).
5. `public/app.js`: `?v=1` on static ES module imports.
6. `public/manifest.json`: `?v=1` on `/icon.svg`.

## Fix / Pattern to Follow
When updating frontend assets, increment the integer consistently across all 6 files and run `python3 -m unittest discover -s tests -p "test_*.py"` to verify version parity automatically.
