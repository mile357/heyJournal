# Asset Version & Service Worker Cache-Busting

- **Area**: PWA / Browser Caching / CSP
- **Key Files**: `public/sw.js`, `public/index.html`, `public/theme-boot.js`, `public/theme-engine.js`, `public/app.js`, `public/charts.js`, `public/export.js`, `public/manifest.json`

## Symptom / Problem
Editing frontend ES modules, stylesheets, or theme CSS without bumping `?v=N` across all entry points (including secondary module imports in `charts.js` and `export.js`) can leave browsers or installed PWAs running mismatched or duplicate cached modules.

## Root Cause / Invariant
HeyJournal uses a zero-bundler manual integer version token (`v=N`) across:
1. `public/sw.js`: `CACHE_NAME = "heyjournal-vN"` and `SHELL_ASSETS` query strings (`/api/` is strictly excluded from `CacheStorage`).
2. `public/theme-engine.js`: `export const ASSET_VERSION = "N";`.
3. `public/index.html`: `?v=N` on `/manifest.json`, `/icon.svg`, `/styles.css`, `/theme-boot.js`, `/app.js`.
4. `public/theme-boot.js`: `"?v=N"` appended to cached theme stylesheets (kept in an external `.js` file so CSP stays strict `script-src 'self'` with zero `'unsafe-inline'`).
5. `public/app.js`, `public/charts.js`, `public/export.js`: `?v=N` on static ES module imports and the printable summary's `/print-summary.js?v=N` script tag.
6. `public/manifest.json`: `?v=N` on `/icon.svg`.

## Fix / Pattern to Follow
When updating frontend assets, increment the integer consistently across all 8 files and run `python3 -m unittest discover -s tests -p "test_*.py"` to verify version parity automatically.
