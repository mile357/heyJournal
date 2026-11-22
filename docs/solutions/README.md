# Solutions & Institutional Memory (`docs/solutions/`)

Short, high-signal notes capturing solved gotchas, invariants, and architectural lessons in **HeyJournal**.
Consult relevant notes before making cross-cutting changes, and add a new note whenever a non-obvious bug or subtle contract is resolved.

## Index

- [`zero-knowledge-dual-crypto.md`](zero-knowledge-dual-crypto.md) — Dual Web Crypto + NIST-verified pure-JS AES-256-GCM/PBKDF2 architecture for HTTPS and plain LAN HTTP.
- [`asset-version-cache-busting.md`](asset-version-cache-busting.md) — Synchronizing `?v=N` and Service Worker cache tokens across all entry points while maintaining strict `script-src 'self'` CSP.
- [`csp-safe-blob-exports-and-concurrency.md`](csp-safe-blob-exports-and-concurrency.md) — CSP-safe `blob:` printing, keeping PBKDF2 outside `DB_LOCK`, and 3-way vault metadata conflict merging.

---

## Template for New Notes

```markdown
# <Short Descriptive Title>

- **Area**: <e.g., Crypto / Auth / SQLite / Quizzes / Themes / Charts / PWA>
- **Key Files**: `<relative/path>`

## Symptom / Problem
What broke or could silently regress.

## Root Cause / Invariant
Why it happens and the exact rule to respect.

## Fix / Pattern to Follow
Concrete steps or code pattern to use going forward.
```
