# AGENTS.md — HeyJournal

Project instructions for AI coding assistants working in `/Users/josh/Documents/HeyJournal`.
Derived from [`WORKING_WITH_JOSH.md`](WORKING_WITH_JOSH.md) and adapted with lightweight **Compound Engineering** practices (`docs/solutions/`).

---

## 1. Compound Engineering Loop (How We Work)

Before non-trivial changes:
1. **Check Institutional Memory**: Scan [`docs/solutions/`](docs/solutions/README.md) for relevant prior gotchas (encryption/crypto invariants, caching, concurrency, quiz/theme contracts) before designing or editing.
2. **Co-Architect First, Implement Second**:
   - When Josh asks a design or architectural question, **do not jump straight into writing code**. Provide a concise, structured trade-off analysis with a concrete recommendation and wait for approval.
   - Once a direction is approved, execute the full change cleanly without half-measures.
3. **Map Edge Cases Up Front**: Before coding crypto/key derivation, quiz scoring, chart scales, or persistence changes, explicitly map boundary and failure states.
4. **Review Before Finishing**: Check edits against the **4 Blind Spots** below, verify syntax/runtime behavior and tests, and keep explanations concise and high-signal.
5. **Compound After Non-Obvious Fixes**: When solving a tricky bug, crypto pitfall, concurrency race, caching trap, or cross-cutting invariant, add a short note in [`docs/solutions/`](docs/solutions/) using the template in [`docs/solutions/README.md`](docs/solutions/README.md).

### Version Control Discipline
- Do **not** `git commit` or `git push` automatically after edits. Wait until a feature or fix is verified and Josh explicitly asks to commit/push.

---

## 2. UI/UX Design Philosophy

- **"Content, Not Chrome"**: Eliminate visual clutter, redundant labels, borders, drop shadows, and permanent admin controls. Everyday views show daily-use content; settings, theme switching, account management, and destructive actions belong inside contextual drawers (`•••`) or explicit edit modes.
- **Subtle Visual Encoding Over Verbose Labels**: Encode information via typography, scale, proximity, and meaningful thresholds rather than cluttered captions.
- **Strict Visual & Typographic Alignment**: Match optical sizing, baselines, and grid alignment across headers, cards, tabs, and charts.
- **Physical Form Factor First**: Design for fast daily journaling across phone, tablet, and desktop — generous tap targets, clean keyboard flow, and zero-friction quiz stepping.

---

## 3. Software Architecture Philosophy

- **Uniform Abstractions ("No Special Cases")**: Generalize capabilities in the host engine (metric types, quiz schema/scoring engine, theme token engine) rather than hard-coding individual quizzes or metrics into core JS or `server.py`.
- **Zero-Ceremony Modularity**:
  - **Quizzes (`quizzes/*.json`)**: Self-contained, one-quiz-per-file, auto-discovered by the server. Adding a new clinical/self-report quiz requires only dropping in a JSON file.
  - **Themes (`public/themes/<theme-id>/`)**: Drop-in, auto-discovered themes compatible with the Family Hub 20-theme engine (`GET /api/themes`).
- **Zero-Knowledge Encryption Boundary**: Plaintext journal entries, metric values, and quiz responses are encrypted client-side before leaving the browser and decrypted only in memory on the user's device. The server never sees or stores the user's encryption key or plaintext journal content.
- **Zero-Dependency Resilience**: Favor Python 3 standard library + SQLite in `server.py` and native browser APIs (Web Crypto API, native ES Modules, vanilla CSS, SVG charts) so the app runs identically on macOS and Linux/Coolify Docker without fragile build chains.

---

## 4. Blind Spots to Proactively Catch

Proactively flag and handle these four areas during planning, implementation, and review:

1. **State-Transition & Edge-Case Matrices**:
   - Explicitly map boundary states: missing/partial quiz answers, password change / wrong password / lost session key, <3 vs >=3 chart points, duplicate metric names, min/max chart bounds, and editing or deleting past entries.
2. **Discoverability for First-Time Users**:
   - When stripping chrome or labels, flag interactions that would become invisible (e.g., how to attach a metric or quiz, how to unlock/lock, why a metric isn't yet graphed until 3 data points) and provide subtle zero-clutter cues.
3. **Ergonomics of Data Entry**:
   - Make daily journaling effortless on both mobile touchscreens and desktop keyboards — one-tap quiz option progression, smart numeric keypads (`inputmode="decimal"`), and quick timestamp editing without wrestling date pickers.
4. **Data Lifecycle, Concurrency & Caching**:
   - **Multi-device sync & concurrency**: Handle editing/adding entries across phone and laptop cleanly without clobbering entries.
   - **Zero-knowledge & HTTPS caveat**: Web Crypto API (`crypto.subtle`) requires a secure context (`https://` or `localhost`) in browsers — explicitly account for Coolify LAN deployment over HTTP vs HTTPS!
   - **Browser/SW caching**: Bump asset version tokens consistently across all entry points and ensure `Cache-Control: no-store` for API/auth endpoints.
