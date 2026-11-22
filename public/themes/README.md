# HeyJournal Custom Themes

Drop any theme folder into `public/themes/<theme-id>/` and it is automatically discovered by the server (`GET /api/themes`) and appears in **Settings (`•••`) → Appearance → Theme**. Theme folders share 100% token compatibility with [Metro Family Hub](https://github.com/mile357/FamilyCoordination) themes.

---

## Folder Structure

```text
public/themes/
├── README.md
└── my-theme/
    ├── theme.json          # Required: metadata, supported modes, accents & preview swatches
    ├── theme.css           # Required: CSS variables & optional structural chrome overrides
    └── fonts/              # Optional: self-hosted .woff2 / .ttf font files
        └── custom.woff2
```

Reference local fonts or images inside `theme.css` using relative URLs (`url("./fonts/custom.woff2")`) — they resolve automatically under `/themes/my-theme/`.

---

## `theme.json` Format

```json
{
  "id": "my-theme",
  "name": "My Theme",
  "description": "Short 1–2 line description shown in the Settings theme picker.",
  "author": "Family Hub",
  "order": 50,
  "stylesheet": "theme.css",
  "modes": ["dark", "light"],
  "defaultMode": "dark",
  "defaultAccent": "#00ABA9",
  "accents": [
    { "name": "Teal", "hex": "#00ABA9" },
    { "name": "Amber", "hex": "#F0A30A" }
  ],
  "extensionAccents": {
    "calendar": "#00ABA9",
    "meals": "#A20025",
    "groceries": "#60A917",
    "chores": "#FA6800",
    "notes": "#6A00FF",
    "task-checklist": "#0050EF"
  },
  "metaThemeColor": {
    "dark": "#000000",
    "light": "#FFFFFF"
  },
  "preview": {
    "dark": { "canvas": "#000000", "tile": "#111111", "accent": "#00ABA9" },
    "light": { "canvas": "#FFFFFF", "tile": "#F3F3F3", "accent": "#00ABA9" }
  }
}
```

### Field Reference

- **`id`** *(string)*: URL-safe lowercase identifier matching `[data-theme-id="<id>"]`. Defaults to folder name.
- **`name`** *(string)*: Display name shown in Settings.
- **`description`** *(string)*: Short summary displayed on the theme card.
- **`order`** *(number)*: Sort order in Settings (lower appears first).
- **`stylesheet`** *(string)*: Relative CSS file path inside the theme folder (defaults to `"theme.css"`). Must stay within the folder.
- **`modes`** *(array)*: Any subset of `["dark", "light"]`. Omit light or dark if your theme is intentionally single-mode (for example `["dark"]` for LCARS).
- **`defaultMode`** *(string)*: Preferred mode (`"dark"` or `"light"`) when switching to this theme from an incompatible mode.
- **`defaultAccent`** *(hex)*: Initial global accent color applied when selecting the theme for the first time.
- **`accents`** *(array)*: Curated `{ "name", "hex" }` palette swatches shown in Settings when this theme is active.
- **`extensionAccents`** *(object, optional)*: Per-widget accent overrides keyed by extension ID (`calendar`, `meals`, `groceries`, `chores`, `notes`, `task-checklist`).
- **`metaThemeColor`** *(object, optional)*: Browser / PWA status bar color for `"dark"` and `"light"`.
- **`preview`** *(object, optional)*: Mini strip preview colors (`canvas`, `tile`, `accent`) used in the Settings theme card and early contrast computation.

---

## Scoping Rules & CSS Tokens (`theme.css`)

Always scope your rules to your theme's `data-theme-id` attribute so other themes remain unaffected when switching live:

```css
[data-theme-id="my-theme"] {
  --bg-canvas: #0f1115;
  --bg-tile: #181c24;
  --radius-slot: 14px;
  --radius-card: 10px;
  --radius-btn: 9999px;
}

[data-theme-id="my-theme"][data-theme="light"] {
  --bg-canvas: #f4f5f8;
  --bg-tile: #ffffff;
  --text-primary: #111318;
  --text-secondary: rgba(17, 19, 24, 0.72);
  --text-muted: rgba(17, 19, 24, 0.52);
}
```

### Key Available Tokens (from `public/styles.css`)

- **Surfaces**: `--bg-canvas`, `--bg-canvas-image`, `--bg-header`, `--bg-surface`, `--bg-surface-elevated`, `--bg-tile`, `--bg-tile-hover`, `--bg-tile-subtle`, `--bg-appbar`, `--bg-input`, `--bg-flyout`, `--bg-backdrop`, `--bg-wireframe-overlay`
- **Text & Ink**: `--text-primary`, `--text-secondary`, `--text-muted`, `--accent`, `--accent-fg`, `--accent-text`
- **Semantic Status**: `--danger-color`, `--danger-text`, `--success-color`, `--warning-color`, `--info-color`, `--current-hour-bg`
- **Borders & Geometry**: `--border-color`, `--border-strong`, `--radius-slot`, `--radius-card`, `--radius-btn`, `--radius-input`, `--radius-pill`, `--radius-checkbox`, `--shadow-slot`, `--shadow-card`, `--shadow-flyout`, `--slot-border`, `--slot-border-top`, `--card-border`, `--header-border-bottom`, `--backdrop-filter-slot`, `--backdrop-filter-flyout`
- **Typography & Casing**: `--font-display`, `--font-body`, `--font-mono`, `--title-size`, `--title-weight`, `--title-tracking`, `--title-transform`, `--slot-title-size`, `--slot-title-weight`, `--slot-title-transform`, `--card-title-weight`, `--section-transform`, `--label-transform`, `--btn-transform`, `--badge-transform`, `--clock-size`, `--clock-weight`, `--clock-transform`, `--date-size`, `--date-transform`, `--agenda-day-transform`
- **Scrollbars**: `--scrollbar-track`, `--scrollbar-thumb`, `--scrollbar-thumb-hover`

For structural chrome customization, themes can also style `.panorama-header`, `.metro-slot`, `.slot-header`, `.slot-title`, `.slot-body`, `.metro-btn`, `.metro-input`, `.metro-toggle`, `.pivot-tab`, `.metro-flyout`, and `.extension-card`.

---

## Readability, Accessibility & Touchscreen Guidelines

Because HeyJournal is designed for fast daily journaling across phones, tablets, and desktops, every theme should follow these invariants:

1. **Preserve core layout flow**: Keep `.journal-main`, `.metro-slot`, `.slot-body`, `.modal-panel`, and `.metro-flyout` responsive and scrollable across narrow mobile viewports.
2. **Keep touchscreen hit targets intact**:
   - Buttons (`button`, `.metro-btn`), inputs (`.metro-input`), quiz options (`.quiz-option-btn`), and `.slot-header` headers should remain at least **34–40px** tall.
   - Icon buttons (`.slot-icon-btn`, `.metro-ellipsis-btn`) should keep at least **36x36px** hit areas.
3. **Guarantee WCAG AA contrast (>= 4.5:1 for text, >= 3:1 for large headings & borders)**:
   - Use `--accent-text` and `--slot-accent-text` for colored text rather than raw `--accent` (the host automatically adjusts lightness/darkness against your `--bg-tile`).
   - Always use `var(--accent-fg)` / `var(--slot-accent-fg)` or an explicit high-contrast text color when setting a solid colored background.
   - Provide `preview.dark.tile` and `preview.light.tile` in `theme.json` so early contrast computation matches your CSS background before external stylesheets finish painting.
4. **Never break interactive states or dialogs**:
   - Keep `:focus-visible` outlines clear, preserve `.modal-backdrop.open` and `.flyout-backdrop.open` transitions, and ensure SVG chart tokens (`--border-color`, `--text-muted`, `--success-color`, `--warning-color`, `--danger-color`) stay legible.
