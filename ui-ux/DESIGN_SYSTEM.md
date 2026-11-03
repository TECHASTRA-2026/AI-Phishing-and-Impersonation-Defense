# AI Phishing & Impersonation Defense — UX and design system

## User journey

`Home → Start Analyzing (smooth scroll) → Analyze (message and/or URL) → ANALYZE button spinner → Loading (four status steps + skeleton) → Result → Analyze another (confirmation) → Analyze`

Error branches: `Analyze → Empty input / Invalid URL → inline validation → edit input`; `Analyze → Simulated service error → Retry or Edit`.

## Wireframes before visual design

Open `wireframes.html` for grayscale, low-fidelity desktop and mobile layouts of all five screen states. Open `prototype.html` for the high-fidelity clickable implementation.

## Palette / design tokens

| Role | Dark mode | Light mode | Usage |
|---|---|---|---|
| Background | `#081522` | `#F3F8FC` | Main canvas |
| Surface | `#102235` | `#FFFFFF` | Cards / panes |
| Raised surface | `#142A3E` | `#F6FAFC` | Side panels / results |
| Primary text | `#F1F8FF` | `#142738` | Main typography |
| Muted text | `#98B1C5` | `#516B7E` | Helper copy |
| Primary action | `#55E0D0` | `#087F79` | CTA / focus |
| Supporting accent | `#68A9FF` | `#3474C2` | Secondary visual accents |
| Low risk | `#67DCC0` | `#0E806C` | Check icon + LOW label |
| Medium risk | `#F3C76A` | `#915E0C` | Info icon + MEDIUM label |
| High risk | `#FF848D` | `#BF3345` | Warning icon + HIGH label |

Use **icon + full-text label + color** for risk levels so color is never the only signal. Risk-level backgrounds are translucent for the dark theme and pastel surfaces for the light theme.

## Typography and layout

- Typeface: `Inter` if installed; system sans-serif fallback. Self-contained, no external font or asset fetching.
- Display: 44–69 px desktop / 41–56 px mobile, tight negative tracking, 1.09 line height.
- Screen titles: 28–34 px. Card headings 14–22 px. Body 12–17 px with generous line height.
- 4 px base spacing grid. Common gaps: 8, 12, 16, 24, 32 px.
- Layout width up to 1180 px; 64 px desktop gutters; 34 px mobile gutters.
- Radius: 12 px inputs and buttons, 17–24 px for card surfaces.
- Desktop two-column analyzer and result; mobile single-column stack; minimum control height 42–54 px.

## Button / state components

| State | Feedback |
|---|---|
| Default | Filled teal primary or bordered secondary action |
| Hover | Translate upward 2 px, gentle background shift and soft drop shadow, 180 ms easing |
| Press | CSS `scale(.97)` and pointer-centered ripple, completed within about 550 ms |
| Disabled | Reduced opacity + no pointer activation |
| Loading | Spinner appears inside original button while pending |
| Success | Copy report swaps copy icon for check, shows top-right toast for 3 seconds |

## Motion tokens

- Micro-interactions: **180 ms**, ease-out.
- Page/section fade-and-slide: **520 ms**.
- Result badge pop: **460 ms**, spring-like cubic-bezier.
- Finding stagger: **95 ms apart**.
- Result progress fill: **1250 ms**; number count: **1300 ms**.
- Modal: **300 ms** scale in + background blur.
- Toast: **300 ms** enter and **250 ms** exit; dismiss after **3 seconds**.
- The `prefers-reduced-motion: reduce` media query nearly removes decorative animations, reduces loading wait, and makes scroll changes immediate.

## Clickable UX inventory

1. **Home** — CTA smooth-scrolls to analyzer; How it works anchors to cards; theme toggle changes palette, persists locally when storage is available.
2. **Analyze** — message or URL allowed independently, live `0 / 1500` counter, warning at 85% and danger at 100%; focus glow; inline errors with shake and fade; sample cycles through HIGH, MEDIUM and LOW examples with simulated typing; test checkbox enables simulated service error.
3. **Loading** — submit button spinner; animated scanning ring and four sequential statuses; results skeleton shown instead of an empty state.
4. **Result** — animated score and matched ring/bar; risk badge icon + level; findings stagger; clicking a finding explains *Why it matters* and *How it was detected*; copy report and toast; Analyze another opens confirmation modal.
5. **Errors** — empty input, invalid `http(s)` URL, simulated service error with retry/edit. Error modals close via X, backdrop click, or Escape.
6. **Session dashboard** — live counts and recent analyses; records only score, risk level, timestamp, and indicator categories, not pasted content.

## Accessibility considerations

- Semantic `main`, `section`, `nav`, `form`, and `aside`, with explicit field labels.
- Keyboard-usable buttons and dialogs, `:focus-visible` focus outlines, Escape-to-close and basic modal focus trapping.
- Inline validation uses `role="alert"`, invalid controls use `aria-invalid`.
- Risk summary includes numeric score and text; progress indicator exposes ARIA values.
- Status text uses `role="status"`; notifications use an ARIA live region.
- Tooltips respond to hover or keyboard focus.
- Mobile large controls and wrapping rows; no visual dependency on hover.

## Critical trust limitations / implementation notes

The prototype uses **client-side deterministic keyword and URL-format heuristics only** and reserved `example.com` / `.example` demo domains. It does **not** navigate to submitted URLs, fetch their contents, authenticate a sender, query reputation APIs, compare live trusted sources, or make network requests. The loading status referring to trusted sources is explicitly marked `(demo)` and all reports disclose this limitation. **LOW risk does not mean safe.**

For a production-grade build, integrate a carefully scoped analysis API, reputation/domain intelligence with proper privacy controls, rate limiting, abuse defense, evidence provenance, safe-link handling, telemetry consent, and rigorous testing. The UI can remain similar while detection and result source metadata should be upgraded.
