# Prototype QA checklist — tested in headless Chromium

Tested with desktop 1440×900 and mobile 390×844 viewports.

- [x] Home button scrolls to Analyzer.
- [x] Empty form produces inline validation.
- [x] Invalid URL produces inline validation.
- [x] Sample text and URL auto-populate with animated typing.
- [x] Submit shows loading stage before result.
- [x] High sample produces HIGH and 78 / 100.
- [x] Medium sample produces MEDIUM and 49 / 100.
- [x] Low sample produces LOW and 12 / 100.
- [x] Finding opens explanation modal; Escape closes it.
- [x] Copy report changes button state and displays toast in browser test.
- [x] Analyze another opens confirmation dialog and resets form.
- [x] Theme toggle changes dark to light.
- [x] Simulated server error and retry return to result.
- [x] No JavaScript page errors observed in tested flows.
- [x] No horizontal overflow observed at mobile width.
- [x] Reduced-motion preference produces immediate score and short loading flow.

**Important:** This is a tested interactive UI prototype with a local heuristic demonstration only, not a functional live phishing detection service. Different browsers and clipboard permissions may affect copying when opening the HTML file directly.
