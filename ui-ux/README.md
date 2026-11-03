# AI Phishing & Impersonation Defense

Responsive, clickable desktop and mobile prototype created as **self-contained HTML**: no build step, external packages, API keys, or server required.

### Files

- `wireframes.html` — low-fidelity desktop/mobile screen designs and user flow.
- `prototype.html` — high-fidelity clickable prototype with dark/light themes, form states, animated loading/results, interactive dialogs, report copy, notifications, and session dashboard.
- `DESIGN_SYSTEM.md` — design tokens, component states, timings, accessibility, and threat-model limitations.

### Getting started

Double-click `prototype.html` to open it in Chrome, Edge, Safari, or Firefox. Start at the Home page and select **Start Analyzing**. Click **Try a sample** up to three times to cycle through high / medium / low demo cases. Click **ANALYZE** to show the loading sequence and result. Click any indicator for its explanation. Use **Copy report** (browser clipboard permission may be required). Use **Analyze another** to open a confirmation dialog and restart.

To test errors: click ANALYZE with both fields empty; enter `not-a-url` in the URL field; or select **Simulate service error** before submitting valid input. To inspect mobile, resize to a narrow viewport (e.g. 390×844).

### Important disclaimer

This is a **UI/UX demonstration, not a working live phishing protection service**. Local heuristics illustrate possible explanations but cannot establish whether a message or URL is genuine. It does not fetch, click, visit, or transmit submitted messages or URLs. A low score is not proof of safety. No content is stored in the activity dashboard; only ephemeral category and score summaries exist in browser memory.
