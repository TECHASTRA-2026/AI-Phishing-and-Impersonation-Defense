# Cybersecurity & URL Analysis Layer: Indicator Document

**Scope:** defensive, non-ML, static analysis only. The module never opens, fetches, resolves or scans a URL. It only inspects the text of the message and the structure of the link.

**Pipeline:** `Message + sender + URLs -> Indicators + URL features + Impersonation check -> Risk score (0-100) -> Level + explanation + recommended action`

## 1. Message risk indicators

| ID | Category | Why it matters | How it is detected | Weight |
|---|---|---|---|---|
| URG-01 | Urgency / pressure | Attackers rush victims so they skip verification | Keywords: urgent, immediately, act now, within N hours, final notice | 15 |
| URG-02 | Urgency / pressure | Threats of loss or punishment create fear | Phrases: account suspended/blocked/locked, legal action, penalty, arrest | 15 |
| INFO-01 | Sensitive-information request | Real organisations do not ask for secrets by email/chat | Keywords: password, OTP, PIN, CVV, card number, Aadhaar, PAN, "verify your account" | 25 |
| PAY-01 | Unusual payment request | Gift cards, crypto, wire/UPI "fees" are hard to reverse | Keywords: gift card, wire transfer, bitcoin, Western Union, processing/refund fee | 20 |
| ID-01 | Unverified identity claim | Authority claimed but not provable from the message | Phrases: "I am from", "security team", "bank manager", "official notice" | 10 |
| INS-01 | Suspicious instruction | Pushes an unsafe action | Phrases: click the link, download attachment, scan QR, install, do not tell anyone | 15 |
| LURE-01 | Too-good-to-be-true lure | Prizes/rewards bait users into giving data or fees | Phrases: you have won, lottery, claim your prize, free gift | 12 |
| GEN-01 | Generic greeting | Real providers usually use your name | "Dear customer / user / sir / madam" | 5 |

Each indicator counts **once** per message.

## 2. URL features (structural only)

| ID | Feature | Why it matters | Weight |
|---|---|---|---|
| URL-IP | Raw IP as host | Legitimate brands use domain names | 25 |
| URL-AT | `@` in the authority part | Browsers ignore text before `@`, hiding the true host | 20 |
| URL-PUNY | Punycode (`xn--`) | Lookalike Unicode characters | 20 |
| URL-LEN | Length > 75 chars | Long URLs hide the real destination | 8 |
| URL-SUB | 3+ subdomain levels | Buries the real domain | 10 |
| URL-HYPH | 3+ hyphens in host | Typical of fake "brand-secure-login" hosts | 8 |
| URL-TLD | Frequently abused TLD (.xyz, .top, .tk ...) | Cheap, high-abuse | 10 |
| URL-SHORT | URL shortener | Final destination hidden | 10 |
| URL-HTTP | No HTTPS | No transport security | 8 |
| URL-DIGITS | >30% digits in host | Auto-generated domains | 6 |
| URL-KW | 2+ words like login, verify, secure, account | Credential-harvesting pattern | 8 |
| URL-ENC | Percent-encoded path | Obfuscation | 5 |
| URL-BRAND | Brand name in host/path but domain not official | Domain/name inconsistency | 25 |
| URL-LOOK | Registered domain imitates a trusted one (typo, `0` for `o`, `rn` for `m`) | Typosquatting / homoglyph | 30 |

URL score = sum of signals, capped at 100.

## 3. Impersonation logic (claimed identity vs trusted reference)

Reference data: `trusted_entities.json` (entity, aliases, official domains).

| ID | Check | Weight |
|---|---|---|
| IMP-01 | Message/sender name claims entity X, but the sender's domain is not an official domain of X | 30 |
| IMP-02 | Message claims entity X, but links go to non-official domains | 25 |
| IMP-03 | Sender domain is a lookalike of an official domain | 25 |

Official domain match = exact match or a subdomain of it (`mail.paypal.com` is fine, `paypal.com.evil.xyz` is not, because the registered domain is extracted first).

## 4. Risk-weight recommendations

- **Total score** = message indicators + highest URL score + impersonation findings, capped at 100.
- **Bands:** 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.
- Highest weights go to things a legitimate sender essentially never does (credential requests, lookalike domains, raw-IP links, identity/domain mismatch).
- Lowest weights go to signals that also occur in genuine mail (generic greeting, long URL, no HTTPS).
- Single weak signals alone should stay Low/Medium; **combinations** push to High. This keeps false positives down.
- Always show the **reasons**, not only the score, so users can learn.
- Re-tune weights with the ML member's labelled data. The weights are a starting point, not ground truth.
- Known limits: keyword lists are English-centric (add Hindi/Marathi terms), and the trusted list is small and static.

## 5. Test cases (`test_cases.py`)

| Case | Input idea | Expected |
|---|---|---|
| 01 Legitimate | HDFC statement from `hdfcbank.com` linking to `www.hdfcbank.com` | Low |
| 02 Suspicious | Urgent + OTP/password + penalty threat from random sender | High+ |
| 03 Identity mismatch | "Microsoft Support" from `micros0ft-helpdesk.com` linking to a `.xyz` site | High+ |
| 04 URL warning | Calm text with raw-IP link containing `@paypa1.com` | Medium+ |
| 05 Lookalike link | "Amazon" order mail from `amaz0n.in` | High+ |
| 06 Normal chat | Casual meeting message | Low |

Run: `python3 test_cases.py`

## 6. Integration contract

`analyze_message(text, sender_email, sender_name)` returns JSON with `score`, `level`, `recommended_action`, `breakdown`, `indicators`, `urls`, `impersonation`. The ML member can use `breakdown` values as features; the UI, browser extension and Slack/email bot can display `level` + reasons.
