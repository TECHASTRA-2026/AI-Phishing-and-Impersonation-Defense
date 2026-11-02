# Cybersecurity & URL Analysis Layer

Non-ML security layer for **AI Phishing and Impersonation Defense**. It scores messages, analyzes URLs by structure only (never visits them), and checks claimed identity against a trusted reference list.

## Features
- **Message indicators:** urgency, sensitive-info requests, unusual payments, unverified identity, suspicious instructions
- **URL analyzer:** length, subdomains, raw IP, `@` tricks, punycode, abused TLDs, shorteners, lookalike domains
- **Impersonation check:** claimed identity vs `trusted_entities.json`
- **Explainable output:** score (0-100), level, reasons, recommended action

## Files
| File | Purpose |
|---|---|
| `security_layer.py` | Analyzer and scoring logic |
| `trusted_entities.json` | Trusted entities and official domains |
| `test_cases.py` | Controlled test cases |
| `SECURITY_INDICATORS.md` | Indicators, weights, rationale |

## Usage
```python
from security_layer import analyze_message

r = analyze_message("URGENT: send your OTP now", sender_email="help@random-mail.com")
print(r["score"], r["level"], r["recommended_action"])
```
Run tests: `python test_cases.py` (Python 3.8+, no dependencies)

## Risk Levels
| Score | Level |
|---|---|
| 0-24 | Low |
| 25-49 | Medium |
| 50-74 | High |
| 75-100 | Critical |

Output is JSON with `score`, `level`, `breakdown`, `indicators`, `urls`, `impersonation`, so the ML, UI and bot components can use it directly.

## Limitations
English keywords only, small static trusted list, hand-set weights (to be tuned with labelled data).

**Author:** Anuj Tiwari ([@anujtiwari1427](https://github.com/anujtiwari1427))