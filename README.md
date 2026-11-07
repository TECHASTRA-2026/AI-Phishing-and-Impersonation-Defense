<p align="center">
  <img src="SENTINEL_logo.png" alt="SENTINEL Logo" width="130" style="filter: drop-shadow(0 4px 12px rgba(0, 240, 255, 0.45));" />
</p>

<h1 align="center">SENTINEL — AI Phishing & Impersonation Defense</h1>

<p align="center">
  <strong>Multi-Vector Cybersecurity Intelligence Platform uniting Machine Learning, Deterministic URL Heuristics, and Authoritative Brand Registry Verification.</strong>
</p>

<p align="center">
  <a href="https://ai-phishing-and-impersonation-defen.vercel.app"><img src="https://img.shields.io/badge/Live%20Demo-Vercel%20Production-00f0ff?style=for-the-badge&logo=vercel&logoColor=white" alt="Live Demo" /></a>
  <img src="https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.13" />
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Scikit--Learn-94.0%25%20Acc-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white" alt="Scikit-Learn" />
  <img src="https://img.shields.io/badge/Architecture-XAI%20Explainable-blueviolet?style=for-the-badge" alt="XAI" />
</p>

---

## 🌐 Live Production Deployment

SENTINEL is deployed and operational in production:
* 🚀 **Live Platform URL:** [https://ai-phishing-and-impersonation-defen.vercel.app](https://ai-phishing-and-impersonation-defen.vercel.app)
* 📖 **Interactive Swagger API Docs:** [https://ai-phishing-and-impersonation-defen.vercel.app/docs](https://ai-phishing-and-impersonation-defen.vercel.app/docs)
* 🩺 **API Health Endpoint:** [https://ai-phishing-and-impersonation-defen.vercel.app/health](https://ai-phishing-and-impersonation-defen.vercel.app/health)

---

## 🛡️ Executive Summary

Modern cyber attackers rarely rely on single attack vectors. Real-world credential harvesting campaigns blend:
1. **Psychological Manipulation:** Artificially fabricated urgency, fear of account lockout, and extortion threats.
2. **Structural Obfuscation:** Typo-squatted domains, abusive top-level domains (`.top`, `.xyz`, `.cfd`), and hidden `@` redirects.
3. **Identity Spoofing:** Impersonating reputable institutions (State Bank of India, PayPal, Microsoft, Amazon) from unverified sender domains.

**SENTINEL** is an integrated proof-of-concept cybersecurity platform developed for the **TechAstra Hackathon**. Rather than relying on an opaque "black-box" model, SENTINEL implements **Explainable AI (XAI)**: synthesizing statistical NLP probabilities and deterministic heuristics into a normalized **0–100 risk score** accompanied by verifiable diagnostic evidence and actionable countermeasure playbooks.

---

## 🔬 Core Defense Vectors (The 4 Pillars)

```
                          ┌──────────────────────────┐
                          │   UNIFIED CLIENT INPUT   │
                          │  (Message / URL / Brand) │
                          └─────────────┬────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│    VECTOR 1: NLP    │      │    VECTOR 2: URL    │      │   VECTOR 3: BRAND   │
│   TF-IDF + LogReg   │      │ 14 Heuristic Rules  │      │ Authoritative Reg.  │
│  Urgency & Secrets  │      │ TLD, Homoglyphs, IP │      │ Levenshtein Match   │
└──────────┬──────────┘      └──────────┬──────────┘      └──────────┬──────────┘
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │   VECTOR 4: RISK ENGINE     │
                         │ Multi-Signal Synthesis      │
                         │ Security Floor Lock (>=50)  │
                         └──────────────┬──────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │   EXPLAINABLE RESULT (XAI)  │
                         │ • Composite Score (0-100)   │
                         │ • Risk Level (LOW/MED/HIGH) │
                         │ • Diagnostic Evidence Cards │
                         │ • Actionable Playbooks      │
                         └─────────────────────────────┘
```

### 1. Vector 1: Statistical NLP Language Intelligence (`ML/`)
* **Pipeline:** Lowercased token n-grams $(1, 2)$, sublinear TF-IDF scaling, and calibrated Logistic Regression with balanced class weights.
* **Corpus & Training:** Augmented phishing, scam, extortion, and academic legitimate corpora.
* **Performance:**
  * **Accuracy:** `94.0%`
  * **Precision:** `89.7%`
  * **Recall:** `100.0%`
  * **F1-Score:** `94.5%`
* **Coverage:** Detects cognitive coercion, urgent threats, credential demands, and explicit scam declarations (`SCAM-01`).

### 2. Vector 2: Structural URL Threat Inspection (`security-layer/`)
* **Inspection Scope:** 14 RFC-compliant heuristic detectors executed safely without DNS resolution or payload execution:
  * **Abusive TLDs:** Flags high-risk registrar extensions (`.top`, `.xyz`, `.click`, `.icu`, `.tk`, `.zip`, `.mov`, etc.).
  * **IP Address Literals:** Flags raw IPv4/IPv6 destination targets.
  * **Homograph & Punycode Shield:** Unmasks visual IDN confusable characters (e.g. `pаypal.com` with Cyrillic `а`).
  * **Credential Keywords:** Flags embedded auth terms (`/login`, `/signin`, `/verify`, `/account`, `/banking`).
  * **Deceptive Delimiters:** Identifies HTTP basic auth `@` exploitation (`http://legit.com@attacker.top`).
  * **Subdomain Depth:** Flags excessive subdomain padding (`sbi.com.auth.verify.attacker.top`).
  * **URL Shorteners:** Detects masking via `bit.ly`, `tinyurl.com`, `t.co`, etc.

### 3. Vector 3: Brand Impersonation Registry (`security-layer/trusted_entities.json`)
* **Authoritative Directory:** Curated registry of verified enterprise, banking, and government entities (State Bank of India, HDFC Bank, PayPal, Microsoft, Amazon, Google, etc.).
* **Fuzzy Levenshtein Distance:** Calculates string similarity against registered domains to detect lookalike spoofing (e.g. `amaz0n.in`, `micros0ft.com`).
* **Identity Discrepancy Checks:** Compares claimed brand name against actual sender email address domain and extracted embedded links.

### 4. Vector 4: Multi-Signal Risk Engine & Security Floor (`API-Int/services/risk_engine.py`)
* **Normalized Synthesis:** Integrates multi-vector findings into an objective $0–100$ score:
  $$\text{Base Score} = (0.40 \times \text{ML Score}) + (0.60 \times \text{Heuristic Score})$$
* **Security Floor Rule:** When deterministic heuristics detect confirmed high-confidence threats (e.g. explicit scam declarations $\ge 50$ pts), the composite score locks to at least that heuristic score—preventing an out-of-vocabulary ML bag-of-words model from diluting critical threat findings.
* **Diagnostic Evidence:** Every risk score maps to human-readable diagnostic cards showing *What* was detected, *Why* it matters, and *How* it was verified.

---

## 🎨 Interactive User Experience & Visuals (`ui-ux/`)

* **3D Animated Constellation:** Interactive HTML5 Canvas rendered behind the interface featuring a rotating particle constellation that responds to mouse movement and theme changes.
* **4 Dedicated Analyzers:**
  1. **All-In-One Defense:** Full composite scanner analyzing message body, URL, and claimed sender simultaneously.
  2. **Message NLP Scanner:** Dedicated text classification focusing on urgency, coercive rhetoric, and credential harvesting.
  3. **URL Threat Scanner:** Dedicated link safety analyzer running 14 structural rules.
  4. **Brand Impersonation Verifier:** Dedicated identity verifier cross-referencing sender veracity against the official registry.
* **Phase 2 Live Telemetry Dashboard:**
  * Real-time counters for session analyses and higher-risk findings.
  * Live tracking of the most frequently detected attack signal.
  * Session assessment log with responsive 3-tier mobile formatting and one-click finding review.
* **Mobile-Responsive Adaptive Design:**
  * Automatically switches desktop horizontal glassmorphism tabs into a compact cybernetic dropdown selector on screens $\le 768\text{px}$.
  * Zero horizontal overflow on narrow mobile screens down to $320\text{px}$.
  * Borderless, glowing custom shield logo (`SENTINEL_logo.png`) floating seamlessly across the navbar, hero section, and footer.

---

## 📁 Repository Architecture

```text
AI-Phishing-and-Impersonation-Defense/
├── api/
│   └── index.py                     # Vercel serverless ASGI entrypoint
├── API-Int/
│   ├── main.py                      # FastAPI application with CORS & static routes
│   ├── integrations/
│   │   ├── message_service.py       # Message analyzer integration & security floor
│   │   └── url_service.py           # URL threat scanner integration
│   ├── routes/
│   │   └── analyze.py               # REST endpoints (/analyze, /health, etc.)
│   ├── schemas/
│   │   └── request.py               # Pydantic request models
│   └── services/
│       └── risk_engine.py           # Multi-signal risk synthesis & explainability
├── ML/
│   ├── model.py                     # TF-IDF + Logistic Regression training pipeline
│   ├── Prediction.py                # Cached inference engine (predict_message)
│   ├── techaastra_message_dataset.csv # Training dataset
│   └── model_artifacts/
│       └── techaastra_phishing_model.joblib # Serialized model pipeline (88 KB)
├── security-layer/
│   ├── security_layer.py            # 14 URL rules, 8 message indicators, fuzzy matcher
│   ├── test_cases.py                # Security heuristic unit test suite
│   └── trusted_entities.json        # Curated trusted institutional directory
├── ui-ux/
│   ├── prototype.html               # 3D Cyber visualizer, analyzers & dashboard UI
│   └── SENTINEL_logo.png            # Official brand logo
├── SENTINEL_logo.png                # Root logo & favicon asset
├── requirements.txt                 # Production dependencies for local & Vercel
├── vercel.json                      # Vercel serverless build & routing configuration
├── .vercelignore                    # Deployment artifact exclusions
├── test_e2e_api.py                  # End-to-end integration test suite
└── run.py                           # Single-command local runner
```

---

## 🔌 API Reference

### 1. Unified Multi-Vector Analysis
```http
POST /analyze
Content-Type: application/json

{
  "message": "URGENT: Your SBI account has been locked. Verify KYC at http://sbi-login.top/auth",
  "url": "http://sbi-login.top/auth",
  "sender_email": "support@sbi-alerts-portal.xyz",
  "claimed_brand": "State Bank of India"
}
```

#### Sample Response
```json
{
  "success": true,
  "score": 90,
  "level": "HIGH",
  "summary": "Multiple warning signs suggest high phishing or impersonation risk. Do not interact.",
  "items": [
    {
      "key": "urgency",
      "title": "Pressure to act quickly",
      "summary": "The message creates a deadline or artificial sense of urgency.",
      "severity": "high"
    },
    {
      "key": "url-tld",
      "title": "URL: Suspicious TLD (.top)",
      "summary": "Abusive top-level domain frequently associated with phishing.",
      "severity": "high"
    },
    {
      "key": "imp-sbi",
      "title": "Impersonation: State Bank of India",
      "summary": "Sender domain (sbi-alerts-portal.xyz) does not match official SBI domains.",
      "severity": "high"
    }
  ],
  "recommendations": [
    "Do not click any links or attachments contained in the message.",
    "Never share passwords, OTPs, or financial details through email or chat.",
    "Verify the claimed sender through a known, official telephone number or support portal."
  ]
}
```

### Additional Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/analyze/message` | Dedicated text NLP classification & indicators |
| `POST` | `/analyze/url` | Dedicated 14-rule structural URL threat scan |
| `POST` | `/analyze/impersonation` | Dedicated sender identity verification |
| `GET` | `/trusted-entities` | Returns the directory of verified institutions |
| `GET` | `/health` | System health check (`status: Running`) |
| `GET` | `/docs` | Interactive Swagger API documentation |

---

## 🚀 Quickstart & Local Installation

### Prerequisites
* Python 3.10, 3.11, 3.12, or 3.13
* Git

### 1. Clone the Repository
```bash
git clone https://github.com/TECHASTRA-2026/AI-Phishing-and-Impersonation-Defense.git
cd AI-Phishing-and-Impersonation-Defense
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Platform
```bash
python run.py
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 🧪 Automated Test Suites

The repository includes comprehensive automated test coverage for all modules:

### 1. Comprehensive End-to-End API Suite
```bash
python test_e2e_api.py
```
* Tests web frontend serving, health endpoints, message NLP, URL scanning, brand impersonation, and unified multi-vector risk synthesis.

### 2. Security Heuristics Suite
```bash
python security-layer/test_cases.py
```
* Tests benign messages, suspicious urgency, identity mismatches, abusive URL structures, and lookalike domains.

---

## ☁️ Deployment on Vercel

The repository is configured for serverless deployment on Vercel via [`api/index.py`](api/index.py) and [`vercel.json`](vercel.json):

1. **Deploy with Git (Recommended):**
   * Push your changes: `git push`
   * Import the repository in your [Vercel Dashboard](https://vercel.com/new).
   * Vercel will auto-detect the configuration, install dependencies from `requirements.txt`, and deploy the platform.
2. **Deploy via Vercel CLI:**
   ```bash
   npx vercel --prod
   ```

---

## 🔒 Privacy & Ethical AI Guarantee

* **Ephemeral Processing:** Analyses are executed in ephemeral memory during the lifecycle of the HTTP request.
* **Zero Credential Persistence:** User passwords, OTPs, card numbers, and raw messages are never logged or saved to persistent disk.
* **Safe Heuristics:** URL analysis is performed structurally without executing malicious payloads or triggering active tracking beacons.

---

## 👥 Contributors & TechAstra Technical Team

Developed by the **TechAstra 2026 Technical Team**:
* **Integration & Systems Lead:** Hariom Gupta ([@HARIOMGUPTA30](https://github.com/HARIOMGUPTA30))
* **Frontend & 3D Visualization:** UI/UX Engineering Module
* **Machine Learning & NLP:** Data Science & Modeling Module
* **Cybersecurity & Heuristics:** Threat Analysis & Heuristics Module
* **Backend & API Systems:** FastAPI Architecture Module

---

<p align="center">
  <sub>Built for the <strong>TechAstra 2026 Annual Hackathon</strong>. Designed for explainability, modularity, and rapid threat detection.</sub>
</p>
