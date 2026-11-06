import sys
from pathlib import Path
from typing import Dict, Any

# Ensure security-layer is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SECURITY_DIR = ROOT_DIR / "security-layer"

if str(SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_DIR))

import security_layer


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Analyzes URL structural signals, lookalike homoglyphs, brand spoofing,
    and abuse patterns using the static Cybersecurity intelligence layer.
    """
    cleaned_url = (url or "").strip()
    if not cleaned_url:
        return {
            "url": "",
            "url_status": "Invalid",
            "risk_score": 0,
            "level": "Low",
            "signals": [],
            "indicators": [],
            "recommendations": ["Please enter a valid URL."]
        }

    raw_res = security_layer.analyze_url(cleaned_url)
    score = raw_res.get("score", 0)
    level = raw_res.get("level", "Low")

    indicators = [s.get("description", "") for s in raw_res.get("signals", []) if s.get("description")]

    recommendations = []
    if level in ("High", "Critical"):
        recommendations.extend([
            "Do not open this link or navigate to this domain.",
            "Never enter login credentials, passwords, or payment details on this site.",
            "Verify the destination using a known official search engine or official app.",
            "Report this URL to your security team or cybersecurity helpline."
        ])
    elif level == "Medium":
        recommendations.extend([
            "Caution: This URL exhibits patterns commonly used to disguise destination addresses.",
            "Inspect the domain name carefully for misplaced hyphens, numbers, or odd extensions.",
            "Prefer bookmarking trusted websites rather than following unverified links."
        ])
    else:
        recommendations.extend([
            "No unusual structural URL anomalies were detected.",
            "Always verify that the address bar matches the intended institution before logging in.",
            "Check for valid HTTPS encryption and authentic domain certificates."
        ])

    status = (
        "Malicious" if level == "Critical"
        else "High Risk" if level == "High"
        else "Suspicious" if level == "Medium"
        else "Low Risk"
    )

    return {
        "url": cleaned_url,
        "url_status": status,
        "risk_score": score,
        "level": level,
        "host": raw_res.get("host", ""),
        "registered_domain": raw_res.get("registered_domain", ""),
        "subdomains": raw_res.get("subdomains", 0),
        "signals": raw_res.get("signals", []),
        "indicators": indicators,
        "recommendations": recommendations
    }
