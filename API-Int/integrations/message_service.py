import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
import security_layer

# Ensure sibling directories are on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SECURITY_DIR = ROOT_DIR / "security-layer"
ML_DIR = ROOT_DIR / "ML"

for p in (ROOT_DIR, SECURITY_DIR, ML_DIR):
    p_str = str(p)
    if p_str not in sys.path:
        sys.path.insert(0, p_str)


try:
    from Prediction import predict_message
except Exception as e:
    def predict_message(text: str) -> dict:
        return {
            "prediction": "unavailable",
            "is_phishing": False,
            "confidence": 0.0,
            "phishing_probability": 0.0,
            "probabilities": {}
        }


def analyze_message(
    message: str,
    sender_email: str = "",
    sender_name: str = "",
    urls: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Combines AI/ML text classification with rule-based security heuristics
    and brand impersonation detection.
    """
    cleaned_message = (message or "").strip()

    # 1. AI/ML statistical classifier
    ml_result = predict_message(cleaned_message)
    ml_phishing_prob = ml_result.get("phishing_probability", 0.0)

    # 2. Rule-based security analysis & impersonation checks
    sec_result = security_layer.analyze_message(
        cleaned_message,
        sender_email=sender_email or "",
        sender_name=sender_name or "",
        urls=urls
    )

    # 3. Format human-friendly indicator descriptions
    indicators = []
    for ind in sec_result.get("indicators", []):
        indicators.append(f"[{ind.get('category', 'Indicator')}] {ind.get('why', '')}")

    for imp in sec_result.get("impersonation", []):
        indicators.append(f"[Impersonation Warning] {imp.get('description', '')}")

    # If ML strongly flags phishing, include ML indicator
    if ml_result.get("is_phishing") and ml_phishing_prob >= 0.60:
        pct = int(ml_phishing_prob * 100)
        indicators.append(
            f"[AI Classification] Language pattern closely matches verified phishing corpus ({pct}% confidence)."
        )

    # 4. Recommendations
    recommendations = []
    level = sec_result.get("level", "Low")
    if level in ("High", "Critical") or ml_result.get("is_phishing"):
        recommendations.extend([
            "Do not click any links or attachments contained in the message.",
            "Never share passwords, OTPs, or financial details through email or chat.",
            "Verify the claimed sender through a known, official telephone number or support portal.",
            "Report and delete this message immediately."
        ])
    elif level == "Medium":
        recommendations.extend([
            "Pause and inspect the sender's identity carefully before replying.",
            "Open the organization's official website or application directly instead of following message links.",
            "Look for mismatched sender domains or unexpected urgency."
        ])
    else:
        recommendations.extend([
            "No high-pressure warning signs detected.",
            "Always maintain caution: never reveal passwords or one-time verification codes.",
            "Use official apps or verified bookmarks for routine transactions."
        ])

    # 5. Composite risk score for message alone
    # 40% ML probability + 60% Security heuristic weight (capped at 100)
    ml_score = ml_phishing_prob * 100
    sec_score = sec_result.get("score", 0)
    composite_score = min(100, round((0.40 * ml_score) + (0.60 * sec_score)))

    # Security Floor: High-confidence heuristic signals (>= 50) establish a minimum risk score
    # so out-of-vocabulary words in an ML model do not dilute verified threat indicators.
    if sec_score >= 50:
        composite_score = max(composite_score, sec_score)
    elif sec_score >= 25 and ml_phishing_prob >= 0.50:
        composite_score = max(composite_score, 55)

    classification = "Phishing / Scam" if composite_score >= 50 or ml_result.get("is_phishing") else "Suspicious" if composite_score >= 25 else "Legitimate"

    return {
        "classification": classification,
        "confidence": ml_result.get("confidence", 0.0),
        "risk_score": composite_score,
        "ml_result": ml_result,
        "security_analysis": sec_result,
        "indicators": list(dict.fromkeys(indicators)),
        "detailed_indicators": sec_result.get("indicators", []),
        "impersonation_findings": sec_result.get("impersonation", []),
        "extracted_urls": sec_result.get("urls", []),
        "recommendations": list(dict.fromkeys(recommendations))
    }
