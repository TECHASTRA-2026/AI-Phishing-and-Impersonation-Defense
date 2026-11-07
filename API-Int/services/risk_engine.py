from typing import Optional, Dict, Any, List


def _map_indicator_to_item(ind: Dict[str, Any]) -> Dict[str, Any]:
    """Map a security layer indicator to a structured UI finding item."""
    code = ind.get("id", "")
    category = ind.get("category", "")
    why = ind.get("why", "")

    mapping = {
        "URG-01": {
            "key": "urgency",
            "title": "Pressure to act quickly",
            "summary": "The message creates a deadline or artificial sense of urgency.",
            "severity": "high",
            "how": "Detected time-pressure phrases and deadline-style wording."
        },
        "URG-02": {
            "key": "threat",
            "title": "Threat of negative consequence",
            "summary": "Warns that an account will be blocked, deactivated, or penalized.",
            "severity": "high",
            "how": "Found language threatening account suspension or legal action."
        },
        "INFO-01": {
            "key": "sensitive",
            "title": "Requests for sensitive details",
            "summary": "Mentions passwords,Scam, scam, OTPs, PINs, card numbers, or login credentials.",
            "severity": "high",
            "how": "Matched terms associated with authentication secrets and identity details."
        },
        "PAY-01": {
            "key": "payment",
            "title": "Unusual payment request",
            "summary": "Requests funds via gift cards, wire transfer, crypto, or unverified UPI.",
            "severity": "high",
            "how": "Found non-standard or irreversible payment instructions."
        },
        "ID-01": {
            "key": "authority",
            "title": "Unverified authority claim",
            "summary": "Claims to represent a bank, security department, or official agency.",
            "severity": "medium",
            "how": "Identified phrases asserting institutional authority."
        },
        "INS-01": {
            "key": "instruction",
            "title": "Suspicious action instruction",
            "summary": "Directs user to click links, open attachments, or keep the message secret.",
            "severity": "medium",
            "how": "Matched directives to click, download, or maintain confidentiality."
        },
        "LURE-01": {
            "key": "lure",
            "title": "Too-good-to-be-true lure",
            "summary": "Promises lotteries, prizes, cashbacks, or free gifts.",
            "severity": "medium",
            "how": "Matched unsolicited reward and prize-claiming patterns."
        },
        "GEN-01": {
            "key": "greeting",
            "title": "Generic impersonal greeting",
            "summary": "Uses vague greetings like 'Dear Customer' instead of addressing you by name.",
            "severity": "low",
            "how": "Found mass-phishing generic opening salutations."
        }
    }

    info = mapping.get(code, {
        "key": code.lower(),
        "title": category or "Suspicious Pattern",
        "summary": why,
        "severity": "medium",
        "how": "Identified by security heuristic rule."
    })

    return {
        "key": info["key"],
        "title": info["title"],
        "summary": info["summary"],
        "why": why or "Attackers use this technique to deceive recipients.",
        "how": info["how"],
        "severity": info["severity"]
    }


def _map_url_signal_to_item(signal: Dict[str, Any], url_data: Dict[str, Any]) -> Dict[str, Any]:
    """Map a URL security signal to a structured UI finding item."""
    code = signal.get("code", "")
    desc = signal.get("description", "")
    weight = signal.get("weight", 10)

    severity = "high" if weight >= 20 else "medium" if weight >= 10 else "low"

    why_map = {
        "URL-LOOK": "Attackers register typo-squatted domains that mimic legitimate brands to trick you into entering credentials.",
        "URL-BRAND": "A known organization's brand is mentioned in the URL, but the actual domain belongs to an unauthorized third party.",
        "URL-IP": "Legitimate organizations rarely send links pointing to raw IP addresses instead of trusted domain names.",
        "URL-AT": "The '@' character instructs browsers to ignore everything preceding it, hiding the true destination.",
        "URL-PUNY": "Punycode (xn--) allows foreign characters that visually resemble standard Latin letters to deceive users.",
        "URL-TLD": "Certain top-level domains are cheap or poorly regulated, making them disproportionately favored by phishing kits.",
        "URL-SHORT": "URL shorteners conceal where the link really points, preventing a preview of the true destination.",
        "URL-HTTP": "Plain HTTP sends traffic unencrypted. Anyone on the local network can intercept the data.",
        "URL-SUB": "Attackers create deep subdomains (e.g. sbi.com.security.xyz) to hide the real domain on mobile screens.",
        "URL-KW": "Keyword stuffing (login, verify, secure) is commonly used to create a false sense of security."
    }

    why = why_map.get(code, "Unusual structural patterns in a URL are a common sign of deceptive intent.")

    return {
        "key": code.lower(),
        "title": f"URL: {desc.split(' - ')[0] if ' - ' in desc else desc}",
        "summary": desc,
        "why": why,
        "how": f"Static structural inspection flagged rule {code} on {url_data.get('registered_domain', 'URL')}.",
        "severity": severity
    }


def calculate_risk(
    message_result: Optional[Dict[str, Any]] = None,
    url_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Synthesizes signals from AI/ML, message heuristics, URL structure, and
    impersonation intelligence into a transparent, explainable risk score (0-100).
    """
    items: List[Dict[str, Any]] = []
    recommendations: List[str] = []
    seen_keys = set()

    message_score = 0
    url_score = 0
    impersonation_score = 0
    ml_prob = 0.0

    # 1. Process Message Results
    if message_result is not None:
        message_score = message_result.get("risk_score", 0)
        ml_data = message_result.get("ml_result", {})
        ml_prob = ml_data.get("phishing_probability", 0.0)

        # Security indicators
        for ind in message_result.get("detailed_indicators", []):
            item = _map_indicator_to_item(ind)
            if item["key"] not in seen_keys:
                items.append(item)
                seen_keys.add(item["key"])

        # Impersonation findings
        for imp in message_result.get("impersonation_findings", []):
            imp_code = imp.get("code", "IMP")
            key = f"imp-{imp.get('entity', '').lower()}-{imp_code.lower()}"
            if key not in seen_keys:
                items.append({
                    "key": key,
                    "title": f"Impersonation: {imp.get('entity', 'Organization')}",
                    "summary": imp.get("description", "Sender or link identity does not match official records."),
                    "why": "Phishers impersonate reputable entities to leverage your trust and provoke hasty actions.",
                    "how": f"Cross-referenced with verified entity database ({imp.get('entity', '')}).",
                    "severity": "high"
                })
                seen_keys.add(key)
                impersonation_score += imp.get("weight", 25)

        # ML indicator if strongly flagged
        if ml_data.get("is_phishing") and ml_prob >= 0.65:
            if "ai-ml" not in seen_keys:
                pct = int(ml_prob * 100)
                items.append({
                    "key": "ai-ml",
                    "title": "AI Classifier: Phishing Pattern Match",
                    "summary": f"Text matches known phishing language with {pct}% probability.",
                    "why": "The vocabulary, tone, and phrasing closely align with historical fraudulent campaigns.",
                    "how": f"TF-IDF vectorizer + Logistic Regression classifier (confidence: {pct}%).",
                    "severity": "high" if ml_prob >= 0.80 else "medium"
                })
                seen_keys.add("ai-ml")

        # Extracted URLs from message
        for ext_url in message_result.get("extracted_urls", []):
            for sig in ext_url.get("signals", []):
                item = _map_url_signal_to_item(sig, ext_url)
                if item["key"] not in seen_keys:
                    items.append(item)
                    seen_keys.add(item["key"])

        recommendations.extend(message_result.get("recommendations", []))

    # 2. Process URL Results
    if url_result is not None:
        url_score = url_result.get("risk_score", 0)
        for sig in url_result.get("signals", []):
            item = _map_url_signal_to_item(sig, url_result)
            if item["key"] not in seen_keys:
                items.append(item)
                seen_keys.add(item["key"])

        recommendations.extend(url_result.get("recommendations", []))

    # 3. Compute Composite Risk Score (0-100)
    if message_result is not None and url_result is not None:
        # Both provided: balanced synthesis
        base = (0.45 * message_score) + (0.45 * url_score)
        imp_boost = min(30, impersonation_score)
        final_score = min(100, round(base + (imp_boost * 0.4)))
        # Do not allow composite score to drop significantly below a critical sub-score
        final_score = max(final_score, round(max(message_score, url_score) * 0.9))
    elif message_result is not None:
        imp_boost = min(30, impersonation_score)
        final_score = min(100, round(message_score + (imp_boost * 0.3)))
    elif url_result is not None:
        final_score = url_score
    else:
        final_score = 0

    # Fallback finding if empty
    if not items:
        items.append({
            "key": "no-clear",
            "title": "No strong pattern matched",
            "summary": "The analysis did not detect obvious high-risk indicators or malicious patterns.",
            "why": "Some subtle attacks do not match standard patterns. A low score cannot guarantee complete safety.",
            "how": "Evaluated against ML classification, static URL rules, and impersonation reference lists.",
            "severity": "low"
        })

    # Deduplicate recommendations and limit to 4 key steps
    deduped_recs = list(dict.fromkeys(recommendations))
    if not deduped_recs:
        deduped_recs = [
            "Verify requests independently through official channels.",
            "Never share passwords, PINs, or one-time passcodes.",
            "Access accounts by typing official web addresses directly into your browser."
        ]
    recommendations = deduped_recs[:4]

    # Risk level categorization
    if final_score >= 65:
        risk_level = "HIGH"
        summary = "Multiple warning signs suggest high phishing or impersonation risk. Do not interact."
    elif final_score >= 35:
        risk_level = "MEDIUM"
        summary = "Suspicious signals detected. Proceed with caution and verify independently."
    else:
        risk_level = "LOW"
        summary = "Few common warning signs detected. Maintain standard security awareness."

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "summary": summary,
        "items": items,
        "indicators": [f"{item['title']}: {item['summary']}" for item in items if item['key'] != 'no-clear'],
        "recommendations": recommendations,
        "breakdown": {
            "message_score": message_score,
            "url_score": url_score,
            "impersonation_score": impersonation_score,
            "ml_probability": round(ml_prob * 100, 1)
        }
    }
