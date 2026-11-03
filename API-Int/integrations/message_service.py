def analyze_message(message):

    # Temporary mock response
    return {
        "classification": "Suspicious",
        "confidence": 0.89,
        "risk_score": 85,
        "indicators": [
            "Urgent language detected",
            "Request for sensitive information detected"
        ],
        "recommendations": [
            "Verify the sender before responding.",
            "Never share OTPs or passwords."
        ]
    }