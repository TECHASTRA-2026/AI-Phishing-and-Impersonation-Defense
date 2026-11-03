def calculate_risk(message_result=None, url_result=None):

    scores = []
    indicators = []
    recommendations = []

    # Get message analysis results
    if message_result is not None:

        scores.append(message_result["risk_score"])

        indicators.extend(
            message_result.get("indicators", [])
        )

        recommendations.extend(
            message_result.get("recommendations", [])
        )

    # Get URL analysis results
    if url_result is not None:

        scores.append(url_result["risk_score"])

        indicators.extend(
            url_result.get("indicators", [])
        )

        recommendations.extend(
            url_result.get("recommendations", [])
        )

    # Calculate final risk score
    if scores:
        risk_score = round(sum(scores) / len(scores))
    else:
        risk_score = 0

    # Determine risk level
    if risk_score >= 70:
        risk_level = "HIGH"

    elif risk_score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    # Remove duplicate indicators and recommendations
    indicators = list(dict.fromkeys(indicators))
    recommendations = list(dict.fromkeys(recommendations))

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendations": recommendations
    }