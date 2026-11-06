from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List

from schemas.request import (
    MessageRequest,
    URLRequest,
    ImpersonationRequest,
    CombinedRequest
)

from integrations.message_service import analyze_message
from integrations.url_service import analyze_url
from services.risk_engine import calculate_risk
import security_layer

router = APIRouter()


# GET TRUSTED ENTITIES LIST
@router.get("/trusted-entities")
def get_trusted_entities():
    """Returns the trusted institutional directory used for impersonation verification."""
    return {
        "success": True,
        "count": len(security_layer.ENTITIES),
        "entities": [
            {
                "name": e["name"],
                "aliases": e["aliases"],
                "official_domains": e["official_domains"]
            }
            for e in security_layer.ENTITIES
        ]
    }


# MESSAGE ANALYSIS API
@router.post("/analyze/message")
def message_analysis(data: MessageRequest):
    try:
        message_result = analyze_message(
            data.message,
            sender_email=data.sender_email or "",
            sender_name=data.sender_name or ""
        )

        final_result = calculate_risk(
            message_result=message_result
        )

        return {
            "success": True,
            "analysis_type": "Message Analysis",
            "score": final_result["risk_score"],
            "level": final_result["risk_level"],
            "summary": final_result["summary"],
            "items": final_result["items"],
            "recommendations": final_result["recommendations"],
            "breakdown": final_result["breakdown"],
            "message_analysis": message_result,
            "final_result": final_result
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Message analysis failed: {str(error)}"
        )


# URL ANALYSIS API
@router.post("/analyze/url")
def url_analysis(data: URLRequest):
    try:
        url_result = analyze_url(data.url)

        final_result = calculate_risk(
            url_result=url_result
        )

        return {
            "success": True,
            "analysis_type": "URL Analysis",
            "score": final_result["risk_score"],
            "level": final_result["risk_level"],
            "summary": final_result["summary"],
            "items": final_result["items"],
            "recommendations": final_result["recommendations"],
            "breakdown": final_result["breakdown"],
            "url_analysis": url_result,
            "final_result": final_result
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"URL analysis failed: {str(error)}"
        )


# IMPERSONATION ANALYSIS API
@router.post("/analyze/impersonation")
def impersonation_analysis(data: ImpersonationRequest):
    try:
        # Combine brand, sender_name, and message to catch all mentions
        brand = (data.claimed_entity or "").strip()
        sender_email = (data.sender_email or "").strip()
        sender_name = (data.sender_name or "").strip()
        message = (data.message or "").strip()
        url = (data.url or "").strip()

        urls_list = [url] if url else None
        combined_sender_name = f"{sender_name} {brand}".strip()
        combined_text = f"{brand}\n{message}".strip()

        # Run impersonation engine
        findings = security_layer.analyze_impersonation(
            text=combined_text,
            sender_email=sender_email,
            sender_name=combined_sender_name,
            urls=urls_list
        )

        claimed = security_layer.claimed_entities(combined_text, combined_sender_name)
        claimed_names = [e["name"] for e in claimed]
        official_domains = [d for e in claimed for d in e["official_domains"]]

        # Calculate score specifically for impersonation
        imp_score = min(100, sum(f.get("weight", 25) for f in findings))

        items: List[Dict[str, Any]] = []
        for f in findings:
            items.append({
                "key": f.get("code", "IMP").lower(),
                "title": f"Impersonation Flag: {f.get('entity', 'Entity')}",
                "summary": f.get("description", "Identity mismatch detected against official records."),
                "why": "Phishers impersonate reputable organizations to manipulate victims into immediate compliance.",
                "how": f"Rule {f.get('code')}: Verified against official domains: {', '.join(official_domains)}",
                "severity": "high"
            })

        if not items:
            if claimed_names:
                summary = f"Claimed identity matches trusted official records for {', '.join(claimed_names)}."
                level = "LOW"
                items.append({
                    "key": "imp-verified",
                    "title": f"Verified Domain Match: {', '.join(claimed_names)}",
                    "summary": f"Sender and link domains match official records ({', '.join(official_domains)}).",
                    "why": "Legitimate communications originate exclusively from official authenticated domains.",
                    "how": f"Domain match verified against official repository.",
                    "severity": "low"
                })
            else:
                summary = "No known impersonated institutions detected in submitted text or addresses."
                level = "LOW"
                items.append({
                    "key": "imp-clean",
                    "title": "No Brand Inconsistencies Detected",
                    "summary": "Sender domain does not mimic or conflict with registered institutions.",
                    "why": "The sender is not claiming an entity from our recognized banking or enterprise registry.",
                    "how": "Compared against trusted institutional database.",
                    "severity": "low"
                })
        else:
            summary = f"High-risk brand impersonation detected! Spoofing claimed identity of {', '.join(claimed_names) or 'recognized entity'}."
            level = "HIGH" if imp_score >= 50 else "MEDIUM"

        recommendations = [
            f"Never trust emails or links claiming to represent {claimed_names[0] if claimed_names else 'an institution'} if the domain does not end in: {', '.join(official_domains) if official_domains else 'their official address'}.",
            "Open your browser and navigate directly to the official homepage manually.",
            "Report spoofed sender domains to the legitimate organization's cybersecurity fraud desk."
        ]

        return {
            "success": True,
            "analysis_type": "Impersonation Analysis",
            "score": imp_score,
            "level": level,
            "summary": summary,
            "claimed_entities": claimed_names,
            "official_domains": official_domains,
            "findings": findings,
            "items": items,
            "recommendations": recommendations,
            "breakdown": {
                "impersonation_score": imp_score,
                "message_score": 0,
                "url_score": 0,
                "ml_probability": 0
            }
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Impersonation analysis failed: {str(error)}"
        )


# COMBINED ANALYSIS API
@router.post("/analyze")
def combined_analysis(data: CombinedRequest):
    try:
        message_result = None
        url_result = None

        brand = (data.claimed_entity or "").strip()
        combined_sender_name = f"{data.sender_name or ''} {brand}".strip()

        if data.message and data.message.strip():
            attached_urls = [data.url.strip()] if (data.url and data.url.strip()) else None
            message_result = analyze_message(
                data.message,
                sender_email=data.sender_email or "",
                sender_name=combined_sender_name,
                urls=attached_urls
            )

        if data.url and data.url.strip():
            url_result = analyze_url(data.url)

        final_result = calculate_risk(
            message_result=message_result,
            url_result=url_result
        )

        kind = (
            "Message + URL" if message_result and url_result
            else "Message" if message_result
            else "URL"
        )

        return {
            "success": True,
            "analysis_type": f"{kind} Analysis",
            "kind": kind,
            "score": final_result["risk_score"],
            "level": final_result["risk_level"],
            "summary": final_result["summary"],
            "items": final_result["items"],
            "recommendations": final_result["recommendations"],
            "breakdown": final_result["breakdown"],
            "message_analysis": message_result,
            "url_analysis": url_result,
            "final_result": final_result
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Combined analysis failed: {str(error)}"
        )
