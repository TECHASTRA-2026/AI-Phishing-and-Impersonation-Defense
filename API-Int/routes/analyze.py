from fastapi import APIRouter, HTTPException

from schemas.request import (
    MessageRequest,
    URLRequest,
    CombinedRequest
)

from integrations.message_service import analyze_message
from integrations.url_service import analyze_url

from services.risk_engine import calculate_risk


router = APIRouter()


# MESSAGE ANALYSIS API
@router.post("/analyze/message")
def message_analysis(data: MessageRequest):

    try:
        message_result = analyze_message(data.message)

        final_result = calculate_risk(
            message_result=message_result
        )

        return {
            "success": True,
            "analysis_type": "Message Analysis",
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
            "url_analysis": url_result,
            "final_result": final_result
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"URL analysis failed: {str(error)}"
        )


# COMBINED ANALYSIS API
@router.post("/analyze")
def combined_analysis(data: CombinedRequest):

    try:
        message_result = None
        url_result = None

        if data.message and data.message.strip():
            message_result = analyze_message(data.message)

        if data.url and data.url.strip():
            url_result = analyze_url(data.url)

        final_result = calculate_risk(
            message_result=message_result,
            url_result=url_result
        )

        return {
            "success": True,
            "analysis_type": "Combined Analysis",
            "message_analysis": message_result,
            "url_analysis": url_result,
            "final_result": final_result
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Combined analysis failed: {str(error)}"
        )