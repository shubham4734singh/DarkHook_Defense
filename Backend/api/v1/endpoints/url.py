from fastapi import APIRouter, HTTPException, Request
from schemas.url import URLAnalyzeRequest, URLAnalyzeResponse
from services.url_analyzer import url_analyzer
from repositories.url_cache_repository import url_cache_repository
from datetime import datetime
from uuid import uuid4

router = APIRouter()

@router.get("/history")
async def get_scan_history():
    """Retrieve the history of scanned URLs from MongoDB cache."""
    try:
        # Fetch latest 50 scans from MongoDB
        scans = list(url_cache_repository.collection.find().sort("scanned_at", -1).limit(50))
        history_list = []
        for scan in scans:
            res = scan.get("result", {})
            history_list.append({
                "url": scan["url"],
                "score": res.get("score", 0),
                "verdict": res.get("verdict", "Unknown"),
                "status": res.get("status", "safe"),
                "scanned_at": scan["scanned_at"].isoformat() if isinstance(scan.get("scanned_at"), datetime) else str(scan.get("scanned_at")),
                "feature_summary": res.get("feature_summary", {}),
                "flags": res.get("flags", []),
                "explanation": res.get("explanation", ""),
                "screenshot": res.get("screenshot"),
                "analysis_details": res.get("analysis_details", {}),
            })
        return history_list
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scan history: {e}")

@router.post("/url", response_model=URLAnalyzeResponse)
async def analyze_url(payload: URLAnalyzeRequest, request: Request):
    """Scan a target URL for phishing indicators, typosquatting, and zero-day threat signals."""
    try:
        result = url_analyzer.scan_url(payload.url, str(request.base_url))
        return URLAnalyzeResponse(
            scan_id=str(uuid4()),
            url=result["url"],
            score=result["score"],
            confidence=result["confidence"],
            verdict=result["verdict"],
            status=result["status"],
            flags=result["flags"],
            feature_summary=result["feature_summary"],
            analysis_details=result["analysis_details"],
            explanation=result["explanation"],
            screenshot=result["screenshot"],
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {exc}")
