from fastapi import APIRouter, HTTPException, Request
from schemas.url import URLAnalyzeRequest, URLAnalyzeResponse
from services.url_analyzer import url_analyzer
from repositories.url_cache_repository import url_cache_repository
from datetime import datetime
from uuid import uuid4

router = APIRouter()

@router.get("/history")
async def get_scan_history():
    """Retrieve merged scan history across URLs, Documents, and Emails."""
    try:
        from repositories.scan_history_repository import scan_history_repository
        return scan_history_repository.get_recent(limit=50)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scan history: {e}")

@router.post("/url", response_model=URLAnalyzeResponse)
async def analyze_url(payload: URLAnalyzeRequest, request: Request):
    """Scan a target URL for phishing indicators, typosquatting, and zero-day threat signals."""
    try:
        result = url_analyzer.scan_url(payload.url, str(request.base_url))
        url_cache_repository.save_cached_scan(payload.url, result)

        try:
            from repositories.scan_history_repository import scan_history_repository
            scan_history_repository.save_scan({
                "fileName": payload.url,
                "fileHash": "",
                "riskScore": result.get("score", 0),
                "verdict": result.get("verdict", "Safe"),
                "totalFindings": len(result.get("flags", [])),
                "scanTime": 0.5,
                "extractedUrls": [payload.url],
                "findings": result.get("flags", []),
                "scanType": "URL"
            })
        except Exception as db_exc:
            print(f"[!] Warning: Failed saving URL scan to scan_history: {db_exc}")

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
