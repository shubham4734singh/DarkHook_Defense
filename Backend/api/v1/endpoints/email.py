import os
from time import perf_counter
import tempfile
from fastapi import APIRouter, File, HTTPException, UploadFile
from schemas.email import EmailScanResult
from services.email_analyzer import email_analyzer
from core.config import settings

router = APIRouter()

def _score_to_severity(score: int) -> str:
    if score <= 39:
        return "LOW"
    if score <= 69:
        return "MEDIUM"
    return "CRITICAL"

@router.post("/email", response_model=EmailScanResult)
async def scan_email(file: UploadFile = File(...)):
    """Upload and analyze a raw .eml file for header spoofing, phishing links, and body text anomalies."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    suffix = os.path.splitext(file.filename)[1].lower()
    if suffix != ".eml":
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    file_data = await file.read()
    if not file_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    if len(file_data) > settings.MAX_EMAIL_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file is too large. Maximum allowed size is {settings.MAX_EMAIL_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )

    # Save to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
        tmp_file.write(file_data)
        tmp_path = tmp_file.name

    started = perf_counter()
    try:
        analysis = email_analyzer.analyze(tmp_path)
        score = int(analysis.get("score", 0))

        return EmailScanResult(
            fileName=file.filename,
            riskScore=score,
            verdict=str(analysis.get("verdict", "SAFE")),
            severity=_score_to_severity(score),
            scanTime=round(perf_counter() - started, 4),
            headerFlags=[str(x) for x in (analysis.get("header_flags") or [])],
            bodyFlags=[str(x) for x in (analysis.get("body_flags") or [])],
            extractedUrls=[str(x) for x in (analysis.get("extracted_urls") or [])],
            extractedAttachments=[str(x) for x in (analysis.get("extracted_attachments") or [])],
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error scanning email: {exc}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
