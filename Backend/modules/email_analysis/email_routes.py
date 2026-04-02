from __future__ import annotations

import os
import tempfile
from functools import lru_cache
from time import perf_counter
from typing import List

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from .email_parser import EmailAnalyzer

router = APIRouter()
MAX_EMAIL_UPLOAD_BYTES = int(os.getenv("MAX_EMAIL_UPLOAD_BYTES", str(5 * 1024 * 1024)))


class EmailScanResult(BaseModel):
    fileName: str
    riskScore: int
    verdict: str
    severity: str
    scanTime: float
    headerFlags: List[str]
    bodyFlags: List[str]
    extractedUrls: List[str]
    extractedAttachments: List[str]


def _score_to_severity(score: int) -> str:
    if score <= 39:
        return "LOW"
    if score <= 69:
        return "MEDIUM"
    return "CRITICAL"


@lru_cache(maxsize=1)
def get_email_analyzer() -> EmailAnalyzer:
    # Reuse the analyzer so ML artifacts are loaded once per process.
    return EmailAnalyzer()


@router.post("/email", response_model=EmailScanResult)
async def scan_email(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    suffix = os.path.splitext(file.filename)[1].lower()
    if suffix != ".eml":
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    file_data = await file.read()
    if not file_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(file_data) > MAX_EMAIL_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file is too large. Maximum allowed size is {MAX_EMAIL_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
        tmp_file.write(file_data)
        tmp_path = tmp_file.name

    started = perf_counter()
    try:
        analyzer = get_email_analyzer()
        analysis = analyzer.analyze(tmp_path)

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
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error scanning email: {exc}") from exc
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
