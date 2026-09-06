from fastapi import APIRouter, File, HTTPException, UploadFile
from starlette.concurrency import run_in_threadpool

from schemas.document import DocumentScanResult, FindingItem, ScoreBreakdown, MitreTechnique, ExtractedUrlInfo
from services.document_analyzer import document_analyzer
from core.config import settings

router = APIRouter()


@router.post("/document", response_model=DocumentScanResult)
async def scan_document(file: UploadFile = File(...)):
    """Upload and analyze documents/images (.pdf, .docx, .docm, .xlsx, .xlsm, .pptx, .ppt, .png, .jpg, etc.) for embedded malware, macros, and phishing indicators."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    file_data = await file.read()
    if not file_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    if len(file_data) > settings.MAX_DOCUMENT_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file is too large. Maximum allowed size is {settings.MAX_DOCUMENT_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )

    try:
        # Offload synchronous CPU-heavy document parsing to thread pool
        result = await run_in_threadpool(document_analyzer.analyze_document, file.filename, file_data)
        
        # Convert raw dict lists to pydantic model lists
        findings_detailed = [
            FindingItem(
                name=f["name"],
                findingType=f["findingType"],
                severity=f["severity"],
                score=f["score"],
                mitre=MitreTechnique(**f["mitre"]) if f.get("mitre") else None
            ) for f in result.get("findingsDetailed", [])
        ]
        
        score_breakdown = [
            ScoreBreakdown(
                finding_type=sb["finding_type"],
                count=sb["count"],
                score=sb["score"]
            ) for sb in result.get("scoreBreakdown", [])
        ]

        mitre_techniques = [
            MitreTechnique(
                id=m["id"],
                name=m["name"],
                tactic=m["tactic"],
                description=m["description"]
            ) for m in result.get("mitreTechniques", [])
        ]

        extracted_urls = [
            ExtractedUrlInfo(
                url=u["url"],
                domain=u["domain"],
                is_suspicious=u["is_suspicious"],
                reasons=u["reasons"]
            ) for u in result.get("extractedUrls", [])
        ]

        return DocumentScanResult(
            fileName=result["fileName"],
            fileSize=result["fileSize"],
            fileHash=result["fileHash"],
            riskScore=result["riskScore"],
            verdict=result["verdict"],
            severity=result["severity"],
            scanTime=result["scanTime"],
            totalFindings=result["totalFindings"],
            findings=result["findings"],
            findingsDetailed=findings_detailed,
            scoreBreakdown=score_breakdown,
            mitreTechniques=mitre_techniques,
            extractedUrls=extracted_urls,
            details=result["details"]
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error scanning document: {exc}")


@router.get("/document/formats")
async def supported_formats():
    """Retrieve the list of supported file formats and extensions for document scanning."""
    formats = document_analyzer.get_supported_formats()
    return {"formats": formats}
