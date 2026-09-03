from fastapi import APIRouter, File, HTTPException, UploadFile
from schemas.document import DocumentScanResult, FindingItem, ScoreBreakdown
from services.document_analyzer import document_analyzer
from core.config import settings

router = APIRouter()

@router.post("/document", response_model=DocumentScanResult)
async def scan_document(file: UploadFile = File(...)):
    """Upload and analyze documents/images (.pdf, .docx, .xlsx, .xls, .pptx, .png, .jpg, .jpeg) for embedded malware/phishing indicators."""
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
        result = document_analyzer.analyze_document(file.filename, file_data)
        
        # Convert raw dict lists to pydantic model lists
        findings_detailed = [
            FindingItem(
                name=f["name"],
                findingType=f["findingType"],
                severity=f["severity"],
                score=f["score"]
            ) for f in result["findingsDetailed"]
        ]
        
        score_breakdown = [
            ScoreBreakdown(
                finding_type=sb["finding_type"],
                count=sb["count"],
                score=sb["score"]
            ) for sb in result["scoreBreakdown"]
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
