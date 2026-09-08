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
        
        # Convert raw dict lists to pydantic model lists safely
        findings_detailed = []
        for f in result.get("findingsDetailed", []):
            if isinstance(f, dict):
                mitre_dict = f.get("mitre")
                mitre_obj = None
                if isinstance(mitre_dict, dict) and "id" in mitre_dict:
                    try:
                        mitre_obj = MitreTechnique(
                            id=mitre_dict.get("id", ""),
                            name=mitre_dict.get("name", ""),
                            tactic=mitre_dict.get("tactic", ""),
                            description=mitre_dict.get("description", "")
                        )
                    except Exception:
                        pass
                findings_detailed.append(
                    FindingItem(
                        name=f.get("name", f.get("findingType", "").replace("_", " ").title()),
                        findingType=f.get("findingType", "unknown"),
                        severity=f.get("severity", "safe"),
                        score=int(f.get("score", 0)),
                        count=int(f.get("count", 1)),
                        mitre=mitre_obj,
                        evidence=f.get("evidence", []) if isinstance(f.get("evidence"), list) else []
                    )
                )

        score_breakdown = []
        for sb in result.get("scoreBreakdown", []):
            if isinstance(sb, dict):
                score_breakdown.append(
                    ScoreBreakdown(
                        finding_type=sb.get("finding_type", "Unknown"),
                        count=int(sb.get("count", 1)),
                        score=int(sb.get("score", 0))
                    )
                )

        mitre_techniques = []
        for m in result.get("mitreTechniques", []):
            if isinstance(m, dict) and "id" in m:
                try:
                    mitre_techniques.append(
                        MitreTechnique(
                            id=m.get("id", ""),
                            name=m.get("name", ""),
                            tactic=m.get("tactic", ""),
                            description=m.get("description", "")
                        )
                    )
                except Exception:
                    pass

        extracted_urls = []
        for u in result.get("extractedUrls", []):
            if isinstance(u, dict):
                extracted_urls.append(
                    ExtractedUrlInfo(
                        url=u.get("url", ""),
                        domain=u.get("domain", ""),
                        is_suspicious=bool(u.get("is_suspicious", False)),
                        reasons=u.get("reasons", []) if isinstance(u.get("reasons"), list) else []
                    )
                )

        # Automatically persist scan result to scan_history database for dashboard stats
        try:
            from repositories.scan_history_repository import scan_history_repository
            scan_history_repository.save_scan(result)
        except Exception as db_exc:
            print(f"[!] Warning: Non-critical failure saving scan to dashboard database: {db_exc}")

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
        import traceback
        traceback.print_exc()
        print(f"[!] Error scanning document: {exc}")
        raise HTTPException(status_code=500, detail=f"Error scanning document: {exc}")


@router.get("/document/formats")
async def supported_formats():
    """Retrieve the list of supported file formats and extensions for document scanning."""
    formats = document_analyzer.get_supported_formats()
    return {"formats": formats}


@router.get("/document/history")
@router.get("/history")
async def get_document_scan_history(limit: int = 10):
    """Retrieve the history of scanned documents from SQLite database."""
    try:
        from repositories.scan_history_repository import scan_history_repository
        return scan_history_repository.get_recent(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch document scan history: {exc}")

