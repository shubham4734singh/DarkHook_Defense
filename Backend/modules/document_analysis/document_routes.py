"""
Document Analysis Router - PDF, DOCX, Excel, PPT scanning
"""

import os
import hashlib
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import tempfile

from ..document_analysis.pdf_parser import parse_pdf
from ..document_analysis.scorer import calculate_score

router = APIRouter()


# ================================================================
# RESPONSE MODELS
# ================================================================

class FindingItem(BaseModel):
    """Individual finding/threat detected"""
    name: str
    severity: str  # safe, warning, danger, critical


class ScoreBreakdown(BaseModel):
    """Score breakdown by finding type"""
    finding_type: str
    count: int
    score: int


class DocumentScanResult(BaseModel):
    """Complete scan result for a document"""
    fileName: str
    fileSize: str
    fileHash: str
    riskScore: int
    verdict: str
    scanTime: float
    totalFindings: int
    findings: List[str]
    scoreBreakdown: List[Dict[str, Any]]
    details: List[str]


# ================================================================
# HELPER FUNCTIONS
# ================================================================

def get_file_hash(file_data: bytes) -> str:
    """Calculate SHA256 hash of file"""
    return hashlib.sha256(file_data).hexdigest()


def map_severity(finding_type: str) -> str:
    """Map finding types to severity levels"""
    critical_findings = [
        "javascript_detected",
        "embedded_executable",
        "powershell_detected",
        "dropper_pattern",
        "openaction_detected",
        "launch_action_detected",
    ]
    
    high_findings = [
        "base64_payload",
        "hex_payload",
        "malicious_macro",
        "credential_harvesting",
        "ip_based_url",
        "homograph_domain",
        "at_symbol_trick",
    ]
    
    medium_findings = [
        "embedded_file_detected",
        "high_entropy_string",
        "suspicious_url",
        "shortened_url",
        "suspicious_tld",
        "external_network_call",
    ]
    
    if finding_type in critical_findings:
        return "critical"
    elif finding_type in high_findings:
        return "danger"
    elif finding_type in medium_findings:
        return "warning"
    else:
        return "safe"


# ================================================================
# ENDPOINTS
# ================================================================

@router.post("/document", response_model=DocumentScanResult)
async def scan_document(file: UploadFile = File(...)):
    """
    Scan a document (PDF, DOCX, Excel, PPT) for phishing threats
    
    Currently supported:
    - PDF (.pdf) - Full analysis with 4-layer detection
    
    Coming soon:
    - Word (.docx) - Macro and embedded object analysis
    - Excel (.xlsx, .xls) - Formula and macro detection
    - PowerPoint (.pptx) - Embedded file and macro analysis
    """
    
    try:
        # Read file data
        file_data = await file.read()
        file_hash = get_file_hash(file_data)
        file_size = len(file_data)
        
        # Save to temporary file
        suffix = os.path.splitext(file.filename)[1].lower()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            tmp_file.write(file_data)
            tmp_path = tmp_file.name
        
        try:
            # Parse based on file type
            if suffix == ".pdf":
                result = parse_pdf(tmp_path)
            elif suffix == ".docx":
                # DOCX parser coming soon
                raise HTTPException(
                    status_code=501,
                    detail="DOCX analysis coming soon. Currently supporting PDF only."
                )
            elif suffix in [".xlsx", ".xls"]:
                # Excel parser coming soon
                raise HTTPException(
                    status_code=501,
                    detail="Excel analysis coming soon. Currently supporting PDF only."
                )
            elif suffix == ".pptx":
                # PowerPoint parser coming soon
                raise HTTPException(
                    status_code=501,
                    detail="PowerPoint analysis coming soon. Currently supporting PDF only."
                )
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported file format: {suffix}. Currently supporting: .pdf"
                )
            
            # Calculate score
            score_result = calculate_score(result["findings"])
            
            # Format findings with severity
            findings_with_severity = []
            for finding in result["findings"]:
                findings_with_severity.append({
                    "name": finding.replace("_", " ").title(),
                    "severity": map_severity(finding)
                })
            
            # Format score breakdown
            score_breakdown = []
            if score_result.get("breakdown"):
                for finding_type, points in sorted(
                    score_result["breakdown"].items(),
                    key=lambda x: x[1],
                    reverse=True
                ):
                    score_breakdown.append({
                        "finding_type": finding_type.replace("_", " ").title(),
                        "score": points
                    })
            
            # Build response
            response = DocumentScanResult(
                fileName=file.filename,
                fileSize=f"{file_size / 1024:.2f} KB",
                fileHash=file_hash,
                riskScore=score_result["score"],
                verdict=score_result["verdict"],
                scanTime=0.1,  # Could be tracked in parsers
                totalFindings=len(result["findings"]),
                findings=result["findings"],
                scoreBreakdown=score_breakdown,
                details=result["details"]
            )
            
            return response
            
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except:
                pass
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error scanning document: {str(e)}"
        )


@router.get("/document/formats")
async def supported_formats():
    """Get list of supported document formats"""
    return {
        "formats": [
            {
                "name": "PDF",
                "extension": ".pdf",
                "description": "Portable Document Format - Fully Supported",
                "supported": True
            },
            {
                "name": "Word",
                "extension": ".docx",
                "description": "Microsoft Word Document - Coming Soon",
                "supported": False
            },
            {
                "name": "Excel",
                "extension": ".xlsx, .xls",
                "description": "Microsoft Excel Spreadsheet - Coming Soon",
                "supported": False
            },
            {
                "name": "PowerPoint",
                "extension": ".pptx",
                "description": "Microsoft PowerPoint Presentation - Coming Soon",
                "supported": False
            }
        ]
    }
