from pydantic import BaseModel
from typing import List

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
