from pydantic import BaseModel
from typing import List

class FindingItem(BaseModel):
    name: str
    findingType: str
    severity: str
    score: int

class ScoreBreakdown(BaseModel):
    finding_type: str
    count: int
    score: int

class DocumentScanResult(BaseModel):
    fileName: str
    fileSize: str
    fileHash: str
    riskScore: int
    verdict: str
    severity: str
    scanTime: float
    totalFindings: int
    findings: List[str]
    findingsDetailed: List[FindingItem]
    scoreBreakdown: List[ScoreBreakdown]
    details: List[str]
