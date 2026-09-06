from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    description: str


class ExtractedUrlInfo(BaseModel):
    url: str
    domain: str
    is_suspicious: bool
    reasons: List[str]


class FindingItem(BaseModel):
    name: str
    findingType: str
    severity: str
    score: int
    mitre: Optional[MitreTechnique] = None


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
    mitreTechniques: Optional[List[MitreTechnique]] = []
    extractedUrls: Optional[List[ExtractedUrlInfo]] = []
    details: List[str]
