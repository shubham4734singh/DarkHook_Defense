from pydantic import BaseModel, Field

class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=4, description="URL to analyze")

class URLAnalyzeResponse(BaseModel):
    scan_id: str
    url: str
    score: int
    confidence: float
    verdict: str
    status: str
    flags: list[str]
    feature_summary: dict
    analysis_details: dict
    explanation: str = Field(..., description="Human-readable explanation of the analysis result")
    screenshot: dict | None = Field(None, description="Website screenshot data")
