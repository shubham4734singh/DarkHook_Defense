import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from core.sql_database import Base


def _utc_now():
    return datetime.now(timezone.utc)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    file_name = Column(String(255), nullable=False, index=True)
    file_hash = Column(String(64), nullable=False, default="")
    risk_score = Column(Integer, nullable=False, default=0)
    verdict = Column(String(50), nullable=False, default="Safe")
    threat_count = Column(Integer, nullable=False, default=0)
    scan_duration = Column(Float, nullable=False, default=0.0)
    extracted_url_count = Column(Integer, nullable=False, default=0)
    findings = Column(Text, nullable=False, default="[]")  # JSON string of finding IDs
    scanned_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)

    def get_findings_list(self) -> list:
        """Helper to parse findings JSON string into a Python list."""
        if not self.findings:
            return []
        try:
            return json.loads(self.findings)
        except Exception:
            return []

    def set_findings_list(self, findings_list: list) -> None:
        """Helper to serialize Python list into findings JSON string."""
        self.findings = json.dumps(findings_list or [])

    def to_dict(self) -> dict:
        """Serialize model instance to dictionary."""
        return {
            "id": self.id,
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "threat_count": self.threat_count,
            "scan_duration": self.scan_duration,
            "extracted_url_count": self.extracted_url_count,
            "findings": self.get_findings_list(),
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
        }
