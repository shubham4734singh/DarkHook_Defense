import os
import sys
import json
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

# Add Backend root directory to sys.path for test discovery
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from core.sql_database import init_sqlite_db, SessionLocal
from models.scan_history import ScanHistory
from repositories.scan_history_repository import scan_history_repository

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    """Ensure database tables are created before test and cleaned after test."""
    init_sqlite_db()
    db = SessionLocal()
    try:
        db.query(ScanHistory).delete()
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(ScanHistory).delete()
        db.commit()
    finally:
        db.close()


def test_save_scan_and_get_stats():
    """Test saving scan results and calculating dashboard stats."""
    sample_scan_1 = {
        "fileName": "malicious_payload.docx",
        "fileHash": "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
        "riskScore": 75,
        "verdict": "Phishing",
        "totalFindings": 3,
        "scanTime": 1.25,
        "extractedUrls": [{"url": "http://evil-domain.com"}],
        "findings": ["phishing_keyword", "shortened_url", "virustotal_malicious"],
    }
    sample_scan_2 = {
        "fileName": "clean_invoice.pdf",
        "fileHash": "f6e5d4c3b2a10987f6e5d4c3b2a10987f6e5d4c3b2a10987f6e5d4c3b2a10987",
        "riskScore": 0,
        "verdict": "Safe",
        "totalFindings": 0,
        "scanTime": 0.45,
        "extractedUrls": [],
        "findings": [],
    }
    sample_scan_3 = {
        "fileName": "suspicious_macro.xlsm",
        "fileHash": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "riskScore": 30,
        "verdict": "Suspicious",
        "totalFindings": 1,
        "scanTime": 0.85,
        "extractedUrls": [],
        "findings": ["phishing_keyword"],
    }

    rec1 = scan_history_repository.save_scan(sample_scan_1)
    rec2 = scan_history_repository.save_scan(sample_scan_2)
    rec3 = scan_history_repository.save_scan(sample_scan_3)

    assert rec1 is not None
    assert rec2 is not None
    assert rec3 is not None
    assert rec1.id > 0

    stats = scan_history_repository.get_stats()
    assert stats["total_scans"] == 3
    assert stats["phishing_count"] == 1
    assert stats["suspicious_count"] == 1
    assert stats["safe_count"] == 1
    # Avg score: (75 + 0 + 30) / 3 = 35.0
    assert stats["average_risk_score"] == 35.0
    assert stats["most_common_finding"] == "phishing_keyword"
    assert stats["scans_today"] == 3


def test_get_recent_scans():
    """Test retrieving recent scans sorted newest first with limit."""
    for i in range(15):
        scan_history_repository.save_scan({
            "fileName": f"doc_{i}.pdf",
            "riskScore": i * 5,
            "verdict": "Safe" if i % 2 == 0 else "Phishing",
            "totalFindings": i,
            "scanTime": 0.5,
        })

    recent = scan_history_repository.get_recent(limit=5)
    assert len(recent) == 5
    # Should be sorted newest first (highest ID since autoincrement ID aligns with insertion order)
    assert recent[0]["file_name"] == "doc_14.pdf"
    assert recent[4]["file_name"] == "doc_10.pdf"


def test_get_daily_trend():
    """Test daily trend counts grouped by day."""
    scan_history_repository.save_scan({
        "fileName": "today_doc.docx",
        "riskScore": 80,
        "verdict": "Phishing",
        "totalFindings": 2,
        "scanTime": 0.5,
    })

    trend = scan_history_repository.get_daily_trend(days=7)
    assert len(trend) == 7
    today_str = datetime.now(timezone.utc).date().isoformat()

    today_bucket = [b for b in trend if b["date"] == today_str]
    assert len(today_bucket) == 1
    assert today_bucket[0]["phishing"] == 1
    assert today_bucket[0]["safe"] == 0


def test_dashboard_api_endpoints():
    """Test GET endpoints for stats, recent, and daily-trend via FastAPI TestClient."""
    scan_history_repository.save_scan({
        "fileName": "api_test.pdf",
        "riskScore": 15,
        "verdict": "Safe",
        "totalFindings": 1,
        "scanTime": 0.3,
        "findings": ["suspicious_metadata"],
    })

    # Test /api/v1/dashboard/stats
    response_stats = client.get("/api/v1/dashboard/stats")
    assert response_stats.status_code == 200
    data_stats = response_stats.json()
    assert data_stats["total_scans"] == 1
    assert data_stats["safe_count"] == 1
    assert data_stats["most_common_finding"] == "suspicious_metadata"

    # Test /dashboard/stats direct mount compatibility
    response_stats_direct = client.get("/dashboard/stats")
    assert response_stats_direct.status_code == 200

    # Test /api/v1/dashboard/recent
    response_recent = client.get("/api/v1/dashboard/recent?limit=5")
    assert response_recent.status_code == 200
    data_recent = response_recent.json()
    assert len(data_recent) == 1
    assert data_recent[0]["file_name"] == "api_test.pdf"

    # Test /api/v1/dashboard/daily-trend
    response_trend = client.get("/api/v1/dashboard/daily-trend?days=7")
    assert response_trend.status_code == 200
    data_trend = response_trend.json()
    assert len(data_trend) == 7


def test_save_scan_error_handling(monkeypatch):
    """Test that a database error during save_scan returns None without crashing."""
    def mock_save_error(*args, **kwargs):
        raise RuntimeError("Simulated Database Error")

    monkeypatch.setattr("repositories.scan_history_repository.SessionLocal", mock_save_error)
    res = scan_history_repository.save_scan({"fileName": "broken.docx"})
    assert res is None
