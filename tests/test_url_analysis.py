"""
API-level tests for URL analysis.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


backend_path = Path(__file__).resolve().parent.parent / "Backend"
sys.path.insert(0, str(backend_path))
os.chdir(backend_path)

from app import app  # noqa: E402
from modules.url_analysis import link  # noqa: E402


def _stub_ml_service(_: str) -> dict:
    return {"error": "disabled in tests", "available": False}


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(link, "call_hf_ml_service", _stub_ml_service)
    return TestClient(app)


def test_response_structure(monkeypatch):
    client = _client(monkeypatch)
    response = client.post("/scan/url", json={"url": "https://example.com"})

    assert response.status_code == 200
    result = response.json()

    required_fields = [
        "scan_id",
        "url",
        "score",
        "confidence",
        "verdict",
        "status",
        "flags",
        "feature_summary",
        "explanation",
    ]
    for field in required_fields:
        assert field in result

    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100
    assert isinstance(result["confidence"], float)
    assert isinstance(result["flags"], list)
    assert isinstance(result["feature_summary"], dict)
    assert isinstance(result["explanation"], str)
    assert result["explanation"]


def test_url_analysis_endpoint(monkeypatch):
    client = _client(monkeypatch)

    test_cases = [
        {"url": "https://google.com", "expected_status": "safe", "max_score": 45},
        {"url": "http://paypa1.com/login", "expected_status": "phishing", "min_score": 70},
        {"url": "https://secure-login.tk/verify", "expected_status": "phishing", "min_score": 70},
        {"url": "http://bit.ly/abc123", "expected_status": "phishing", "min_score": 40},
        {"url": "https://dev-environment.example.com", "expected_status": "safe", "max_score": 45},
    ]

    for case in test_cases:
        response = client.post("/scan/url", json={"url": case["url"]})
        assert response.status_code == 200, case["url"]

        result = response.json()
        assert result["status"] == case["expected_status"], case["url"]

        if "min_score" in case:
            assert result["score"] >= case["min_score"], case["url"]
        if "max_score" in case:
            assert result["score"] <= case["max_score"], case["url"]
