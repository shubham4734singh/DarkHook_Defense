from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from Backend.modules.email_analysis import email_routes
from Backend.modules.email_analysis.email_parser import EmailAnalyzer
from Backend.modules.email_analysis.header_parser import analyze_headers


BASE_DIR = Path(__file__).resolve().parent


def test_header_analyzer_detects_reply_to_mismatch() -> None:
    """
    TEST 1 (Unit):
    Ensure that a mismatch between From and Reply-To domains is flagged
    as suspicious by the header analyzer.
    """
    msg = EmailMessage()
    msg["From"] = "PayPal Support <service@paypal.com>"
    msg["Reply-To"] = "Attacker <phish@evil-attacker.com>"

    result: Dict[str, Any] = analyze_headers(msg)

    assert result["is_suspicious"] is True
    assert any(
        "From / Reply-To domain mismatch" in flag
        for flag in result["header_flags"]
    )


def test_urgency_keyword_scoring_increases_with_phishing_terms() -> None:
    """
    TEST 2 (Unit):
    Verify that the urgency keyword scoring increases when the body text
    contains classic phishing trigger words.
    """
    neutral_text = "Hello, this is a normal message with no security concerns."
    phishing_text = (
        "Your account is suspended. This is an urgent security alert. "
        "Please verify your login immediately to restore access."
    )

    neutral_score, _ = EmailAnalyzer._compute_urgency_score(neutral_text)
    phishing_score, _ = EmailAnalyzer._compute_urgency_score(phishing_text)

    assert neutral_score >= 0.0
    assert phishing_score > neutral_score
    assert phishing_score > 0.0


@pytest.fixture
def app() -> FastAPI:
    """
    Provide a FastAPI application instance with the email analysis router
    mounted for integration tests.
    """
    app = FastAPI()
    app.include_router(email_routes.router)
    return app


@pytest_asyncio.fixture
async def async_client(app: FastAPI) -> httpx.AsyncClient:
    """
    Provide an HTTPX AsyncClient bound to the FastAPI ASGI app.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.asyncio
async def test_analyze_phishing_email_integration(async_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    TEST 3 (Integration):
    - Upload a realistic phishing .eml file.
    - Assert the endpoint responds successfully.
    - Assert the verdict is PHISHING and score is high.
    - Assert the phishing URL is extracted.

    The ML probability component is monkeypatched to be high so that
    the test is deterministic and does not depend on local model files.
    """

    def fake_ml_phishing_probability(self, _: str) -> float:
        return 0.95

    # Ensure any call into the ML scorer yields a strong phishing signal.
    monkeypatch.setattr(
        EmailAnalyzer,
        "_ml_phishing_probability",
        fake_ml_phishing_probability,
        raising=False,
    )

    phishing_eml_path = BASE_DIR / "test_emails" / "sample_phishing.eml"
    assert phishing_eml_path.exists(), "Sample phishing .eml file is missing."

    eml_bytes = phishing_eml_path.read_bytes()

    files = {
        "file": (
            "sample_phishing.eml",
            eml_bytes,
            "message/rfc822",
        )
    }

    response = await async_client.post("/email", files=files)

    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    data = response.json()

    assert data["verdict"] == "PHISHING"
    assert data["riskScore"] > 70
    assert "http://paypa1-login.com/verify" in data["extractedUrls"]


@pytest.mark.asyncio
async def test_uploading_non_eml_file_returns_client_error(async_client: httpx.AsyncClient) -> None:
    """
    TEST 4 (Edge Case):
    Upload a non-.eml file and assert that the API rejects it with
    a client error (400 / 422).
    """
    fake_content = b"This is just a plain text file, not a real email."

    files = {
        "file": (
            "not_an_email.txt",
            fake_content,
            "text/plain",
        )
    }

    response = await async_client.post("/email", files=files)

    # Our router raises a 400, but allow 422 if validation changes.
    assert response.status_code in (400, 422)

