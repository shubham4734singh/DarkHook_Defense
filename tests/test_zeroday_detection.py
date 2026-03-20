"""Zero-day phishing heuristic tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import (
    build_flags,
    build_analysis_details,
    calculate_verdict_confidence,
    calculate_anomaly_score,
    compute_heuristic_score,
    decode_leetspeak,
    detect_brand_impersonation,
    detect_homograph_attack,
    detect_urgency_manipulation,
    extract_features,
    normalize_url,
)
from modules.url_analysis.dynamic import analyze_runtime_url
import modules.url_analysis.dynamic as dynamic_module
import modules.url_analysis.link as link_module


def test_decode_leetspeak():
    assert decode_leetspeak("w4ll3t") == "wallet"


def test_homograph_detection():
    assert detect_homograph_attack("аррӏе-login.com")


def test_urgency_detection():
    has_urgency, score = detect_urgency_manipulation("verify-now-urgent-action-required.example")
    assert has_urgency is True
    assert score >= 30


def test_brand_impersonation_detection():
    detected, brand, similarity = detect_brand_impersonation("gooogle-verify", "http://gooogle-verify.com/login")
    assert detected is True
    assert brand == "google"
    assert similarity >= 0.75


def test_trusted_brand_domain_is_not_marked_as_impersonation():
    detected, brand, similarity = detect_brand_impersonation("accounts.google.com", "https://accounts.google.com")
    assert detected is False
    assert brand == ""
    assert similarity == 0.0


def test_detailed_analysis_payload_contains_structured_sections():
    normalized = normalize_url("http://paypa1.com/login")
    feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    dynamic_result = {
        "available": True,
        "dynamic_score": 22,
        "flags": ["Redirect chain observed (2 hops)"],
        "redirect_chain": [],
        "redirect_count": 2,
        "initial_url": normalized,
        "final_url": "https://evil.example/login",
        "page": {"password_field_count": 1, "external_form_actions": []},
        "screenshot": {
            "available": True,
            "error": None,
            "path": "C:/tmp/example.png",
            "relative_url": "/artifacts/url_screenshots/example.png",
            "url": "/artifacts/url_screenshots/example.png",
        },
        "tls": {},
        "headers": {},
        "errors": [],
    }
    analysis = build_analysis_details(
        normalized,
        score,
        "Phishing",
        "phishing",
        feature_map,
        dynamic_result,
        False,
        "disabled in tests",
        "http://127.0.0.1:8001/",
    )

    assert analysis["summary"]
    assert "parsed_url" in analysis
    assert "risk_factors" in analysis
    assert "recommendations" in analysis
    assert "dynamic_analysis" in analysis
    assert analysis["dynamic_status"] == "available"
    assert analysis["dynamic_analysis"]["screenshot"]["url"].startswith("http://127.0.0.1:8001/")
    assert analysis["parsed_url"]["hostname"]
    assert isinstance(analysis["risk_factors"], list)


def test_dynamic_runtime_analysis_detects_redirect_and_password_form(monkeypatch):
    class FakeResponse:
        def __init__(self, url: str, status_code: int, headers: dict[str, str], text: str = "", history=None):
            self.url = url
            self.status_code = status_code
            self.headers = headers
            self.text = text
            self.history = history or []

    class FakeSession:
        def get(self, url, timeout, allow_redirects, headers):
            redirect = FakeResponse(
                "http://example.com/start",
                302,
                {"Location": "https://evil.example/login"},
            )
            final_html = """
            <html>
              <head><title>PayPal Secure Login</title></head>
              <body>
                <form action="https://collector.example/post">
                  <input type="password" name="password" />
                  <input type="hidden" name="token" value="abc" />
                </form>
                <script>eval('danger')</script>
              </body>
            </html>
            """
            return FakeResponse(
                "https://evil.example/login",
                200,
                {"Content-Type": "text/html", "Server": "nginx"},
                text=final_html,
                history=[redirect],
            )

    monkeypatch.setattr("modules.url_analysis.dynamic.requests.Session", lambda: FakeSession())
    monkeypatch.setattr("modules.url_analysis.dynamic._extract_tls_info", lambda host, port=443: {"available": False, "error": "stubbed"})
    monkeypatch.setattr(
        "modules.url_analysis.dynamic._capture_website_screenshot",
        lambda url, timeout_ms=12000: {
            "available": True,
            "error": None,
            "path": "C:/tmp/fake.png",
            "relative_url": "/artifacts/url_screenshots/fake.png",
        },
    )

    result = analyze_runtime_url("http://example.com/start")

    assert result["available"] is True
    assert result["redirect_count"] == 1
    assert result["dynamic_score"] > 0
    assert result["page"]["password_field_count"] == 1
    assert result["page"]["external_form_actions"]
    assert result["screenshot"]["relative_url"] == "/artifacts/url_screenshots/fake.png"
    assert any("domain changed" in flag.lower() for flag in result["flags"])


def test_dynamic_runtime_analysis_attempts_screenshot_when_fetch_fails(monkeypatch):
    def _raise_request_error(*args, **kwargs):
        raise dynamic_module.requests.RequestException("dns failed")

    monkeypatch.setattr("modules.url_analysis.dynamic.requests.Session", lambda: type("FakeSession", (), {"get": _raise_request_error})())
    monkeypatch.setattr(dynamic_module, "SCREENSHOTS_ENABLED", True)
    monkeypatch.setattr(
        dynamic_module,
        "_capture_website_screenshot",
        lambda url, timeout_ms=12000: {
            "available": True,
            "error": None,
            "path": "C:/tmp/failure.png",
            "relative_url": "/artifacts/url_screenshots/failure.png",
        },
    )

    result = analyze_runtime_url("https://bad-host.example")

    assert result["available"] is False
    assert result["errors"]
    assert result["screenshot"]["relative_url"] == "/artifacts/url_screenshots/failure.png"


def test_ml_service_503_becomes_clean_fallback(monkeypatch):
    class FakeResponse:
        status_code = 503

        def json(self):
            return {}

    monkeypatch.setattr(link_module, "URL_ML_ENABLED", True)
    monkeypatch.setattr(link_module, "HF_API_URL", "https://example.invalid/scan")
    monkeypatch.setattr(link_module.requests, "post", lambda *args, **kwargs: FakeResponse())

    result = link_module.call_hf_ml_service("https://example.com")

    assert result["available"] is False
    assert result["error"] == "ML service temporarily unavailable (503)"


def test_ml_service_can_be_disabled(monkeypatch):
    monkeypatch.setattr(link_module, "URL_ML_ENABLED", False)

    result = link_module.call_hf_ml_service("https://example.com")

    assert result["available"] is False
    assert result["error"] == "ML service disabled by configuration"


def test_safe_confidence_is_not_zero_for_low_risk_clean_url():
    normalized = normalize_url("https://example.com")
    feature_map = extract_features(normalized)
    confidence = calculate_verdict_confidence(
        score=0,
        status="safe",
        feature_map=feature_map,
        dynamic_result={"dynamic_score": 0},
    )

    assert confidence > 0.5


def test_delete_runtime_screenshot_only_removes_managed_files(monkeypatch):
    test_root = Path(__file__).parent / "_runtime_cleanup_test"
    screenshot_dir = test_root / "url_screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    artifact = screenshot_dir / "example.png"
    artifact.write_bytes(b"fake-image")

    monkeypatch.setattr(dynamic_module, "SCREENSHOT_DIR", screenshot_dir)

    try:
        deleted = dynamic_module.delete_runtime_screenshot("/artifacts/url_screenshots/example.png")

        assert deleted is True
        assert artifact.exists() is False
    finally:
        if artifact.exists():
            artifact.unlink(missing_ok=True)
        if screenshot_dir.exists():
            screenshot_dir.rmdir()
        if test_root.exists():
            test_root.rmdir()


@pytest.mark.parametrize(
    "url",
    [
        "w3b3-w4ll3t-v3rify.pages.dev",
        "gooogle-accounts-verify.com",
        "p4yp4l-secure-urgent-verify-now.site",
        "un1sw4p-c0nn3ct-w4ll3t.pages.dev",
        "auth-verification--portal.onrender.com",
    ],
)
def test_zero_day_urls_are_flagged(url: str):
    normalized = normalize_url(url)
    feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    flags = build_flags(normalized, score, feature_map)

    assert calculate_anomaly_score(feature_map) >= 0
    assert score >= 45, f"{url} scored {score}, expected at least suspicious"
    assert flags, f"{url} returned no flags"
