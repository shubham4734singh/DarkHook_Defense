"""Coverage tests for phishing URLs outside fixed hardcoded examples."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import build_flags, compute_heuristic_score, extract_features, normalize_url


@pytest.mark.parametrize(
    ("url", "min_score"),
    [
        ("w3b3-w4ll3t-v3rify.pages.dev", 70),
        ("secure-acc0unt-xk92jd.com", 45),
        ("verify-bank-account.shop", 70),
        ("http://192.168.1.100/login.html", 70),
        ("auth-portal--secure.onrender.com", 45),
        ("bitc0in-wallet-secure.xyz", 70),
    ],
)
def test_novel_threat_detection(url: str, min_score: int):
    normalized = normalize_url(url)
    feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    flags = build_flags(normalized, score, feature_map)

    assert score >= min_score, f"{url} scored {score}, expected >= {min_score}"
    assert flags, f"{url} returned no explanation flags"


def test_brand_in_fake_subdomain_chain_is_detected():
    normalized = normalize_url("https://login.microsoft.com.evil-site.top/auth")
    feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)

    assert feature_map["brand_impersonation"] == 1
    assert feature_map["num_subdomains"] >= 3
    assert score >= 70


def test_embedded_credentials_are_treated_as_high_risk():
    normalized = normalize_url("http://paypal.com@evil-site.top/login")
    feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    flags = build_flags(normalized, score, feature_map)

    assert feature_map["has_credentials"] == 1
    assert score >= 70
    assert any("credentials" in flag.lower() for flag in flags)
