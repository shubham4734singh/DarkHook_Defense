"""Zero-day phishing heuristic tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import (
    build_flags,
    calculate_anomaly_score,
    compute_heuristic_score,
    decode_leetspeak,
    detect_brand_impersonation,
    detect_homograph_attack,
    detect_urgency_manipulation,
    extract_features,
    normalize_url,
)


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
