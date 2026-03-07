"""Heuristic regression tests for known malicious URLs."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import compute_heuristic_score, extract_features, normalize_url


MALICIOUS_URLS = [
    "web-trezorr-login-x-en.pages.dev",
    "web-sso--app-crypto---cdn.webflow.io",
]


def analyze_url(url: str) -> int:
    normalized = normalize_url(url)
    feature_map = extract_features(normalized)
    return compute_heuristic_score(feature_map, normalized)


def test_known_malicious_urls_score_high():
    for url in MALICIOUS_URLS:
        score = analyze_url(url)
        assert score >= 70, f"{url} scored {score}, expected >= 70"
