"""Test malicious URLs that should be detected but aren't"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import extract_features, compute_heuristic_score, normalize_url


def test_url(url: str):
    """Analyze a URL and print detailed results"""
    print(f"\n{'='*80}")
    print(f"Testing: {url}")
    print('='*80)
    
    normalized = normalize_url(url)
    features_df, feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    
    print(f"\nNormalized URL: {normalized}")
    print(f"Heuristic Score: {score}/100")
    
    print("\n📊 Key Features:")
    print(f"  - HTTPS: {feature_map['is_https']}")
    print(f"  - Has IP: {feature_map['has_ip']}")
    print(f"  - Suspicious TLD: {feature_map['suspicious_tld']}")
    print(f"  - Keyword Hits: {feature_map['keyword_hits']}")
    print(f"  - Num Subdomains: {feature_map['num_subdomains']}")
    print(f"  - Num Hyphens: {feature_map['num_hyphens']}")
    print(f"  - URL Length: {feature_map['url_length']}")
    print(f"  - URL Entropy: {feature_map['url_entropy']:.2f}")
    print(f"  - Has Lookalike: {feature_map.get('has_lookalike', 0)}")
    print(f"  - Free Hosting: {feature_map.get('is_free_hosting', 0)}")
    
    if score >= 70:
        verdict = "🚨 DANGEROUS (Phishing)"
    elif score >= 45:
        verdict = "⚠️  SUSPICIOUS"
    else:
        verdict = "✅ SAFE (Low Risk)"
    
    print(f"\n{verdict}")
    return score


if __name__ == "__main__":
    # Test the URLs user reported as malicious but not detected
    url1 = "web-trezorr-login-x-en.pages.dev"
    url2 = "web-sso--app-crypto---cdn.webflow.io"
    
    score1 = test_url(url1)
    score2 = test_url(url2)
    
    print(f"\n{'='*80}")
    print("SUMMARY")
    print('='*80)
    print(f"URL 1: {score1}/100 - {'❌ NOT DETECTED' if score1 < 70 else '✅ DETECTED'}")
    print(f"URL 2: {score2}/100 - {'❌ NOT DETECTED' if score2 < 70 else '✅ DETECTED'}")
    print("\nThese are phishing URLs targeting Trezor wallet and cryptocurrency users.")
    print("They should score 70+ but are likely scoring much lower.")
