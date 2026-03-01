"""Test detection of phishing URLs that don't match hardcoded lists"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import extract_features, compute_heuristic_score, normalize_url, build_flags


def test_novel_threat(url: str, description: str):
    """Test URL that doesn't match typical keyword/TLD patterns"""
    print(f"\n{'='*90}")
    print(f"TEST: {description}")
    print(f"URL: {url}")
    print('='*90)
    
    normalized = normalize_url(url)
    features_df, feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    flags = build_flags(normalized, score, feature_map)
    
    if score >= 70:
        verdict = "🚨 DANGEROUS"
    elif score >= 45:
        verdict = "⚠️  SUSPICIOUS"
    else:
        verdict = "✅ SAFE"
    
    print(f"\n{verdict} - Score: {score}/100")
    print(f"\n🔍 Detection Reasons:")
    for flag in flags[:4]:  # Show first 4 flags
        print(f"  {flag}")
    
    print(f"\n📊 Key Detection Features:")
    print(f"  - Entropy: {feature_map['url_entropy']:.2f} (high = suspicious)")
    print(f"  - Keyword Hits: {feature_map['keyword_hits']}")
    print(f"  - Has Digits in Domain: {'Yes' if any(c.isdigit() for c in normalized.split('//')[1].split('/')[0].split('.')[0]) else 'No'}")
    print(f"  - Free Hosting: {'Yes' if feature_map.get('is_free_hosting', 0) == 1 else 'No'}")
    print(f"  - Consecutive Hyphens: {'Yes' if feature_map.get('consecutive_hyphens', 0) == 1 else 'No'}")
    
    return score


if __name__ == "__main__":
    print("="*90)
    print("🧪 TESTING NOVEL PHISHING THREATS (Not in Hardcoded Lists)")
    print("="*90)
    
    novel_threats = [
        # Novel crypto brand names (not in keyword list)
        ("w3b3-w4ll3t-v3rify.pages.dev", "Leet-speak obfuscation (not in keyword list)"),
        
        # Random domain with suspicious patterns
        ("secure-acc0unt-xk92jd.com", "Random characters + digit substitution"),
        
        # New TLD not in suspicious list
        ("verify-bank-account.shop", "Legitimate TLD but suspicious context"),
        
        # IP address (always caught)
        ("http://192.168.1.100/login.html", "Direct IP address"),
        
        # Excessive hyphens (structural pattern)
        ("my-secure-online-banking-portal.net", "Many hyphens mimicking legitimate names"),
        
        # New hosting platform pattern
        ("auth-portal--secure.onrender.com", "Consecutive hyphens + hosting platform"),
        
        # Long obfuscated URL
        ("verify-account-suspended-urgent-action-required-immediately-click-here.online", "Extremely long URL with urgency keywords"),
        
        # Homograph/lookalike not in list
        ("bitc0in-wallet-secure.xyz", "Digit substitution in crypto term"),
    ]
    
    results = []
    for url, description in novel_threats:
        score = test_novel_threat(url, description)
        results.append((description, score))
    
    print("\n\n" + "="*90)
    print("📈 NOVEL THREAT DETECTION SUMMARY")
    print("="*90)
    
    detected = sum(1 for _, score in results if score >= 70)
    suspicious = sum(1 for _, score in results if 45 <= score < 70)
    missed = sum(1 for _, score in results if score < 45)
    
    for desc, score in results:
        status = "🚨 DETECTED" if score >= 70 else "⚠️  SUSPICIOUS" if score >= 45 else "❌ MISSED"
        print(f"\n{desc}")
        print(f"  Score: {score}/100 - {status}")
    
    print(f"\n\n🎯 RESULTS:")
    print(f"  Dangerous (70+): {detected}/{len(results)} ({detected*100//len(results)}%)")
    print(f"  Suspicious (45-69): {suspicious}/{len(results)} ({suspicious*100//len(results)}%)")
    print(f"  Missed (<45): {missed}/{len(results)} ({missed*100//len(results)}%)")
    
    print(f"\n✨ Total Detection Rate: {(detected+suspicious)*100//len(results)}% caught threats outside hardcoded lists!")
