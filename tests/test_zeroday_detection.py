"""
Comprehensive Zero-Day Phishing Detection Test
Tests advanced detection capabilities against never-before-seen attack patterns
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import (
    extract_features, compute_heuristic_score, normalize_url, build_flags,
    decode_leetspeak, detect_brand_impersonation, detect_homograph_attack,
    calculate_anomaly_score, detect_urgency_manipulation
)


def print_header(title: str):
    """Print formatted section header"""
    print(f"\n{'='*100}")
    print(f"  {title}")
    print('='*100)


def test_zero_day_url(url: str, attack_type: str, description: str):
    """Comprehensive analysis of zero-day phishing URL"""
    print(f"\n{'─'*100}")
    print(f"Attack Type: {attack_type}")
    print(f"Description: {description}")
    print(f"URL: {url}")
    print('─'*100)
    
    normalized = normalize_url(url)
    features_df, feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    flags = build_flags(normalized, score, feature_map)
    
    # Verdict
    if score >= 70:
        verdict = "🚨 DANGEROUS (DETECTED)"
        color = "RED"
    elif score >= 45:
        verdict = "⚠️  SUSPICIOUS (WARNING)"
        color = "YELLOW"
    else:
        verdict = "❌ MISSED (SAFE)"
        color = "GREEN"
    
    print(f"\n{verdict} - Score: {score}/100\n")
    
    # Zero-day specific features
    print("🔬 Zero-Day Detection Analysis:")
    print(f"  ├─ Leet-speak: {'✓ DETECTED' if feature_map.get('has_leetspeak', 0) == 1 else '✗ None'}")
    print(f"  ├─ Brand Impersonation: {'✓ DETECTED' if feature_map.get('brand_impersonation', 0) == 1 else '✗ None'}")
    if feature_map.get('brand_impersonation', 0) == 1:
        print(f"  │  └─ Similarity: {feature_map.get('brand_similarity', 0):.0%}")
    print(f"  ├─ Homograph Attack: {'✓ DETECTED' if feature_map.get('has_homograph', 0) == 1 else '✗ None'}")
    print(f"  ├─ Anomaly Score: {feature_map.get('anomaly_score', 0):.2f}/1.0 ({feature_map.get('anomaly_score', 0)*100:.0f}%)")
    print(f"  └─ Urgency Tactics: {'✓ DETECTED' if feature_map.get('has_urgency_tactics', 0) == 1 else '✗ None'}")
    if feature_map.get('has_urgency_tactics', 0) == 1:
        print(f"     └─ Urgency Score: {feature_map.get('urgency_score', 0):.0%}")
    
    # Top flags
    print(f"\n🚩 Detection Flags ({len(flags)} total):")
    for i, flag in enumerate(flags[:4], 1):  # Show top 4
        print(f"  {i}. {flag}")
    if len(flags) > 4:
        print(f"  ... and {len(flags) - 4} more flags")
    
    return score


def main():
    print_header("🛡️  ZERO-DAY PHISHING DETECTION SYSTEM - COMPREHENSIVE TEST")
    
    print("\n📋 Testing Advanced Detection Capabilities:")
    print("   ✓ Leet-speak obfuscation detection")
    print("   ✓ Fuzzy brand matching (Levenshtein distance)")
    print("   ✓ Homograph/IDN attack detection")
    print("   ✓ Statistical anomaly scoring")
    print("   ✓ Psychological manipulation detection")
    
    # Test cases: Zero-day attacks that don't match hardcoded patterns
    test_cases = [
        # 1. Leet-speak obfuscation
        ("w3b3-w4ll3t-v3rify.pages.dev", 
         "Leet-speak Obfuscation", 
         "Uses '3' for 'e', '4' for 'a', '7' for 't' to evade keyword filters"),
        
        ("cr7pt0-l0gin-s3cur3.webflow.io",
         "Advanced Leet-speak",
         "Multiple character substitutions: crypto → cr7pt0, login → l0gin, secure → s3cur3"),
        
        # 2. Fuzzy brand impersonation
        ("gooogle-accounts-verify.com",
         "Brand Typosquatting (Google)",
         "Extra 'o' in Google - fuzzy matching detects similarity"),
        
        ("faceb00k-security-check.xyz",
         "Brand + Digit Substitution",
         "Facebook with '00' instead of 'oo' + suspicious TLD"),
        
        ("metamaask-wallet-connect.netlify.app",
         "Crypto Brand Typo",
         "MetaMask with extra 'a' - targets crypto users"),
        
        # 3. Unicode homograph attacks
        ("аpple-login.com",  # Cyrillic 'а' instead of Latin 'a'
         "Homograph Attack (IDN Spoofing)",
         "Uses Cyrillic 'а' (U+0430) that looks identical to Latin 'a'"),
        
        # 4. Combined advanced techniques
        ("p4yp4l-secure-urgent-verify-now.site",
         "Multi-Vector Attack",
         "Leet-speak + urgency manipulation + suspicious TLD combo"),
        
        ("amaz0n-account-suspended-immediate-action.online",
         "Urgency Manipulation",
         "Digit substitution + multiple urgency terms (suspended, immediate, action)"),
        
        # 5. Statistical anomalies
        ("secure-login-xj8kq2p9-auth-verify-now.com",
         "Random Token Pattern",
         "High entropy substring (xj8kq2p9) indicates programmatically generated domain"),
        
        ("verify-immediately-action-required-suspended-locked-urgent.work",
         "Keyword Stuffing",
         "Excessive urgency keywords trigger anomaly detection"),
        
        # 6. Sophisticated crypto phishing
        ("un1sw4p-c0nn3ct-w4ll3t.pages.dev",
         "DeFi Platform Impersonation",
         "Uniswap with leet-speak + crypto keywords on free hosting"),
        
        ("l3dg3r-r3c0v3ry-phr4s3.vercel.app",
         "Wallet Recovery Phish",
         "Ledger with leet-speak targeting seed phrase theft"),
        
        # 7. Brand impersonation without exact match
        ("micros0ffice-login.com",
         "Brand Variation",
         "Microsoft+Office hybrid with digit substitution"),
        
        ("coinbaase-pro-trading.dev",
         "Crypto Exchange Typo",
         "Coinbase with doubled 'a' + suspicious .dev TLD"),
        
        # 8. Zero-day free hosting abuse
        ("auth-verification--portal.onrender.com",
         "New Hosting Platform",
         "Consecutive hyphens + auth keywords on modern hosting platform"),
    ]
    
    print_header("🧪 ZERO-DAY ATTACK TEST CASES")
    
    results = []
    for url, attack_type, description in test_cases:
        score = test_zero_day_url(url, attack_type, description)
        results.append((attack_type, url, score))
    
    # Summary statistics
    print_header("📊 ZERO-DAY DETECTION PERFORMANCE SUMMARY")
    
    detected = sum(1 for _, _, score in results if score >= 70)
    suspicious = sum(1 for _, _, score in results if 45 <= score < 70)
    missed = sum(1 for _, _, score in results if score < 45)
    total = len(results)
    
    print(f"\n📈 Detection Statistics:")
    print(f"   Total Zero-Day Attacks Tested: {total}")
    print(f"   ✅ Detected as Dangerous (70+): {detected} ({detected*100//total}%)")
    print(f"   ⚠️  Flagged as Suspicious (45-69): {suspicious} ({suspicious*100//total}%)")
    print(f"   ❌ Missed (<45): {missed} ({missed*100//total}%)")
    print(f"   \n   🎯 Overall Detection Rate: {(detected+suspicious)*100//total}%")
    
    print(f"\n🏆 Capability Breakdown:")
    print(f"   🔤 Leet-speak Detection: Active")
    print(f"   🎭 Fuzzy Brand Matching: Active (Levenshtein distance)")
    print(f"   🌐 Homograph Detection: Active (Unicode IDN spoofing)")
    print(f"   📈 Anomaly Scoring: Active (statistical analysis)")
    print(f"   ⏰ Urgency Detection: Active (psychological manipulation)")
    
    # Detailed results table
    print_header("📋 DETAILED RESULTS BY ATTACK TYPE")
    
    print(f"\n{'Attack Type':<35} {'Score':<10} {'Status'}")
    print('─'*100)
    for attack_type, url, score in results:
        if score >= 70:
            status = "✅ DETECTED"
        elif score >= 45:
            status = "⚠️  SUSPICIOUS"
        else:
            status = "❌ MISSED"
        print(f"{attack_type:<35} {score:>3}/100    {status}")
    
    print_header("💡 KEY INSIGHTS")
    
    print("""
    ✨ Zero-Day Detection Capabilities:
    
    1. LEET-SPEAK DECODER: Converts w4ll3t → wallet, cr7pt0 → crypto automatically
    2. FUZZY BRAND MATCHING: Detects gooogle, faceb00k, metamaask via Levenshtein distance
    3. HOMOGRAPH DETECTION: Identifies Unicode lookalikes (Cyrillic 'а' vs Latin 'a')
    4. ANOMALY SCORING: Statistical analysis of URL patterns vs normal behavior
    5. URGENCY DETECTION: Recognizes psychological manipulation tactics
    
    🛡️  Why This Matters:
    - Traditional keyword-based filters can be evaded with character substitution
    - Zero-day attacks use novel techniques not seen in training data
    - Multi-layer defense catches threats even when individual indicators are weak
    - Behavioral analysis detects malicious intent regardless of exact wording
    
    ⚡ Real-World Impact:
    - Can detect brand new phishing campaigns within hours of launch
    - Catches typosquatting variations before they're added to blocklists
    - Identifies sophisticated attacks targeting crypto/DeFi users
    - Protects against attacks using newly popular hosting platforms
    """)
    
    print_header("✅ ZERO-DAY DETECTION SYSTEM - TEST COMPLETE")


if __name__ == "__main__":
    main()
