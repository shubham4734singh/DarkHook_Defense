"""Detection Improvements Report - Shows before/after comparison"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "Backend"))

from modules.url_analysis.link import extract_features, compute_heuristic_score, normalize_url, build_flags


def analyze_url_detailed(url: str):
    """Detailed URL analysis with all flags"""
    print(f"\n{'='*90}")
    print(f"URL: {url}")
    print('='*90)
    
    normalized = normalize_url(url)
    features_df, feature_map = extract_features(normalized)
    score = compute_heuristic_score(feature_map, normalized)
    flags = build_flags(normalized, score, feature_map)
    
    if score >= 70:
        verdict = "🚨 DANGEROUS"
        color = "RED"
    elif score >= 45:
        verdict = "⚠️  SUSPICIOUS"
        color = "YELLOW"
    else:
        verdict = "✅ SAFE"
        color = "GREEN"
    
    print(f"\n{verdict} - Score: {score}/100")
    print(f"\n🔍 Detection Details:")
    for flag in flags:
        print(f"  {flag}")
    
    print(f"\n📋 Key Features:")
    print(f"  - Keyword Hits: {feature_map.get('keyword_hits', 0)}")
    print(f"  - Brand Impersonation: {'Yes' if feature_map.get('has_lookalike', 0) == 1 else 'No'}")
    print(f"  - Free Hosting: {'Yes' if feature_map.get('is_free_hosting', 0) == 1 else 'No'}")
    print(f"  - Consecutive Hyphens: {'Yes' if feature_map.get('consecutive_hyphens', 0) == 1 else 'No'}")
    print(f"  - URL Length: {feature_map.get('url_length', 0)}")
    print(f"  - Number of Hyphens: {feature_map.get('num_hyphens', 0)}")
    
    return score


def print_improvements():
    print("\n" + "="*90)
    print("🛡️  PHISHING DETECTION SYSTEM - IMPROVEMENTS SUMMARY")
    print("="*90)
    
    print("\n✨ What Was Enhanced:\n")
    
    print("1. 🎯 Cryptocurrency Keywords Added:")
    print("   - crypto, bitcoin, ethereum, blockchain, defi, nft, token, swap")
    print("   - trezor, ledger, metamask, coinbase, binance, kraken, exodus")
    print("   - Impact: Now detects crypto wallet/exchange phishing")
    
    print("\n2. 🔐 Authentication/SSO Keywords Added:")
    print("   - sso, auth, oauth, api, validate, authenticate, recovery")
    print("   - Impact: Detects fake SSO/authentication pages")
    
    print("\n3. 🏢 Modern Hosting Platforms Added:")
    print("   - pages.dev (Cloudflare Pages)")
    print("   - webflow.io (Webflow)")
    print("   - netlify.app, vercel.app, render.com, railway.app, fly.dev")
    print("   - Impact: +15 points for high-risk hosting platforms")
    
    print("\n4. 🎭 Brand Impersonation Detection Enhanced:")
    print("   - Detects typosquatting patterns (trezorr, tresor, ledgerr)")
    print("   - Detects crypto brands in suspicious contexts")
    print("   - Impact: +35 points for brand impersonation")
    
    print("\n5. ➖ Consecutive Hyphen Detection:")
    print("   - Detects -- or --- patterns in domain names")
    print("   - Impact: +20 points for consecutive hyphens")
    
    print("\n6. 🌐 Suspicious TLD List Expanded:")
    print("   - Added: .online, .site, .website, .space, .tech, .store, .fun, .live")
    print("   - Impact: Better coverage of abused TLDs")


if __name__ == "__main__":
    print_improvements()
    
    print("\n\n" + "="*90)
    print("📊 TESTING MALICIOUS URLS")
    print("="*90)
    
    malicious_urls = [
        "web-trezorr-login-x-en.pages.dev",
        "web-sso--app-crypto---cdn.webflow.io",
        "verify-metamask-wallet-login.netlify.app",
        "coinbase-secure-auth-verify.pages.dev",
    ]
    
    scores = []
    for url in malicious_urls:
        score = analyze_url_detailed(url)
        scores.append((url, score))
    
    print("\n\n" + "="*90)
    print("📈 FINAL RESULTS")
    print("="*90)
    
    for url, score in scores:
        status = "✅ DETECTED" if score >= 70 else "⚠️  WARNING" if score >= 45 else "❌ MISSED"
        print(f"\n{url}")
        print(f"  Score: {score}/100 - {status}")
    
    detected = sum(1 for _, score in scores if score >= 70)
    print(f"\n\n🎯 Detection Rate: {detected}/{len(scores)} ({detected*100//len(scores)}%) malicious URLs detected")
