"""
Test suite for URL Analysis API endpoint
Tests phishing detection accuracy against known patterns
"""
import sys
import os
from pathlib import Path

# Add Backend to path for imports and change to Backend directory for .env
backend_path = Path(__file__).resolve().parent.parent / "Backend"
sys.path.insert(0, str(backend_path))
os.chdir(backend_path)

from fastapi.testclient import TestClient
from app import app


def test_url_analysis_endpoint():
    """Test URL analysis endpoint with various URL patterns"""
    client = TestClient(app)
    
    test_cases = [
        # ===== LEGITIMATE TRUSTED DOMAINS =====
        {
            'url': 'https://google.com',
            'description': 'Google homepage',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://accounts.google.com/signin',
            'description': 'Google login',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.amazon.com/dp/B08N5M7S6K',
            'description': 'Amazon product',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.facebook.com/login',
            'description': 'Facebook login',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.youtube.com/watch',
            'description': 'YouTube video',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.microsoft.com/account',
            'description': 'Microsoft account',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.apple.com/account',
            'description': 'Apple account',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.netflix.com/login',
            'description': 'Netflix login',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.linkedin.com/login',
            'description': 'LinkedIn login',
            'expected_status': 'safe',
            'max_score': 45
        },
        
        # ===== TYPOSQUATTING ATTACKS =====
        {
            'url': 'http://paypa1.com/login',
            'description': 'PayPal typosquatting (digit 1)',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'http://g00gle.com',
            'description': 'Google typosquatting (zeros)',
            'expected_status': 'suspicious',
            'min_score': 45
        },
        {
            'url': 'http://micros0ft.com/security',
            'description': 'Microsoft typosquatting',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'http://amaz0n.com/account/verify',
            'description': 'Amazon typosquatting with verify',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== IP-BASED PHISHING =====
        {
            'url': 'http://192.168.1.1/login',
            'description': 'IP-based login page',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'http://10.0.0.1/admin',
            'description': 'IP-based admin panel',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'http://172.16.0.1/verify',
            'description': 'IP-based verification',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== SUSPICIOUS TLD ATTACKS =====
        {
            'url': 'https://secure-login.tk/verify',
            'description': 'Suspicious .tk TLD with keywords',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://paypal-verify.ml/confirm',
            'description': 'Fake PayPal on .ml TLD',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://amazon-account.ga/login',
            'description': 'Fake Amazon on .ga TLD',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://apple-id.cf/security',
            'description': 'Fake Apple ID on .cf TLD',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://bank-security.xyz/update',
            'description': 'Fake banking on .xyz',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== URL SHORTENERS (SUSPICIOUS) =====
        {
            'url': 'http://bit.ly/abc123',
            'description': 'bit.ly shortener',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'http://tinyurl.com/abcde',
            'description': 'TinyURL shortener',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'http://t.co/abcdefg',
            'description': 'Twitter shortener',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== FREE HOSTING ABUSE =====
        {
            'url': 'http://paypal-verify.github.io/login',
            'description': 'Phishing on GitHub Pages',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://amazon-login.herokuapp.com/account',
            'description': 'Phishing on Heroku',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://google-auth.repl.co/signin',
            'description': 'Phishing on Repl.co',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== DEEP SUBDOMAINS =====
        {
            'url': 'http://secure.verify.account.paypal-confirm.tk/login',
            'description': 'Multiple suspicious subdomains',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://mail.verify.myaccount.signin.google-verify.tk',
            'description': 'Deep suspicious subdomains',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== PHISHING KEYWORDS OVERDOSE =====
        {
            'url': 'http://verify-account-login-password.tk/confirm',
            'description': 'Multiple phishing keywords',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://urgent-action-required-verify-account.ga',
            'description': 'Urgency + action keywords',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== NO HTTPS =====
        {
            'url': 'http://example.com/login',
            'description': 'No HTTPS on login page',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'http://secure-login-bank.com',
            'description': 'No HTTPS despite "secure" in name',
            'expected_status': 'suspicious',
            'min_score': 45
        },
        
        # ===== LEGITIMATE BUT SUSPICIOUS PATTERNS =====
        {
            'url': 'https://dev-environment.example.com',
            'description': 'Dev environment (no phishing keywords)',
            'expected_status': 'safe',
            'max_score': 45
        },
        {
            'url': 'https://www.example.com/settings',
            'description': 'Legitimate account settings',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://shop.example.com/order-confirmation',
            'description': 'Legitimate order page',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        
        # ===== EDGE CASES =====
        {
            'url': 'https://example.com:8080',
            'description': 'Non-standard port',
            'expected_status': 'dangerous',
            'min_score': 70
        },
        {
            'url': 'https://example.com/?next=https://phishing.tk',
            'description': 'Redirect parameter to phishing site',
            'expected_status': 'dangerous',
            'min_score': 70
        },
    ]
    
    print("\n" + "=" * 120)
    print(f"URL ANALYSIS API TEST RESULTS ({len(test_cases)} test cases)")
    print("=" * 120)
    
    passed = 0
    failed = 0
    failed_tests = []
    
    for i, test_case in enumerate(test_cases, 1):
        url = test_case['url']
        response = client.post('/analyze/url', json={'url': url})
        
        assert response.status_code == 200, f"Failed to analyze {url}"
        
        result = response.json()
        status = result['status']
        score = result['score']
        
        # Check expectations
        test_passed = True
        error_msg = ""
        
        if 'expected_status' in test_case and status != test_case['expected_status']:
            test_passed = False
            error_msg = f"Expected status '{test_case['expected_status']}' | Got '{status}'"
        
        if 'min_score' in test_case and score < test_case['min_score']:
            test_passed = False
            error_msg = f"Score {score} below min {test_case['min_score']}"
        
        if 'max_score' in test_case and score > test_case['max_score']:
            test_passed = False
            error_msg = f"Score {score} above max {test_case['max_score']}"
        
        # Print result
        result_icon = "✓" if test_passed else "✗"
        status_display = f"{status:12s}"
        score_display = f"Score={score:3d}"
        desc = test_case['description'][:45]
        
        if i % 5 == 1:
            print()  # Add spacing every 5 tests
        
        print(f"{result_icon} {i:2d}. {status_display} | {score_display} | {desc:45s}")
        
        if not test_passed:
            print(f"     ✗ ERROR: {error_msg}")
            failed += 1
            failed_tests.append((i, test_case['description'], error_msg))
        else:
            passed += 1
    
    print("\n" + "=" * 120)
    print(f"SUMMARY: {passed}/{len(test_cases)} passed, {failed} failed")
    print("=" * 120)
    
    if failed_tests:
        print("\nFailed Tests:")
        for idx, desc, msg in failed_tests:
            print(f"  Test {idx}: {desc}")
            print(f"    → {msg}")
    
    print()
    assert failed == 0, f"{failed} test(s) failed"


def test_response_structure():
    """Test that response has all required fields"""
    client = TestClient(app)
    
    response = client.post('/analyze/url', json={'url': 'https://example.com'})
    
    if response.status_code != 200:
        print(f"ERROR: Status code {response.status_code}")
        print(f"Response: {response.text}")
    
    assert response.status_code == 200
    
    result = response.json()
    
    # Check required fields
    required_fields = ['scan_id', 'url', 'score', 'confidence', 'verdict', 'status', 'flags', 'feature_summary', 'explanation']
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"
    
    # Check types
    assert isinstance(result['score'], int)
    assert 0 <= result['score'] <= 100
    assert isinstance(result['confidence'], float)
    assert isinstance(result['flags'], list)
    assert isinstance(result['feature_summary'], dict)
    assert isinstance(result['explanation'], str)
    assert len(result['explanation']) > 0, "Explanation should not be empty"


if __name__ == "__main__":
    print("Running URL Analysis Tests...")
    
    try:
        test_response_structure()
        print("✓ Response structure test passed")
        
        test_url_analysis_endpoint()
        
        print("\n✓ All tests passed successfully!")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
