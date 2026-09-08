import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import requests

# Add Backend to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.document_parsers.virustotal_checker import (
    check_url,
    check_multiple_urls,
    get_virustotal_findings,
)
from services.document_parsers.scorer import WEIGHTS, calculate_score


class TestVirusTotalChecker(unittest.TestCase):
    def test_weights_exist(self):
        self.assertEqual(WEIGHTS.get("virustotal_malicious"), 40)
        self.assertEqual(WEIGHTS.get("virustotal_suspicious"), 20)
        self.assertEqual(WEIGHTS.get("virustotal_low_confidence"), 10)
        self.assertEqual(WEIGHTS.get("virustotal_clean"), 0)
        self.assertEqual(WEIGHTS.get("virustotal_unknown"), 0)

    def test_missing_api_key_raises_value_error(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                check_url("https://example.com/test-url-12345", "")

    def test_empty_url_list_returns_empty(self):
        self.assertEqual(get_virustotal_findings([], "dummy_key"), [])
        self.assertEqual(check_multiple_urls([], "dummy_key"), [])

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.requests.get")
    def test_check_url_malicious(self, mock_get, mock_sleep):
        get_response = MagicMock()
        get_response.status_code = 200
        get_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 10,
                        "timeout": 0,
                    }
                }
            }
        }
        mock_get.return_value = get_response

        result = check_url("https://malicious-phishing-test.com/login", "test_key")

        self.assertEqual(result["url"], "https://malicious-phishing-test.com/login")
        self.assertEqual(result["malicious"], 8)
        self.assertEqual(result["suspicious"], 2)
        self.assertEqual(result["harmless"], 60)
        self.assertEqual(result["total_engines"], 80)
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["finding_type"], "virustotal_malicious")
        self.assertEqual(result["percentage"], 10.0)

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.requests.get")
    def test_check_url_low_confidence_false_positive(self, mock_get, mock_sleep):
        get_response = MagicMock()
        get_response.status_code = 200
        # 1/90 detections = 1.11% (< 5%), should trigger low_confidence verdict
        get_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 84,
                        "undetected": 5,
                        "timeout": 0,
                    }
                }
            }
        }
        mock_get.return_value = get_response

        result = check_url("https://google.com", "test_key")

        self.assertEqual(result["verdict"], "low_confidence")
        self.assertEqual(result["finding_type"], "virustotal_low_confidence")
        self.assertEqual(result["malicious"], 1)
        self.assertEqual(result["total_engines"], 90)
        self.assertEqual(result["percentage"], 1.11)

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.requests.get")
    def test_check_url_suspicious(self, mock_get, mock_sleep):
        get_response = MagicMock()
        get_response.status_code = 200
        get_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 1,
                        "harmless": 70,
                        "undetected": 5,
                        "timeout": 0,
                    }
                }
            }
        }
        mock_get.return_value = get_response

        result = check_url("https://suspicious-test-domain.xyz/account", "test_key")

        self.assertEqual(result["verdict"], "suspicious")
        self.assertEqual(result["finding_type"], "virustotal_suspicious")

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.requests.get")
    def test_check_url_clean(self, mock_get, mock_sleep):
        get_response = MagicMock()
        get_response.status_code = 200
        get_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 75,
                        "undetected": 5,
                        "timeout": 0,
                    }
                }
            }
        }
        mock_get.return_value = get_response

        result = check_url("https://clean-legit-domain.com/about", "test_key")

        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(result["finding_type"], "virustotal_clean")

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.requests.get")
    def test_zero_engines_returns_unknown(self, mock_get, mock_sleep):
        get_response = MagicMock()
        get_response.status_code = 200
        get_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0,
                        "timeout": 0,
                    }
                }
            }
        }
        mock_get.return_value = get_response

        result = check_url("https://unanalyzed-domain.com/test", "test_key")

        self.assertEqual(result["verdict"], "unknown")
        self.assertEqual(result["finding_type"], "virustotal_unknown")
        self.assertEqual(result["total_engines"], 0)

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.requests.get")
    def test_check_url_timeout_returns_unknown(self, mock_get, mock_sleep):
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        result = check_url("https://timeout-test.com/path", "test_key")

        self.assertEqual(result["verdict"], "unknown")
        self.assertEqual(result["finding_type"], "virustotal_unknown")
        self.assertEqual(result["malicious"], 0)
        self.assertEqual(result["total_engines"], 0)

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.requests.get")
    def test_invalid_api_key_raises(self, mock_get, mock_sleep):
        bad_response = MagicMock()
        bad_response.status_code = 401
        mock_get.return_value = bad_response

        with self.assertRaises(ValueError):
            check_url("https://example.com/test-url-12345", "invalid_key")

    @patch("services.document_parsers.virustotal_checker.time.sleep", return_value=None)
    @patch("services.document_parsers.virustotal_checker.check_url")
    def test_check_multiple_urls_skips_short_and_calls_findings(self, mock_check, mock_sleep):
        mock_check.side_effect = [
            {
                "url": "https://malicious.org/download",
                "finding_type": "virustotal_malicious",
                "verdict": "malicious",
            },
            {
                "url": "https://safe-domain.com/home",
                "finding_type": "virustotal_clean",
                "verdict": "clean",
            }
        ]

        urls = [
            None,
            "",
            "http://a",  # < 10 chars, should be skipped
            "https://malicious.org/download",
            "https://safe-domain.com/home",
        ]

        findings = get_virustotal_findings(urls, "dummy_key")
        self.assertEqual(findings, ["virustotal_malicious", "virustotal_clean"])


if __name__ == "__main__":
    unittest.main()
