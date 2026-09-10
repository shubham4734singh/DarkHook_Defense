"""
VirusTotal URL Threat Intelligence Checker for DarkHook Defense.

Integrates VirusTotal API v3 to scan and analyze extracted URLs,
providing engine detection counts, threat verdicts, and findings for scoring.
"""

import base64
import os
import time
from typing import Any, Dict, List, Optional
import requests

try:
    from core.config import settings
except ImportError:
    settings = None

VT_URL_SCAN_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses"

def _get_poll_interval() -> int:
    if settings:
        return getattr(settings, "VIRUSTOTAL_POLL_INTERVAL_SECONDS", 15)
    return int(os.getenv("VIRUSTOTAL_POLL_INTERVAL_SECONDS", "15"))

def _get_request_interval() -> int:
    if settings:
        return getattr(settings, "VIRUSTOTAL_REQUEST_INTERVAL_SECONDS", 16)
    return int(os.getenv("VIRUSTOTAL_REQUEST_INTERVAL_SECONDS", "16"))

def _get_backoff_interval() -> int:
    if settings:
        return getattr(settings, "VIRUSTOTAL_RATE_LIMIT_BACKOFF_SECONDS", 60)
    return int(os.getenv("VIRUSTOTAL_RATE_LIMIT_BACKOFF_SECONDS", "60"))


def _get_url_id(url: str) -> str:
    """Generates Base64 URL identifier for VirusTotal API v3 URL report lookup."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


def check_url(url: str, api_key: str = "") -> dict:
    """
    Submits a single URL to VirusTotal API v3 and retrieves analysis results.

    Flow:
      1. Validates API key and URL.
      2. Checks existing VT database record via GET /api/v3/urls/{url_id}.
      3. If URL is not in VT database or unanalyzed, submits via POST /api/v3/urls.
      4. Polls analysis endpoint GET /api/v3/analyses/{id} up to 3 tries (15s apart).
      5. Parses last_analysis_stats and computes strict threat verdict and finding type.

    Args:
        url (str): Target URL to analyze.
        api_key (str): VirusTotal API v3 key. If omitted, reads VIRUSTOTAL_API_KEY from env.

    Returns:
        dict: Standardized VirusTotal scan result dictionary:
            {
                "url": str,
                "malicious": int,
                "suspicious": int,
                "harmless": int,
                "total_engines": int,
                "verdict": "malicious" | "suspicious" | "clean" | "unknown",
                "percentage": float,
                "finding_type": "virustotal_malicious" | "virustotal_suspicious" | "virustotal_clean" | "virustotal_unknown"
            }

    Raises:
        ValueError: If api_key is missing or rejected as invalid (HTTP 401/403).
    """
    key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key or not key.strip():
        raise ValueError("Invalid API key: VirusTotal API key is missing or empty.")

    clean_url = (url or "").strip()
    if not clean_url:
        return {
            "url": url,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "percentage": 0.0,
            "finding_type": "virustotal_unknown",
        }

    headers = {
        "x-apikey": key.strip(),
        "Accept": "application/json",
    }

    try:
        stats: Dict[str, Any] = {}

        # Step 1: Check existing VT database record via GET /api/v3/urls/{url_id}
        url_id = _get_url_id(clean_url)
        report_url = f"{VT_URL_SCAN_ENDPOINT}/{url_id}"

        get_rep = requests.get(report_url, headers=headers, timeout=15)
        if get_rep.status_code in (401, 403):
            raise ValueError(
                f"Invalid API key: Unauthorized access to VirusTotal API (HTTP {get_rep.status_code})."
            )

        if get_rep.status_code == 200:
            rep_data = get_rep.json()
            stats = (
                rep_data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

        # Step 2: If URL not in VT database (HTTP 404 or missing stats), submit for scanning and poll
        if get_rep.status_code == 404 or stats is None:
            post_response = requests.post(
                VT_URL_SCAN_ENDPOINT,
                headers=headers,
                data={"url": clean_url},
                timeout=15,
            )

            if post_response.status_code in (401, 403):
                raise ValueError(
                    f"Invalid API key: Unauthorized access to VirusTotal API (HTTP {post_response.status_code})."
                )

            if post_response.status_code == 429:
                post_response.raise_for_status()

            post_response.raise_for_status()
            analysis_id = post_response.json().get("data", {}).get("id")

            if analysis_id:
                analysis_url = f"{VT_ANALYSIS_ENDPOINT}/{analysis_id}"
                # Poll up to 3 times, configurable seconds apart
                for attempt in range(3):
                    time.sleep(_get_poll_interval())
                    poll_res = requests.get(analysis_url, headers=headers, timeout=15)
                    if poll_res.status_code in (401, 403):
                        raise ValueError(
                            f"Invalid API key: Unauthorized access to VirusTotal API (HTTP {poll_res.status_code})."
                        )
                    if poll_res.status_code == 200:
                        poll_json = poll_res.json()
                        attr = poll_json.get("data", {}).get("attributes", {})
                        poll_stats = attr.get("stats", {})
                        status_val = attr.get("status", "")

                        if status_val == "completed" or (poll_stats and sum(int(poll_stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")) > 0):
                            stats = poll_stats
                            break

        # Log raw last_analysis_stats dict for debugging visibility
        print(f"[VirusTotal] Raw last_analysis_stats for {clean_url}: {stats}")

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        timeout_count = int(stats.get("timeout", 0))

        total_engines = malicious + suspicious + harmless + undetected + timeout_count

        percentage = (
            round((malicious / total_engines) * 100.0, 2)
            if total_engines > 0
            else 0.0
        )

        # Step 3: Ratio and threshold-based verdict determination
        malicious_ratio = (malicious / total_engines) if total_engines > 0 else 0.0

        if total_engines == 0:
            finding_type = "virustotal_unknown"
            verdict = "unknown"
        elif malicious == 0 and suspicious == 0:
            finding_type = "virustotal_clean"
            verdict = "clean"
        elif malicious_ratio >= 0.05 or malicious >= 3:
            finding_type = "virustotal_malicious"
            verdict = "malicious"
        elif malicious_ratio < 0.05 and malicious <= 2 and malicious > 0:
            finding_type = "virustotal_low_confidence"
            verdict = "low_confidence"
        elif suspicious >= 1:
            finding_type = "virustotal_suspicious"
            verdict = "suspicious"
        else:
            finding_type = "virustotal_clean"
            verdict = "clean"

        return {
            "url": clean_url,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total_engines,
            "verdict": verdict,
            "percentage": percentage,
            "finding_type": finding_type,
        }

    except ValueError:
        raise
    except Exception as err:
        print(f"[VirusTotal Error] Failed to scan {clean_url}: {err}")
        return {
            "url": clean_url,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_engines": 0,
            "verdict": "unknown",
            "percentage": 0.0,
            "finding_type": "virustotal_unknown",
        }


def check_multiple_urls(urls: list, api_key: str = "") -> list:
    """
    Iterates through a list of URLs and scans each with VirusTotal.

    Filters out invalid/short URLs, adds rate-limiting delays between calls,
    handles HTTP 429 backoff/retry, and recovers gracefully from individual failures.

    Args:
        urls (list): List of URL strings to scan.
        api_key (str): VirusTotal API v3 key. If omitted, reads VIRUSTOTAL_API_KEY from env.

    Returns:
        list: List of scan result dicts for each processed URL.

    Raises:
        ValueError: If api_key is invalid or rejected by VirusTotal.
    """
    if not urls or not isinstance(urls, list):
        return []

    key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key or not key.strip():
        raise ValueError("Invalid API key: VirusTotal API key is missing or empty.")

    results: List[Dict[str, Any]] = []

    for url in urls:
        # Skip empty, None, or URLs under 10 characters
        if not url or not isinstance(url, str):
            continue

        clean_url = url.strip()
        if len(clean_url) < 10:
            continue

        # Add configurable delay between successive URL scans if multiple
        if results:
            time.sleep(_get_request_interval())

        try:
            res = check_url(clean_url, key)
            if res:
                results.append(res)
        except ValueError:
            raise
        except requests.exceptions.HTTPError as http_err:
            if http_err.response is not None and http_err.response.status_code == 429:
                time.sleep(_get_backoff_interval())
                try:
                    retry_res = check_url(clean_url, key)
                    if retry_res:
                        results.append(retry_res)
                except ValueError:
                    raise
                except Exception as err:
                    print(f"[VirusTotal Error] Retry failed for {clean_url}: {err}")
                    results.append({
                        "url": clean_url,
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "total_engines": 0,
                        "verdict": "unknown",
                        "percentage": 0.0,
                        "finding_type": "virustotal_unknown",
                    })
            else:
                print(f"[VirusTotal Error] HTTP failure scanning {clean_url}: {http_err}")
                results.append({
                    "url": clean_url,
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "total_engines": 0,
                    "verdict": "unknown",
                    "percentage": 0.0,
                    "finding_type": "virustotal_unknown",
                })
        except Exception as exc:
            print(f"[VirusTotal Error] Request failed scanning {clean_url}: {exc}")
            results.append({
                "url": clean_url,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "total_engines": 0,
                "verdict": "unknown",
                "percentage": 0.0,
                "finding_type": "virustotal_unknown",
            })

    return results


def get_virustotal_findings(urls: list, api_key: str = "") -> list:
    """
    Scans multiple URLs and extracts only the VirusTotal finding_type strings.

    Args:
        urls (list): List of URL strings to analyze.
        api_key (str): VirusTotal API v3 key. If omitted, reads VIRUSTOTAL_API_KEY from env.

    Returns:
        list: List of finding_type strings (e.g. ["virustotal_malicious", "virustotal_clean"]).
    """
    if not urls:
        return []

    scan_results = check_multiple_urls(urls, api_key)
    return [
        item["finding_type"]
        for item in scan_results
        if isinstance(item, dict) and "finding_type" in item
    ]
