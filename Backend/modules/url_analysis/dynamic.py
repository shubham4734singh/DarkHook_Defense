import socket
import ssl
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
from uuid import uuid4

import requests
from bs4 import BeautifulSoup


DYNAMIC_USER_AGENT = (
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
	"AppleWebKit/537.36 (KHTML, like Gecko) "
	"Chrome/131.0.0.0 Safari/537.36 DarkHookDefense/1.0"
)

SUSPICIOUS_SCRIPT_PATTERNS = [
	"eval(",
	"document.write(",
	"atob(",
	"fromcharcode",
	"settimeout(",
	"setinterval(",
	"localstorage",
	"sessionstorage",
	"crypto.subtle",
	"web3",
	"ethereum",
]

TITLE_BRAND_KEYWORDS = [
	"paypal", "microsoft", "office", "google", "apple", "amazon",
	"bank", "wallet", "coinbase", "binance", "ledger", "trezor",
]
SCREENSHOT_DIR = Path(__file__).resolve().parents[2] / "runtime_artifacts" / "url_screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOTS_ENABLED = os.getenv("URL_ANALYSIS_SCREENSHOTS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
SCREENSHOTS_ON_RISK_ONLY = os.getenv("URL_ANALYSIS_SCREENSHOTS_ON_RISK_ONLY", "true").strip().lower() in {"1", "true", "yes", "on"}
TLS_LOOKUP_ENABLED = os.getenv("URL_ANALYSIS_TLS_LOOKUP_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
DYNAMIC_TIMEOUT_SECONDS = int(os.getenv("URL_ANALYSIS_DYNAMIC_TIMEOUT_SECONDS", "6"))
SCREENSHOT_TIMEOUT_MS = int(os.getenv("URL_ANALYSIS_SCREENSHOT_TIMEOUT_MS", "7000"))


def _get_hostname(url: str) -> str:
	parsed = urlparse(url)
	return (parsed.hostname or "").strip().lower().rstrip(".")


def _get_base_domain(host: str) -> str:
	if not host:
		return ""
	parts = host.split(".")
	if len(parts) <= 2:
		return host
	return ".".join(parts[-2:])


def _extract_tls_info(host: str, port: int = 443) -> dict[str, Any]:
	"""Attempt to collect basic TLS certificate metadata."""
	if not host:
		return {"available": False, "error": "missing hostname"}

	try:
		context = ssl.create_default_context()
		with socket.create_connection((host, port), timeout=5) as sock:
			with context.wrap_socket(sock, server_hostname=host) as secure_sock:
				cert = secure_sock.getpeercert()

		subject = dict(item[0] for item in cert.get("subject", []) if item)
		issuer = dict(item[0] for item in cert.get("issuer", []) if item)
		not_after_raw = cert.get("notAfter")
		expires_at = None
		days_remaining = None
		if not_after_raw:
			expires_at = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
			days_remaining = (expires_at - datetime.now(timezone.utc)).days

		return {
			"available": True,
			"subject_common_name": subject.get("commonName"),
			"issuer_common_name": issuer.get("commonName"),
			"subject_alt_names": [entry[1] for entry in cert.get("subjectAltName", []) if len(entry) > 1],
			"expires_at": expires_at.isoformat() if expires_at else None,
			"days_remaining": days_remaining,
		}
	except Exception as exc:
		return {"available": False, "error": str(exc)}


def _inspect_html(html: str, final_url: str) -> dict[str, Any]:
	"""Extract runtime page features from fetched HTML."""
	if not html:
		return {
			"title": "",
			"form_count": 0,
			"password_field_count": 0,
			"hidden_input_count": 0,
			"external_form_actions": [],
			"iframe_count": 0,
			"external_script_count": 0,
			"suspicious_script_keywords": [],
			"title_brand_keywords": [],
		}

	soup = BeautifulSoup(html, "html.parser")
	final_host = _get_hostname(final_url)
	final_base = _get_base_domain(final_host)

	forms = soup.find_all("form")
	external_form_actions: list[str] = []
	password_field_count = 0
	hidden_input_count = 0

	for form in forms:
		action = (form.get("action") or "").strip()
		resolved_action = urljoin(final_url, action) if action else final_url
		action_host = _get_hostname(resolved_action)
		action_base = _get_base_domain(action_host)
		if action and action_host and action_base and action_base != final_base:
			external_form_actions.append(resolved_action)

		password_field_count += len(form.find_all("input", attrs={"type": "password"}))
		hidden_input_count += len(form.find_all("input", attrs={"type": "hidden"}))

	iframes = soup.find_all("iframe")
	script_src_count = 0
	script_text_blobs: list[str] = []
	for script in soup.find_all("script"):
		if script.get("src"):
			script_host = _get_hostname(urljoin(final_url, script.get("src", "")))
			if script_host and _get_base_domain(script_host) != final_base:
				script_src_count += 1
		else:
			text = script.get_text(" ", strip=True)
			if text:
				script_text_blobs.append(text.lower())

	combined_script_text = " ".join(script_text_blobs)
	suspicious_script_keywords = [
		pattern for pattern in SUSPICIOUS_SCRIPT_PATTERNS if pattern in combined_script_text
	]

	title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
	title_lower = title.lower()
	title_brand_keywords = [brand for brand in TITLE_BRAND_KEYWORDS if brand in title_lower]

	return {
		"title": title,
		"form_count": len(forms),
		"password_field_count": password_field_count,
		"hidden_input_count": hidden_input_count,
		"external_form_actions": external_form_actions[:5],
		"iframe_count": len(iframes),
		"external_script_count": script_src_count,
		"suspicious_script_keywords": suspicious_script_keywords[:8],
		"title_brand_keywords": title_brand_keywords[:6],
	}


def _capture_website_screenshot(url: str, timeout_ms: int = 12000) -> dict[str, Any]:
	"""Attempt to capture a rendered screenshot using Playwright if available."""
	if not SCREENSHOTS_ENABLED:
		return {"available": False, "error": "screenshot capture disabled", "path": None, "relative_url": None}

	try:
		from playwright.sync_api import sync_playwright
	except ImportError:
		return {"available": False, "error": "playwright not installed", "path": None, "relative_url": None}

	file_name = f"{uuid4().hex}.png"
	output_path = SCREENSHOT_DIR / file_name

	try:
		with sync_playwright() as playwright:
			browser = playwright.chromium.launch(headless=True)
			page = browser.new_page(viewport={"width": 1365, "height": 768})
			page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
			page.wait_for_timeout(600)
			page.screenshot(path=str(output_path), full_page=False)
			page.close()
			browser.close()
	except Exception as exc:
		if output_path.exists():
			output_path.unlink(missing_ok=True)
		return {"available": False, "error": str(exc), "path": None, "relative_url": None}

	return {
		"available": True,
		"error": None,
		"path": str(output_path),
		"relative_url": f"/artifacts/url_screenshots/{file_name}",
	}


def delete_runtime_screenshot(relative_url: str | None) -> bool:
	"""Delete a captured screenshot only if it belongs to the managed artifacts folder."""
	if not relative_url:
		return False

	normalized_relative = relative_url.strip()
	prefix = "/artifacts/url_screenshots/"
	if not normalized_relative.startswith(prefix):
		return False

	file_name = Path(normalized_relative).name
	if not file_name or file_name in {".", ".."}:
		return False

	target_path = (SCREENSHOT_DIR / file_name).resolve()
	try:
		target_path.relative_to(SCREENSHOT_DIR.resolve())
	except ValueError:
		return False

	if not target_path.exists() or not target_path.is_file():
		return False

	target_path.unlink(missing_ok=True)
	return True


def _should_capture_screenshot(page: dict[str, Any], redirect_count: int, initial_base: str, final_base: str) -> bool:
	"""Only capture screenshots for pages with meaningful runtime risk by default."""
	if not SCREENSHOTS_ENABLED:
		return False
	if not SCREENSHOTS_ON_RISK_ONLY:
		return True

	if redirect_count >= 1 and initial_base and final_base and initial_base != final_base:
		return True
	if int(page.get("password_field_count", 0)) > 0:
		return True
	if bool(page.get("external_form_actions")):
		return True
	if bool(page.get("title_brand_keywords")):
		return True
	if bool(page.get("suspicious_script_keywords")):
		return True
	return False


def analyze_runtime_url(url: str, timeout: int | None = None) -> dict[str, Any]:
	"""
	Run lightweight dynamic URL analysis by fetching the page and inspecting
	redirect behavior, final destination, HTML forms, and TLS metadata.
	"""
	result: dict[str, Any] = {
		"available": False,
		"status": "unavailable",
		"dynamic_score": 0,
		"flags": [],
		"redirect_chain": [],
		"redirect_count": 0,
		"initial_url": url,
		"final_url": url,
		"page": {},
		"screenshot": {
			"available": False,
			"error": "not captured",
			"path": None,
			"relative_url": None,
			"url": None,
		},
		"tls": {},
		"headers": {},
		"errors": [],
	}

	timeout = timeout or DYNAMIC_TIMEOUT_SECONDS

	try:
		session = requests.Session()
		response = session.get(
			url,
			timeout=timeout,
			allow_redirects=True,
			headers={"User-Agent": DYNAMIC_USER_AGENT},
		)
	except requests.RequestException as exc:
		result["errors"].append(str(exc))
		return result

	result["available"] = True
	result["status"] = "available"
	result["final_url"] = response.url
	result["headers"] = {
		"content_type": response.headers.get("Content-Type", ""),
		"server": response.headers.get("Server", ""),
		"content_length": response.headers.get("Content-Length", ""),
	}

	redirect_chain = []
	for item in list(response.history) + [response]:
		redirect_chain.append(
			{
				"status_code": item.status_code,
				"url": item.url,
				"host": _get_hostname(item.url),
			}
		)
	result["redirect_chain"] = redirect_chain
	result["redirect_count"] = max(0, len(response.history))

	initial_host = _get_hostname(url)
	final_host = _get_hostname(response.url)
	initial_base = _get_base_domain(initial_host)
	final_base = _get_base_domain(final_host)

	html = response.text if "html" in response.headers.get("Content-Type", "").lower() else ""
	page = _inspect_html(html, response.url)
	result["page"] = page
	if _should_capture_screenshot(page, result["redirect_count"], initial_base, final_base):
		screenshot = _capture_website_screenshot(response.url, timeout_ms=SCREENSHOT_TIMEOUT_MS)
	else:
		screenshot = {
			"available": False,
			"error": "skipped to keep scan fast",
			"path": None,
			"relative_url": None,
		}
	result["screenshot"] = {**screenshot, "url": screenshot.get("relative_url")}

	if TLS_LOOKUP_ENABLED and urlparse(response.url).scheme == "https":
		result["tls"] = _extract_tls_info(final_host, urlparse(response.url).port or 443)
	else:
		result["tls"] = {
			"available": False,
			"error": "tls lookup disabled" if not TLS_LOOKUP_ENABLED else "final url is not https",
		}

	score = 0
	flags: list[str] = []

	if result["redirect_count"] >= 1:
		score += min(10, result["redirect_count"] * 3)
		flags.append(f"Redirect chain observed ({result['redirect_count']} hops)")

	if final_base and initial_base and final_base != initial_base:
		score += 15
		flags.append(f"Final domain changed from {initial_base} to {final_base}")
	elif final_host and initial_host and final_host != initial_host:
		score += 5
		flags.append(f"Final host changed from {initial_host} to {final_host}")

	if page.get("password_field_count", 0) > 0:
		score += 12
		flags.append(f"Rendered page contains {page['password_field_count']} password field(s)")

	if page.get("external_form_actions"):
		score += 15
		flags.append("Form submits to an external domain")

	if page.get("iframe_count", 0) > 0:
		score += min(8, page["iframe_count"] * 3)
		flags.append(f"Page embeds {page['iframe_count']} iframe(s)")

	if page.get("suspicious_script_keywords"):
		score += min(10, len(page["suspicious_script_keywords"]) * 3)
		flags.append(
			"Suspicious client-side script patterns: "
			+ ", ".join(page["suspicious_script_keywords"][:4])
		)

	if page.get("title_brand_keywords") and final_base:
		score += 8
		flags.append(
			"Page title references trusted-brand keywords: "
			+ ", ".join(page["title_brand_keywords"])
		)

	if page.get("hidden_input_count", 0) >= 5:
		score += 4
		flags.append(f"High hidden-input count detected ({page['hidden_input_count']})")

	tls_info = result.get("tls", {})
	if tls_info.get("available") and tls_info.get("days_remaining") is not None and tls_info["days_remaining"] < 15:
		score += 5
		flags.append("TLS certificate is close to expiry")

	result["dynamic_score"] = min(45, score)
	result["flags"] = flags
	return result
