import base64
import io
import re
import socket
import ssl
from datetime import datetime, timezone
import os
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from PIL import Image, ImageDraw


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
TLS_LOOKUP_ENABLED = os.getenv("URL_ANALYSIS_TLS_LOOKUP_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
DYNAMIC_TIMEOUT_SECONDS = int(os.getenv("URL_ANALYSIS_DYNAMIC_TIMEOUT_SECONDS", "6"))
SCREENSHOT_SERVICE_URL = os.getenv("URL_ANALYSIS_SCREENSHOT_SERVICE_URL", "").strip()
SCREENSHOT_SERVICE_TIMEOUT_SECONDS = int(os.getenv("URL_ANALYSIS_SCREENSHOT_SERVICE_TIMEOUT_SECONDS", "25"))
SCREENSHOT_SERVICE_API_KEY = os.getenv("URL_ANALYSIS_SCREENSHOT_SERVICE_API_KEY", "").strip()
SCREENSHOT_LOCAL_FALLBACK_ENABLED = os.getenv("URL_ANALYSIS_SCREENSHOT_LOCAL_FALLBACK_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
SCREENSHOT_LOCAL_TIMEOUT_SECONDS = int(os.getenv("URL_ANALYSIS_SCREENSHOT_LOCAL_TIMEOUT_SECONDS", "20"))
SCREENSHOT_CAPTURE_MODE = os.getenv("URL_ANALYSIS_SCREENSHOT_CAPTURE_MODE", "local_first").strip().lower()
URL_ANALYSIS_DYNAMIC_FAST_MODE = os.getenv("URL_ANALYSIS_DYNAMIC_FAST_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}


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
			"form_action_mismatch_count": 0,
			"iframe_count": 0,
			"external_script_count": 0,
			"suspicious_script_keywords": [],
			"js_redirect_indicators": [],
			"meta_refresh_targets": [],
			"title_brand_keywords": [],
		}

	soup = BeautifulSoup(html, "html.parser")
	final_host = _get_hostname(final_url)
	final_base = _get_base_domain(final_host)

	forms = soup.find_all("form")
	external_form_actions: list[str] = []
	password_field_count = 0
	hidden_input_count = 0
	form_action_mismatch_count = 0

	for form in forms:
		action = (form.get("action") or "").strip()
		resolved_action = urljoin(final_url, action) if action else final_url
		action_host = _get_hostname(resolved_action)
		action_base = _get_base_domain(action_host)
		if action and action_host and action_base and action_base != final_base:
			external_form_actions.append(resolved_action)

		has_password_input = bool(form.find_all("input", attrs={"type": "password"}))
		if has_password_input and action and action_host and action_base and action_base != final_base:
			form_action_mismatch_count += 1

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
	js_redirect_patterns = [
		"window.location",
		"location.href",
		"location.replace(",
		"location.assign(",
		"top.location",
		"document.location",
		"window.open(",
	]
	js_redirect_indicators = [pattern for pattern in js_redirect_patterns if pattern in combined_script_text]

	meta_refresh_targets: list[str] = []
	for meta in soup.find_all("meta"):
		http_equiv = (meta.get("http-equiv") or "").strip().lower()
		if http_equiv != "refresh":
			continue
		content = (meta.get("content") or "").strip()
		match = re.search(r"url\s*=\s*([^;]+)$", content, flags=re.IGNORECASE)
		if not match:
			continue
		target = match.group(1).strip().strip('"').strip("'")
		if not target:
			continue
		meta_refresh_targets.append(urljoin(final_url, target))

	title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
	title_lower = title.lower()
	title_brand_keywords = [brand for brand in TITLE_BRAND_KEYWORDS if brand in title_lower]

	return {
		"title": title,
		"form_count": len(forms),
		"password_field_count": password_field_count,
		"hidden_input_count": hidden_input_count,
		"external_form_actions": external_form_actions[:5],
		"form_action_mismatch_count": form_action_mismatch_count,
		"iframe_count": len(iframes),
		"external_script_count": script_src_count,
		"suspicious_script_keywords": suspicious_script_keywords[:8],
		"js_redirect_indicators": js_redirect_indicators[:8],
		"meta_refresh_targets": meta_refresh_targets[:5],
		"title_brand_keywords": title_brand_keywords[:6],
	}


def _capture_remote_screenshot(url: str) -> dict[str, Any]:
	"""Use a hosted screenshot service instead of local browser automation."""
	if not SCREENSHOT_SERVICE_URL:
		return {"available": False, "error": "screenshot service not configured", "url": None}

	headers = {"Content-Type": "application/json"}
	if SCREENSHOT_SERVICE_API_KEY:
		headers["X-Screenshot-Service-Key"] = SCREENSHOT_SERVICE_API_KEY
		headers["X-API-Key"] = SCREENSHOT_SERVICE_API_KEY
		headers["Authorization"] = f"Bearer {SCREENSHOT_SERVICE_API_KEY}"

	try:
		response = requests.post(
			SCREENSHOT_SERVICE_URL,
			json={"url": url},
			headers=headers,
			timeout=SCREENSHOT_SERVICE_TIMEOUT_SECONDS,
		)
		if response.status_code >= 500:
			return {"available": False, "error": f"screenshot service unavailable ({response.status_code})", "url": None}
		if response.status_code >= 400:
			return {"available": False, "error": f"screenshot service request failed ({response.status_code})", "url": None}

		payload = response.json()
		data_url = (
			payload.get("data_url")
			or payload.get("url")
			or payload.get("image_url")
			or payload.get("screenshot_url")
		)
		return {
			"available": bool(payload.get("available") or data_url),
			"error": payload.get("error"),
			"url": data_url,
			"content_type": payload.get("content_type"),
			"size_bytes": payload.get("size_bytes"),
			"final_url": payload.get("final_url"),
			"source": "remote_service",
		}
	except requests.exceptions.Timeout:
		return {"available": False, "error": f"screenshot service timeout after {SCREENSHOT_SERVICE_TIMEOUT_SECONDS} seconds", "url": None}
	except requests.exceptions.RequestException as exc:
		return {"available": False, "error": f"screenshot service error: {exc}", "url": None}


def _capture_local_screenshot(url: str) -> dict[str, Any]:
	"""Capture screenshot locally using Playwright and return as data URL."""
	if not SCREENSHOT_LOCAL_FALLBACK_ENABLED:
		return {"available": False, "error": "local screenshot fallback disabled", "url": None}

	try:
		from playwright.sync_api import sync_playwright
	except Exception as exc:
		return {
			"available": False,
			"error": f"playwright import failed: {exc}",
			"url": None,
		}

	try:
		with sync_playwright() as p:
			browser = p.chromium.launch(headless=True)
			context = browser.new_context(
				viewport={"width": 1366, "height": 768},
				user_agent=DYNAMIC_USER_AGENT,
				ignore_https_errors=True,
			)
			page = context.new_page()
			nav_error = None
			try:
				page.goto(url, wait_until="commit", timeout=SCREENSHOT_LOCAL_TIMEOUT_SECONDS * 1000)
			except Exception as goto_exc:
				nav_error = str(goto_exc)
			page.wait_for_timeout(220)
			image_bytes = page.screenshot(full_page=False, type="png")
			final_url = page.url
			context.close()
			browser.close()

		data_url = "data:image/png;base64," + base64.b64encode(image_bytes).decode("ascii")
		return {
			"available": True,
			"error": nav_error,
			"url": data_url,
			"content_type": "image/png",
			"size_bytes": len(image_bytes),
			"final_url": final_url,
			"source": "local_playwright",
		}
	except Exception as exc:
		msg = str(exc)
		if "Executable doesn't exist" in msg:
			msg += " | Run: playwright install chromium"
		return {
			"available": False,
			"error": f"local screenshot failed: {msg}",
			"url": None,
		}


def _build_placeholder_screenshot(url: str, error: str | None) -> dict[str, Any]:
	"""Generate a small PNG fallback so screenshot is always present."""
	img = Image.new("RGB", (1366, 768), (16, 24, 39))
	draw = ImageDraw.Draw(img)

	lines = [
		"Screenshot unavailable - fallback generated",
		f"URL: {url[:140]}",
	]
	if error:
		lines.append(f"Reason: {error[:180]}")

	y = 40
	for line in lines:
		draw.text((40, y), line, fill=(226, 232, 240))
		y += 36

	buf = io.BytesIO()
	img.save(buf, format="PNG")
	image_bytes = buf.getvalue()
	data_url = "data:image/png;base64," + base64.b64encode(image_bytes).decode("ascii")
	return {
		"available": True,
		"error": error,
		"url": data_url,
		"content_type": "image/png",
		"size_bytes": len(image_bytes),
		"final_url": url,
		"source": "generated_placeholder",
	}


def _capture_screenshot(url: str) -> dict[str, Any]:
	"""Try remote screenshot service first, then local Playwright fallback."""
	if SCREENSHOT_CAPTURE_MODE == "local_first":
		local = _capture_local_screenshot(url)
		if local.get("available"):
			return local
		if SCREENSHOT_SERVICE_URL:
			remote = _capture_remote_screenshot(url)
			if remote.get("available"):
				return remote
			combined_error = f"local: {local.get('error')}; remote: {remote.get('error')}"
			return _build_placeholder_screenshot(url, combined_error)
		return _build_placeholder_screenshot(url, str(local.get("error")))

	if SCREENSHOT_SERVICE_URL:
		remote = _capture_remote_screenshot(url)
		if remote.get("available"):
			return remote

		if SCREENSHOT_LOCAL_FALLBACK_ENABLED:
			local = _capture_local_screenshot(url)
			if local.get("available"):
				return local
			local_error = local.get("error")
			remote_error = remote.get("error")
			return {
				**_build_placeholder_screenshot(url, f"remote: {remote_error}; local: {local_error}"),
			}

		return remote

	local = _capture_local_screenshot(url)
	if local.get("available"):
		return local
	return _build_placeholder_screenshot(url, str(local.get("error")))

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
			"error": "screenshot service not configured" if not SCREENSHOT_SERVICE_URL else "not captured",
			"url": None,
		},
		"tls": {},
		"headers": {},
		"errors": [],
	}

	timeout = timeout or DYNAMIC_TIMEOUT_SECONDS

	if URL_ANALYSIS_DYNAMIC_FAST_MODE:
		result["available"] = True
		result["status"] = "available"
		result["screenshot"] = _capture_screenshot(url)
		result["final_url"] = result["screenshot"].get("final_url") or url
		result["errors"].append("fast mode enabled: skipped html runtime fetch")
		return result

	try:
		session = requests.Session()
		response = session.get(
			url,
			timeout=timeout,
			allow_redirects=True,
			headers={"User-Agent": DYNAMIC_USER_AGENT},
		)
	except requests.exceptions.SSLError as exc:
		result["errors"].append(str(exc))
		result["errors"].append("TLS verification failed, runtime fetch stopped without insecure retry.")
		return result
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
	result["screenshot"] = _capture_screenshot(response.url)

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

	if int(page.get("form_action_mismatch_count", 0)) > 0:
		score += min(16, int(page.get("form_action_mismatch_count", 0)) * 8)
		flags.append(
			f"Credential form action mismatch detected ({int(page.get('form_action_mismatch_count', 0))} form(s) post to external domain)"
		)

	if page.get("iframe_count", 0) > 0:
		score += min(8, page["iframe_count"] * 3)
		flags.append(f"Page embeds {page['iframe_count']} iframe(s)")

	if page.get("suspicious_script_keywords"):
		score += min(10, len(page["suspicious_script_keywords"]) * 3)
		flags.append(
			"Suspicious client-side script patterns: "
			+ ", ".join(page["suspicious_script_keywords"][:4])
		)

	if page.get("js_redirect_indicators"):
		score += min(12, len(page["js_redirect_indicators"]) * 4)
		flags.append(
			"JavaScript redirect behavior detected: "
			+ ", ".join(page["js_redirect_indicators"][:3])
		)

	if page.get("meta_refresh_targets"):
		meta_targets = page.get("meta_refresh_targets", [])
		cross_domain_meta = False
		for target in meta_targets:
			target_base = _get_base_domain(_get_hostname(target))
			if target_base and final_base and target_base != final_base:
				cross_domain_meta = True
				break
		score += 10 if cross_domain_meta else 4
		if cross_domain_meta:
			flags.append("Meta refresh redirects to a different domain")
		else:
			flags.append("Meta refresh redirect present")

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
