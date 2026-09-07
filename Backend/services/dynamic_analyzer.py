import base64
import hashlib
import io
import re
import socket
import ssl
from datetime import datetime, timezone
import os
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup, Tag
from PIL import Image, ImageDraw

from core.config import settings

_tld_extractor = tldextract.TLDExtract(include_psl_private_domains=True)

DYNAMIC_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 DarkHookDefense/1.0"
)

EXFILTRATION_SINKS = [
    "api.telegram.org",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "formspree.io",
    "formsubmit.co",
    "firebaseio.com",
    "webhook.site",
]

AUTHENTIC_BRAND_FAVICONS = {
    # Microsoft 365 / Azure AD / Entra ID login favicon
    "b68fd2548725646144ec5ee6b9d901c1": {
        "brand": "Microsoft 365",
        "allowed_domains": {"microsoft.com", "office.com", "live.com", "azure.com", "windows.net", "msauth.net", "microsoftonline.com"},
    },
    # Microsoft corporate favicon
    "bfd093e42dfed48a0323ae8d8432a82b": {
        "brand": "Microsoft",
        "allowed_domains": {"microsoft.com", "office.com", "live.com", "azure.com", "windows.net", "msauth.net"},
    },
    # Google
    "f3418a443e7d841097c714d69ec4bcb8": {
        "brand": "Google",
        "allowed_domains": {"google.com", "gmail.com", "gstatic.com", "google.co.in", "google.co.uk", "google.com.au"},
    },
    # PayPal
    "e1528b5176081f0ed963ec8397bc8fd3": {
        "brand": "PayPal",
        "allowed_domains": {"paypal.com", "paypalobjects.com"},
    },
    # Binance
    "43365839589fc348172246e108c1297c": {
        "brand": "Binance",
        "allowed_domains": {"binance.com", "bnbstatic.com"},
    },
}

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

def _get_hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").strip().lower().rstrip(".")

def _get_base_domain(host: str) -> str:
    if not host:
        return ""
    ext = _tld_extractor(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or ext.suffix or host

def _get_tag_attr_str(tag: Tag, attr: str, default: str = "") -> str:
    """Safely extract an attribute value as a clean string.

    BeautifulSoup returns AttributeValueList (a subclass of list) for multi-valued
    attributes (such as 'class') or when attributes appear multiple times on a tag.
    Calling .strip() directly on tag.get(...) raises an AttributeError if an
    AttributeValueList is returned.
    """
    val = tag.get(attr)
    if val is None:
        return default
    if isinstance(val, (list, tuple)):
        return " ".join(str(item) for item in val if item is not None).strip()
    return str(val).strip()

def _extract_tls_info(host: str, port: int = 443) -> dict[str, Any]:
    """Attempt to collect basic TLS certificate metadata."""
    if not host:
        return {"available": False, "error": "missing hostname"}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()

        if not cert:
            return {"available": False, "error": "TLS certificate not available"}

        subject_dict: dict[str, str] = {}
        for rdn in cert.get("subject", ()):
            for item in rdn:
                if len(item) >= 2:
                    subject_dict[str(item[0])] = str(item[1])

        issuer_dict: dict[str, str] = {}
        for rdn in cert.get("issuer", ()):
            for item in rdn:
                if len(item) >= 2:
                    issuer_dict[str(item[0])] = str(item[1])

        not_after_raw = cert.get("notAfter")
        expires_at = None
        days_remaining = None
        if isinstance(not_after_raw, str):
            expires_at = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (expires_at - datetime.now(timezone.utc)).days

        san_entries = cert.get("subjectAltName", ())
        subject_alt_names: list[str] = []
        if isinstance(san_entries, (list, tuple)):
            for entry in san_entries:
                if isinstance(entry, (list, tuple)) and len(entry) > 1:
                    subject_alt_names.append(str(entry[1]))

        return {
            "available": True,
            "subject_common_name": subject_dict.get("commonName"),
            "issuer_common_name": issuer_dict.get("commonName"),
            "subject_alt_names": subject_alt_names,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "days_remaining": days_remaining,
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}

def _inspect_html(html: str, final_url: str) -> dict[str, Any]:
    """Extract runtime page features, exfiltration sinks, and behavioral metrics from fetched HTML."""
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
            "exfiltration_sinks": [],
            "favicon_url": None,
            "line_count": 0,
            "largest_line_length": 0,
            "has_password_field": 0,
            "has_hidden_fields": 0,
            "has_submit_button": 0,
            "image_count": 0,
            "css_link_count": 0,
        }

    soup = BeautifulSoup(html, "html.parser")
    final_host = _get_hostname(final_url)
    final_base = _get_base_domain(final_host)

    forms = soup.find_all("form")
    external_form_actions: list[str] = []
    password_field_count = 0
    hidden_input_count = 0
    form_action_mismatch_count = 0
    exfiltration_sinks_detected: list[str] = []

    for form in forms:
        action = _get_tag_attr_str(form, "action")
        resolved_action = urljoin(final_url, action) if action else final_url
        action_host = _get_hostname(resolved_action)
        action_base = _get_base_domain(action_host)
        if action and action_host and action_base and action_base != final_base:
            external_form_actions.append(resolved_action)

        # Check for exfiltration sinks in form action
        action_lower = resolved_action.lower()
        for sink in EXFILTRATION_SINKS:
            if sink in action_lower:
                exfiltration_sinks_detected.append(sink)

        password_inputs = form.find_all("input", attrs={"type": "password"})
        has_password_input = len(password_inputs) > 0
        if has_password_input and action and action_host and action_base and action_base != final_base:
            form_action_mismatch_count += 1

        password_field_count += len(password_inputs)
        hidden_input_count += len(form.find_all("input", attrs={"type": "hidden"}))

    iframes = soup.find_all("iframe")
    script_src_count = 0
    script_text_blobs: list[str] = []
    for script in soup.find_all("script"):
        src = _get_tag_attr_str(script, "src")
        if src:
            script_host = _get_hostname(urljoin(final_url, src))
            if script_host and _get_base_domain(script_host) != final_base:
                script_src_count += 1
        else:
            text = script.get_text(" ", strip=True)
            if text:
                script_text_blobs.append(text.lower())

    combined_script_text = " ".join(script_text_blobs)
    for sink in EXFILTRATION_SINKS:
        if sink in combined_script_text and sink not in exfiltration_sinks_detected:
            exfiltration_sinks_detected.append(sink)

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
        http_equiv = _get_tag_attr_str(meta, "http-equiv").lower()
        if http_equiv != "refresh":
            continue
        content = _get_tag_attr_str(meta, "content")
        match = re.search(r"url\s*=\s*([^;]+)", content, flags=re.IGNORECASE)
        if not match:
            continue
        target = match.group(1).strip().strip('"').strip("'")
        if not target:
            continue
        meta_refresh_targets.append(urljoin(final_url, target))

    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    title_lower = title.lower()
    title_brand_keywords = [brand for brand in TITLE_BRAND_KEYWORDS if brand in title_lower]

    # Favicon resolution and CSS link count
    css_link_count = 0
    favicon_url = None
    for link in soup.find_all("link"):
        rel_attr = link.get("rel")
        if isinstance(rel_attr, str):
            rel_vals = [r.strip().lower() for r in rel_attr.split()]
        elif isinstance(rel_attr, (list, tuple)):
            rel_vals = [str(r).strip().lower() for r in rel_attr if r]
        else:
            rel_vals = []

        if any("stylesheet" in r for r in rel_vals):
            css_link_count += 1

        if not favicon_url and any(r in rel_vals for r in ["icon", "shortcut icon", "apple-touch-icon"]):
            href = _get_tag_attr_str(link, "href")
            if href:
                favicon_url = urljoin(final_url, href)

    if not favicon_url:
        parsed_final = urlparse(final_url)
        if parsed_final.netloc:
            favicon_url = f"{parsed_final.scheme or 'http'}://{parsed_final.netloc}/favicon.ico"

    lines = html.splitlines() if html else []
    has_submit_button = 1 if (
        soup.find("input", attrs={"type": "submit"}) is not None
        or soup.find("button", attrs={"type": "submit"}) is not None
    ) else 0

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
        "exfiltration_sinks": sorted(list(set(exfiltration_sinks_detected))),
        "favicon_url": favicon_url,
        "line_count": len(lines),
        "largest_line_length": max((len(line) for line in lines), default=0),
        "has_password_field": 1 if password_field_count > 0 else 0,
        "has_hidden_fields": 1 if hidden_input_count > 0 else 0,
        "has_submit_button": has_submit_button,
        "image_count": len(soup.find_all("img")),
        "css_link_count": css_link_count,
    }

def _capture_remote_screenshot(url: str) -> dict[str, Any]:
    """Use a hosted screenshot service instead of local browser automation."""
    if not settings.URL_ANALYSIS_SCREENSHOT_SERVICE_URL:
        return {"available": False, "error": "screenshot service not configured", "url": None}

    headers = {"Content-Type": "application/json"}
    if settings.URL_ANALYSIS_SCREENSHOT_SERVICE_API_KEY:
        headers["X-Screenshot-Service-Key"] = settings.URL_ANALYSIS_SCREENSHOT_SERVICE_API_KEY
        headers["X-API-Key"] = settings.URL_ANALYSIS_SCREENSHOT_SERVICE_API_KEY
        headers["Authorization"] = f"Bearer {settings.URL_ANALYSIS_SCREENSHOT_SERVICE_API_KEY}"

    try:
        response = requests.post(
            settings.URL_ANALYSIS_SCREENSHOT_SERVICE_URL,
            json={"url": url},
            headers=headers,
            timeout=settings.URL_ANALYSIS_SCREENSHOT_SERVICE_TIMEOUT_SECONDS,
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
        return {"available": False, "error": f"screenshot service timeout after {settings.URL_ANALYSIS_SCREENSHOT_SERVICE_TIMEOUT_SECONDS} seconds", "url": None}
    except requests.exceptions.RequestException as exc:
        return {"available": False, "error": f"screenshot service error: {exc}", "url": None}

def _capture_local_screenshot(url: str) -> dict[str, Any]:
    """Capture screenshot locally using Playwright and return as data URL."""
    if not settings.URL_ANALYSIS_SCREENSHOT_LOCAL_FALLBACK_ENABLED:
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
                page.goto(url, wait_until="commit", timeout=settings.URL_ANALYSIS_SCREENSHOT_LOCAL_TIMEOUT_SECONDS * 1000)
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
    if settings.URL_ANALYSIS_SCREENSHOT_CAPTURE_MODE == "local_first":
        local = _capture_local_screenshot(url)
        if local.get("available"):
            return local
        if settings.URL_ANALYSIS_SCREENSHOT_SERVICE_URL:
            remote = _capture_remote_screenshot(url)
            if remote.get("available"):
                return remote
            combined_error = f"local: {local.get('error')}; remote: {remote.get('error')}"
            return _build_placeholder_screenshot(url, combined_error)
        return _build_placeholder_screenshot(url, str(local.get("error")))

    if settings.URL_ANALYSIS_SCREENSHOT_SERVICE_URL:
        remote = _capture_remote_screenshot(url)
        if remote.get("available"):
            return remote

        if settings.URL_ANALYSIS_SCREENSHOT_LOCAL_FALLBACK_ENABLED:
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
            "error": "screenshot service not configured" if not settings.URL_ANALYSIS_SCREENSHOT_SERVICE_URL else "not captured",
            "url": None,
        },
        "tls": {},
        "headers": {},
        "errors": [],
    }

    timeout = timeout or settings.URL_ANALYSIS_DYNAMIC_TIMEOUT_SECONDS

    if settings.URL_ANALYSIS_DYNAMIC_FAST_MODE:
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

    # Favicon hash brand spoofing detection
    favicon_url = page.get("favicon_url")
    favicon_hash = None
    favicon_spoof_detected = None
    if settings.URL_ANALYSIS_FAVICON_ENABLED and favicon_url:
        try:
            fav_resp = session.get(
                favicon_url,
                timeout=2,
                headers={"User-Agent": DYNAMIC_USER_AGENT},
                stream=True,
            )
            if fav_resp.status_code == 200:
                fav_bytes = fav_resp.raw.read(65536)
                if fav_bytes:
                    favicon_hash = hashlib.md5(fav_bytes).hexdigest()
                    if favicon_hash in AUTHENTIC_BRAND_FAVICONS:
                        brand_info = AUTHENTIC_BRAND_FAVICONS[favicon_hash]
                        brand_name = brand_info["brand"]
                        if final_base and final_base not in brand_info["allowed_domains"]:
                            favicon_spoof_detected = brand_name
        except Exception:
            pass

    page["favicon_hash"] = favicon_hash
    page["favicon_spoof"] = favicon_spoof_detected
    result["page"] = page
    result["screenshot"] = _capture_screenshot(response.url)

    if settings.URL_ANALYSIS_TLS_LOOKUP_ENABLED and urlparse(response.url).scheme == "https":
        result["tls"] = _extract_tls_info(final_host, urlparse(response.url).port or 443)
    else:
        result["tls"] = {
            "available": False,
            "error": "tls lookup disabled" if not settings.URL_ANALYSIS_TLS_LOOKUP_ENABLED else "final url is not https",
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

    # Exfiltration sinks penalty
    if page.get("exfiltration_sinks"):
        score += 25
        sinks_str = ", ".join(page["exfiltration_sinks"])
        flags.append(f"🚨 Phishing credential exfiltration sink detected: page routes data to credential drop service ({sinks_str})")

    # Favicon brand spoofing penalty
    if page.get("favicon_spoof"):
        score += 35
        flags.append(
            f"🚨 Favicon brand spoofing detected: Page displays authentic {page['favicon_spoof']} favicon on unrelated domain ({final_base})"
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

    result["dynamic_score"] = min(55, score)
    result["flags"] = flags
    return result

