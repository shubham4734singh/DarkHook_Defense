import math
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from ipaddress import ip_address
from urllib.parse import urlparse
from uuid import uuid4

import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from modules.url_analysis.dynamic import analyze_runtime_url


router = APIRouter()


def _get_env_bool(name: str, default: bool) -> bool:
	value = os.getenv(name)
	if value is None:
		return default
	return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_env_int(name: str, default: int) -> int:
	value = os.getenv(name)
	if value is None:
		return default
	try:
		return int(value.strip())
	except ValueError:
		return default


URL_ML_ENABLED = _get_env_bool("URL_ANALYSIS_ML_ENABLED", True)
HF_API_URL = os.getenv("URL_ANALYSIS_ML_API_URL", "").strip()
HF_API_TIMEOUT_SECONDS = _get_env_int("URL_ANALYSIS_ML_TIMEOUT_SECONDS", 20)
URL_THREAT_INTEL_ENABLED = _get_env_bool("URL_ANALYSIS_THREAT_INTEL_ENABLED", True)
URL_THREAT_INTEL_API_URL = os.getenv("URL_ANALYSIS_THREAT_INTEL_API_URL", "").strip()
URL_THREAT_INTEL_API_KEY = os.getenv("URL_ANALYSIS_THREAT_INTEL_API_KEY", "").strip()
URL_THREAT_INTEL_TIMEOUT_SECONDS = _get_env_int("URL_ANALYSIS_THREAT_INTEL_TIMEOUT_SECONDS", 5)
URL_THREAT_INTEL_CACHE_TTL_SECONDS = _get_env_int("URL_ANALYSIS_THREAT_INTEL_CACHE_TTL_SECONDS", 1800)

SUSPICIOUS_TLDS = {
	"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support", "zip", "country",
	"loan", "men", "review", "racing", "win", "bid", "download", "stream", "icu"
}

SUSPICIOUS_KEYWORDS = {
	"login", "verify", "secure", "account", "update", "bank", "wallet", "password", "signin", "confirm",
	"crypto", "bitcoin", "ethereum", "blockchain", "defi", "nft", "token",
	"trezor", "ledger", "metamask", "coinbase", "binance", "kraken", "exodus",
	"sso", "auth", "oauth", "api", "validation", "authenticate", "recovery",
	"service", "setup", "support", "help", "client", "admin", "panel",
	"reset", "forgot", "recover", "restore", "sync", "connect", "enable",
	"certificate", "security", "alert", "warning", "urgent", "action",
	"payment", "billing", "charge", "transaction", "invoice", "receipt",
	"office", "outlook", "azure", "teams", "sharepoint", "microsoft",
	"stripe", "paypal", "ebay", "amazon", "apple", "google", "facebook",
	"itunes", "icloud", "appstore", "playstore", "steam", "epic",
	"2fa", "2factor", "otp", "totp", "authenticator", "verification"
}

# Well-known legitimate domains to avoid false positives
TRUSTED_DOMAINS = {
	"google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
	"netflix.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "reddit.com",
	"wikipedia.org", "github.com", "stackoverflow.com", "adobe.com", "paypal.com", "ebay.com",
	"yahoo.com", "live.com", "outlook.com", "office.com", "dropbox.com", "zoom.us",
	"salesforce.com", "slack.com", "wordpress.com", "shopify.com", "stripe.com",
	"tryhackme.com", "paruluniversity.ac.in",
}

# Popular brands for zero-day impersonation detection
POPULAR_BRANDS = {
	"google", "facebook", "amazon", "microsoft", "apple", "paypal", "netflix", "instagram",
	"twitter", "linkedin", "ebay", "yahoo", "adobe", "whatsapp", "telegram", "discord",
	"gmail", "outlook", "office", "dropbox", "zoom", "spotify", "tiktok", "snapchat",
	"trezor", "ledger", "metamask", "coinbase", "binance", "kraken", "exodus", "phantom",
	"uniswap", "opensea", "blockchain", "bitcoin", "ethereum", "wallet"
}

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
COMMON_SECOND_LEVEL_SUFFIXES = {
	"ac.uk", "co.uk", "gov.uk", "org.uk",
	"com.au", "net.au", "org.au",
	"co.in", "firm.in", "net.in", "org.in", "bank.in", "gen.in", "ind.in", "nic.in",
	"com.br", "com.mx", "com.sg", "co.jp",
}

BLOCKED_HOSTNAMES = {
	"localhost",
	"localhost.localdomain",
}

FREE_HOSTING_DOMAINS = {
	"repl.co", "herokuapp.com", "github.io", "blogspot.com", "blogspot.ae",
	"blogspot.be", "blogspot.ch", "blogspot.co.at", "blogspot.com.ar", "blogspot.com.cy",
	"blogspot.com.es", "blogspot.com.tr", "blogspot.co.uk", "blogspot.de", "blogspot.dk",
	"blogspot.hk", "blogspot.hu", "blogspot.it", "blogspot.lt", "blogspot.no", "blogspot.pe",
	"blogspot.pt", "blogspot.qa", "blogspot.ro", "blogspot.rs", "blogspot.sk", "blogspot.tw",
	"wordpress.com", "wix.com", "wixsite.com", "weebly.com", "000webhostapp.com",
	"pantheonsite.io", "onedumb.com", "ddns.net", "duckdns.org", "pages.dev",
	"webflow.io", "netlify.app", "vercel.app", "render.com", "fly.dev", "railway.app",
	"glitch.me", "surge.sh", "web.app", "firebaseapp.com", "teachable.com",
	"jdevcloud.com", "webmo.fr", "mooo.com", "netsons.org", "wpenginepowered.com",
	"siaedu.net", "mybluehost.me", "nspace.pl", "mdbgo.io", "wasmer.app",
	"mystrikingly.com", "cloudaccess.host", "sviluppo.host", "azurewebsites.net",
}

SHORTENER_DOMAINS = {
	"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
}

CONFUSABLE_CHAR_MAP = {
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
	'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ο': 'o',
}

KNOWN_BAD_INFRA_SUFFIXES = {
	"duckdns.org", "ddns.net", "hopto.org", "no-ip.org", "servehttp.com",
}

_THREAT_INTEL_CACHE: dict[str, tuple[float, dict]] = {}


def _parse_csv_set(value: str) -> set[str]:
	if not value:
		return set()
	return {item.strip().lower() for item in value.split(",") if item.strip()}


def lookup_threat_intel(url: str) -> dict:
	"""Return threat-intel verdict with safe fallback behavior and TTL caching."""
	host = get_hostname(url)
	base_domain = get_base_domain(host)
	cache_key = f"{host}|{base_domain}"
	now = time.time()

	if cache_key in _THREAT_INTEL_CACHE:
		expires_at, cached = _THREAT_INTEL_CACHE[cache_key]
		if now < expires_at:
			return cached

	result = {
		"enabled": URL_THREAT_INTEL_ENABLED,
		"available": False,
		"matched": False,
		"score_boost": 0,
		"sources": [],
		"evidence": [],
		"domain_age_days": None,
		"asn_reputation": None,
		"error": None,
	}

	if not URL_THREAT_INTEL_ENABLED or not host:
		result["available"] = bool(URL_THREAT_INTEL_ENABLED)
		_THREAT_INTEL_CACHE[cache_key] = (now + URL_THREAT_INTEL_CACHE_TTL_SECONDS, result)
		return result

	bad_domains = _parse_csv_set(os.getenv("URL_ANALYSIS_THREAT_INTEL_DOMAINS", ""))
	bad_suffixes = _parse_csv_set(os.getenv("URL_ANALYSIS_THREAT_INTEL_SUFFIXES", ""))
	bad_suffixes |= KNOWN_BAD_INFRA_SUFFIXES

	if host in bad_domains or base_domain in bad_domains:
		result["matched"] = True
		result["score_boost"] += 35
		result["sources"].append("local_domain_feed")
		result["evidence"].append(f"Domain matched local threat feed: {host}")

	for suffix in bad_suffixes:
		if host_matches_domain(host, suffix):
			result["matched"] = True
			result["score_boost"] += 20
			result["sources"].append("local_infra_suffix_feed")
			result["evidence"].append(f"Domain matches suspicious infra suffix: {suffix}")
			break

	if URL_THREAT_INTEL_API_URL:
		headers = {"Content-Type": "application/json"}
		if URL_THREAT_INTEL_API_KEY:
			headers["Authorization"] = f"Bearer {URL_THREAT_INTEL_API_KEY}"
		try:
			response = requests.post(
				URL_THREAT_INTEL_API_URL,
				json={"url": url, "host": host, "base_domain": base_domain},
				headers=headers,
				timeout=URL_THREAT_INTEL_TIMEOUT_SECONDS,
			)
			if response.status_code < 400:
				data = response.json() if response.content else {}
				result["available"] = True
				is_malicious = bool(
					data.get("malicious")
					or data.get("is_malicious")
					or data.get("listed")
					or str(data.get("verdict", "")).strip().lower() in {"malicious", "phishing", "dangerous"}
				)
				confidence = float(data.get("confidence", 0) or 0)
				if is_malicious:
					result["matched"] = True
					result["score_boost"] += 35
					if confidence >= 0.8:
						result["score_boost"] += 8
					result["sources"].append(str(data.get("source") or "external_threat_intel"))
					reason = str(data.get("reason") or "External threat feed marked this URL as malicious")
					result["evidence"].append(reason)

				domain_age_days = data.get("domain_age_days")
				if isinstance(domain_age_days, (int, float)):
					result["domain_age_days"] = int(domain_age_days)
					if domain_age_days <= 30:
						result["score_boost"] += 8
						result["evidence"].append(f"Very new domain age: {int(domain_age_days)} days")

				asn_reputation = str(data.get("asn_reputation") or "").strip().lower()
				if asn_reputation:
					result["asn_reputation"] = asn_reputation
					if asn_reputation in {"bad", "high_risk", "malicious"}:
						result["score_boost"] += 8
						result["evidence"].append(f"High-risk ASN reputation: {asn_reputation}")
			else:
				result["available"] = False
				result["error"] = f"threat-intel API returned {response.status_code}"
		except Exception as exc:
			result["available"] = False
			result["error"] = f"threat-intel API error: {exc}"
	else:
		result["available"] = True

	result["score_boost"] = min(45, int(result["score_boost"]))
	_THREAT_INTEL_CACHE[cache_key] = (now + URL_THREAT_INTEL_CACHE_TTL_SECONDS, result)
	return result


class URLAnalyzeRequest(BaseModel):
	url: str = Field(..., min_length=4, description="URL to analyze")


class URLAnalyzeResponse(BaseModel):
	scan_id: str
	url: str
	score: int
	confidence: float
	verdict: str
	status: str
	flags: list[str]
	feature_summary: dict
	analysis_details: dict
	explanation: str = Field(..., description="Human-readable explanation of the analysis result")
	screenshot: dict | None = Field(None, description="Website screenshot data")


def normalize_url(raw_url: str) -> str:
	clean = raw_url.strip()
	if not clean:
		return ""
	if not clean.startswith(("http://", "https://")):
		clean = f"http://{clean}"

	parsed = urlparse(clean)
	if not parsed.netloc:
		return ""

	return clean


def get_hostname(url: str) -> str:
	"""Return a normalized hostname without credentials, port, or trailing dot."""
	parsed = urlparse(url)
	host = (parsed.hostname or "").strip().lower().rstrip(".")
	if not host:
		return ""

	try:
		host = host.encode("ascii").decode("idna")
	except (UnicodeEncodeError, UnicodeDecodeError):
		pass

	return host


def get_base_domain(host: str) -> str:
	"""Best-effort registrable domain extraction without public suffix data."""
	if not host:
		return ""

	parts = host.split(".")
	if len(parts) <= 2:
		return host

	last_two = ".".join(parts[-2:])
	if last_two in COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
		return ".".join(parts[-3:])

	return last_two


def is_ip_host(host: str) -> bool:
	"""Return True when the hostname is an IPv4 or IPv6 literal."""
	if not host:
		return False

	try:
		ip_address(host)
		return True
	except ValueError:
		return False


def is_blocked_ip(ip_str: str) -> bool:
	"""Return True when an IP is private, loopback, link-local, or otherwise non-routable."""
	try:
		parsed_ip = ip_address(ip_str)
	except ValueError:
		return True

	return (
		parsed_ip.is_private
		or parsed_ip.is_loopback
		or parsed_ip.is_link_local
		or parsed_ip.is_multicast
		or parsed_ip.is_reserved
		or parsed_ip.is_unspecified
	)


def host_matches_domain(host: str, suffix: str) -> bool:
	"""Return True for exact host match or subdomain match against a suffix."""
	if not host or not suffix:
		return False
	return host == suffix or host.endswith("." + suffix)


def validate_scan_target(url: str) -> tuple[bool, str | None]:
	"""Reject targets that can be used for SSRF into local or non-routable networks."""
	parsed = urlparse(url)
	if parsed.scheme not in {"http", "https"}:
		return False, "Only http and https URLs are supported"

	host = get_hostname(url)
	if not host:
		return False, "Invalid hostname"

	if host in BLOCKED_HOSTNAMES:
		return False, "Localhost targets are not allowed"

	if is_ip_host(host):
		if is_blocked_ip(host):
			return False, "Private or non-routable IP targets are not allowed"
		return True, None

	try:
		resolved = socket.getaddrinfo(host, None)
	except socket.gaierror:
		return False, "Hostname could not be resolved"

	for entry in resolved:
		ip_str = entry[4][0]
		if is_blocked_ip(ip_str):
			return False, "Target resolves to private or non-routable network"

	return True, None


def is_trusted_domain(url: str) -> bool:
	"""Check if URL belongs to a well-known trusted domain"""
	host = get_hostname(url)
	base_domain = get_base_domain(host)
	return host in TRUSTED_DOMAINS or base_domain in TRUSTED_DOMAINS


def is_low_risk_legit_pattern(feature_map: dict, url: str) -> bool:
	"""Detect likely legitimate URLs to reduce ML-driven false positives."""
	host = get_hostname(url)

	if not host:
		return False

	strong_indicators = (
		feature_map["has_ip"] == 1
		or feature_map["suspicious_tld"] == 1
		or int(feature_map.get("has_lookalike", 0)) == 1
		or int(feature_map.get("is_shortener", 0)) == 1
		or int(feature_map.get("is_free_hosting", 0)) == 1
		or int(feature_map.get("has_port", 0)) == 1
		or float(feature_map.get("url_entropy", 0)) >= 4.8
		or int(feature_map.get("num_subdomains", 0)) >= 4
		or int(feature_map.get("url_length", 0)) >= 120
	)

	if strong_indicators:
		return False

	# Normal HTTPS URLs with minimal weak indicators should not be marked dangerous.
	return feature_map["is_https"] == 1 and int(feature_map.get("keyword_hits", 0)) <= 1


# ============================================================================
# ZERO-DAY PHISHING DETECTION SYSTEM
# ============================================================================

def decode_leetspeak(text: str) -> str:
	"""Convert leet-speak to normal text for pattern matching"""
	leet_map = {
		'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', 
		'7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
		'!': 'i', '|': 'l', '+': 't', '()': 'o', '[]': 'l'
	}
	decoded = text.lower()
	for leet, normal in leet_map.items():
		decoded = decoded.replace(leet, normal)
	return decoded


def levenshtein_distance(s1: str, s2: str) -> int:
	"""Calculate edit distance between two strings for fuzzy matching"""
	if len(s1) < len(s2):
		return levenshtein_distance(s2, s1)
	if len(s2) == 0:
		return len(s1)
	
	previous_row = range(len(s2) + 1)
	for i, c1 in enumerate(s1):
		current_row = [i + 1]
		for j, c2 in enumerate(s2):
			insertions = previous_row[j + 1] + 1
			deletions = current_row[j] + 1
			substitutions = previous_row[j] + (c1 != c2)
			current_row.append(min(insertions, deletions, substitutions))
		previous_row = current_row
	
	return previous_row[-1]


def detect_brand_impersonation(domain: str, url: str) -> tuple[bool, str, float]:
	"""
	Zero-day brand impersonation detection using fuzzy matching
	Returns: (is_impersonation, brand_name, similarity_score)
	"""
	if domain in TRUSTED_DOMAINS or get_base_domain(domain) in TRUSTED_DOMAINS:
		return False, "", 0.0

	base_domain = get_base_domain(domain)
	labels = [label for label in domain.split(".") if label]
	base_label = base_domain.split(".")[0] if "." in base_domain else base_domain
	candidate_labels = labels[:-2] + ([base_label] if base_label else [])

	tokens: list[str] = []
	for label in candidate_labels:
		tokens.extend(token for token in re.split(r"[-_]", label) if token)
	if not tokens and domain:
		tokens = [domain]

	decoded_tokens = [decode_leetspeak(token) for token in tokens]
	url_lower = url.lower()
	
	for brand in POPULAR_BRANDS:
		# Direct substring match
		if any(brand in token for token in tokens + decoded_tokens):
			# Check if it's in a suspicious context (with hyphens, numbers, etc.)
			if any("-" in label or any(c.isdigit() for c in label) for label in candidate_labels):
				return True, brand, 1.0
			# Check if brand is combined with phishing keywords
			if any(kw in url_lower for kw in ['login', 'verify', 'secure', 'account', 'update', 'wallet']):
				return True, brand, 1.0
		
		# Fuzzy matching for typosquatting (e.g., "gooogle", "faceb00k")
		for candidate in decoded_tokens:
			distance = levenshtein_distance(candidate, brand)
			max_distance = max(2, len(brand) // 4)  # Allow 25% character changes
			
			if distance <= max_distance and distance > 0:
				similarity = 1.0 - (distance / len(brand))
				if similarity >= 0.75:
					return True, brand, similarity
	
	return False, "", 0.0


def detect_homograph_attack(domain: str) -> bool:
	"""
	Detect homograph/IDN attacks using suspicious Unicode patterns
	"""
	if not domain:
		return False

	if "xn--" in domain:
		return True

	labels = [label for label in domain.split(".") if label]
	for label in labels:
		has_latin = any(('A' <= c <= 'Z') or ('a' <= c <= 'z') for c in label)
		has_cyrillic = any('\u0400' <= c <= '\u04FF' for c in label)
		has_greek = any('\u0370' <= c <= '\u03FF' for c in label)
		script_count = int(has_latin) + int(has_cyrillic) + int(has_greek)
		if script_count > 1:
			return True

	if any(char in CONFUSABLE_CHAR_MAP for char in domain):
		return True

	return False


def calculate_anomaly_score(features: dict) -> float:
	"""
	Calculate anomaly score based on feature deviations from normal patterns
	Returns score 0.0-1.0 (higher = more anomalous)
	"""
	anomaly_points = 0.0
	max_points = 10.0
	
	# Statistical anomalies
	if features.get("url_entropy", 0) > 4.8:
		anomaly_points += 1.5  # Very high randomness
	
	if features.get("char_diversity", 0) > 0.7:
		anomaly_points += 1.0  # Highly diverse characters (unusual)
	
	if features.get("digit_ratio", 0) > 0.15:
		anomaly_points += 1.5  # Too many digits
	
	# Structural anomalies
	if features.get("num_hyphens", 0) >= 4:
		anomaly_points += 1.0  # Excessive hyphens
	
	if features.get("num_subdomains", 0) >= 4:
		anomaly_points += 1.5  # Deep subdomain nesting
	
	if features.get("path_length", 0) > 50 and features.get("query_length", 0) == 0:
		anomaly_points += 1.0  # Long path with no query (unusual)
	
	# Behavioral anomalies
	if features.get("is_https", 0) == 0 and features.get("keyword_hits", 0) >= 2:
		anomaly_points += 2.0  # No HTTPS but phishing keywords
	
	if features.get("consecutive_hyphens", 0) == 1:
		anomaly_points += 0.5  # Consecutive hyphens (obfuscation)
	
	return min(1.0, anomaly_points / max_points)


def detect_urgency_manipulation(url: str) -> tuple[bool, int]:
	"""
	Detect psychological manipulation tactics (urgency, scarcity, fear)
	Returns: (has_manipulation, urgency_score 0-100)
	"""
	urgency_terms = [
		'urgent', 'immediately', 'now', 'quick', 'hurry', 'fast', 'expire', 
		'limited', 'act-now', 'expires', 'suspended', 'locked', 'warning',
		'alert', 'action-required', 'confirm-now', 'verify-now', 'update-now'
	]
	
	url_lower = url.lower()
	urgency_hits = sum(1 for term in urgency_terms if term in url_lower)
	
	if urgency_hits >= 2:
		return True, min(100, urgency_hits * 40)
	elif urgency_hits == 1:
		return True, 30
	
	return False, 0


def get_detected_keywords(url: str) -> list[str]:
	"""Return phishing-related keywords actually present in the URL."""
	url_lower = url.lower()
	return sorted({keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in url_lower})


def extract_features(url: str) -> dict:
	"""Extract 31 features from URL matching the v2 trained model"""
	parsed = urlparse(url)
	domain = get_hostname(url)
	path = parsed.path.lower()
	query = parsed.query.lower()
	full_url = url.lower()
	
	features = {}
	
	# Basic metrics
	features["url_length"] = len(url)
	features["domain_length"] = len(domain)
	features["path_length"] = len(path)
	features["query_length"] = len(query)
	
	# Character analysis
	features["num_dots"] = url.count(".")
	features["num_hyphens"] = url.count("-")
	features["num_underscores"] = url.count("_")
	features["num_slashes"] = url.count("/")
	features["num_question_marks"] = url.count("?")
	features["num_equal_signs"] = url.count("=")
	features["num_ampersands"] = url.count("&")
	features["num_at_signs"] = url.count("@")
	features["num_digits"] = sum(c.isdigit() for c in url)
	
	# Protocol and security
	features["is_https"] = 1 if url.startswith("https://") else 0
	features["has_ip"] = 1 if is_ip_host(domain) else 0
	try:
		parsed_port = parsed.port
	except ValueError:
		parsed_port = None
	features["has_port"] = 1 if parsed_port is not None else 0
	features["has_credentials"] = 1 if parsed.username else 0
	
	# Domain analysis
	base_domain = get_base_domain(domain)
	domain_tokens = domain.replace("-", " ").replace("_", " ").split(".")
	base_parts = base_domain.split(".") if base_domain else []
	features["num_subdomains"] = max(0, len([label for label in domain.split(".") if label]) - len(base_parts))
	
	# TLD analysis - now including commonly abused modern TLDs
	suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
	                  ".loan", ".men", ".review", ".racing", ".win", ".bid", ".download",
	                  ".stream", ".icu", ".club", ".info", ".online", ".site", ".website",
	                  ".space", ".tech", ".store", ".fun", ".live", ".cyou", ".sbs", ".cfd",
	                  ".boats", ".vip", ".pw", ".ninja", ".rocks", ".party", ".red", ".webcam",
	                  ".monster", ".wtf", ".faith", ".trade", ".science", ".shop", ".host"}
	tld = "." + domain.split(".")[-1] if "." in domain else ""
	features["suspicious_tld"] = 1 if tld in suspicious_tlds else 0
	features["tld_is_country_code"] = 1 if (len(tld) == 3 and tld[1:].isalpha()) else 0
	
	detected_keywords = get_detected_keywords(full_url)
	features["detected_keywords"] = detected_keywords
	features["keyword_hits"] = len(detected_keywords)
	
	# Entropy calculations (Shannon entropy)
	def shannon_entropy(text: str) -> float:
		if not text:
			return 0.0
		counter = Counter(text)
		length = len(text)
		return -sum((count / length) * math.log2(count / length) for count in counter.values())
	
	features["domain_entropy"] = shannon_entropy(domain)
	features["path_entropy"] = shannon_entropy(path)
	features["url_entropy"] = shannon_entropy(url)
	
	# Character diversity
	features["char_diversity"] = len(set(url)) / len(url) if url else 0
	
	# Ratio features
	features["digit_ratio"] = features["num_digits"] / len(url) if url else 0
	features["special_char_ratio"] = (features["num_hyphens"] + features["num_underscores"]) / len(domain) if domain else 0
	
	# Advanced heuristics - enhanced brand impersonation
	lookalike_patterns = ["pa.ypal", "g00gle", "micros0ft", "yah00", "netfl1x", "amaz0n"]
	# Crypto wallet brand variations (typosquatting)
	crypto_brands = ["trezor", "ledger", "metamask", "coinbase", "binance", "kraken", "exodus"]
	brand_found = any(brand in domain for brand in crypto_brands)
	# Check for brand name with typo (extra/missing letters) or in suspicious context
	has_brand_typo = (
		"trezorr" in domain or "tresor" in domain or "meta-mask" in domain or 
		"coin-base" in domain or "ledgerr" in domain or "exoduss" in domain
	)
	features["has_lookalike"] = 1 if (any(pattern in full_url for pattern in lookalike_patterns) or has_brand_typo or 
	                                    (brand_found and ("login" in full_url or "verify" in full_url or "secure" in full_url))) else 0
	
	features["is_free_hosting"] = 1 if any(host_matches_domain(domain, item) for item in FREE_HOSTING_DOMAINS) else 0
	
	features["is_shortener"] = 1 if any(host_matches_domain(domain, item) for item in SHORTENER_DOMAINS) else 0
	
	features["path_depth"] = path.count("/")
	features["has_suspicious_path"] = 1 if any(x in path for x in ["../", "//", "%", "script"]) else 0
	
	# Consecutive hyphen detection (-- or ---) - strong phishing indicator
	features["consecutive_hyphens"] = 1 if ("--" in domain or "---" in domain) else 0
	
	# Service prefix detection (strong phishing indicator: servicelpo, servicetrezor, etc.)
	domain_name_only = base_domain.split('.')[0].lower() if base_domain else domain.split('.')[0].lower()
	service_keywords = ["trezor", "ledger", "metamask", "coinbase", "binance", "kraken", "exodus",
	                     "paypal", "amazon", "apple", "microsoft", "google", "facebook", "yahoo",
	                     "office", "outlook", "mail", "orange", "sfr", "aruba", "infomaniak"]
	has_service_prefix = domain_name_only.startswith("service") and any(
		kw in domain_name_only for kw in service_keywords
	)
	features["has_service_prefix"] = 1 if has_service_prefix else 0

	# ============================================================================
	# ZERO-DAY DETECTION FEATURES
	# ============================================================================
	
	# Leet-speak detection
	decoded_domain = decode_leetspeak(domain)
	features["has_leetspeak"] = 1 if decoded_domain != domain else 0
	
	# Advanced brand impersonation with fuzzy matching
	is_impersonating, brand_name, similarity = detect_brand_impersonation(domain, full_url)
	features["brand_impersonation"] = 1 if is_impersonating else 0
	features["brand_similarity"] = similarity
	
	# Homograph attack detection
	features["has_homograph"] = 1 if detect_homograph_attack(domain) else 0

	# URL encoding / obfuscation
	features["percent_encoded_count"] = full_url.count("%")
	
	# Anomaly scoring
	features["anomaly_score"] = calculate_anomaly_score(features)
	
	# Urgency manipulation detection
	has_urgency, urgency_score = detect_urgency_manipulation(full_url)
	features["has_urgency_tactics"] = 1 if has_urgency else 0
	features["urgency_score"] = urgency_score / 100  # Normalize to 0-1
	
	return features


def build_flags(
	url: str,
	score: int,
	feature_map: dict,
	dynamic_result: dict | None = None,
	threat_intel: dict | None = None,
) -> list[str]:
	parsed = urlparse(url)
	host = get_hostname(url)
	domain = get_base_domain(host)
	path = parsed.path.lower()
	tld = host.split(".")[-1] if "." in host else ""
	dynamic_result = dynamic_result or {}
	threat_intel = threat_intel or {}

	flags: list[str] = []

	if int(feature_map.get("has_credentials", 0)) == 1:
		flags.append("Embedded URL credentials detected - Often used to disguise the real destination host")

	# Critical security issues
	if feature_map["is_https"] == 0:
		flags.append("⚠️ No HTTPS encryption - Data transmitted in plain text, vulnerable to interception")
	
	if feature_map["has_ip"] == 1:
		flags.append("🚨 IP address used instead of domain - Common phishing technique to hide identity")
	
	# Typosquatting detection - enhanced for crypto brands
	crypto_brands = ["trezor", "ledger", "metamask", "coinbase", "binance", "kraken", "exodus"]
	has_crypto_brand = any(brand in host for brand in crypto_brands)
	
	if feature_map.get("has_lookalike", 0) == 1:
		if has_crypto_brand:
			flags.append("🎯 Cryptocurrency brand impersonation detected - Domain mimics wallet/exchange brand")
		else:
			flags.append("🎯 Typosquatting detected - Domain mimics legitimate brand with character substitution")
	elif any(char.isdigit() for char in domain.split(".")[0]):
		flags.append("⚠️ Digit substitution in domain name - Possible typosquatting (e.g., paypa1 instead of paypal)")
	
	# TLD analysis
	if feature_map["suspicious_tld"] == 1:
		flags.append(f"🔴 Suspicious TLD '.{tld}' - Commonly abused for phishing (free domains with minimal verification)")
	
	# Hosting analysis
	if feature_map.get("is_shortener", 0) == 1:
		flags.append("🔗 URL shortener detected - Hides actual destination, commonly used to mask phishing links")
	
	if feature_map.get("is_free_hosting", 0) == 1:
		hosting_platforms = ["pages.dev", "webflow.io", "netlify.app", "vercel.app", "render.com"]
		detected_platform = next((p for p in hosting_platforms if p in host), "free hosting")
		flags.append(f"📦 Free hosting platform detected ({detected_platform}) - Often abused for temporary phishing sites")
	
	# Keyword analysis - enhanced with crypto awareness
	keyword_hits = int(feature_map.get("keyword_hits", 0))
	if keyword_hits > 0:
		detected_keywords = feature_map.get("detected_keywords") or get_detected_keywords(url)
		keyword_str = ", ".join(detected_keywords[:5])  # Show first 5
		if keyword_hits >= 3:
			flags.append(f"⚡ High phishing keyword density ({keyword_hits} keywords) - Contains: {keyword_str}")
		elif keyword_hits >= 1:
			flags.append(f"⚠️ Phishing keywords detected ({keyword_hits}) - Contains: {keyword_str}")
	
	# Subdomain analysis
	if feature_map["num_subdomains"] >= 3:
		flags.append(f"🔍 Deep subdomain chain ({int(feature_map['num_subdomains'])} levels) - Obfuscation technique to hide real domain")
	
	# URL complexity
	if feature_map["url_entropy"] >= 4.5:
		flags.append(f"📊 High URL randomness (entropy: {feature_map['url_entropy']:.2f}) - Unusual character patterns detected")
	
	if feature_map["url_length"] >= 90:
		flags.append(f"📏 Unusually long URL ({int(feature_map['url_length'])} chars) - May hide malicious intent")
	
	if int(feature_map.get("percent_encoded_count", 0)) >= 3:
		flags.append("Heavy percent-encoding detected - Obfuscation often used to hide malicious paths or payloads")

	# Path analysis
	if feature_map.get("has_suspicious_path", 0) == 1:
		flags.append("⚠️ Suspicious path patterns detected - Contains potentially malicious URL encoding or traversal")
	
	if feature_map.get("has_port", 0) == 1:
		flags.append("🔌 Non-standard port detected - Legitimate sites rarely use custom ports")
	
	# Hyphen abuse - enhanced detection
	if int(feature_map.get("consecutive_hyphens", 0)) == 1:
		flags.append("🚨 Consecutive hyphens detected (-- or ---) - Strong indicator of domain name obfuscation")
	elif domain.count("-") >= 2:
		flags.append(f"⚠️ Multiple hyphens in domain ({domain.count('-')}) - Common in fake domains mimicking brands")
	
	# Service prefix impersonation (servicelpo, servicetrezor, etc.)
	if int(feature_map.get("has_service_prefix", 0)) == 1:
		flags.append("🎭 Service prefix impersonation detected - Domain mimics legitimate service with brand name (e.g., servicelpo, servicetrezor)")
	
	# ============================================================================
	# ZERO-DAY DETECTION FLAGS
	# ============================================================================
	
	# Leet-speak detection
	if int(feature_map.get("has_leetspeak", 0)) == 1:
		flags.append("🔤 Leet-speak obfuscation detected - Character substitution used to evade keyword filters (e.g., w4ll3t, cr7pt0)")
	
	# Advanced brand impersonation
	if int(feature_map.get("brand_impersonation", 0)) == 1:
		similarity = float(feature_map.get("brand_similarity", 0))
		flags.append(f"🎭 Zero-day brand impersonation detected - Fuzzy match similarity: {similarity:.0%} (typosquatting/lookalike)")
	
	# Homograph attack
	if int(feature_map.get("has_homograph", 0)) == 1:
		flags.append("🌐 Homograph attack detected - Unicode characters that visually mimic legitimate domains (advanced IDN spoofing)")
	
	# Anomaly detection
	anomaly = float(feature_map.get("anomaly_score", 0))
	if anomaly >= 0.6:
		flags.append(f"📈 Statistical anomaly detected - URL characteristics deviate significantly from normal patterns (anomaly score: {anomaly:.0%})")
	
	# Urgency manipulation
	if int(feature_map.get("has_urgency_tactics", 0)) == 1:
		urgency = float(feature_map.get("urgency_score", 0))
		flags.append(f"⏰ Psychological manipulation detected - Urgency tactics designed to rush victims (urgency score: {urgency:.0%})")

	for dynamic_flag in dynamic_result.get("flags", [])[:5]:
		flags.append(f"Runtime analysis: {dynamic_flag}")

	if threat_intel.get("matched"):
		evidence = threat_intel.get("evidence") or []
		if evidence:
			flags.append(f"Threat intel hit: {evidence[0]}")
		else:
			flags.append("Threat intel hit: external or local feed marked this URL as risky")

	# If no specific flags but high score
	if not flags:
		if score >= 70:
			flags.append("🤖 ML Model Alert: Strong phishing pattern detected based on URL characteristics")
		elif score >= 45:
			flags.append("🤖 ML Model Warning: Suspicious URL characteristics detected")
		else:
			flags.append("✅ No major phishing indicators detected - URL appears legitimate")

	return flags


def compute_structural_signal_score(feature_map: dict) -> int:
	"""Score structural/lexical URL characteristics so extracted parameters affect detection."""
	points = 0

	url_length = int(feature_map.get("url_length", 0))
	domain_length = int(feature_map.get("domain_length", 0))
	path_length = int(feature_map.get("path_length", 0))
	query_length = int(feature_map.get("query_length", 0))
	num_dots = int(feature_map.get("num_dots", 0))
	num_underscores = int(feature_map.get("num_underscores", 0))
	num_slashes = int(feature_map.get("num_slashes", 0))
	num_question_marks = int(feature_map.get("num_question_marks", 0))
	num_equal_signs = int(feature_map.get("num_equal_signs", 0))
	num_ampersands = int(feature_map.get("num_ampersands", 0))
	num_at_signs = int(feature_map.get("num_at_signs", 0))
	path_depth = int(feature_map.get("path_depth", 0))
	keyword_hits = int(feature_map.get("keyword_hits", 0))

	domain_entropy = float(feature_map.get("domain_entropy", 0.0))
	path_entropy = float(feature_map.get("path_entropy", 0.0))
	char_diversity = float(feature_map.get("char_diversity", 0.0))
	special_char_ratio = float(feature_map.get("special_char_ratio", 0.0))
	tld_is_country_code = int(feature_map.get("tld_is_country_code", 0))

	if domain_length >= 40:
		points += 4
	elif domain_length >= 28:
		points += 2

	if path_length >= 70:
		points += 4
	elif path_length >= 35:
		points += 2

	if query_length >= 80:
		points += 4
	elif query_length >= 30:
		points += 2

	if num_dots >= 5:
		points += 3
	if num_underscores >= 2:
		points += 2
	if num_slashes >= 8:
		points += 2
	if num_question_marks >= 2:
		points += 3
	if num_equal_signs >= 4:
		points += 3
	if num_ampersands >= 3:
		points += 2
	if num_at_signs >= 1:
		points += 10

	if path_depth >= 6:
		points += 3

	if domain_entropy >= 4.0:
		points += 3
	if path_entropy >= 4.2:
		points += 3

	if special_char_ratio >= 0.25:
		points += 2
	if char_diversity >= 0.62 and url_length >= 70:
		points += 2

	# ccTLD alone is not suspicious; only add weak signal when phishing context exists.
	if tld_is_country_code == 1 and keyword_hits >= 2:
		points += 2

	return min(30, max(0, points))


def compute_heuristic_score(feature_map: dict, url: str) -> int:
	score = 0
	
	parsed = urlparse(url)
	host = get_hostname(url)
	domain = get_base_domain(host)

	if feature_map["is_https"] == 0:
		score += 20
	if feature_map["has_ip"] == 1:
		score += 35
	if int(feature_map.get("has_credentials", 0)) == 1:
		score += 35
	if feature_map["suspicious_tld"] == 1:
		score += 28  # Increased from 18 - suspicious TLDs are strong indicator

	keyword_hits = int(feature_map["keyword_hits"])
	score += min(25, keyword_hits * 8)  # Increased multiplier for keywords
	if feature_map["suspicious_tld"] == 1 and keyword_hits >= 2:
		score += 18
	
	# Check for digit substitution in domain (common typosquatting technique)
	# e.g., paypa1.com, g00gle.com, micros0ft.com
	if any(char.isdigit() for char in domain.split(".")[0]):  # Digits in domain name (not TLD)
		score += 30  # Strong indicator of typosquatting
	
	# Check for excessive hyphens (phishing-site-example.com)
	if domain.count("-") >= 2:
		score += 15
	
	# Consecutive hyphens (-- or ---) - very suspicious
	if int(feature_map.get("consecutive_hyphens", 0)) == 1:
		score += 20
	
	# Service prefix + brand name = very strong phishing indicator
	if int(feature_map.get("has_service_prefix", 0)) == 1:
		score += 50  # Extremely suspicious pattern
	
	# Brand impersonation with lookalike patterns or crypto brands
	if int(feature_map.get("has_lookalike", 0)) == 1:
		score += 35
	
	# Free hosting platforms commonly used for phishing - INCREASED from 15
	if int(feature_map.get("is_free_hosting", 0)) == 1:
		# Free hosting + phishing keywords = very high risk
		keyword_hits = int(feature_map.get("keyword_hits", 0))
		if keyword_hits >= 2:
			score += 45  # Free hosting + multiple keywords = strong phishing indicator
		elif keyword_hits >= 1:
			score += 35  # Free hosting + one keyword = still suspicious
		else:
			score += 25  # Free hosting alone = moderately suspicious

	if int(feature_map.get("is_shortener", 0)) == 1:
		score += 55

	if feature_map["url_entropy"] >= 4.5:
		score += 10
	if feature_map["num_subdomains"] >= 3:
		score += 10
	if feature_map["url_length"] >= 90:
		score += 7
	
	# ============================================================================
	# ZERO-DAY DETECTION SCORING
	# ============================================================================
	
	# Leet-speak obfuscation
	if int(feature_map.get("has_leetspeak", 0)) == 1:
		score += 25  # Character substitution to evade detection
	
	# Advanced brand impersonation (fuzzy matching)
	if int(feature_map.get("brand_impersonation", 0)) == 1:
		similarity = float(feature_map.get("brand_similarity", 0))
		score += int(30 * similarity)  # Scale by similarity (0-30 points)
		if keyword_hits >= 1:
			score += 12
	
	# Homograph attacks (Unicode lookalikes)
	if int(feature_map.get("has_homograph", 0)) == 1:
		score += 40  # Very sophisticated attack
	
	# Anomaly detection (statistical outliers)
	anomaly = float(feature_map.get("anomaly_score", 0))
	if anomaly >= 0.6:
		score += int(15 * anomaly)  # Up to 15 points for high anomaly
	
	# Urgency manipulation tactics
	if int(feature_map.get("has_urgency_tactics", 0)) == 1:
		urgency = float(feature_map.get("urgency_score", 0))
		score += int(12 * urgency)  # Up to 12 points for high urgency

	if int(feature_map.get("percent_encoded_count", 0)) >= 3:
		score += 10

	if int(feature_map.get("has_port", 0)) == 1:
		score += 8

	# Bring additional extracted parameters into decisioning.
	score += compute_structural_signal_score(feature_map)

	return max(0, min(100, score))


def map_verdict(score: int) -> tuple[str, str]:
	if score >= 70:
		return "Phishing", "phishing"
	if score >= 40:
		return "Suspicious", "suspicious"
	return "Safe", "safe"


def calculate_verdict_confidence(score: int, status: str, feature_map: dict, dynamic_result: dict) -> float:
	"""Estimate confidence in the current verdict, not just raw risk score."""
	keyword_hits = int(feature_map.get("keyword_hits", 0))
	dynamic_score = int(dynamic_result.get("dynamic_score", 0))
	risk_signal_count = sum(
		int(bool(feature_map.get(key)))
		for key in [
			"has_ip",
			"suspicious_tld",
			"has_credentials",
			"is_shortener",
			"is_free_hosting",
			"has_port",
			"has_lookalike",
			"brand_impersonation",
			"has_homograph",
			"has_urgency_tactics",
		]
	)

	if status == "safe":
		base = 0.72
		base += 0.10 if feature_map.get("is_https") == 1 else -0.05
		base -= min(0.18, keyword_hits * 0.05)
		base -= min(0.15, dynamic_score / 100)
		base -= min(0.10, risk_signal_count * 0.03)
		return round(max(0.35, min(0.95, base)), 4)

	if status == "suspicious":
		base = 0.55 + min(0.18, score / 200)
		base += min(0.10, dynamic_score / 120)
		base += min(0.08, risk_signal_count * 0.02)
		return round(max(0.45, min(0.9, base)), 4)

	base = 0.72 + min(0.18, score / 150)
	base += min(0.10, dynamic_score / 100)
	base += min(0.08, risk_signal_count * 0.02)
	return round(max(0.65, min(0.98, base)), 4)


def build_risk_factors(
	url: str,
	score: int,
	feature_map: dict,
	dynamic_result: dict | None = None,
	threat_intel: dict | None = None,
) -> list[dict]:
	"""Build a structured list of the strongest risk drivers."""
	host = get_hostname(url)
	base_domain = get_base_domain(host)
	tld = host.split(".")[-1] if "." in host else ""
	detected_keywords = feature_map.get("detected_keywords") or get_detected_keywords(url)
	dynamic_result = dynamic_result or {}
	threat_intel = threat_intel or {}
	risk_factors: list[dict] = []

	def add_factor(title: str, severity: str, category: str, evidence: str, impact: str) -> None:
		risk_factors.append(
			{
				"title": title,
				"severity": severity,
				"category": category,
				"evidence": evidence,
				"impact": impact,
			}
		)

	if int(feature_map.get("has_credentials", 0)) == 1:
		add_factor(
			"Embedded credentials in URL",
			"high",
			"deception",
			f"The URL includes a username-like prefix before the real host: {urlparse(url).netloc}",
			"Attackers use this trick to make a malicious host look like a trusted brand.",
		)

	if threat_intel.get("matched"):
		evidence = threat_intel.get("evidence") or ["Feed marked URL as suspicious or malicious"]
		sources = ", ".join(threat_intel.get("sources") or ["threat-intel"])
		add_factor(
			"Threat intelligence feed match",
			"high",
			"threat-intel",
			f"Sources: {sources}. Evidence: {evidence[0]}",
			"External threat intelligence correlates this URL with known malicious activity or risky infrastructure.",
		)

	if feature_map.get("has_ip") == 1:
		add_factor(
			"Raw IP address used as host",
			"high",
			"infrastructure",
			f"Hostname resolved as IP literal: {host}",
			"Phishing sites often avoid registered domains to hide ownership and rotate quickly.",
		)

	if feature_map.get("suspicious_tld") == 1:
		add_factor(
			"Suspicious top-level domain",
			"high" if score >= 70 else "medium",
			"domain",
			f"Domain ends with .{tld}",
			"Cheap and lightly vetted TLDs are frequently abused in phishing campaigns.",
		)

	if feature_map.get("brand_impersonation") == 1:
		add_factor(
			"Brand impersonation detected",
			"high",
			"brand-abuse",
			f"Fuzzy brand-matching similarity score: {float(feature_map.get('brand_similarity', 0)):.0%}",
			"This domain appears designed to impersonate a legitimate service and steal trust.",
		)
	elif feature_map.get("has_lookalike") == 1:
		add_factor(
			"Lookalike / typosquatting pattern",
			"high" if score >= 70 else "medium",
			"brand-abuse",
			f"Base domain under review: {base_domain}",
			"Small character changes can trick users into believing the URL is legitimate.",
		)

	if feature_map.get("is_shortener") == 1:
		add_factor(
			"Shortened redirect link",
			"high" if score >= 70 else "medium",
			"redirection",
			f"Shortener host detected: {host}",
			"Short links hide the final destination and are commonly used to mask malicious landing pages.",
		)

	if feature_map.get("is_free_hosting") == 1:
		add_factor(
			"Free hosting platform",
			"medium",
			"infrastructure",
			f"Host appears to be on a free hosting provider: {host}",
			"Disposable hosting lowers attacker cost and makes takedown-and-redeploy attacks easier.",
		)

	if int(feature_map.get("num_subdomains", 0)) >= 3:
		add_factor(
			"Deep subdomain chain",
			"medium",
			"structure",
			f"Detected {int(feature_map.get('num_subdomains', 0))} subdomain levels in {host}",
			"Nested subdomains are often used to hide the true registrable domain from victims.",
		)

	if detected_keywords:
		add_factor(
			"Credential / urgency keywords in URL",
			"medium" if len(detected_keywords) < 3 else "high",
			"content",
			f"Detected keywords: {', '.join(detected_keywords[:8])}",
			"Attackers often embed trust, account, or urgency words directly in phishing URLs.",
		)

	if float(feature_map.get("anomaly_score", 0)) >= 0.6:
		add_factor(
			"Anomalous URL structure",
			"medium",
			"anomaly",
			f"Anomaly score: {float(feature_map.get('anomaly_score', 0)):.0%}, entropy: {float(feature_map.get('url_entropy', 0)):.2f}",
			"The URL structure differs significantly from normal, human-friendly links.",
		)

	if int(feature_map.get("has_homograph", 0)) == 1:
		add_factor(
			"Unicode / homograph spoofing",
			"high",
			"unicode-spoofing",
			f"Hostname contains Unicode or punycode-like spoofing indicators: {host}",
			"Visual lookalike characters can make a malicious domain appear identical to a trusted one.",
		)

	if int(feature_map.get("has_urgency_tactics", 0)) == 1:
		add_factor(
			"Urgency manipulation language",
			"medium",
			"social-engineering",
			f"Urgency score: {float(feature_map.get('urgency_score', 0)):.0%}",
			"Urgency cues are commonly used to pressure users into clicking before they inspect the link.",
		)

	if feature_map.get("has_port") == 1:
		add_factor(
			"Non-standard network port",
			"medium",
			"network",
			f"URL explicitly uses port {urlparse(url).port}",
			"Legitimate login pages rarely rely on unusual ports in user-facing links.",
		)

	if int(feature_map.get("percent_encoded_count", 0)) >= 3:
		add_factor(
			"Heavy URL obfuscation",
			"medium",
			"encoding",
			f"Percent-encoded character count: {int(feature_map.get('percent_encoded_count', 0))}",
			"Encoding can be used to hide redirects, scripts, or suspicious path content from casual inspection.",
		)

	if dynamic_result.get("available"):
		page = dynamic_result.get("page", {})
		redirect_count = int(dynamic_result.get("redirect_count", 0))
		final_url = dynamic_result.get("final_url", url)
		final_host = get_hostname(final_url)
		final_base = get_base_domain(final_host)

		if redirect_count >= 1:
			add_factor(
				"Redirect behavior observed",
				"medium" if redirect_count < 3 else "high",
				"runtime",
				f"Live request followed {redirect_count} redirect hop(s) before landing on {final_url}",
				"Attackers commonly use redirect chains to hide the final destination from users and filters.",
			)

		if final_base and base_domain and final_base != base_domain:
			add_factor(
				"Runtime destination changed domains",
				"high",
				"runtime",
				f"Initial base domain {base_domain} resolved to final base domain {final_base}",
				"A domain swap during navigation is a strong sign of deceptive routing or link masking.",
			)

		if int(page.get("password_field_count", 0)) > 0:
			add_factor(
				"Credential capture form detected",
				"high",
				"page-content",
				f"Rendered page includes {int(page.get('password_field_count', 0))} password field(s)",
				"Credential prompts on suspicious domains are one of the strongest phishing indicators.",
			)

		if page.get("external_form_actions"):
			add_factor(
				"Form posts to another domain",
				"high",
				"page-content",
				f"Detected external form actions: {', '.join(page['external_form_actions'][:2])}",
				"Users may think they are submitting to one site while credentials are posted elsewhere.",
			)

		if page.get("title_brand_keywords"):
			add_factor(
				"Page content references trusted brands",
				"medium",
				"page-content",
				f"Page title contains brand-like terms: {', '.join(page['title_brand_keywords'])}",
				"Brand language in the rendered page can reinforce impersonation even when the URL looks unfamiliar.",
			)

	return risk_factors[:8]


def build_analysis_details(
	url: str,
	score: int,
	verdict: str,
	status: str,
	feature_map: dict,
	dynamic_result: dict,
	threat_intel: dict,
	ml_available: bool,
	ml_error_msg: str | None,
	base_url: str | None = None,
) -> dict:
	"""Return a detailed structured explanation for frontend/UI rendering."""
	parsed = urlparse(url)
	host = get_hostname(url)
	base_domain = get_base_domain(host)
	detected_keywords = feature_map.get("detected_keywords") or get_detected_keywords(url)
	risk_factors = build_risk_factors(url, score, feature_map, dynamic_result, threat_intel)

	if status == "phishing":
		summary = (
			f"This URL is high risk because multiple phishing indicators align. "
			f"It scored {score}/100 and was classified as phishing."
		)
	elif status == "suspicious":
		summary = (
			f"This URL shows meaningful warning signs but not enough certainty for a hard phishing label. "
			f"It scored {score}/100 and should be handled cautiously."
		)
	else:
		summary = (
			f"This URL did not trigger major phishing patterns in the current analysis and scored {score}/100. "
			f"It appears relatively low risk based on the inspected signals."
		)

	model_source = "hybrid_ml_plus_heuristics" if ml_available else "heuristics_only"
	dynamic_errors = dynamic_result.get("errors") or []
	dynamic_status = dynamic_result.get("status", "available" if dynamic_result.get("available") else "unavailable")
	dynamic_summary = (
		"Live runtime fetch completed and the rendered response was inspected."
		if dynamic_result.get("available")
		else "Live runtime fetch was not available for this scan."
	)

	if status == "phishing":
		recommendations = [
			"Do not open the link or submit any credentials.",
			"Block or report the URL if it came through email, chat, or SMS.",
			"Check whether similar messages were sent to other users in your environment.",
		]
	elif status == "suspicious":
		recommendations = [
			"Open only in an isolated environment if you absolutely must investigate it.",
			"Verify the destination with the claimed organization through an official channel.",
			"Treat any login, payment, or wallet request from this URL as untrusted.",
		]
	else:
		recommendations = [
			"No major phishing signal was detected, but continue normal caution with credentials and downloads.",
			"Verify the sender context if the link arrived unexpectedly.",
			"Re-scan if the URL changes, redirects, or expands after opening.",
		]

	return {
		"summary": summary,
		"parsed_url": {
			"scheme": parsed.scheme,
			"hostname": host,
			"base_domain": base_domain,
			"port": parsed.port,
			"path": parsed.path or "/",
			"query": parsed.query,
			"fragment": parsed.fragment,
			"subdomain_count": int(feature_map.get("num_subdomains", 0)),
		},
		"model_source": model_source,
		"model_status": "available" if ml_available else f"unavailable: {ml_error_msg}",
		"threat_intel": threat_intel,
		"detected_keywords": detected_keywords,
		"top_risks": [factor["title"] for factor in risk_factors[:3]],
		"risk_factors": risk_factors,
		"recommendations": recommendations,
		"dynamic_analysis": dynamic_result,
		"dynamic_status": dynamic_status,
		"dynamic_summary": dynamic_summary,
		"dynamic_error": dynamic_errors[0] if dynamic_errors else None,
		"indicator_snapshot": {
			"https": bool(feature_map.get("is_https")),
			"ip_host": bool(feature_map.get("has_ip")),
			"embedded_credentials": bool(feature_map.get("has_credentials")),
			"suspicious_tld": bool(feature_map.get("suspicious_tld")),
			"shortener": bool(feature_map.get("is_shortener")),
			"free_hosting": bool(feature_map.get("is_free_hosting")),
			"brand_impersonation": bool(feature_map.get("brand_impersonation")),
			"homograph": bool(feature_map.get("has_homograph")),
			"urgency_tactics": bool(feature_map.get("has_urgency_tactics")),
			"percent_encoded_count": int(feature_map.get("percent_encoded_count", 0)),
			"url_entropy": round(float(feature_map.get("url_entropy", 0)), 4),
		},
	}


def call_hf_ml_service(url: str) -> dict:
	"""Call HuggingFace ML service for URL prediction with error handling."""
	if not URL_ML_ENABLED:
		return {"error": "ML service disabled by configuration", "available": False}

	if not HF_API_URL:
		return {"error": "ML service URL not configured", "available": False}

	try:
		response = requests.post(
			HF_API_URL,
			json={"url": url},
			timeout=HF_API_TIMEOUT_SECONDS
		)
		if response.status_code >= 500:
			return {"error": f"ML service temporarily unavailable ({response.status_code})", "available": False}
		if response.status_code >= 400:
			return {"error": f"ML service request failed ({response.status_code})", "available": False}
		return response.json()
	except requests.exceptions.Timeout:
		return {"error": f"ML service timeout after {HF_API_TIMEOUT_SECONDS} seconds", "available": False}
	except requests.exceptions.ConnectionError:
		return {"error": "ML service unavailable - connection failed", "available": False}
	except requests.exceptions.RequestException as e:
		return {"error": f"ML service request error: {str(e)}", "available": False}


@router.post("/url", response_model=URLAnalyzeResponse)
def analyze_url(payload: URLAnalyzeRequest, request: Request):
	normalized = normalize_url(payload.url)
	if not normalized:
		raise HTTPException(status_code=400, detail="Invalid URL")

	is_allowed_target, blocked_reason = validate_scan_target(normalized)
	if not is_allowed_target:
		raise HTTPException(status_code=400, detail=f"Blocked URL target: {blocked_reason}")

	try:
		feature_map = extract_features(normalized)
		heuristic_score = compute_heuristic_score(feature_map, normalized)

		# Run runtime analysis and ML lookup concurrently to reduce total scan time.
		with ThreadPoolExecutor(max_workers=2) as executor:
			dynamic_future = executor.submit(analyze_runtime_url, normalized)
			ml_future = executor.submit(call_hf_ml_service, normalized)
			dynamic_result = dynamic_future.result()
			ml_result = ml_future.result()
		model_score = None
		ml_available = True
		ml_error_msg = None
		
		if "error" not in ml_result or ml_result.get("available", False):
			# Extract confidence/probability from HF response
			try:
				raw_ml_score = ml_result.get("prediction_score")
				if raw_ml_score is None:
					raw_ml_score = ml_result.get("score")
				if raw_ml_score is None:
					probability = ml_result.get("probability")
					if probability is not None:
						raw_ml_score = float(probability) * 100.0

				# Some simple APIs return prediction=0/1 only; map that to a coarse score.
				if raw_ml_score is None and "prediction" in ml_result:
					prediction = int(ml_result.get("prediction"))
					raw_ml_score = 95 if prediction == 1 else 5

				if raw_ml_score is None:
					raw_ml_score = heuristic_score

				model_score = int(float(raw_ml_score))
				model_score = max(0, min(100, model_score))
			except (ValueError, TypeError):
				ml_available = False
				ml_error_msg = "Invalid response format from ML service"
		else:
			ml_available = False
			ml_error_msg = ml_result.get("error", "ML service unavailable")

		# Use model score if available, otherwise use heuristic
		if ml_available and model_score is not None:
			score = max(model_score, heuristic_score)
		else:
			score = heuristic_score

		threat_intel = lookup_threat_intel(normalized)
		if threat_intel.get("matched"):
			score = min(100, score + int(threat_intel.get("score_boost", 0)))

		dynamic_score = int(dynamic_result.get("dynamic_score", 0))
		if dynamic_score > 0:
			score = min(100, max(score, score + dynamic_score))

		initial_base = get_base_domain(get_hostname(normalized))
		final_base = get_base_domain(get_hostname(dynamic_result.get("final_url", normalized)))
		runtime_domain_changed = bool(dynamic_result.get("available") and initial_base and final_base and final_base != initial_base)

		has_strong_risk_evidence = (
			bool(threat_intel.get("matched"))
			or
			int(feature_map.get("has_credentials", 0)) == 1
			or int(feature_map.get("has_ip", 0)) == 1
			or int(feature_map.get("suspicious_tld", 0)) == 1
			or int(feature_map.get("brand_impersonation", 0)) == 1
			or int(feature_map.get("has_homograph", 0)) == 1
			or int(feature_map.get("keyword_hits", 0)) >= 2
			or dynamic_score >= 12
			or runtime_domain_changed
		)

		# If ML predicts very high risk but URL evidence is weak, dampen ML-driven false positives.
		if (
			ml_available
			and model_score is not None
			and model_score >= 80
			and heuristic_score <= 25
			and not has_strong_risk_evidence
		):
			score = min(score, 39)
		
		# Trusted domains with weak risk evidence should remain low-risk even if ML over-scores.
		if is_trusted_domain(normalized) and not has_strong_risk_evidence:
			score = min(score, 30)

		# Apply conservative false-positive dampening without forcing risky URLs into "safe".
		if is_trusted_domain(normalized) and score >= 40:
			high_risk_signals = (
				bool(threat_intel.get("matched"))
				or
				int(feature_map.get("has_credentials", 0)) == 1
				or int(feature_map.get("has_ip", 0)) == 1
				or int(feature_map.get("brand_impersonation", 0)) == 1
				or int(feature_map.get("has_homograph", 0)) == 1
				or dynamic_score >= 12
				or runtime_domain_changed
			)
			if not high_risk_signals:
				score = max(0, score - 12)
		elif is_low_risk_legit_pattern(feature_map, normalized) and score >= 70 and dynamic_score == 0:
			score = max(40, score - 25)

		# Runtime destination switching is a hard floor: it should never be downgraded to "safe".
		if runtime_domain_changed:
			score = max(score, 45)

		if threat_intel.get("matched"):
			score = max(score, 45)
		
		verdict, status = map_verdict(score)
		confidence = calculate_verdict_confidence(score, status, feature_map, dynamic_result)
		flags = build_flags(normalized, score, feature_map, dynamic_result, threat_intel)
		analysis_details = build_analysis_details(
			normalized,
			score,
			verdict,
			status,
			feature_map,
			dynamic_result,
			threat_intel,
			ml_available,
			ml_error_msg,
			str(request.base_url),
		)

		# Enhanced feature summary with more context
		feature_summary = {
			"is_https": int(feature_map["is_https"]),
			"has_ip": int(feature_map["has_ip"]),
			"has_credentials": int(feature_map.get("has_credentials", 0)),
			"suspicious_tld": int(feature_map["suspicious_tld"]),
			"num_subdomains": int(feature_map["num_subdomains"]),
			"keyword_hits": int(feature_map["keyword_hits"]),
			"url_entropy": round(float(feature_map["url_entropy"]), 4),
			"url_length": int(feature_map["url_length"]),
			"has_typosquatting": int(feature_map.get("has_lookalike", 0)) or (1 if any(char.isdigit() for char in normalized.split("//")[1].split("/")[0].split(".")[0]) else 0),
			"is_shortener": int(feature_map.get("is_shortener", 0)),
			"is_free_hosting": int(feature_map.get("is_free_hosting", 0)),
			"has_port": int(feature_map.get("has_port", 0)),
			"percent_encoded_count": int(feature_map.get("percent_encoded_count", 0)),
			"dynamic_score": dynamic_score,
			"redirect_count": int(dynamic_result.get("redirect_count", 0)),
			"runtime_final_domain_changed": int(
				get_base_domain(get_hostname(dynamic_result.get("final_url", normalized)))
				!= get_base_domain(get_hostname(normalized))
			),
			"runtime_password_fields": int(dynamic_result.get("page", {}).get("password_field_count", 0)),
			"consecutive_hyphens": int(feature_map.get("consecutive_hyphens", 0)),
			"has_service_prefix": int(feature_map.get("has_service_prefix", 0)),
			# Zero-day detection features
			"has_leetspeak": int(feature_map.get("has_leetspeak", 0)),
			"brand_impersonation": int(feature_map.get("brand_impersonation", 0)),
			"brand_similarity": round(float(feature_map.get("brand_similarity", 0)), 4),
			"has_homograph": int(feature_map.get("has_homograph", 0)),
			"anomaly_score": round(float(feature_map.get("anomaly_score", 0)), 4),
			"has_urgency_tactics": int(feature_map.get("has_urgency_tactics", 0)),
			"urgency_score": round(float(feature_map.get("urgency_score", 0)), 4),
			"threat_intel_hit": 1 if threat_intel.get("matched") else 0,
			"threat_intel_boost": int(threat_intel.get("score_boost", 0)),
		}
		
		# Generate explanation summary
		explanation = [analysis_details["summary"]]
		if analysis_details["top_risks"]:
			explanation.append("Top signals: " + "; ".join(analysis_details["top_risks"]) + ".")
		if analysis_details["recommendations"]:
			explanation.append("Recommended action: " + analysis_details["recommendations"][0])

		# Add ML service status message if unavailable
		explanation_str = " ".join(explanation)
		if not ml_available:
			explanation_str += f" (Heuristic engine used because external ML is unavailable: {ml_error_msg})"

		return URLAnalyzeResponse(
			scan_id=str(uuid4()),
			url=normalized,
			score=score,
			confidence=confidence,
			verdict=verdict,
			status=status,
			flags=flags,
			feature_summary=feature_summary,
			analysis_details=analysis_details,
			explanation=explanation_str,
			screenshot=dynamic_result.get("screenshot"),
		)
	except HTTPException:
		raise
	except Exception as exc:
		raise HTTPException(status_code=500, detail=f"URL analysis failed: {exc}") from exc
