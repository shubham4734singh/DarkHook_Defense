import math
import os
import re
from collections import Counter
from urllib.parse import urlparse
from uuid import uuid4

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter()

SUSPICIOUS_TLDS = {
	"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support", "zip", "country",
	"loan", "men", "review", "racing", "win", "bid", "download", "stream", "icu"
}

SUSPICIOUS_KEYWORDS = {
	"login", "verify", "secure", "account", "update", "bank", "wallet", "password", "signin", "confirm",
	"crypto", "bitcoin", "ethereum", "blockchain", "defi", "nft", "token",
	"trezor", "ledger", "metamask", "coinbase", "binance", "kraken", "exodus",
	"sso", "auth", "oauth", "api", "validation", "authenticate", "recovery"
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
	explanation: str = Field(..., description="Human-readable explanation of the analysis result")


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


def is_trusted_domain(url: str) -> bool:
	"""Check if URL belongs to a well-known trusted domain"""
	parsed = urlparse(url)
	host = (parsed.netloc or "").split(":")[0].lower()
	
	# Extract base domain (remove subdomains)
	parts = host.split(".")
	if len(parts) >= 2:
		base_domain = ".".join(parts[-2:])  # e.g., "google.com" from "accounts.google.com"
		return base_domain in TRUSTED_DOMAINS
	
	return host in TRUSTED_DOMAINS


def is_low_risk_legit_pattern(feature_map: dict, url: str) -> bool:
	"""Detect likely legitimate URLs to reduce ML-driven false positives."""
	parsed = urlparse(url)
	host = (parsed.netloc or "").split(":")[0].lower()

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
	# Remove TLD for analysis
	domain_name = domain.split('.')[0] if '.' in domain else domain
	decoded_domain = decode_leetspeak(domain_name)
	
	for brand in POPULAR_BRANDS:
		# Direct substring match
		if brand in domain_name or brand in decoded_domain:
			# Check if it's in a suspicious context (with hyphens, numbers, etc.)
			if '-' in domain_name or any(c.isdigit() for c in domain_name):
				return True, brand, 1.0
			# Check if brand is combined with phishing keywords
			if any(kw in url for kw in ['login', 'verify', 'secure', 'account', 'update', 'wallet']):
				return True, brand, 1.0
		
		# Fuzzy matching for typosquatting (e.g., "gooogle", "faceb00k")
		distance = levenshtein_distance(decoded_domain, brand)
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
	# Check for mixed character sets (e.g., Cyrillic 'а' looks like Latin 'a')
	has_latin = any('\u0041' <= c <= '\u007A' for c in domain)
	has_cyrillic = any('\u0400' <= c <= '\u04FF' for c in domain)
	has_greek = any('\u0370' <= c <= '\u03FF' for c in domain)
	
	# Mixed scripts in domain = potential homograph attack
	script_count = sum([has_latin, has_cyrillic, has_greek])
	if script_count > 1:
		return True
	
	# Check for confusing Unicode characters
	confusables = {
		'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',  # Cyrillic
		'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ο': 'o',  # Mixed
	}
	
	return any(char in domain for char in confusables.keys())


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


def extract_features(url: str) -> dict:
	"""Extract 31 features from URL matching the v2 trained model"""
	parsed = urlparse(url)
	domain = parsed.netloc.lower()
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
	features["has_ip"] = 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0
	features["has_port"] = 1 if ":" in domain.split(".")[-1] else 0
	
	# Domain analysis
	domain_tokens = domain.replace("-", " ").replace("_", " ").split(".")
	features["num_subdomains"] = len(domain_tokens) - 2 if len(domain_tokens) > 1 else 0
	
	# TLD analysis - now including commonly abused modern TLDs
	suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
	                  ".loan", ".men", ".review", ".racing", ".win", ".bid", ".download",
	                  ".stream", ".icu", ".club", ".info", ".online", ".site", ".website",
	                  ".space", ".tech", ".store", ".fun", ".live"}
	tld = "." + domain.split(".")[-1] if "." in domain else ""
	features["suspicious_tld"] = 1 if tld in suspicious_tlds else 0
	features["tld_is_country_code"] = 1 if (len(tld) == 3 and tld[1:].isalpha()) else 0
	
	# Keyword analysis - expanded with crypto and auth terms
	phishing_keywords = [
		"login", "signin", "account", "verify", "update", "secure", "banking",
		"paypal", "ebay", "amazon", "apple", "microsoft", "google", "confirm",
		"suspended", "locked", "unusual", "click", "urgent", "immediately",
		"password", "credential", "wallet", "crypto", "invest", "prize", "winner",
		"free", "bonus", "gift", "limited", "expire", "claim",
		"trezor", "ledger", "metamask", "coinbase", "binance", "kraken", "exodus",
		"blockchain", "bitcoin", "ethereum", "defi", "nft", "token", "swap",
		"sso", "auth", "oauth", "api", "validate", "authenticate", "recovery",
		"support", "help", "restore", "sync", "connect", "enable"
	]
	features["keyword_hits"] = sum(1 for kw in phishing_keywords if kw in full_url)
	
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
	
	free_hosting = ["repl.co", "herokuapp.com", "github.io", "blogspot.com", "wordpress.com",
	               "wix.com", "weebly.com", "000webhostapp.com", "pantheonsite.io",
	               "onedumb.com", "ddns.net", "duckdns.org", "pages.dev", "webflow.io",
	               "netlify.app", "vercel.app", "render.com", "fly.dev", "railway.app",
	               "glitch.me", "surge.sh", "web.app", "firebaseapp.com"]
	features["is_free_hosting"] = 1 if any(host in domain for host in free_hosting) else 0
	
	shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]
	features["is_shortener"] = 1 if any(short in domain for short in shorteners) else 0
	
	features["path_depth"] = path.count("/")
	features["has_suspicious_path"] = 1 if any(x in path for x in ["../", "//", "%", "script"]) else 0
	
	# Consecutive hyphen detection (-- or ---) - strong phishing indicator
	features["consecutive_hyphens"] = 1 if ("--" in domain or "---" in domain) else 0
	
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
	
	# Anomaly scoring
	features["anomaly_score"] = calculate_anomaly_score(features)
	
	# Urgency manipulation detection
	has_urgency, urgency_score = detect_urgency_manipulation(full_url)
	features["has_urgency_tactics"] = 1 if has_urgency else 0
	features["urgency_score"] = urgency_score / 100  # Normalize to 0-1
	
	return features


def build_flags(url: str, score: int, feature_map: dict) -> list[str]:
	parsed = urlparse(url)
	host = (parsed.netloc or "").lower()
	domain = ".".join(host.split(".")[-2:]) if "." in host else host
	path = parsed.path.lower()
	tld = host.split(".")[-1] if "." in host else ""

	flags: list[str] = []

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
		phishing_keywords_list = [
			"login", "signin", "account", "verify", "update", "secure", "banking",
			"paypal", "ebay", "amazon", "apple", "microsoft", "google", "confirm",
			"suspended", "locked", "unusual", "urgent", "password",
			"crypto", "wallet", "trezor", "ledger", "metamask", "coinbase", "binance",
			"blockchain", "bitcoin", "ethereum", "defi", "nft", "token",
			"sso", "auth", "oauth", "recovery"
		]
		detected_keywords = [kw for kw in phishing_keywords_list if kw in url.lower()]
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

	# If no specific flags but high score
	if not flags:
		if score >= 70:
			flags.append("🤖 ML Model Alert: Strong phishing pattern detected based on URL characteristics")
		elif score >= 45:
			flags.append("🤖 ML Model Warning: Suspicious URL characteristics detected")
		else:
			flags.append("✅ No major phishing indicators detected - URL appears legitimate")

	return flags


def compute_heuristic_score(feature_map: dict, url: str) -> int:
	score = 0
	
	parsed = urlparse(url)
	host = (parsed.netloc or "").lower()
	domain = ".".join(host.split(".")[-2:]) if "." in host else host  # Get base domain

	if feature_map["is_https"] == 0:
		score += 20
	if feature_map["has_ip"] == 1:
		score += 35
	if feature_map["suspicious_tld"] == 1:
		score += 28  # Increased from 18 - suspicious TLDs are strong indicator

	keyword_hits = int(feature_map["keyword_hits"])
	score += min(25, keyword_hits * 8)  # Increased multiplier for keywords
	
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
	
	# Brand impersonation with lookalike patterns or crypto brands
	if int(feature_map.get("has_lookalike", 0)) == 1:
		score += 35
	
	# Free hosting platforms commonly used for phishing
	if int(feature_map.get("is_free_hosting", 0)) == 1:
		score += 15

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

	return max(0, min(100, score))


def map_verdict(score: int) -> tuple[str, str]:
	if score >= 70:
		return "Phishing", "dangerous"
	if score >= 45:
		return "Suspicious", "suspicious"
	return "Safe", "safe"


# HuggingFace API Configuration
HF_API_URL = "https://cybersky4734-phising.hf.space/scan"


def call_hf_ml_service(url: str) -> dict:
	"""Call HuggingFace ML service for URL prediction with error handling."""
	try:
		response = requests.post(
			HF_API_URL,
			json={"url": url},
			timeout=60
		)
		response.raise_for_status()
		return response.json()
	except requests.exceptions.Timeout:
		return {"error": "ML service timeout - took longer than 60 seconds", "available": False}
	except requests.exceptions.ConnectionError:
		return {"error": "ML service unavailable - connection failed", "available": False}
	except requests.exceptions.RequestException as e:
		return {"error": f"ML service error: {str(e)}", "available": False}


@router.post("/url", response_model=URLAnalyzeResponse)
def analyze_url(payload: URLAnalyzeRequest):
	normalized = normalize_url(payload.url)
	if not normalized:
		raise HTTPException(status_code=400, detail="Invalid URL")

	try:
		feature_map = extract_features(normalized)
		heuristic_score = compute_heuristic_score(feature_map, normalized)
		
		# Call HuggingFace ML service for prediction
		ml_result = call_hf_ml_service(normalized)
		model_score = None
		ml_available = True
		ml_error_msg = None
		
		if "error" not in ml_result or ml_result.get("available", False):
			# Extract confidence/probability from HF response
			try:
				model_score = int(ml_result.get("prediction_score", heuristic_score))
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
		
		# Apply trusted domain override to avoid false positives
		if is_trusted_domain(normalized) and score >= 45:
			score = min(score, 30)  # Cap score below suspicious threshold for trusted domains
		elif is_low_risk_legit_pattern(feature_map, normalized) and score >= 70:
			score = min(score, 44)  # Prevent benign HTTPS URLs from being marked dangerous
		
		verdict, status = map_verdict(score)
		flags = build_flags(normalized, score, feature_map)

		# Enhanced feature summary with more context
		feature_summary = {
			"is_https": int(feature_map["is_https"]),
			"has_ip": int(feature_map["has_ip"]),
			"suspicious_tld": int(feature_map["suspicious_tld"]),
			"num_subdomains": int(feature_map["num_subdomains"]),
			"keyword_hits": int(feature_map["keyword_hits"]),
			"url_entropy": round(float(feature_map["url_entropy"]), 4),
			"url_length": int(feature_map["url_length"]),
			"has_typosquatting": int(feature_map.get("has_lookalike", 0)) or (1 if any(char.isdigit() for char in normalized.split("//")[1].split("/")[0].split(".")[0]) else 0),
			"is_shortener": int(feature_map.get("is_shortener", 0)),
			"is_free_hosting": int(feature_map.get("is_free_hosting", 0)),
			"has_port": int(feature_map.get("has_port", 0)),
			"consecutive_hyphens": int(feature_map.get("consecutive_hyphens", 0)),
			# Zero-day detection features
			"has_leetspeak": int(feature_map.get("has_leetspeak", 0)),
			"brand_impersonation": int(feature_map.get("brand_impersonation", 0)),
			"brand_similarity": round(float(feature_map.get("brand_similarity", 0)), 4),
			"has_homograph": int(feature_map.get("has_homograph", 0)),
			"anomaly_score": round(float(feature_map.get("anomaly_score", 0)), 4),
			"has_urgency_tactics": int(feature_map.get("has_urgency_tactics", 0)),
			"urgency_score": round(float(feature_map.get("urgency_score", 0)), 4),
		}
		
		# Generate explanation summary
		explanation = []
		if status == "dangerous":
			explanation.append(f"This URL scored {score}/100 indicating a HIGH RISK of phishing.")
			if feature_map["has_ip"] == 1:
				explanation.append("IP addresses are used by attackers to hide domain identity.")
			if feature_map["suspicious_tld"] == 1:
				explanation.append("The domain uses a TLD commonly associated with phishing campaigns.")
			if feature_map.get("has_lookalike", 0) == 1 or any(char.isdigit() for char in normalized.split("//")[1].split("/")[0].split(".")[0]):
				explanation.append("Domain name shows typosquatting patterns mimicking legitimate brands.")
			if int(feature_map.get("keyword_hits", 0)) >= 2:
				explanation.append("Multiple phishing-related keywords detected in URL.")
			# Zero-day detection explanations
			if int(feature_map.get("has_leetspeak", 0)) == 1:
				explanation.append("Leet-speak obfuscation detected - attackers using character substitution to evade filters.")
			if int(feature_map.get("brand_impersonation", 0)) == 1:
				explanation.append("Advanced brand impersonation detected using fuzzy matching techniques.")
			if int(feature_map.get("has_homograph", 0)) == 1:
				explanation.append("Homograph attack detected - Unicode characters mimicking legitimate domains.")
			if float(feature_map.get("anomaly_score", 0)) >= 0.6:
				explanation.append("Statistical anomalies indicate this URL significantly deviates from normal patterns.")
		elif status == "suspicious":
			explanation.append(f"This URL scored {score}/100 indicating MODERATE RISK.")
			explanation.append("Exercise caution and verify the source before interacting.")
		else:
			explanation.append(f"This URL scored {score}/100 indicating LOW RISK.")
			explanation.append("No major phishing indicators detected, but always verify the true sender.")

		# Add ML service status message if unavailable
		explanation_str = " ".join(explanation)
		if not ml_available:
			explanation_str += f" (ML service unavailable; heuristic engine used: {ml_error_msg})"

		return URLAnalyzeResponse(
			scan_id=str(uuid4()),
			url=normalized,
			score=score,
			confidence=round(score / 100, 4),
			verdict=verdict,
			status=status,
			flags=flags,
			feature_summary=feature_summary,
			explanation=explanation_str,
		)
	except HTTPException:
		raise
	except Exception as exc:
		raise HTTPException(status_code=500, detail=f"URL analysis failed: {exc}") from exc