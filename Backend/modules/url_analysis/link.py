import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter()

SUSPICIOUS_TLDS = {
	"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support", "zip", "country"
}

SUSPICIOUS_KEYWORDS = {
	"login", "verify", "secure", "account", "update", "bank", "wallet", "password", "signin", "confirm"
}

# Well-known legitimate domains to avoid false positives
TRUSTED_DOMAINS = {
	"google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
	"netflix.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "reddit.com",
	"wikipedia.org", "github.com", "stackoverflow.com", "adobe.com", "paypal.com", "ebay.com",
	"yahoo.com", "live.com", "outlook.com", "office.com", "dropbox.com", "zoom.us",
	"salesforce.com", "slack.com", "wordpress.com", "shopify.com", "stripe.com",
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
	host = (parsed.netloc or "").lower()
	
	# Extract base domain (remove subdomains)
	parts = host.split(".")
	if len(parts) >= 2:
		base_domain = ".".join(parts[-2:])  # e.g., "google.com" from "accounts.google.com"
		return base_domain in TRUSTED_DOMAINS
	
	return host in TRUSTED_DOMAINS


def extract_features(url: str) -> tuple[pd.DataFrame, dict]:
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
	
	# TLD analysis
	suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
	                  ".loan", ".men", ".review", ".racing", ".win", ".bid", ".download",
	                  ".stream", ".icu", ".club", ".info"}
	tld = "." + domain.split(".")[-1] if "." in domain else ""
	features["suspicious_tld"] = 1 if tld in suspicious_tlds else 0
	features["tld_is_country_code"] = 1 if (len(tld) == 3 and tld[1:].isalpha()) else 0
	
	# Keyword analysis
	phishing_keywords = [
		"login", "signin", "account", "verify", "update", "secure", "banking",
		"paypal", "ebay", "amazon", "apple", "microsoft", "google", "confirm",
		"suspended", "locked", "unusual", "click", "urgent", "immediately",
		"password", "credential", "wallet", "crypto", "invest", "prize", "winner",
		"free", "bonus", "gift", "limited", "expire", "claim"
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
	
	# Advanced heuristics
	lookalike_patterns = ["pa.ypal", "g00gle", "micros0ft", "yah00", "netfl1x", "amaz0n"]
	features["has_lookalike"] = 1 if any(pattern in full_url for pattern in lookalike_patterns) else 0
	
	free_hosting = ["repl.co", "herokuapp.com", "github.io", "blogspot.com", "wordpress.com",
	               "wix.com", "weebly.com", "000webhostapp.com", "pantheonsite.io",
	               "onedumb.com", "ddns.net", "duckdns.org"]
	features["is_free_hosting"] = 1 if any(host in domain for host in free_hosting) else 0
	
	shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]
	features["is_shortener"] = 1 if any(short in domain for short in shorteners) else 0
	
	features["path_depth"] = path.count("/")
	features["has_suspicious_path"] = 1 if any(x in path for x in ["../", "//", "%", "script"]) else 0
	
	feature_frame = pd.DataFrame([features])
	return feature_frame, features


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
	
	# Typosquatting detection
	if feature_map.get("has_lookalike", 0) == 1:
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
		flags.append("📦 Free hosting platform detected - Often abused for temporary phishing sites")
	
	# Keyword analysis
	keyword_hits = int(feature_map.get("keyword_hits", 0))
	if keyword_hits > 0:
		phishing_keywords_list = [
			"login", "signin", "account", "verify", "update", "secure", "banking",
			"paypal", "ebay", "amazon", "apple", "microsoft", "google", "confirm",
			"suspended", "locked", "unusual", "urgent", "password"
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
	
	# Hyphen abuse
	if domain.count("-") >= 2:
		flags.append(f"⚠️ Multiple hyphens in domain ({domain.count('-')}) - Common in fake domains mimicking brands")

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

	if feature_map["url_entropy"] >= 4.5:
		score += 10
	if feature_map["num_subdomains"] >= 3:
		score += 10
	if feature_map["url_length"] >= 90:
		score += 7

	return max(0, min(100, score))


def map_verdict(score: int) -> tuple[str, str]:
	if score >= 70:
		return "Phishing", "dangerous"
	if score >= 45:
		return "Suspicious", "suspicious"
	return "Safe", "safe"


@lru_cache(maxsize=1)
def load_url_model():
	backend_root = Path(__file__).resolve().parents[2]
	preferred = backend_root / "ml" / "models" / "url_xgb_model_v2.pkl"
	fallback = backend_root / "ml" / "models" / "url_rf_model_v2.pkl"

	model_path = preferred if preferred.exists() else fallback
	if not model_path.exists():
		raise FileNotFoundError(
			"No trained URL model found. Expected one of: "
			f"{preferred} or {fallback}. Train model first using ml/train_link_model_v2.py"
		)

	return pd.read_pickle(model_path)


@router.post("/url", response_model=URLAnalyzeResponse)
def analyze_url(payload: URLAnalyzeRequest):
	normalized = normalize_url(payload.url)
	if not normalized:
		raise HTTPException(status_code=400, detail="Invalid URL")

	try:
		model = load_url_model()
	except FileNotFoundError as exc:
		raise HTTPException(status_code=500, detail=str(exc)) from exc
	except Exception as exc:
		raise HTTPException(status_code=500, detail=f"Failed to load model: {exc}") from exc

	try:
		features_df, feature_map = extract_features(normalized)

		if hasattr(model, "predict_proba"):
			probability = float(model.predict_proba(features_df)[0][1])
		else:
			prediction = int(model.predict(features_df)[0])
			probability = 0.99 if prediction == 1 else 0.01

		model_score = max(0, min(100, int(round(probability * 100))))
		heuristic_score = compute_heuristic_score(feature_map, normalized)
		score = max(model_score, heuristic_score)
		
		# Apply trusted domain override to avoid false positives
		if is_trusted_domain(normalized) and score >= 45:
			score = min(score, 30)  # Cap score below suspicious threshold for trusted domains
		
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
		elif status == "suspicious":
			explanation.append(f"This URL scored {score}/100 indicating MODERATE RISK.")
			explanation.append("Exercise caution and verify the source before interacting.")
		else:
			explanation.append(f"This URL scored {score}/100 indicating LOW RISK.")
			explanation.append("No major phishing indicators detected, but always verify the true sender.")

		return URLAnalyzeResponse(
			scan_id=str(uuid4()),
			url=normalized,
			score=score,
			confidence=round(score / 100, 4),
			verdict=verdict,
			status=status,
			flags=flags,
			feature_summary=feature_summary,
			explanation=" ".join(explanation),
		)
	except HTTPException:
		raise
	except Exception as exc:
		raise HTTPException(status_code=500, detail=f"URL analysis failed: {exc}") from exc