from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
import joblib

logger = logging.getLogger(__name__)

# ============================================================
# HEADER PARSER LOGIC
# ============================================================

BRAND_KEYWORDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "gov": [".gov"],
}

AUTH_RESULT_PATTERN = re.compile(
    r"(spf|dkim|dmarc)=(pass|fail|none|neutral|softfail|temperror|permerror)",
    re.IGNORECASE,
)

def _extract_domain(email_address: str) -> Optional[str]:
    """Return the domain part of an email address if available."""
    if not email_address:
        return None
    _, addr = parseaddr(email_address)
    if "@" not in addr:
        return None
    return addr.split("@", 1)[1].lower()

def _extract_display_name(email_address: str) -> str:
    """Return the display name component from an email address."""
    display_name, addr = parseaddr(email_address)
    if display_name:
        return display_name.strip()
    if "@" in addr:
        return addr.split("@", 1)[0]
    return addr or ""

def _parse_authentication_results(headers: List[str]) -> Dict[str, str]:
    """Parse Authentication-Results headers for SPF/DKIM/DMARC result tokens."""
    result: Dict[str, str] = {}
    combined = " ".join(headers)
    if not combined:
        return result
    for mech, status in AUTH_RESULT_PATTERN.findall(combined):
        mech_l = mech.lower()
        status_l = status.lower()
        if mech_l not in result:
            result[mech_l] = status_l
    return result

def _parse_received_spf(headers: List[str]) -> Optional[str]:
    """Very lightweight parser for Received-SPF headers."""
    if not headers:
        return None
    header_value = " ".join(headers)
    match = re.search(
        r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        header_value,
        flags=re.IGNORECASE,
    )
    if match:
        return match.group(1).lower()
    return None

def _evaluate_authentication_status(
    spf_status: Optional[str],
    dkim_status: Optional[str],
    dmarc_status: Optional[str],
) -> Tuple[bool, List[str]]:
    """Convert SPF/DKIM/DMARC statuses into flags and an overall suspicion signal."""
    flags: List[str] = []
    suspicious = False

    def add_flag(label: str, status: Optional[str]) -> None:
        nonlocal suspicious
        if status is None:
            flags.append(f"{label} result missing")
            suspicious = True
            return

        normalized = status.lower()
        if normalized in {"fail", "softfail", "permerror", "temperror"}:
            flags.append(f"{label} check {normalized}")
            suspicious = True
        elif normalized in {"neutral", "none"}:
            flags.append(f"{label} result inconclusive ({normalized})")
        elif normalized == "pass":
            return
        else:
            flags.append(f"{label} status {normalized}")

    add_flag("SPF", spf_status)
    add_flag("DKIM", dkim_status)
    add_flag("DMARC", dmarc_status)

    return suspicious, flags

def _detect_reply_to_spoofing(message: Message) -> Optional[str]:
    """Check for sender spoofing via mismatched From / Reply-To domains."""
    from_addrs = getaddresses(message.get_all("From", []))
    reply_to_addrs = getaddresses(message.get_all("Reply-To", []))

    if not from_addrs or not reply_to_addrs:
        return None

    _, from_addr = from_addrs[0]
    _, reply_addr = reply_to_addrs[0]

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_addr)

    if from_domain and reply_domain and from_domain != reply_domain:
        return (
            "From / Reply-To domain mismatch "
            f"(from: {from_domain}, reply-to: {reply_domain})"
        )
    return None

def _detect_display_name_mismatch(message: Message) -> Optional[str]:
    """Detect branding misuse where the display name suggests a trusted brand but underlying domain is unrelated."""
    from_header = message.get("From", "")
    if not from_header:
        return None

    display_name = _extract_display_name(from_header).lower()
    domain = _extract_domain(from_header) or ""

    if not display_name or not domain:
        return None

    for brand_keyword, trusted_domains in BRAND_KEYWORDS.items():
        if brand_keyword in display_name:
            aligned = any(trusted.lower() in domain for trusted in trusted_domains)
            if not aligned:
                return (
                    "Display name suggests trusted brand "
                    f"('{display_name}') but sender domain is '{domain}'"
                )
    return None

def analyze_headers(message: Message) -> Dict[str, Any]:
    """Perform header-level analysis for email inspection."""
    header_flags: List[str] = []

    auth_headers = message.get_all("Authentication-Results", []) or []
    auth_results = _parse_authentication_results(auth_headers)

    spf_status: Optional[str] = auth_results.get("spf")
    dkim_status: Optional[str] = auth_results.get("dkim")
    dmarc_status: Optional[str] = auth_results.get("dmarc")

    if spf_status is None:
        received_spf_headers = message.get_all("Received-SPF", []) or []
        spf_status = _parse_received_spf(received_spf_headers)

    auth_suspicious, auth_flags = _evaluate_authentication_status(
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
    )
    header_flags.extend(auth_flags)

    spoof_flag = _detect_reply_to_spoofing(message)
    if spoof_flag:
        header_flags.append(spoof_flag)

    display_flag = _detect_display_name_mismatch(message)
    if display_flag:
        header_flags.append(display_flag)

    is_suspicious = bool(auth_suspicious or spoof_flag or display_flag)

    return {
        "is_suspicious": is_suspicious,
        "header_flags": header_flags,
    }


# ============================================================
# CORE EMAIL ANALYZER LOGIC
# ============================================================

DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parents[1]
    / "ml"
    / "models"
    / "email_nb_model.pkl"
)
DEFAULT_VECTORIZER_PATH = (
    Path(__file__).resolve().parents[1]
    / "ml"
    / "models"
    / "email_vectorizer.pkl"
)

URGENCY_KEYWORDS: Sequence[str] = [
    "account", "action required", "alert", "approve", "attention", "confirm",
    "credentials", "disable", "dispute", "failed", "fraud", "immediately",
    "important", "invoice", "limited time", "login", "locked", "password",
    "payment", "pending", "promptly", "restore", "review", "risk", "secure",
    "security notice", "statement", "suspended", "unauthorized", "urgent",
    "verify", "warning",
]

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s'">)]+)""",
    re.IGNORECASE,
)

HTML_TAG_REGEX = re.compile(r"<[^>]+>")


class EmailAnalyzer:
    """Core orchestrator for DarkHook Defense email analysis."""

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        vectorizer_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.vectorizer_path = (
            Path(vectorizer_path) if vectorizer_path else DEFAULT_VECTORIZER_PATH
        )

        self._model = None
        self._vectorizer = None
        self._ml_available = False

        self._load_ml_artifacts()

    def _load_ml_artifacts(self) -> None:
        """Load the Naive Bayes model and TF-IDF vectorizer."""
        try:
            if self.model_path.exists() and self.vectorizer_path.exists():
                self._model = joblib.load(self.model_path)
                self._vectorizer = joblib.load(self.vectorizer_path)
                self._ml_available = True
                logger.info(
                    "Loaded email ML model from %s and vectorizer from %s",
                    self.model_path,
                    self.vectorizer_path,
                )
            else:
                logger.warning(
                    "Email ML artifacts not found at %s and %s; "
                    "falling back to heuristic-only scoring.",
                    self.model_path,
                    self.vectorizer_path,
                )
        except Exception as exc:
            logger.error("Failed to load ML artifacts: %s", exc)
            self._ml_available = False

    @staticmethod
    def _parse_eml(file_path: Union[str, Path]) -> EmailMessage:
        """Parse an .eml file into an EmailMessage object."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"EML file not found: {path}")

        with path.open("rb") as f:
            parser = BytesParser(policy=policy.default)
            message = parser.parse(f)

        if not isinstance(message, EmailMessage):
            message = EmailMessage(policy=policy.default)
        return message

    @staticmethod
    def _extract_bodies(message: EmailMessage) -> Tuple[str, str]:
        """Extract plain text and HTML bodies."""
        text_body = ""
        html_body = ""

        try:
            text_part = message.get_body(preferencelist=("plain",))
            if text_part is not None:
                text_body = text_part.get_content() or ""

            html_part = message.get_body(preferencelist=("html",))
            if html_part is not None:
                html_body = html_part.get_content() or ""
        except Exception as exc:
            logger.warning("Failed to use get_body helpers: %s", exc)

        if not text_body or not html_body:
            for part in message.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" and not text_body:
                    try:
                        text_body = part.get_content() or ""
                    except Exception:
                        continue
                elif content_type == "text/html" and not html_body:
                    try:
                        html_body = part.get_content() or ""
                    except Exception:
                        continue

        if not text_body and html_body:
            text_body = HTML_TAG_REGEX.sub(" ", html_body)

        return text_body, html_body

    @staticmethod
    def _extract_urls(*bodies: str) -> List[str]:
        """Extract unique URLs from the provided body strings."""
        seen: set[str] = set()
        urls: List[str] = []

        for body in bodies:
            if not body:
                continue
            for match in URL_REGEX.findall(body):
                url = match.strip().rstrip(").,;")
                if url and url not in seen:
                    seen.add(url)
                    urls.append(url)
        return urls

    @staticmethod
    def _extract_attachments(message: EmailMessage) -> List[str]:
        """Return a list of attachment filenames."""
        attachments: List[str] = []
        for part in message.iter_attachments():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
        return attachments

    @staticmethod
    def _compute_html_text_ratio(text_body: str, html_body: str) -> float:
        """Approximate the HTML-to-text ratio to catch HTML-heavy lures."""
        text_len = len(text_body.strip())
        html_len = len(html_body.strip())
        if text_len == 0:
            return float("inf") if html_len > 0 else 0.0
        return html_len / max(1, text_len)

    @staticmethod
    def _compute_urgency_score(text: str) -> Tuple[float, List[str]]:
        """Compute keyword-based urgency score and per-body flags."""
        flags: List[str] = []
        normalized = text.lower()
        if not normalized.strip():
            return 0.0, flags

        total_words = max(1, len(re.findall(r"\b\w+\b", normalized)))
        keyword_hits = 0

        for keyword in URGENCY_KEYWORDS:
            pattern = re.escape(keyword.lower())
            hits = len(re.findall(pattern, normalized))
            keyword_hits += hits

        density = keyword_hits / total_words
        score = min(1.0, density * 20.0)

        if score >= 0.5:
            flags.append("High density of urgency / security keywords in body text")
        elif score >= 0.2:
            flags.append("Moderate density of urgency / security keywords in body text")

        return score, flags

    def _ml_phishing_probability(self, text: str) -> float:
        """Return the model-estimated phishing probability in [0, 1]."""
        if not self._ml_available or not self._model or not self._vectorizer:
            return 0.5

        try:
            features = self._vectorizer.transform([text])
            proba = getattr(self._model, "predict_proba", None)
            if proba is None:
                return 0.5

            probs = proba(features)[0]
            if len(probs) == 2:
                return float(probs[1])
            return float(max(probs))
        except Exception as exc:
            logger.error("ML scoring error: %s", exc)
            return 0.5

    @staticmethod
    def _combine_scores(
        ml_proba: float,
        header_suspicious: bool,
        urgency_score: float,
        html_text_ratio: float,
    ) -> Tuple[int, str]:
        """Fuse ML and heuristic signals into a risk score."""
        header_component = 1.0 if header_suspicious else 0.0
        urgency_component = max(0.0, min(1.0, urgency_score))

        html_component = 0.0
        if html_text_ratio == float("inf") or html_text_ratio > 3.0:
            html_component = 1.0
        elif html_text_ratio > 1.5:
            html_component = 0.5

        combined = (
            0.6 * ml_proba
            + 0.2 * header_component
            + 0.15 * urgency_component
            + 0.05 * html_component
        )
        score = int(round(max(0.0, min(1.0, combined)) * 100))

        if score >= 70:
            verdict = "PHISHING"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        return score, verdict

    def analyze(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """End-to-end analysis of a single .eml file."""
        message = self._parse_eml(file_path)

        header_result = analyze_headers(message)
        header_flags: List[str] = header_result.get("header_flags", [])
        header_suspicious: bool = bool(header_result.get("is_suspicious", False))

        text_body, html_body = self._extract_bodies(message)
        html_text_ratio = self._compute_html_text_ratio(text_body, html_body)

        extracted_urls = self._extract_urls(text_body, html_body)
        attachments = self._extract_attachments(message)

        urgency_score, urgency_flags = self._compute_urgency_score(text_body)
        body_flags: List[str] = list(urgency_flags)

        if html_text_ratio == float("inf"):
            body_flags.append("HTML-only message with no plain text body")
        elif html_text_ratio > 3.0:
            body_flags.append("Unusually high HTML-to-text ratio")

        model_input_text = text_body or HTML_TAG_REGEX.sub(" ", html_body)
        ml_proba = self._ml_phishing_probability(model_input_text)

        score, verdict = self._combine_scores(
            ml_proba=ml_proba,
            header_suspicious=header_suspicious,
            urgency_score=urgency_score,
            html_text_ratio=html_text_ratio,
        )

        result: Dict[str, Any] = {
            "score": score,
            "verdict": verdict,
            "header_flags": header_flags,
            "body_flags": body_flags,
            "extracted_urls": extracted_urls,
            "extracted_attachments": attachments,
        }

        try:
            json.dumps(result)
        except TypeError as exc:
            logger.error("Serialization issue in EmailAnalyzer result: %s", exc)
            result["header_flags"] = [str(x) for x in header_flags]
            result["body_flags"] = [str(x) for x in body_flags]

        return result

email_analyzer = EmailAnalyzer()
