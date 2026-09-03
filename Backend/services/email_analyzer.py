from __future__ import annotations

import io
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from urllib.parse import urlparse
import joblib

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency guard
    _BS4_AVAILABLE = False

try:
    from oletools.olevba import VBA_Parser
    _OLETOOLS_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency guard
    _OLETOOLS_AVAILABLE = False

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

def _levenshtein_distance(a: str, b: str) -> int:
    """Standard edit distance (insertions, deletions, substitutions)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i] + [0] * len(b)
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current_row[j] = min(
                previous_row[j] + 1,       # deletion
                current_row[j - 1] + 1,    # insertion
                previous_row[j - 1] + cost,  # substitution
            )
        previous_row = current_row
    return previous_row[len(b)]


def _domain_edit_distance_flag(domain: str, trusted_domains: List[str]) -> Optional[str]:
    """Flag domains that are suspiciously close (typosquats/homographs) to a trusted domain
    without being an exact match or legitimate subdomain.

    Compares only the core label (before the first dot) of each domain using true edit
    distance, with a threshold scaled to the trusted brand's name length. This avoids
    false positives between short, unrelated words that merely happen to be the same
    length (e.g. 'chess' vs 'chase') while still catching classic typosquats like
    'micros0ft' vs 'microsoft' or 'paypa1' vs 'paypal'.
    """
    if not domain:
        return None

    for trusted in trusted_domains:
        trusted_l = trusted.lower()
        if domain == trusted_l or domain.endswith("." + trusted_l):
            return None  # exact match or legitimate subdomain, not a typosquat

    core_domain = domain.split(".")[0]
    best_trusted: Optional[str] = None
    best_distance: Optional[int] = None

    for trusted in trusted_domains:
        trusted_l = trusted.lower()
        if trusted_l.startswith("."):
            continue
        core_trusted = trusted_l.split(".")[0]

        # Very short brand names (e.g. generic words) are too easy to collide with
        # unrelated domains by chance; skip them to avoid false positives.
        if len(core_trusted) < 5:
            continue

        distance = _levenshtein_distance(core_domain, core_trusted)
        # A single-character typo/substitution is the classic typosquat signature.
        # Only allow 2 edits for longer brand names, where coincidental collisions
        # with an unrelated word are far less likely.
        threshold = 1 if len(core_trusted) <= 10 else 2

        if 0 < distance <= threshold and (best_distance is None or distance < best_distance):
            best_distance = distance
            best_trusted = trusted_l

    if best_trusted:
        return (
            f"Sender domain '{domain}' closely resembles trusted domain "
            f"'{best_trusted}' (possible typosquat, edit distance {best_distance})"
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


def _detect_typosquatting(message: Message) -> Optional[str]:
    """Detect sender domains that are a close-but-not-exact match to a known trusted domain,
    regardless of what the display name says (catches silent typosquats)."""
    from_header = message.get("From", "")
    if not from_header:
        return None

    domain = _extract_domain(from_header) or ""
    if not domain:
        return None

    for _, trusted_domains in BRAND_KEYWORDS.items():
        clean_trusted = [d for d in trusted_domains if not d.startswith(".")]
        flag = _domain_edit_distance_flag(domain, clean_trusted)
        if flag:
            return flag
    return None


def _detect_envelope_from_mismatch(message: Message) -> Optional[str]:
    """Check for mismatch between the visible From header and the envelope sender
    (Return-Path), a common spoofing technique."""
    return_path_addrs = getaddresses(message.get_all("Return-Path", []))
    from_addrs = getaddresses(message.get_all("From", []))

    if not return_path_addrs or not from_addrs:
        return None

    _, return_path_addr = return_path_addrs[0]
    _, from_addr = from_addrs[0]

    return_path_domain = _extract_domain(return_path_addr)
    from_domain = _extract_domain(from_addr)

    if not return_path_domain or not from_domain:
        return None

    if return_path_domain != from_domain and not (
        return_path_domain.endswith("." + from_domain)
        or from_domain.endswith("." + return_path_domain)
    ):
        return (
            "Envelope sender (Return-Path) domain "
            f"'{return_path_domain}' does not match From domain '{from_domain}'"
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

    typosquat_flag = _detect_typosquatting(message)
    if typosquat_flag:
        header_flags.append(typosquat_flag)

    envelope_flag = _detect_envelope_from_mismatch(message)
    if envelope_flag:
        header_flags.append(envelope_flag)

    is_suspicious = bool(
        auth_suspicious or spoof_flag or display_flag or typosquat_flag or envelope_flag
    )

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

DANGEROUS_ATTACHMENT_EXTS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".jar",
    ".bat", ".cmd", ".ps1", ".msi", ".wsf", ".com", ".pif",
}

MACRO_ENABLED_EXTS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"}

SUSPICIOUS_VBA_KEYWORDS = (
    "auto_open", "autoopen", "autoexec", "autoclose", "document_open",
    "shell", "wscript.shell", "createobject", "powershell",
)


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
    def _url_domain(value: str) -> Optional[str]:
        """Best-effort extraction of a bare domain from a URL or a bit of link text."""
        if not value:
            return None
        candidate = value.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", candidate):
            candidate = "http://" + candidate
        try:
            netloc = urlparse(candidate).netloc.lower()
        except Exception:
            return None
        netloc = netloc.split("@")[-1]  # strip any userinfo
        netloc = netloc.split(":")[0]  # strip port
        return netloc or None

    def _detect_link_mismatches(self, html_body: str) -> List[str]:
        """Flag anchor tags whose visible text names a different domain than the actual href
        (classic phishing lure: link text shows a trusted brand, href points elsewhere)."""
        flags: List[str] = []
        if not html_body or not _BS4_AVAILABLE:
            return flags

        try:
            soup = BeautifulSoup(html_body, "html.parser")
        except Exception as exc:
            logger.warning("Failed to parse HTML body for link-mismatch check: %s", exc)
            return flags

        seen: set[Tuple[str, str]] = set()
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            visible_text = anchor.get_text(strip=True)

            href_domain = self._url_domain(href)
            # Only compare when the visible text itself looks like a domain/URL,
            # otherwise "Click here" style text would false-positive on everything.
            looks_like_domain = bool(re.search(r"[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", visible_text))
            if not looks_like_domain:
                continue

            visible_domain = self._url_domain(visible_text)
            if not href_domain or not visible_domain:
                continue

            if visible_domain != href_domain and (visible_domain, href_domain) not in seen:
                seen.add((visible_domain, href_domain))
                flags.append(
                    f"Link text shows '{visible_domain}' but actually points to '{href_domain}'"
                )
        return flags

    @staticmethod
    def _score_attachment_risk(filename: str, content_bytes: Optional[bytes]) -> List[str]:
        """Flag dangerous file types, double extensions, and macro-enabled Office documents."""
        flags: List[str] = []
        if not filename:
            return flags

        lower_name = filename.lower()
        name_parts = lower_name.split(".")
        suffix = "." + name_parts[-1] if len(name_parts) > 1 else ""

        if suffix in DANGEROUS_ATTACHMENT_EXTS:
            flags.append(f"Dangerous attachment type: '{filename}'")

        if len(name_parts) > 2 and ("." + name_parts[-2]) in {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt",
        }:
            flags.append(f"Attachment has a suspicious double extension: '{filename}'")

        if suffix in MACRO_ENABLED_EXTS and content_bytes:
            if not _OLETOOLS_AVAILABLE:
                flags.append(
                    f"Macro-capable attachment '{filename}' could not be scanned "
                    "(oletools not installed)"
                )
            else:
                try:
                    vba_parser = VBA_Parser(filename, data=content_bytes)
                    if vba_parser.detect_vba_macros():
                        combined_code = ""
                        for (_, _, _, vba_code) in vba_parser.extract_macros():
                            combined_code += (vba_code or "").lower()
                        hits = [
                            kw for kw in SUSPICIOUS_VBA_KEYWORDS if kw in combined_code
                        ]
                        if hits:
                            flags.append(
                                f"Attachment '{filename}' contains macros with suspicious "
                                f"calls: {', '.join(sorted(set(hits)))}"
                            )
                        else:
                            flags.append(f"Attachment '{filename}' contains macros")
                    vba_parser.close()
                except Exception as exc:
                    logger.warning("oletools scan failed for %s: %s", filename, exc)

        return flags

    @staticmethod
    def _extract_attachments(message: EmailMessage) -> List[str]:
        """Return a list of attachment filenames."""
        attachments: List[str] = []
        for part in message.iter_attachments():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
        return attachments

    def _extract_and_score_attachments(
        self, message: EmailMessage
    ) -> Tuple[List[str], List[str]]:
        """Return (filenames, risk_flags) for all attachments on the message."""
        filenames: List[str] = []
        risk_flags: List[str] = []
        for part in message.iter_attachments():
            filename = part.get_filename()
            if not filename:
                continue
            filenames.append(filename)
            try:
                content_bytes = part.get_payload(decode=True)
            except Exception:
                content_bytes = None
            risk_flags.extend(self._score_attachment_risk(filename, content_bytes))
        return filenames, risk_flags

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
        link_mismatch_count: int = 0,
        attachment_risk_count: int = 0,
    ) -> Tuple[int, str]:
        """Fuse ML and heuristic signals into a risk score."""
        header_component = 1.0 if header_suspicious else 0.0
        urgency_component = max(0.0, min(1.0, urgency_score))

        html_component = 0.0
        if html_text_ratio == float("inf") or html_text_ratio > 3.0:
            html_component = 1.0
        elif html_text_ratio > 1.5:
            html_component = 0.5

        link_component = min(1.0, link_mismatch_count * 0.5)
        attachment_component = min(1.0, attachment_risk_count * 0.5)

        combined = (
            0.5 * ml_proba
            + 0.15 * header_component
            + 0.1 * urgency_component
            + 0.05 * html_component
            + 0.1 * link_component
            + 0.1 * attachment_component
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
        attachments, attachment_risk_flags = self._extract_and_score_attachments(message)

        urgency_score, urgency_flags = self._compute_urgency_score(text_body)
        body_flags: List[str] = list(urgency_flags)

        if html_text_ratio == float("inf"):
            body_flags.append("HTML-only message with no plain text body")
        elif html_text_ratio > 3.0:
            body_flags.append("Unusually high HTML-to-text ratio")

        link_mismatch_flags = self._detect_link_mismatches(html_body)
        body_flags.extend(link_mismatch_flags)
        body_flags.extend(attachment_risk_flags)

        model_input_text = text_body or HTML_TAG_REGEX.sub(" ", html_body)
        ml_proba = self._ml_phishing_probability(model_input_text)

        score, verdict = self._combine_scores(
            ml_proba=ml_proba,
            header_suspicious=header_suspicious,
            urgency_score=urgency_score,
            html_text_ratio=html_text_ratio,
            link_mismatch_count=len(link_mismatch_flags),
            attachment_risk_count=len(attachment_risk_flags),
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