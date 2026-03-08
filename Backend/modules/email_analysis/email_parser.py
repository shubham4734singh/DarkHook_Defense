from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import joblib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from .header_parser import analyze_headers


logger = logging.getLogger(__name__)


DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parents[2]
    / "ml"
    / "models"
    / "email_nb_model.pkl"
)
DEFAULT_VECTORIZER_PATH = (
    Path(__file__).resolve().parents[2]
    / "ml"
    / "models"
    / "email_vectorizer.pkl"
)


URGENCY_KEYWORDS: Sequence[str] = [
    "account",
    "action required",
    "alert",
    "approve",
    "attention",
    "confirm",
    "credentials",
    "disable",
    "dispute",
    "failed",
    "fraud",
    "immediately",
    "important",
    "invoice",
    "limited time",
    "login",
    "locked",
    "password",
    "payment",
    "pending",
    "promptly",
    "restore",
    "review",
    "risk",
    "secure",
    "security notice",
    "statement",
    "suspended",
    "unauthorized",
    "urgent",
    "verify",
    "warning",
]

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s'">)]+)""",
    re.IGNORECASE,
)

HTML_TAG_REGEX = re.compile(r"<[^>]+>")


class EmailAnalyzer:
    """
    Core orchestrator for DarkHook Defense email analysis.

    Responsibilities:
    - parse .eml into an EmailMessage
    - run header analysis
    - extract text / HTML bodies and attachments
    - extract URLs
    - compute keyword-based body risk score
    - score using the trained ML model
    - fuse signals into a final score and verdict
    """

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
        """
        Load the Naive Bayes model and TF-IDF vectorizer.

        If loading fails, the analyzer will gracefully fall back to heuristic-only
        scoring so that the system remains usable without trained artifacts.
        """
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
        except Exception as exc:  # noqa: BLE001
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
            # Under the default policy this should already be EmailMessage.
            message = EmailMessage(policy=policy.default)
        return message

    @staticmethod
    def _extract_bodies(message: EmailMessage) -> Tuple[str, str]:
        """
        Extract plain text and HTML bodies.

        Where only HTML is present, plain text is approximated by stripping tags.
        """
        text_body = ""
        html_body = ""

        # Policy-aware helpers can simplify multipart handling.
        try:
            text_part = message.get_body(preferencelist=("plain",))
            if text_part is not None:
                text_body = text_part.get_content() or ""

            html_part = message.get_body(preferencelist=("html",))
            if html_part is not None:
                html_body = html_part.get_content() or ""
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to use get_body helpers: %s", exc)

        # Fallback for older or unusual messages.
        if not text_body or not html_body:
            for part in message.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" and not text_body:
                    try:
                        text_body = part.get_content() or ""
                    except Exception:  # noqa: BLE001
                        continue
                elif content_type == "text/html" and not html_body:
                    try:
                        html_body = part.get_content() or ""
                    except Exception:  # noqa: BLE001
                        continue

        # If there is only HTML, derive a crude text version.
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
        """
        Compute keyword-based urgency score and per-body flags.

        Returns:
            (score_0_to_1, flags)
        """
        flags: List[str] = []

        normalized = text.lower()
        if not normalized.strip():
            return 0.0, flags

        total_words = max(1, len(re.findall(r"\b\w+\b", normalized)))
        keyword_hits = 0

        for keyword in URGENCY_KEYWORDS:
            # Treat multi-word phrases as sequences.
            pattern = re.escape(keyword.lower())
            hits = len(re.findall(pattern, normalized))
            keyword_hits += hits

        density = keyword_hits / total_words

        # Cap density contribution before scaling.
        score = min(1.0, density * 20.0)

        if score >= 0.5:
            flags.append("High density of urgency / security keywords in body text")
        elif score >= 0.2:
            flags.append("Moderate density of urgency / security keywords in body text")

        return score, flags

    def _ml_phishing_probability(self, text: str) -> float:
        """
        Return the model-estimated phishing probability in [0, 1].

        If the ML artifacts are not available, returns a neutral probability
        around 0.5 so that heuristic signals dominate the verdict.
        """
        if not self._ml_available or not self._model or not self._vectorizer:
            return 0.5

        try:
            features = self._vectorizer.transform([text])
            proba = getattr(self._model, "predict_proba", None)
            if proba is None:
                # Fall back to decision function if available, otherwise neutral.
                return 0.5

            probs = proba(features)[0]
            # Assume label 1 corresponds to phishing/spam.
            if len(probs) == 2:
                return float(probs[1])
            # Fallback: choose the highest probability if labels are encoded differently.
            return float(max(probs))
        except Exception as exc:  # noqa: BLE001
            logger.error("ML scoring error: %s", exc)
            return 0.5

    @staticmethod
    def _combine_scores(
        ml_proba: float,
        header_suspicious: bool,
        urgency_score: float,
        html_text_ratio: float,
    ) -> Tuple[int, str]:
        """
        Fuse ML and heuristic signals into a DarkHook Defense risk score.

        Heuristic design:
        - ML probability is the primary driver (60% weight)
        - header suspicion and urgency add structured boosts
        - very HTML-heavy messages with no plain text hint at obfuscation
        """
        header_component = 1.0 if header_suspicious else 0.0

        # Clip urgency to [0, 1].
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
        """
        End-to-end analysis of a single .eml file.

        Returns JSON-serializable structure:
            {
                "score": int (0-100),
                "verdict": "SAFE" | "SUSPICIOUS" | "PHISHING",
                "header_flags": List[str],
                "body_flags": List[str],
                "extracted_urls": List[str],
                "extracted_attachments": List[str],
            }
        """
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

        # Feed the plain text body (plus some HTML if needed) into the classifier.
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

        # Ensure the structure is JSON-serializable before returning.
        try:
            json.dumps(result)
        except TypeError as exc:
            logger.error("Serialization issue in EmailAnalyzer result: %s", exc)
            # If something is not serializable, coerce lists to plain lists of str.
            result["header_flags"] = [str(x) for x in header_flags]
            result["body_flags"] = [str(x) for x in body_flags]

        return result

