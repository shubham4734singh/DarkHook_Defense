from __future__ import annotations

import logging
import re
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Brand keywords are used to detect suspicious display-name/domain combinations.
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
    # Fallback: sometimes the local part is used as display name.
    if "@" in addr:
        return addr.split("@", 1)[0]
    return addr or ""


def _parse_authentication_results(headers: List[str]) -> Dict[str, str]:
    """
    Parse Authentication-Results headers for SPF/DKIM/DMARC result tokens.

    This relies on the MTA already performing DNS-based checks and recording the
    outcome in Authentication-Results. DarkHook Defense does not reach out to
    external DNS services here.
    """
    result: Dict[str, str] = {}
    combined = " ".join(headers)
    if not combined:
        return result

    for mech, status in AUTH_RESULT_PATTERN.findall(combined):
        mech_l = mech.lower()
        status_l = status.lower()
        # Prefer the first decisive result we see.
        if mech_l not in result:
            result[mech_l] = status_l
    return result


def _parse_received_spf(headers: List[str]) -> Optional[str]:
    """
    Very lightweight parser for Received-SPF headers.

    Examples:
        Received-SPF: pass (google.com: domain of example@gmail.com designates ...)
        Received-SPF: fail (example.com: domain of ...)
    """
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
    """
    Convert SPF/DKIM/DMARC statuses into flags and an overall suspicion signal.
    """
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
            # Passing auth alone is not a guarantee of safety, so no flag.
            return
        else:
            flags.append(f"{label} status {normalized}")

    add_flag("SPF", spf_status)
    add_flag("DKIM", dkim_status)
    add_flag("DMARC", dmarc_status)

    return suspicious, flags


def _detect_reply_to_spoofing(message: Message) -> Optional[str]:
    """
    Check for sender spoofing via mismatched From / Reply-To domains.

    Mismatches do not always indicate phishing (newsletters, ticketing systems),
    but they often correlate with credential-harvesting campaigns.
    """
    from_addrs = getaddresses(message.get_all("From", []))
    reply_to_addrs = getaddresses(message.get_all("Reply-To", []))

    if not from_addrs or not reply_to_addrs:
        return None

    # Use the first address in each header.
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
    """
    Detect branding misuse where the display name suggests a trusted brand but
    the underlying domain is unrelated.
    """
    from_header = message.get("From", "")
    if not from_header:
        return None

    display_name = _extract_display_name(from_header).lower()
    domain = _extract_domain(from_header) or ""

    if not display_name or not domain:
        return None

    for brand_keyword, trusted_domains in BRAND_KEYWORDS.items():
        if brand_keyword in display_name:
            # If any trusted domain substring appears in the domain, treat it as aligned.
            aligned = any(trusted.lower() in domain for trusted in trusted_domains)
            if not aligned:
                return (
                    "Display name suggests trusted brand "
                    f"('{display_name}') but sender domain is '{domain}'"
                )
    return None


def analyze_headers(message: Message) -> Dict[str, Any]:
    """
    Perform header-level analysis for DarkHook Defense email inspection.

    Returns a dictionary:
        {
            "is_suspicious": bool,
            "header_flags": List[str],
        }
    """
    header_flags: List[str] = []

    # Parse authentication results recorded by the upstream MTA.
    auth_headers = message.get_all("Authentication-Results", []) or []
    auth_results = _parse_authentication_results(auth_headers)

    spf_status: Optional[str] = auth_results.get("spf")
    dkim_status: Optional[str] = auth_results.get("dkim")
    dmarc_status: Optional[str] = auth_results.get("dmarc")

    # Fallback to Received-SPF for SPF information if Authentication-Results is absent.
    if spf_status is None:
        received_spf_headers = message.get_all("Received-SPF", []) or []
        spf_status = _parse_received_spf(received_spf_headers)

    auth_suspicious, auth_flags = _evaluate_authentication_status(
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
    )
    header_flags.extend(auth_flags)

    # Spoofing / impersonation style checks.
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

