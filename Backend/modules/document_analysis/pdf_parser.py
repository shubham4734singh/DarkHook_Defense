# ================================================================
# pdf_parser.py — DarkHOOK_ Defence
# Version  : 2.0 Advanced
# Purpose  : Industry-grade PDF phishing detection using:
#            Layer 1 → Structural Analysis
#            Layer 2 → Content Analysis
#            Layer 3 → Behavioral Indicators
#            Layer 4 → Heuristic Risk Scoring
# Libraries: PyMuPDF (fitz), re, hashlib, math, urllib
# ================================================================


# ----------------------------------------------------------------
# IMPORTS — all tools we need
# ----------------------------------------------------------------

import fitz                         # PyMuPDF — reads PDF internals
import re                           # Pattern matching
import math                         # For entropy calculation
import hashlib                      # For SHA256 hash
import string                       # For string analysis
from urllib.parse import urlparse   # Breaks URLs into parts
from collections import Counter     # Counts occurrences


# ================================================================
# CONFIGURATION — All detection rules in one place
# Change weights here to tune sensitivity
# ================================================================

# ----------------------------------------------------------------
# HEURISTIC WEIGHTS — how dangerous each finding is
# These weights feed into scorer.py
# ----------------------------------------------------------------

WEIGHTS = {
    # Structural findings
    "javascript_detected"      : 40,
    "openaction_detected"      : 35,
    "launch_action_detected"   : 35,
    "embedded_file_detected"   : 30,
    "high_object_count"        : 15,
    "encrypted_object"         : 20,
    "acroform_detected"        : 20,
    "xfa_form_detected"        : 25,

    # Content findings
    "phishing_keyword"         : 10,
    "urgent_tone_detected"     : 15,
    "financial_terms_detected" : 15,
    "credential_harvesting"    : 20,

    # URL findings
    "suspicious_url"           : 15,
    "ip_based_url"             : 30,
    "shortened_url"            : 20,
    "suspicious_tld"           : 20,
    "at_symbol_trick"          : 25,
    "mismatched_anchor"        : 25,
    "homograph_domain"         : 30,

    # Image findings
    "single_image_pdf"         : 25,
    "clickable_image_overlay"  : 20,

    # Behavioral findings
    "base64_payload"           : 35,
    "hex_payload"              : 30,
    "high_entropy_string"      : 25,
    "powershell_detected"      : 40,
    "external_network_call"    : 30,
    "dropper_pattern"          : 40,
    "split_string_concat"      : 20,
    "embedded_executable"      : 45,
}


# ----------------------------------------------------------------
# PHISHING KEYWORDS — 80+ real phishing phrases
# Grouped by attack category
# ----------------------------------------------------------------

PHISHING_KEYWORDS = {

    "account_threats": [
        "verify your account",
        "confirm your account",
        "validate your account",
        "account verification required",
        "account suspended",
        "account will be closed",
        "account has been compromised",
        "account limited",
        "account will be terminated",
        "reactivate your account",
        "unlock your account",
    ],

    "urgency_phrases": [
        "urgent action required",
        "immediate action required",
        "act now",
        "respond immediately",
        "limited time",
        "expires today",
        "final warning",
        "last chance",
        "do not ignore",
        "failure to respond",
        "within 24 hours",
        "within 48 hours",
        "time sensitive",
        "don't delay",
    ],

    "credential_harvesting": [
        "enter your password",
        "confirm your password",
        "reset your password",
        "update your password",
        "password expired",
        "enter your credentials",
        "login credentials required",
        "verify your identity",
        "sign in to continue",
        "log in to verify",
        "enter your username",
        "enter your email",
    ],

    "financial_terms": [
        "bank account details",
        "credit card details",
        "debit card number",
        "enter your card details",
        "billing information required",
        "payment details required",
        "update payment method",
        "transaction failed",
        "refund pending",
        "wire transfer",
        "western union",
        "gift card",
        "bitcoin payment",
        "cryptocurrency",
    ],

    "reward_tricks": [
        "you have won",
        "prize money",
        "claim your reward",
        "lottery winner",
        "congratulations you won",
        "selected as winner",
        "free gift",
        "cash prize",
    ],

    "legal_threats": [
        "legal action will be taken",
        "police complaint filed",
        "court notice",
        "government notice",
        "income tax department",
        "irs notice",
        "tax refund",
        "customs clearance",
        "warrant issued",
        "arrest warrant",
    ],

    "india_specific": [
        "aadhar number",
        "aadhar card",
        "pan card details",
        "pan number",
        "kyc verification",
        "kyc update required",
        "upi details",
        "otp verification",
        "enter otp",
    ],

    "fake_security_alerts": [
        "your computer is infected",
        "virus detected",
        "malware found",
        "security breach",
        "unauthorized access",
        "your device is at risk",
        "install this update",
        "download the security patch",
        "suspicious login attempt",
        "unusual activity detected",
        "security alert",
    ],

    "download_tricks": [
        "click the link below",
        "click here to verify",
        "download the attachment",
        "open the document",
        "view your invoice",
        "access your account here",
        "download now",
        "click here immediately",
        "view document",
    ],
}


# ----------------------------------------------------------------
# SUSPICIOUS DOMAINS — URL shorteners and known bad patterns
# ----------------------------------------------------------------

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
    "qlink.me", "hyperurl.co", "bl.ink", "t2m.io",
    "shorte.st", "adf.ly", "bc.vc",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".ru", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".pw", ".cc", ".su", ".to",
    ".click", ".link", ".download", ".loan",
    ".work", ".party", ".review", ".science",
]

SUSPICIOUS_PDF_ACTIONS = [
    "/JavaScript", "/JS", "/Launch", "/EmbeddedFile",
    "/AA", "/OpenAction", "/AcroForm", "/JBIG2Decode",
    "/RichMedia", "/ObjStm", "/XFA", "/URI",
    "/SubmitForm", "/GoToR",
]

POWERSHELL_PATTERNS = [
    "powershell", "cmd.exe", "wscript", "cscript",
    "shell.application", "createobject",
    "shellexecute", "winexec", "system32",
]

DROPPER_PATTERNS = [
    "http.open", "xmlhttp", "urldownloadtofile",
    "writetext", "savetofile", "shell(",
    "wscript.shell", "document.write(",
]


# ================================================================
# HELPER FUNCTIONS
# ================================================================

# ----------------------------------------------------------------
# HELPER 1 — Calculate entropy of a string
# High entropy = random looking = possibly encoded payload
# ----------------------------------------------------------------

def calculate_entropy(text):
    """
    Shannon entropy measures randomness in a string.
    Normal text has low entropy (3.0-4.0)
    Encoded/encrypted content has high entropy (6.0+)
    """
    if not text or len(text) < 20:
        return 0.0

    # Count frequency of each character
    counter = Counter(text)
    length = len(text)

    # Shannon entropy formula
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 2)


# ----------------------------------------------------------------
# HELPER 2 — Check if string looks like Base64
# ----------------------------------------------------------------

def is_base64_like(text):
    """
    Base64 strings use A-Z a-z 0-9 + / =
    If a long string uses only these chars = suspicious
    """
    if len(text) < 50:
        return False

    base64_chars = set(string.ascii_letters + string.digits + "+/=")
    text_chars = set(text)
    ratio = len(text_chars.intersection(base64_chars)) / len(text_chars)

    return ratio > 0.95 and len(text) > 100


# ----------------------------------------------------------------
# HELPER 3 — Check if string looks like Hex encoded
# ----------------------------------------------------------------

def is_hex_encoded(text):
    """
    Hex strings use only 0-9 and A-F characters
    Long hex strings = hidden encoded payload
    """
    if len(text) < 40:
        return False

    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(hex_pattern.match(text.strip()))


# ----------------------------------------------------------------
# HELPER 4 — Check if URL uses IP address
# ----------------------------------------------------------------

def is_ip_url(url):
    """
    Legitimate sites use domain names.
    Attackers often use raw IP addresses.
    http://185.220.101.45/steal.php → suspicious ⚠️
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        if ":" in host:
            host = host.split(":")[0]
        ip_pattern = re.compile(
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        )
        return bool(ip_pattern.match(host))
    except:
        return False


# ----------------------------------------------------------------
# HELPER 5 — Full URL analysis
# ----------------------------------------------------------------

def analyze_url(url):
    """
    Runs all URL checks and returns list of findings
    with their finding type for scorer.py
    """
    url_findings = []
    url_details  = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()

        # Check 1 — IP based URL
        if is_ip_url(url):
            url_findings.append("ip_based_url")
            url_details.append(f"🚨 IP-based URL detected: {url}")

        # Check 2 — URL shortener
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                url_findings.append("shortened_url")
                url_details.append(
                    f"⚠️ URL shortener detected: {shortener} → {url}"
                )
                break

        # Check 3 — Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                url_findings.append("suspicious_tld")
                url_details.append(
                    f"⚠️ Suspicious TLD detected: {tld} in {url}"
                )
                break

        # Check 4 — @ symbol trick
        if "@" in url:
            url_findings.append("at_symbol_trick")
            url_details.append(
                f"🚨 @ symbol redirect trick: {url}"
            )

        # Check 5 — HTTP (insecure)
        if url.startswith("http://"):
            url_findings.append("suspicious_url")
            url_details.append(f"⚠️ Insecure HTTP link: {url}")

        # Check 6 — Extremely long URL
        if len(url) > 200:
            url_findings.append("suspicious_url")
            url_details.append(
                f"⚠️ Unusually long URL ({len(url)} chars): {url[:80]}..."
            )

        # Check 7 — Double HTTP obfuscation
        if url.count("http") > 1:
            url_findings.append("suspicious_url")
            url_details.append(
                f"🚨 URL obfuscation — multiple http: {url}"
            )

        # Check 8 — Fake login keywords in URL path
        fake_login_words = [
            "login", "signin", "verify", "secure",
            "account", "update", "confirm", "banking",
            "password", "credential", "authenticate"
        ]
        for word in fake_login_words:
            if word in path:
                url_findings.append("suspicious_url")
                url_details.append(
                    f"⚠️ Fake login keyword in URL path: '{word}' → {url}"
                )
                break

        # Check 9 — Homograph detection (mixed character sets)
        homograph_pattern = re.compile(
            r'[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]'
        )
        if homograph_pattern.search(domain):
            url_findings.append("homograph_domain")
            url_details.append(
                f"🚨 Homograph domain detected: {domain}"
            )

    except Exception as e:
        url_details.append(f"URL analysis error: {str(e)}")

    return url_findings, url_details


# ================================================================
# LAYER 1 — STRUCTURAL ANALYSIS
# ================================================================

def structural_analysis(file_path, raw_text):
    """
    Checks internal PDF structure for dangerous elements.
    Reads raw bytes of PDF to find hidden commands.
    """
    findings = []
    details  = []

    details.append("--- LAYER 1: STRUCTURAL ANALYSIS ---")

    # Check each dangerous PDF action
    for action in SUSPICIOUS_PDF_ACTIONS:
        if action in raw_text:

            if action in ["/JavaScript", "/JS"]:
                findings.append("javascript_detected")
                details.append(
                    f"🚨 CRITICAL: JavaScript embedded in PDF"
                )

            elif action == "/OpenAction":
                findings.append("openaction_detected")
                details.append(
                    f"🚨 CRITICAL: OpenAction found — auto-executes on open"
                )

            elif action == "/Launch":
                findings.append("launch_action_detected")
                details.append(
                    f"🚨 CRITICAL: Launch action found — can execute programs"
                )

            elif action == "/EmbeddedFile":
                findings.append("embedded_file_detected")
                details.append(
                    f"🚨 HIGH: Embedded file found inside PDF"
                )

            elif action in ["/AcroForm"]:
                findings.append("acroform_detected")
                details.append(
                    f"⚠️ HIGH: AcroForm detected — credential theft form"
                )

            elif action == "/XFA":
                findings.append("xfa_form_detected")
                details.append(
                    f"⚠️ HIGH: XFA form detected — advanced phishing form"
                )

            elif action == "/ObjStm":
                findings.append("high_object_count")
                details.append(
                    f"⚠️ MEDIUM: Object stream detected — used for obfuscation"
                )

    # Check for high object count using regex
    obj_count = len(re.findall(r'\d+ \d+ obj', raw_text))
    if obj_count > 100:
        findings.append("high_object_count")
        details.append(
            f"⚠️ HIGH: Suspicious object count: {obj_count} objects"
        )

    # Check for encrypted objects
    if "/Encrypt" in raw_text:
        findings.append("encrypted_object")
        details.append(
            f"⚠️ MEDIUM: Encrypted content detected in PDF"
        )

    # Check for embedded executables
    exe_patterns = [b'MZ\x90\x00', b'MZ\x00\x00']
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
            for pattern in exe_patterns:
                if pattern in raw_bytes:
                    findings.append("embedded_executable")
                    details.append(
                        "🚨 CRITICAL: Executable (EXE) embedded inside PDF!"
                    )
                    break
    except:
        pass

    details.append(
        f"Structural findings: {len(findings)}"
    )
    return findings, details


# ================================================================
# LAYER 2 — CONTENT ANALYSIS
# ================================================================

def content_analysis(pdf_document):
    """
    Analyses text content, keywords and URLs
    across all pages of the PDF.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- LAYER 2: CONTENT ANALYSIS ---")

    total_pages    = len(pdf_document)
    total_text     = ""
    total_images   = 0
    total_links    = 0
    all_text_urls  = []

    for page_number in range(total_pages):

        page      = pdf_document[page_number]
        page_text = page.get_text().lower()
        total_text += page_text

        # Count images on this page
        image_list   = page.get_images()
        total_images += len(image_list)

        # --------------------------------------------------
        # URL EXTRACTION — Method 1: Clickable links
        # --------------------------------------------------

        links = page.get_links()
        for link in links:
            url = link.get("uri", "")
            if url:
                total_links += 1
                url_findings, url_details = analyze_url(url)
                findings.extend(url_findings)
                for d in url_details:
                    details.append(f"Page {page_number+1}: {d}")

        # --------------------------------------------------
        # URL EXTRACTION — Method 2: Plain text URLs
        # --------------------------------------------------

        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        text_urls   = url_pattern.findall(page.get_text())

        for url in text_urls:
            url_findings, url_details = analyze_url(url)
            if url_findings:
                findings.extend(url_findings)
                for d in url_details:
                    details.append(f"Page {page_number+1} (text): {d}")

        # --------------------------------------------------
        # CHECK FOR MISMATCHED ANCHOR TEXT vs REAL URL
        # --------------------------------------------------

        page_dict = page.get_text("dict")
        blocks    = page_dict.get("blocks", [])

        for block in blocks:
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    span_text = span.get("text", "").lower()
                    # If visible text looks like URL but differs from link
                    if ("http" in span_text or "www." in span_text):
                        for link in links:
                            real_url    = link.get("uri", "").lower()
                            visible_url = span_text.strip()
                            if (real_url and visible_url and
                                    real_url != visible_url and
                                    len(visible_url) > 10):
                                findings.append("mismatched_anchor")
                                details.append(
                                    f"⚠️ Page {page_number+1}: "
                                    f"Mismatched anchor — "
                                    f"shows '{visible_url[:40]}' "
                                    f"but links to '{real_url[:40]}'"
                                )

    # --------------------------------------------------
    # KEYWORD ANALYSIS — check entire document text
    # --------------------------------------------------

    keyword_hits      = 0
    urgency_hits      = 0
    financial_hits    = 0
    credential_hits   = 0

    for category, keywords in PHISHING_KEYWORDS.items():
        for keyword in keywords:
            count = total_text.count(keyword)
            if count > 0:
                keyword_hits += count
                findings.append("phishing_keyword")
                details.append(
                    f"⚠️ Keyword [{category}]: "
                    f"'{keyword}' found {count}x"
                )

                # Track specific categories
                if category == "urgency_phrases":
                    urgency_hits += count
                elif category == "financial_terms":
                    financial_hits += count
                elif category == "credential_harvesting":
                    credential_hits += count

    # Add category-level findings
    if urgency_hits >= 2:
        findings.append("urgent_tone_detected")
        details.append(
            f"🚨 Urgency tone detected: {urgency_hits} urgency phrases"
        )

    if financial_hits >= 2:
        findings.append("financial_terms_detected")
        details.append(
            f"🚨 Financial targeting: {financial_hits} financial terms"
        )

    if credential_hits >= 1:
        findings.append("credential_harvesting")
        details.append(
            f"🚨 Credential harvesting: {credential_hits} credential phrases"
        )

    # --------------------------------------------------
    # IMAGE-BASED PHISHING DETECTION
    # --------------------------------------------------

    # Check 1 — Large single image PDF
    if total_images >= 1 and len(total_text.strip()) < 100:
        findings.append("single_image_pdf")
        details.append(
            f"🚨 Single-image PDF detected — "
            f"{total_images} image(s), very little text. "
            f"Classic image-based phishing!"
        )

    # Check 2 — Many images with links (clickable overlays)
    if total_images > 0 and total_links > 0:
        ratio = total_links / max(total_images, 1)
        if ratio >= 1:
            findings.append("clickable_image_overlay")
            details.append(
                f"⚠️ Clickable image overlay suspected: "
                f"{total_images} images, {total_links} links"
            )

    details.append(f"Content findings: {len(findings)}")
    return findings, details


# ================================================================
# LAYER 3 — BEHAVIORAL INDICATORS
# ================================================================

def behavioral_analysis(raw_text):
    """
    Looks for behavioral patterns that indicate
    the PDF is trying to execute code or call network.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- LAYER 3: BEHAVIORAL ANALYSIS ---")

    raw_lower = raw_text.lower()

    # --------------------------------------------------
    # CHECK 1 — PowerShell and shell commands
    # --------------------------------------------------

    for pattern in POWERSHELL_PATTERNS:
        if pattern in raw_lower:
            findings.append("powershell_detected")
            details.append(
                f"🚨 CRITICAL: Shell command detected: '{pattern}'"
            )

    # --------------------------------------------------
    # CHECK 2 — Dropper behavior patterns
    # --------------------------------------------------

    for pattern in DROPPER_PATTERNS:
        if pattern in raw_lower:
            findings.append("dropper_pattern")
            details.append(
                f"🚨 CRITICAL: Dropper pattern detected: '{pattern}'"
            )

    # --------------------------------------------------
    # CHECK 3 — Base64 encoded payload
    # --------------------------------------------------

    # Find long strings that look like Base64
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
    b64_matches = b64_pattern.findall(raw_text)

    for match in b64_matches:
        if is_base64_like(match):
            findings.append("base64_payload")
            details.append(
                f"🚨 HIGH: Base64 encoded payload detected "
                f"({len(match)} chars): {match[:40]}..."
            )
            break  # Report once

    # --------------------------------------------------
    # CHECK 4 — Hex encoded payload
    # --------------------------------------------------

    hex_pattern = re.compile(r'[0-9a-fA-F]{40,}')
    hex_matches = hex_pattern.findall(raw_text)

    for match in hex_matches:
        if is_hex_encoded(match):
            findings.append("hex_payload")
            details.append(
                f"🚨 HIGH: Hex encoded payload detected "
                f"({len(match)} chars): {match[:40]}..."
            )
            break  # Report once

    # --------------------------------------------------
    # CHECK 5 — High entropy strings (obfuscation)
    # --------------------------------------------------

    # Split raw text into chunks and check entropy
    chunk_size = 100
    chunks = [
        raw_text[i:i+chunk_size]
        for i in range(0, min(len(raw_text), 5000), chunk_size)
    ]

    high_entropy_count = 0
    for chunk in chunks:
        entropy = calculate_entropy(chunk)
        if entropy > 6.5:
            high_entropy_count += 1

    if high_entropy_count >= 3:
        findings.append("high_entropy_string")
        details.append(
            f"⚠️ HIGH: {high_entropy_count} high-entropy "
            f"chunks detected — possible obfuscation"
        )

    # --------------------------------------------------
    # CHECK 6 — External network call patterns
    # --------------------------------------------------

    network_patterns = [
        r'xmlhttprequest',
        r'fetch\(',
        r'\.open\(',
        r'getrequest',
        r'postrequest',
        r'wget',
        r'curl ',
    ]

    for pattern in network_patterns:
        if re.search(pattern, raw_lower):
            findings.append("external_network_call")
            details.append(
                f"🚨 HIGH: External network call pattern: '{pattern}'"
            )

    # --------------------------------------------------
    # CHECK 7 — Split string concatenation (obfuscation)
    # --------------------------------------------------

    split_patterns = [
        r'"\s*\+\s*"',          # "str" + "str"
        r"'\s*\+\s*'",          # 'str' + 'str'
        r'chr\(\d+\)',           # chr(80) — char by number
        r'fromcharcode',        # fromCharCode obfuscation
    ]

    for pattern in split_patterns:
        if re.search(pattern, raw_lower):
            findings.append("split_string_concat")
            details.append(
                f"⚠️ MEDIUM: String obfuscation detected: '{pattern}'"
            )

    details.append(f"Behavioral findings: {len(findings)}")
    return findings, details


# ================================================================
# LAYER 4 — HEURISTIC RISK SCORING
# ================================================================

def heuristic_scoring(all_findings):
    """
    Takes all findings from all 3 layers.
    Calculates weighted danger score.
    Returns score, verdict and full breakdown.
    """

    total_score = 0
    breakdown   = {}

    for finding in all_findings:
        weight = WEIGHTS.get(finding, 5)
        total_score += weight

        if finding in breakdown:
            breakdown[finding]["count"] += 1
            breakdown[finding]["score"] += weight
        else:
            breakdown[finding] = {
                "count" : 1,
                "score" : weight
            }

    # Cap at 100
    total_score = min(total_score, 100)

    # Verdict based on score
    if total_score < 30:
        verdict = "Low Risk ✅"
    elif total_score < 60:
        verdict = "Medium Risk ⚠️"
    elif total_score < 80:
        verdict = "High Risk 🔴"
    else:
        verdict = "Critical — Likely Phishing ☠️"

    return total_score, verdict, breakdown


# ================================================================
# MAIN FUNCTION — parse_pdf
# Called by app.py when user uploads a PDF
# ================================================================

def parse_pdf(file_path):
    """
    file_path = full path to uploaded PDF file
    Returns   = complete analysis result dict
    """

    all_findings = []
    all_details  = []

    try:

        # ----------------------------------------------
        # STEP 1 — Generate SHA256 hash of file
        # Can be used to check against malware databases
        # ----------------------------------------------

        sha256_hash = ""
        try:
            with open(file_path, "rb") as f:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()
        except:
            sha256_hash = "Could not calculate"

        all_details.append("=" * 50)
        all_details.append("DARKHOOK_ DEFENCE — PDF ANALYSIS REPORT")
        all_details.append("=" * 50)
        all_details.append(f"File     : {file_path}")
        all_details.append(f"SHA256   : {sha256_hash}")

        # ----------------------------------------------
        # STEP 2 — Open PDF and get basic info
        # ----------------------------------------------

        pdf_document = fitz.open(file_path)
        total_pages  = len(pdf_document)

        all_details.append(f"Pages    : {total_pages}")

        # Get metadata
        metadata = pdf_document.metadata
        if metadata:
            author  = metadata.get("author",  "Unknown")
            creator = metadata.get("creator", "Unknown")
            all_details.append(f"Author   : {author}")
            all_details.append(f"Creator  : {creator}")

            if not author or author == "Unknown":
                all_findings.append("suspicious_url")
                all_details.append(
                    "⚠️ No author in metadata — common in phishing PDFs"
                )

        # ----------------------------------------------
        # STEP 3 — Read raw PDF bytes for structure check
        # ----------------------------------------------

        raw_text = ""
        try:
            with open(file_path, "rb") as f:
                raw_text = f.read().decode("latin-1")
        except:
            all_details.append("⚠️ Could not read raw PDF bytes")

        # ----------------------------------------------
        # STEP 4 — Run all 3 analysis layers
        # ----------------------------------------------

        # Layer 1
        s_findings, s_details = structural_analysis(
            file_path, raw_text
        )
        all_findings.extend(s_findings)
        all_details.extend(s_details)

        # Layer 2
        c_findings, c_details = content_analysis(pdf_document)
        all_findings.extend(c_findings)
        all_details.extend(c_details)

        # Layer 3
        b_findings, b_details = behavioral_analysis(raw_text)
        all_findings.extend(b_findings)
        all_details.extend(b_details)

        # Close PDF
        pdf_document.close()

        # ----------------------------------------------
        # STEP 5 — Heuristic scoring (Layer 4)
        # ----------------------------------------------

        score, verdict, breakdown = heuristic_scoring(all_findings)

        all_details.append("")
        all_details.append("--- LAYER 4: HEURISTIC SCORING ---")
        all_details.append(f"Total findings : {len(all_findings)}")
        all_details.append(f"Danger score   : {score} / 100")
        all_details.append(f"Verdict        : {verdict}")
        all_details.append("")
        all_details.append("Score breakdown:")
        for finding, data in breakdown.items():
            all_details.append(
                f"  {finding}: "
                f"count={data['count']} "
                f"score={data['score']}"
            )

    except Exception as error:
        all_details.append(f"❌ Critical error: {str(error)}")

    return {
        "findings"   : all_findings,
        "details"    : all_details,
        "sha256"     : sha256_hash if 'sha256_hash' in locals() else "",
    }

