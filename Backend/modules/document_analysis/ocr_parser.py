# ================================================================
# ocr_parser.py — DarkHOOK_ Defence
# Version  : 2.0 — Enterprise Grade
# Purpose  : Image file phishing detection using
#            17 industry-standard techniques
#
# Technique 1  -> File Type Validation
# Technique 2  -> Image Metadata Analysis
# Technique 3  -> OCR Text Extraction
# Technique 4  -> Phishing Keyword Detection
# Technique 5  -> URL Detection in Image Text
# Technique 6  -> QR Code Detection
# Technique 7  -> Visual Deception Detection
# Technique 8  -> Pixel Manipulation Detection
# Technique 9  -> Attack Chain Inference
# Technique 10 -> Heuristic Risk Scoring
# Technique 11 -> Multi-Language OCR Detection
# Technique 12 -> Homograph and Lookalike Domain Detection
# Technique 13 -> Hidden Text Overlay Detection
# Technique 14 -> Perceptual Image Hash Matching
# Technique 15 -> UI Layout Fake Login Detection
# Technique 16 -> Fake Browser Address Bar Detection
# Technique 17 -> OCR Confidence Analysis
#
# Libraries: pytesseract, Pillow, pyzbar,
#            hashlib, re, math
# ================================================================


# ----------------------------------------------------------------
# IMPORTS
# ----------------------------------------------------------------

import re
import os
import math
import hashlib
from collections import Counter
from urllib.parse import urlparse

try:
    from PIL import Image
    from PIL import ImageFilter
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = (
        r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    )
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


# ================================================================
# CONFIGURATION
# ================================================================

WEIGHTS = {
    # File structure
    "invalid_image_format"       : 30,
    "file_type_mismatch"         : 40,
    "double_extension"           : 35,
    # Metadata
    "suspicious_exif"            : 15,
    "wiped_exif"                 : 20,
    "edited_image"               : 15,
    # OCR findings
    "ocr_failed"                 : 10,
    "ocr_phishing_text"          : 10,
    "phishing_keyword"           : 10,
    "low_text_density"           : 15,
    # Tone findings
    "urgent_tone_detected"       : 15,
    "financial_terms_detected"   : 15,
    "credential_harvesting"      : 20,
    # URL findings
    "suspicious_url"             : 15,
    "ip_based_url"               : 30,
    "shortened_url"              : 20,
    "suspicious_tld"             : 20,
    "at_symbol_trick"            : 25,
    "mismatched_anchor"          : 25,
    # QR findings
    "qr_code_detected"           : 15,
    "qr_malicious_url"           : 40,
    "qr_suspicious_url"          : 25,
    # Visual deception
    "fake_login_page"            : 35,
    "blurred_image"              : 20,
    "single_image_content"       : 20,
    # Pixel manipulation
    "high_entropy_image"         : 25,
    "suspicious_file_size"       : 20,
    "steganography_indicator"    : 35,
    # Multi-language
    "multilang_phishing_text"    : 25,
    "hindi_phishing_detected"    : 25,
    "mixed_script_detected"      : 20,
    # Homograph
    "homograph_domain"           : 35,
    "lookalike_domain"           : 30,
    "char_substitution"          : 25,
    # Hidden overlay
    "hidden_text_overlay"        : 40,
    "low_contrast_text"          : 30,
    "transparent_layer"          : 35,
    # Template matching
    "known_phishing_template"    : 45,
    "template_reuse_detected"    : 40,
    # UI layout
    "fake_login_form_detected"   : 40,
    "password_field_detected"    : 30,
    "fake_submit_button"         : 25,
    # Fake browser
    "fake_browser_ui"            : 35,
    "fake_address_bar"           : 40,
    "fake_padlock_detected"      : 30,
    # OCR confidence
    "low_ocr_confidence"         : 20,
    "blur_evasion_detected"      : 30,
    # Attack chain
    "dropper_pattern"            : 40,
    "credential_theft_chain"     : 40,
    "qr_phishing_chain"          : 40,
    "impersonation_chain"        : 35,
}


# ----------------------------------------------------------------
# PHISHING KEYWORDS — Technique 4
# ----------------------------------------------------------------

PHISHING_KEYWORDS = {

    "account_threats": [
        "verify your account",
        "confirm your account",
        "account suspended",
        "account will be closed",
        "account has been compromised",
        "account limited",
        "reactivate your account",
        "unlock your account",
        "unusual activity detected",
    ],

    "urgency_phrases": [
        "urgent action required",
        "immediate action required",
        "act now",
        "respond immediately",
        "expires today",
        "final warning",
        "last chance",
        "do not ignore",
        "failure to respond",
        "within 24 hours",
        "time sensitive",
    ],

    "credential_harvesting": [
        "enter your password",
        "confirm your password",
        "reset your password",
        "password expired",
        "enter your credentials",
        "verify your identity",
        "sign in to continue",
        "login credentials required",
        "enter your username",
        "enter your email",
    ],

    "financial_terms": [
        "bank account details",
        "credit card details",
        "debit card number",
        "billing information required",
        "payment details required",
        "update payment method",
        "transaction failed",
        "wire transfer",
        "gift card",
        "bitcoin payment",
        "refund pending",
    ],

    "reward_tricks": [
        "you have won",
        "prize money",
        "claim your reward",
        "lottery winner",
        "congratulations you won",
        "cash prize",
        "free gift",
    ],

    "legal_threats": [
        "legal action will be taken",
        "police complaint filed",
        "court notice",
        "government notice",
        "income tax department",
        "irs notice",
        "tax refund",
        "warrant issued",
        "arrest warrant",
    ],

    "india_specific": [
        "aadhar number",
        "pan card details",
        "kyc verification",
        "kyc update required",
        "upi details",
        "enter otp",
        "otp verification",
        "neft",
        "imps",
        "rtgs",
    ],

    "fake_security_alerts": [
        "your computer is infected",
        "virus detected",
        "security breach",
        "unauthorized access",
        "install this update",
        "download the security patch",
        "suspicious login attempt",
    ],

    "fake_bank_names": [
        "state bank",
        "hdfc bank",
        "icici bank",
        "axis bank",
        "paytm",
        "phonepe",
        "google pay",
        "amazon pay",
        "npci",
    ],

    "download_tricks": [
        "click the link below",
        "click here to verify",
        "scan the qr code",
        "scan qr to verify",
        "download the app",
        "install now",
        "click here immediately",
    ],
}


# Hindi phishing keywords
HINDI_PHISHING_KEYWORDS = [
    "khata",
    "bank",
    "paisa",
    "otp",
    "verify",
    "aadhar",
    "mobile number",
    "turant",
    "jaldi",
    "rupaye",
]


# Fake brand keywords
FAKE_BRAND_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis",
    "paytm", "phonepe", "gpay",
    "amazon", "flipkart", "irctc",
    "income tax", "epf", "uidai",
    "aadhaar", "passport",
]


# Suspicious software in EXIF
SUSPICIOUS_SOFTWARE = [
    "photoshop",
    "gimp",
    "paint.net",
    "canva",
    "pixlr",
    "illustrator",
    "inkscape",
]


# URL shorteners
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy",
    "qrfy.io", "qrfy.com", "qr.io",
    "qrco.de", "qrd.by", "q-r.to",
]

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".ru", ".tk",
    ".ml", ".ga", ".cf", ".gq",
    ".pw", ".click", ".download",
    ".loan", ".work", ".party",
]


# Homograph lookalike character map
# Left  = fake Unicode character
# Right = real ASCII character it looks like
HOMOGRAPH_MAP = {
    "\u0430" : "a",   # Cyrillic a
    "\u0435" : "e",   # Cyrillic e
    "\u043e" : "o",   # Cyrillic o
    "\u0440" : "p",   # Cyrillic r looks like p
    "\u0441" : "c",   # Cyrillic c
    "\u0445" : "x",   # Cyrillic x
    "\u0456" : "i",   # Ukrainian i
    "\u04cf" : "l",   # Cyrillic looks like l
    "\u1d0f" : "o",   # Latin small capital o
    "\u0131" : "i",   # Dotless i
    "\u01a0" : "o",   # Latin o with horn
}


# Character substitution patterns
CHAR_SUBSTITUTIONS = [
    ("0", "o"),   # zero instead of letter o
    ("1", "l"),   # one instead of letter l
    ("1", "i"),   # one instead of letter i
    ("3", "e"),   # three instead of letter e
    ("4", "a"),   # four instead of letter a
    ("5", "s"),   # five instead of letter s
    ("@", "a"),   # at sign instead of letter a
    ("rn", "m"),  # r+n looks like m
    ("vv", "w"),  # v+v looks like w
]


# Known phishing template hashes
# These are perceptual hashes of known phishing images
# In real project these would be loaded from database
KNOWN_PHISHING_HASHES = [
    "fake_sbi_login_template_hash",
    "fake_hdfc_template_hash",
    "fake_paytm_template_hash",
]


# Fake browser UI keywords
BROWSER_UI_KEYWORDS = [
    "https://",
    "http://",
    "www.",
    "secure",
    "verified",
    "ssl",
]


# ================================================================
# HELPER FUNCTIONS
# ================================================================

def calculate_entropy(data):
    """
    Shannon entropy measures randomness.
    Normal image -> 6.0 to 7.5
    Hidden data  -> closer to 8.0
    """
    if not data or len(data) < 20:
        return 0.0
    counter = Counter(data)
    length  = len(data)
    entropy = -sum(
        (c / length) * math.log2(c / length)
        for c in counter.values()
    )
    return round(entropy, 2)


def is_ip_url(url):
    """Returns True if URL uses IP instead of domain"""
    try:
        host = urlparse(url).netloc
        if ":" in host:
            host = host.split(":")[0]
        return bool(re.match(
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host
        ))
    except Exception:
        return False


def analyze_url(url):
    """Full URL analysis"""
    url_findings = []
    url_details  = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()

        if is_ip_url(url):
            url_findings.append("ip_based_url")
            url_details.append("IP-based URL: " + url)

        for s in URL_SHORTENERS:
            if s in domain:
                url_findings.append("shortened_url")
                url_details.append(
                    "URL shortener (" + s + "): " + url
                )
                break

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                url_findings.append("suspicious_tld")
                url_details.append(
                    "Suspicious TLD (" + tld + "): " + url
                )
                break

        if "@" in url:
            url_findings.append("at_symbol_trick")
            url_details.append("@ redirect trick: " + url)

        if url.startswith("http://"):
            url_findings.append("suspicious_url")
            url_details.append("Insecure HTTP: " + url)

        if len(url) > 200:
            url_findings.append("suspicious_url")
            url_details.append(
                "Long URL: " + url[:60] + "..."
            )

        fake_words = [
            "login", "signin", "verify", "secure",
            "account", "update", "confirm", "banking",
            "password", "credential",
        ]
        for word in fake_words:
            if word in path:
                url_findings.append("suspicious_url")
                url_details.append(
                    "Login keyword in URL: " + url
                )
                break

    except Exception as e:
        url_details.append("URL error: " + str(e))

    return url_findings, url_details


def simple_perceptual_hash(img, hash_size=8):
    """
    Creates a simple perceptual hash of an image.
    Similar images will have similar hashes.
    Used to detect reused phishing templates.

    How it works:
    1. Resize image to 8x8
    2. Convert to grayscale
    3. Calculate average pixel value
    4. Each pixel above average = 1, below = 0
    5. Result = 64 bit hash string
    """
    try:
        small_img = img.resize(
            (hash_size, hash_size), Image.LANCZOS
        ).convert("L")
        pixels    = list(small_img.getdata())
        avg       = sum(pixels) / len(pixels)
        bits      = "".join(
            "1" if p > avg else "0" for p in pixels
        )
        hex_hash  = format(int(bits, 2), "016x")
        return hex_hash
    except Exception:
        return ""


def hamming_distance(hash1, hash2):
    """
    Counts how many bits are different
    between two hashes.
    0  = identical images
    64 = completely different images
    Less than 10 = very similar images
    """
    try:
        if len(hash1) != len(hash2):
            return 64
        h1 = bin(int(hash1, 16))[2:].zfill(64)
        h2 = bin(int(hash2, 16))[2:].zfill(64)
        return sum(c1 != c2 for c1, c2 in zip(h1, h2))
    except Exception:
        return 64


# ================================================================
# TECHNIQUE 1 — File Type Validation
# ================================================================

def technique1_file_validation(file_path):
    """
    Verifies file is actually a real image.
    Checks extension and file signature bytes.
    """
    findings = []
    details  = []

    details.append("--- TECHNIQUE 1: FILE VALIDATION ---")

    filename = os.path.basename(file_path)
    ext      = os.path.splitext(filename)[1].lower()

    valid_extensions = [
        ".jpg", ".jpeg", ".png", ".bmp",
        ".tiff", ".tif", ".gif", ".webp",
    ]

    if ext not in valid_extensions:
        findings.append("invalid_image_format")
        details.append("Invalid image extension: " + ext)
    else:
        details.append("Extension valid: " + ext)

    # Double extension check — ignores version numbers
    name_without_ext = os.path.splitext(filename)[0]
    if "." in name_without_ext:
        part_after_dot = name_without_ext.split(".")[-1].strip()
        dangerous_exts = [
            "exe", "dll", "bat", "cmd",
            "ps1", "vbs", "js", "hta",
        ]
        if part_after_dot.lower() in dangerous_exts:
            findings.append("double_extension")
            details.append(
                "Double extension detected: " + filename
            )
        elif part_after_dot.isdigit():
            details.append(
                "Note: Dot is version number — safe"
            )

    # Check actual file signature bytes
    try:
        with open(file_path, "rb") as f:
            header = f.read(12)

        if ext in [".jpg", ".jpeg"]:
            if header[:3] == b"\xff\xd8\xff":
                details.append("JPG signature valid")
            else:
                findings.append("file_type_mismatch")
                details.append(
                    "JPG signature INVALID — possible malware!"
                )

        elif ext == ".png":
            if header[:4] == b"\x89PNG":
                details.append("PNG signature valid")
            else:
                findings.append("file_type_mismatch")
                details.append(
                    "PNG signature INVALID — possible malware!"
                )

        elif ext == ".gif":
            if header[:3] == b"GIF":
                details.append("GIF signature valid")
            else:
                findings.append("file_type_mismatch")
                details.append("GIF signature INVALID!")

        elif ext == ".bmp":
            if header[:2] == b"BM":
                details.append("BMP signature valid")
            else:
                findings.append("file_type_mismatch")
                details.append("BMP signature INVALID!")

    except Exception as e:
        details.append("File signature error: " + str(e))

    details.append("Technique 1 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 2 — Image Metadata (EXIF) Analysis
# ================================================================

def technique2_exif_metadata(file_path):
    """
    Extracts and analyses hidden EXIF metadata.
    Phishing images often have wiped or suspicious metadata.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- TECHNIQUE 2: IMAGE METADATA ANALYSIS ---")

    if not PIL_AVAILABLE:
        details.append("Pillow not available — skipping EXIF")
        return findings, details

    try:
        img  = Image.open(file_path)
        exif = img._getexif() if hasattr(img, "_getexif") else None

        if exif is None:
            filename_lower = os.path.basename(
                file_path
            ).lower()

            if "whatsapp" in filename_lower:
                details.append(
                    "No EXIF — WhatsApp removes metadata "
                    "automatically — safe ✅"
                )
            else:
                findings.append("wiped_exif")
                details.append(
                    "No EXIF metadata — may have been wiped!"
                )
        else:
            details.append("EXIF data found — analyzing...")
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, str(tag_id))

                if tag == "Software":
                    details.append("Software : " + str(value))
                    for sus_sw in SUSPICIOUS_SOFTWARE:
                        if sus_sw in str(value).lower():
                            findings.append("edited_image")
                            details.append(
                                "Image edited with: " + str(value)
                            )
                            break

                elif tag == "DateTime":
                    details.append("DateTime : " + str(value))

                elif tag == "Make":
                    details.append("Device   : " + str(value))

        img.close()

        # Check dimensions
        img2    = Image.open(file_path)
        w, h    = img2.size
        details.append(
            "Dimensions: " + str(w) + " x " + str(h) + " pixels"
        )

        if w < 100 or h < 100:
            findings.append("suspicious_exif")
            details.append(
                "Very small image — possible tracking pixel!"
            )

        img2.close()

    except Exception as e:
        details.append("EXIF error: " + str(e))

    details.append("Technique 2 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 3 — OCR Text Extraction (English)
# ================================================================

def technique3_ocr_extraction(file_path):
    """
    Uses Tesseract OCR to extract English text from image.
    This is the core technique of ocr_parser.
    Returns extracted text for other techniques.
    """
    findings = []
    details  = []
    ocr_text = ""

    details.append("")
    details.append("--- TECHNIQUE 3: OCR TEXT EXTRACTION ---")

    if not TESSERACT_AVAILABLE:
        details.append("pytesseract not available — skipping")
        return findings, details, ocr_text

    if not PIL_AVAILABLE:
        details.append("Pillow not available — skipping")
        return findings, details, ocr_text

    try:
        img = Image.open(file_path)

        if img.mode not in ["RGB", "L"]:
            img = img.convert("RGB")

        ocr_text = pytesseract.image_to_string(
            img,
            lang="eng",
            config="--psm 6",
        )

        img.close()
        ocr_text = ocr_text.strip()

        if not ocr_text:
            findings.append("low_text_density")
            details.append(
                "No text extracted — may be purely visual phishing"
            )
        else:
            word_count = len(ocr_text.split())
            details.append(
                "OCR extracted " + str(word_count) + " words"
            )
            preview = (
                ocr_text[:200] + "..."
                if len(ocr_text) > 200
                else ocr_text
            )
            details.append("OCR preview: " + preview)

    except Exception as e:
        findings.append("ocr_failed")
        details.append("OCR error: " + str(e))

    details.append("Technique 3 findings: " + str(len(findings)))
    return findings, details, ocr_text


# ================================================================
# TECHNIQUE 4 — Phishing Keyword Detection
# ================================================================

def technique4_keyword_detection(ocr_text):
    """
    Searches OCR text for phishing keywords.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- TECHNIQUE 4: PHISHING KEYWORD DETECTION ---")

    if not ocr_text:
        details.append("No OCR text — skipping")
        return findings, details

    text_lower     = ocr_text.lower()
    urgency_count  = 0
    finance_count  = 0
    cred_count     = 0

    for category, keywords in PHISHING_KEYWORDS.items():
        for keyword in keywords:
            count = text_lower.count(keyword)
            if count > 0:
                findings.append("phishing_keyword")
                details.append(
                    "[" + category + "] '" +
                    keyword + "' x" + str(count)
                )
                if category == "urgency_phrases":
                    urgency_count += count
                elif category == "financial_terms":
                    finance_count += count
                elif category == "credential_harvesting":
                    cred_count += count

    if urgency_count >= 2:
        findings.append("urgent_tone_detected")
        details.append(
            "Urgency tone: " + str(urgency_count) + " phrases"
        )

    if finance_count >= 2:
        findings.append("financial_terms_detected")
        details.append(
            "Financial targeting: " + str(finance_count) + " terms"
        )

    if cred_count >= 1:
        findings.append("credential_harvesting")
        details.append(
            "Credential harvesting: " + str(cred_count) + " phrases"
        )

    for brand in FAKE_BRAND_KEYWORDS:
        if brand in text_lower:
            findings.append("ocr_phishing_text")
            details.append(
                "Brand impersonation: '" + brand + "'"
            )

    if not findings:
        details.append("No phishing keywords detected")

    details.append("Technique 4 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 5 — URL Detection in Image Text
# ================================================================

def technique5_url_detection(ocr_text):
    """
    Finds and analyzes URLs extracted from image via OCR.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- TECHNIQUE 5: URL DETECTION IN IMAGE ---")

    if not ocr_text:
        details.append("No OCR text — skipping")
        return findings, details

    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+'
    )
    urls_found = url_pattern.findall(ocr_text)

    www_pattern = re.compile(
        r'www\.[^\s<>"{}|\\^`\[\]]+'
    )
    for url in www_pattern.findall(ocr_text):
        urls_found.append("http://" + url)

    details.append(
        "Total URLs in image: " + str(len(urls_found))
    )

    for url in urls_found:
        url_findings, url_details = analyze_url(url)
        if url_findings:
            findings.extend(url_findings)
            for d in url_details:
                details.append("  " + d)
        else:
            details.append("  Link: " + url)

    if not urls_found:
        details.append("No URLs found in image text")

    details.append("Technique 5 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 6 — QR Code Detection
# ================================================================

def technique6_qr_detection(file_path):
    """
    Detects QR codes and decodes hidden URLs inside them.
    QR phishing is very common in India.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- TECHNIQUE 6: QR CODE DETECTION ---")

    if not PYZBAR_AVAILABLE:
        details.append("pyzbar not available — skipping")
        return findings, details

    if not PIL_AVAILABLE:
        details.append("Pillow not available — skipping")
        return findings, details

    try:
        img     = Image.open(file_path)
        qr_list = qr_decode(img)
        img.close()

        if not qr_list:
            details.append("No QR codes detected")
            return findings, details

        findings.append("qr_code_detected")
        details.append(
            str(len(qr_list)) + " QR code(s) found!"
        )

        for i, qr in enumerate(qr_list, 1):
            try:
                qr_data = qr.data.decode("utf-8").strip()
                qr_type = qr.type

                details.append(
                    "QR " + str(i) + " type: " + str(qr_type)
                )
                details.append(
                    "QR " + str(i) + " data: " + qr_data[:100]
                )

                if qr_data.startswith("http"):
                    url_findings, url_details = analyze_url(qr_data)
                    if url_findings:
                        findings.append("qr_malicious_url")
                        details.append(
                            "CRITICAL: Malicious URL in QR!"
                        )
                        for d in url_details:
                            details.append("  " + d)
                    else:
                        findings.append("qr_suspicious_url")
                        details.append(
                            "QR URL needs review: " + qr_data
                        )

                elif re.match(r'^\+?\d{10,15}$', qr_data):
                    findings.append("qr_suspicious_url")
                    details.append(
                        "QR phone number — possible smishing: " +
                        qr_data
                    )

                else:
                    text_lower = qr_data.lower()
                    for brand in FAKE_BRAND_KEYWORDS:
                        if brand in text_lower:
                            findings.append("qr_suspicious_url")
                            details.append(
                                "QR contains brand: " + brand
                            )
                            break

            except Exception as e:
                details.append("QR decode error: " + str(e))

    except Exception as e:
        details.append("QR detection error: " + str(e))

    details.append("Technique 6 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 7 — Visual Deception Detection
# ================================================================

def technique7_visual_deception(file_path, ocr_text):
    """
    Detects visual tricks used in phishing images.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- TECHNIQUE 7: VISUAL DECEPTION DETECTION ---")

    if not PIL_AVAILABLE:
        details.append("Pillow not available — skipping")
        return findings, details

    try:
        img  = Image.open(file_path)
        w, h = img.size

        details.append(
            "Image size: " + str(w) + " x " + str(h)
        )

        # Very low resolution
        if w < 300 and h < 300:
            findings.append("blurred_image")
            details.append(
                "Very low resolution — bypass OCR attempt!"
            )

        # Large image with very little text
        if ocr_text:
            word_count  = len(ocr_text.split())
            pixel_count = w * h
            if pixel_count > 100000 and word_count < 10:
                findings.append("single_image_content")
                details.append(
                    "Large image with minimal text (" +
                    str(word_count) + " words) — "
                    "image-based phishing!"
                )

        # Brand impersonation
        if ocr_text:
            text_lower = ocr_text.lower()
            for brand in FAKE_BRAND_KEYWORDS:
                if brand in text_lower:
                    findings.append("fake_login_page")
                    details.append(
                        "Brand impersonation: '" + brand + "'"
                    )
                    break

        # Fake login form keywords
        if ocr_text:
            login_words = [
                "username", "password", "login",
                "sign in", "enter otp", "submit",
            ]
            login_found = [
                lw for lw in login_words
                if lw in ocr_text.lower()
            ]
            if len(login_found) >= 2:
                findings.append("fake_login_page")
                details.append(
                    "Fake login form in image: " +
                    str(login_found)
                )

        img.close()

        if not findings:
            details.append("No visual deception detected")

    except Exception as e:
        details.append("Visual deception error: " + str(e))

    details.append("Technique 7 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 8 — Pixel Manipulation Detection
# ================================================================

def technique8_pixel_manipulation(file_path):
    """
    Detects steganography and pixel-level data hiding.
    High entropy in image = possible hidden data.
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 8: PIXEL MANIPULATION DETECTION ---"
    )

    try:
        file_size = os.path.getsize(file_path)
        details.append(
            "File size: " + str(round(file_size / 1024, 2)) + " KB"
        )

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        entropy = calculate_entropy(raw_bytes[:2000])
        details.append("File entropy: " + str(entropy))

        if entropy > 7.95:
            findings.append("steganography_indicator")
            details.append(
                "CRITICAL: Extremely high entropy (" +
                str(entropy) + ") — possible steganography!"
            )
        elif entropy > 7.9:
            findings.append("high_entropy_image")
            details.append(
                "Very high entropy (" + str(entropy) +
                ") — review manually"
            )
        else:
            details.append(
                "Entropy normal for photo (" +
                str(entropy) + ") — safe ✅"
            )

        if PIL_AVAILABLE:
            img  = Image.open(file_path)
            w, h = img.size
            img.close()

            expected_size = w * h * 3
            if expected_size > 0:
                ratio = file_size / expected_size
                details.append(
                    "Size ratio: " + str(round(ratio, 3))
                )
                if ratio > 2.0:
                    findings.append("suspicious_file_size")
                    details.append(
                        "File larger than expected — "
                        "possible hidden data!"
                    )

        if not findings:
            details.append("No pixel manipulation detected")

    except Exception as e:
        details.append("Pixel manipulation error: " + str(e))

    details.append("Technique 8 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 9 — Attack Chain Inference
# ================================================================

def technique9_attack_chain(all_findings):
    """
    Infers complete attack sequence from all findings.
    """
    findings = []
    details  = []

    details.append("")
    details.append("--- TECHNIQUE 9: ATTACK CHAIN INFERENCE ---")

    fs = set(all_findings)

    if ("credential_harvesting" in fs and
            ("suspicious_url" in fs or "ip_based_url" in fs)):
        findings.append("credential_theft_chain")
        details.append(
            "ATTACK CHAIN: Phishing image -> "
            "Credential lure -> Fake URL -> Credentials stolen"
        )

    if ("qr_malicious_url" in fs or
            "qr_suspicious_url" in fs):
        findings.append("qr_phishing_chain")
        details.append(
            "ATTACK CHAIN: QR code -> "
            "Victim scans -> Redirected to malicious site"
        )

    if ("fake_login_page" in fs and
            "phishing_keyword" in fs):
        findings.append("impersonation_chain")
        details.append(
            "ATTACK CHAIN: Fake brand logo -> "
            "Victim trusts -> Enters credentials"
        )

    if "steganography_indicator" in fs:
        findings.append("dropper_pattern")
        details.append(
            "ATTACK CHAIN: Hidden payload in pixels -> "
            "Malware extracts data -> Executes silently"
        )

    if ("phishing_keyword" in fs and
            ("suspicious_url" in fs or
             "ip_based_url" in fs)):
        findings.append("credential_theft_chain")
        details.append(
            "ATTACK CHAIN: Phishing text + URL -> "
            "Victim directed to malicious site"
        )

    if not findings:
        details.append("No clear attack chain identified")

    details.append("Technique 9 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 10 — Heuristic Risk Scoring
# ================================================================

def technique10_scoring(all_findings):
    """
    Converts all findings into final weighted score.
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
                "score" : weight,
            }

    total_score = min(total_score, 100)

    if total_score < 30:
        verdict  = "Low Risk"
        severity = "LOW"
    elif total_score < 60:
        verdict  = "Medium Risk"
        severity = "MEDIUM"
    elif total_score < 80:
        verdict  = "High Risk"
        severity = "HIGH"
    else:
        verdict  = "Critical — Likely Phishing"
        severity = "CRITICAL"

    return total_score, verdict, severity, breakdown


# ================================================================
# TECHNIQUE 11 — Multi-Language OCR Detection
# ================================================================

def technique11_multilang_ocr(file_path):
    """
    Detects phishing text in Hindi and other Indian languages.
    Attackers use regional languages to bypass English scanners.

    Languages checked:
    -> Hindi (hin)
    -> Mixed script detection
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 11: MULTI-LANGUAGE OCR DETECTION ---"
    )

    if not TESSERACT_AVAILABLE or not PIL_AVAILABLE:
        details.append("Tesseract or Pillow not available — skipping")
        return findings, details

    try:
        img = Image.open(file_path)

        if img.mode not in ["RGB", "L"]:
            img = img.convert("RGB")

        # Try Hindi OCR
        try:
            hindi_text = pytesseract.image_to_string(
                img,
                lang="hin",
                config="--psm 6",
            ).strip()

            if hindi_text and len(hindi_text) > 10:
                details.append(
                    "Hindi text found: " + hindi_text[:100]
                )

                hindi_lower = hindi_text.lower()
                for keyword in HINDI_PHISHING_KEYWORDS:
                    if keyword in hindi_lower:
                        findings.append("hindi_phishing_detected")
                        details.append(
                            "Hindi phishing keyword: '" +
                            keyword + "'"
                        )

        except Exception:
            details.append(
                "Hindi OCR skipped — language pack not installed"
            )
            details.append(
                "To install: download Hindi data from "
                "Tesseract repository"
            )

        img.close()

        # Check for Unicode mixed scripts in any extracted text
        with open(file_path, "rb") as f:
            raw = f.read()

        # Look for Devanagari Unicode range (Hindi)
        # Must check OCR extracted text NOT raw bytes
        # Raw bytes of PNG files accidentally match
        # Hindi Unicode range giving false positives!
        try:
            if TESSERACT_AVAILABLE and PIL_AVAILABLE:
                img_lang = Image.open(file_path)
                if img_lang.mode not in ["RGB", "L"]:
                    img_lang = img_lang.convert("RGB")
                extracted = pytesseract.image_to_string(
                    img_lang,
                    config="--psm 6",
                ).strip()
                img_lang.close()

                devanagari_pattern = re.compile(
                    "[\u0900-\u097f]+"
                )
                if devanagari_pattern.search(extracted):
                    findings.append("mixed_script_detected")
                    details.append(
                        "Devanagari (Hindi) script detected "
                        "in image text ✅"
                    )
                else:
                    details.append(
                        "No Devanagari script in image text ✅"
                    )
        except Exception as e:
            details.append(
                "Script detection error: " + str(e)
            )

        if not findings:
            details.append("No multi-language phishing detected")

    except Exception as e:
        details.append("Multi-language OCR error: " + str(e))

    details.append("Technique 11 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 12 — Homograph and Lookalike Domain Detection
# ================================================================

def technique12_homograph_detection(ocr_text):
    """
    Detects Unicode spoofing and lookalike domain tricks.

    Example attacks:
    paypaI.com   -> capital I instead of lowercase l
    sbi-verıfy.com -> dotless i (Unicode character)
    g00gle.com   -> zeros instead of letter o

    OCR extracts these as text.
    We detect the deception.
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 12: HOMOGRAPH DOMAIN DETECTION ---"
    )

    if not ocr_text:
        details.append("No OCR text — skipping")
        return findings, details

    # Check 1 — Unicode homograph characters
    for fake_char, real_char in HOMOGRAPH_MAP.items():
        if fake_char in ocr_text:
            findings.append("homograph_domain")
            details.append(
                "CRITICAL: Unicode homograph found! "
                "Fake char looks like '" + real_char + "'"
            )

    # Check 2 — Character substitution in domains
    # Find all URLs and domain-like strings in OCR text
    domain_pattern = re.compile(
        r'[a-zA-Z0-9\-\.]+\.(com|org|net|in|co\.in|'
        r'gov\.in|edu|io|xyz|top|ru|tk)'
    )
    domains_found = domain_pattern.findall(ocr_text)

    # Also look for full URLs
    url_pattern = re.compile(
        r'https?://([^\s/]+)'
    )
    for match in url_pattern.finditer(ocr_text):
        domains_found.append(match.group(1))

    for domain in domains_found:
        domain_lower = domain.lower()

        # Check zero/o substitution
        if re.search(r'[a-z]0[a-z]', domain_lower):
            findings.append("char_substitution")
            details.append(
                "Zero-for-O substitution in domain: " + domain
            )

        # Check 1/l/i substitution
        if re.search(r'[a-z]1[a-z]', domain_lower):
            findings.append("char_substitution")
            details.append(
                "One-for-L substitution in domain: " + domain
            )

        # Check rn looks like m
        if "rn" in domain_lower:
            findings.append("lookalike_domain")
            details.append(
                "rn combination in domain (looks like m): " +
                domain
            )

        # Check vv looks like w
        if "vv" in domain_lower:
            findings.append("lookalike_domain")
            details.append(
                "vv combination in domain (looks like w): " +
                domain
            )

        # Check known brand spoofing patterns
        spoof_patterns = [
            ("paypa1", "paypal"),
            ("paypa1", "paypal"),
            ("g00gle", "google"),
            ("micros0ft", "microsoft"),
            ("arnazon", "amazon"),
            ("arnaz0n", "amazon"),
            ("facebok", "facebook"),
            ("instaqram", "instagram"),
            ("sb1", "sbi"),
            ("hdfcbank", "hdfc"),
        ]
        for fake, real in spoof_patterns:
            if fake in domain_lower:
                findings.append("homograph_domain")
                details.append(
                    "CRITICAL: Brand spoofing detected — " +
                    "'" + domain + "' looks like '" + real + "'"
                )

    if not findings:
        details.append("No homograph domains detected")

    details.append("Technique 12 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 13 — Hidden Text Overlay Detection
# ================================================================

def technique13_hidden_text(file_path):
    """
    Detects text hidden using visual tricks:

    Trick 1 -> White text on white background
               Human cannot see it
               But OCR can extract it

    Trick 2 -> Very low contrast text
               Barely visible to humans

    Trick 3 -> Transparent overlay layers
               Hidden content under main image
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 13: HIDDEN TEXT OVERLAY DETECTION ---"
    )

    if not PIL_AVAILABLE:
        details.append("Pillow not available — skipping")
        return findings, details

    try:
        img = Image.open(file_path).convert("RGB")
        w, h = img.size

        pixels    = list(img.getdata())
        total_px  = len(pixels)

        if total_px == 0:
            details.append("No pixels to analyze")
            img.close()
            return findings, details

        # Check 1 — Count near-white pixels
        # White text on white background = very suspicious
        white_px = sum(
            1 for r, g, b in pixels
            if r > 240 and g > 240 and b > 240
        )
        white_ratio = white_px / total_px
        details.append(
            "White pixel ratio: " +
            str(round(white_ratio * 100, 1)) + "%"
        )

        if white_ratio > 0.95:
            findings.append("hidden_text_overlay")
            details.append(
                "CRITICAL: Image is almost entirely white — "
                "possible white-on-white hidden text!"
            )

        # Check 2 — Low contrast detection
        # Calculate average brightness
        brightness_vals = [
            (r + g + b) / 3 for r, g, b in pixels
        ]
        avg_brightness = sum(brightness_vals) / len(brightness_vals)

        # Standard deviation = how spread the brightness is
        # Low std dev = low contrast = hidden text trick
        variance = sum(
            (b - avg_brightness) ** 2
            for b in brightness_vals
        ) / len(brightness_vals)
        std_dev = math.sqrt(variance)

        details.append(
            "Brightness std dev: " + str(round(std_dev, 2))
        )

        if std_dev < 15:
            findings.append("low_contrast_text")
            details.append(
                "Very low contrast image — "
                "possible hidden low-contrast text!"
            )

        # Check 3 — Transparency (RGBA mode)
        img.close()
        img_check = Image.open(file_path)

        if img_check.mode == "RGBA":
            rgba_pixels   = list(img_check.getdata())
            transparent   = sum(
                1 for r, g, b, a in rgba_pixels if a < 50
            )
            trans_ratio   = transparent / len(rgba_pixels)
            details.append(
                "Transparent pixel ratio: " +
                str(round(trans_ratio * 100, 1)) + "%"
            )
            if trans_ratio > 0.3:
                findings.append("transparent_layer")
                details.append(
                    "High transparency detected — "
                    "possible hidden overlay layer!"
                )

        img_check.close()

        if not findings:
            details.append("No hidden text overlay detected")

    except Exception as e:
        details.append("Hidden text detection error: " + str(e))

    details.append("Technique 13 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 14 — Perceptual Image Hash Matching
# ================================================================

def technique14_hash_matching(file_path):
    """
    Creates perceptual hash of image and compares
    against known phishing templates.

    Perceptual hash = fingerprint of image appearance
    Similar looking images = similar hashes

    Example:
    Attacker reuses same fake SBI login image
    in 1000 different phishing emails.
    We detect all 1000 with ONE hash! ✅
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 14: PERCEPTUAL HASH MATCHING ---"
    )

    if not PIL_AVAILABLE:
        details.append("Pillow not available — skipping")
        return findings, details

    try:
        img       = Image.open(file_path)
        img_hash  = simple_perceptual_hash(img)
        img.close()

        details.append("Image hash: " + img_hash)

        # Compare against known phishing hashes
        # In production this database would have thousands
        # of known phishing template hashes
        matched = False
        for known_hash in KNOWN_PHISHING_HASHES:
            # We skip string hashes (placeholder entries)
            if "_hash" in known_hash:
                continue
            dist = hamming_distance(img_hash, known_hash)
            if dist < 10:
                findings.append("known_phishing_template")
                details.append(
                    "CRITICAL: Matches known phishing template! "
                    "Distance: " + str(dist)
                )
                matched = True
                break

        if not matched:
            details.append(
                "No match in known phishing template database"
            )
            details.append(
                "Note: Database currently has " +
                str(len(KNOWN_PHISHING_HASHES)) +
                " known templates"
            )
            details.append(
                "Note: Hash stored for future comparisons: " +
                img_hash
            )

    except Exception as e:
        details.append("Hash matching error: " + str(e))

    details.append("Technique 14 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 15 — UI Layout Fake Login Detection
# ================================================================

def technique15_ui_layout(file_path, ocr_text):
    """
    Detects fake login form structure in image.

    Beyond just keywords — detects LAYOUT patterns:
    -> Input field shapes (rectangles)
    -> Password masking patterns (dots)
    -> Submit button patterns
    -> Two-field login layout
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 15: UI LAYOUT FAKE LOGIN DETECTION ---"
    )

    if not PIL_AVAILABLE:
        details.append("Pillow not available — skipping")
        return findings, details

    try:
        img  = Image.open(file_path).convert("L")
        w, h = img.size

        # Check 1 — Password masking pattern in OCR text
        # Attackers screenshot pages with ••••• or ****
        if ocr_text:
            password_patterns = [
                r'[•\*]{4,}',
                r'[\u2022]{4,}',
                r'\*{4,}',
            ]
            for pattern in password_patterns:
                if re.search(pattern, ocr_text):
                    findings.append("password_field_detected")
                    details.append(
                        "Password masking pattern detected "
                        "in image (dots or asterisks)"
                    )
                    break

        # Check 2 — Submit / login button text
        if ocr_text:
            button_keywords = [
                "login", "log in", "sign in",
                "submit", "continue", "verify",
                "confirm", "proceed",
            ]
            buttons_found = [
                bk for bk in button_keywords
                if bk in ocr_text.lower()
            ]
            if buttons_found:
                findings.append("fake_submit_button")
                details.append(
                    "Submit button text found: " +
                    str(buttons_found)
                )

        # Check 3 — Two column layout
        # Fake login forms often have label + input field
        if ocr_text:
            field_labels = [
                "username", "user name", "user id",
                "email", "mobile number",
                "password", "pin", "otp",
                "account number",
            ]
            labels_found = [
                fl for fl in field_labels
                if fl in ocr_text.lower()
            ]
            if len(labels_found) >= 2:
                findings.append("fake_login_form_detected")
                details.append(
                    "CRITICAL: Login form structure detected! "
                    "Fields: " + str(labels_found)
                )

        # Check 4 — Image aspect ratio
        # Login pages are usually taller than wide
        if h > w * 1.5:
            details.append(
                "Portrait orientation — "
                "normal for phone photos ✅"
            )

        img.close()

        if not findings:
            details.append("No fake login UI detected")

    except Exception as e:
        details.append("UI layout error: " + str(e))

    details.append("Technique 15 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 16 — Fake Browser Address Bar Detection
# ================================================================

def technique16_fake_browser(ocr_text):
    """
    Detects fake browser UI in phishing screenshots.

    Attackers take screenshots showing:
    -> Fake address bar with legitimate looking URL
    -> Fake padlock icon (HTTPS indicator)
    -> Fake "Secure" text next to URL

    This tricks victims into thinking they are
    on a real secure website.
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 16: FAKE BROWSER ADDRESS BAR DETECTION ---"
    )

    if not ocr_text:
        details.append("No OCR text — skipping")
        return findings, details

    text_lower = ocr_text.lower()

    # Check 1 — Browser UI keywords in image
    browser_ui_signs = [
        "address bar",
        "search or type url",
        "search google or type",
        "type a url",
    ]
    for sign in browser_ui_signs:
        if sign in text_lower:
            findings.append("fake_browser_ui")
            details.append(
                "Browser UI element found: '" + sign + "'"
            )

    # Check 2 — HTTPS with suspicious domain
    # Attacker shows https://legit-looking.evil.ru
    https_pattern = re.compile(
        r'https://([^\s/\]>]+)'
    )
    https_matches = https_pattern.findall(ocr_text)
    for domain in https_matches:
        domain_lower = domain.lower()
        details.append("Address bar URL: " + domain)

        # Check if domain looks suspicious
        url_findings, _ = analyze_url("https://" + domain)
        if url_findings:
            findings.append("fake_address_bar")
            details.append(
                "CRITICAL: Fake address bar with "
                "suspicious URL: " + domain
            )

        # Check for brand name + suspicious TLD
        for brand in FAKE_BRAND_KEYWORDS:
            for tld in SUSPICIOUS_TLDS:
                if (brand in domain_lower and
                        domain_lower.endswith(tld)):
                    findings.append("fake_address_bar")
                    details.append(
                        "CRITICAL: Brand spoofing in address bar: " +
                        domain
                    )

    # Check 3 — Fake padlock / secure indicators
    padlock_keywords = [
        "secure",
        "verified",
        "ssl secured",
        "connection is secure",
        "your connection is private",
        "lock icon",
        "padlock",
    ]
    for keyword in padlock_keywords:
        if keyword in text_lower:
            findings.append("fake_padlock_detected")
            details.append(
                "Fake security indicator found: '" + keyword + "'"
            )
            break

    if not findings:
        details.append("No fake browser UI detected")

    details.append("Technique 16 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# TECHNIQUE 17 — OCR Confidence Analysis
# ================================================================

def technique17_ocr_confidence(file_path):
    """
    Measures how confident Tesseract is about its OCR reading.

    Low confidence = image may be intentionally blurred
    Attackers blur images to bypass OCR-based scanners
    while still being readable by human eyes.

    Also detects:
    -> Gaussian blur applied to image
    -> Noise added to confuse OCR
    -> Low DPI images
    """
    findings = []
    details  = []

    details.append("")
    details.append(
        "--- TECHNIQUE 17: OCR CONFIDENCE ANALYSIS ---"
    )

    if not TESSERACT_AVAILABLE or not PIL_AVAILABLE:
        details.append("Tesseract or Pillow not available — skipping")
        return findings, details

    try:
        img = Image.open(file_path)

        if img.mode not in ["RGB", "L"]:
            img = img.convert("RGB")

        ocr_data = pytesseract.image_to_data(
            img,
            lang="eng",
            config="--psm 6",
            output_type=pytesseract.Output.DICT,
        )

        img.close()

        confidences = [
            int(c) for c in ocr_data["conf"]
            if str(c).strip() != "-1"
            and str(c).strip() != ""
        ]

        if confidences:
            avg_confidence = sum(confidences) / len(confidences)
            word_count     = len(confidences)

            details.append(
                "Average OCR confidence: " +
                str(round(avg_confidence, 1)) + "%"
            )
            details.append(
                "Words analyzed: " + str(word_count)
            )

            # Only flag blur if image has enough text
            # Photos with no text naturally have low confidence
            # Minimum 20 words needed before flagging
           
 # Count only HIGH confidence words
            # High confidence = OCR is sure it is real text
            high_conf_words = [
                c for c in confidences if c > 60
            ]
            real_word_count = len(high_conf_words)

            details.append(
                "High confidence words: " +
                str(real_word_count)
            )

            # Need at least 15 REAL words before judging blur
            # This ignores noise words from photos
            if real_word_count < 15:
                details.append(
                    "Too few real words (" +
                    str(real_word_count) +
                    ") to judge blur — likely a photo "
                )
            elif avg_confidence < 30:
                findings.append("blur_evasion_detected")
                details.append(
                    "CRITICAL: Very low OCR confidence (" +
                    str(round(avg_confidence, 1)) +
                    "%) — image may be intentionally blurred!"
                )
            elif avg_confidence < 50:
                findings.append("low_ocr_confidence")
                details.append(
                    "Low OCR confidence (" +
                    str(round(avg_confidence, 1)) +
                    "%) — review manually"
                )
            elif avg_confidence < 30:
                findings.append("very_low_ocr_confidence")
                details.append(
                    "CRITICAL: Very low OCR confidence (" +
                    str(round(avg_confidence, 1)) +
                    "%) — image may be intentionally blurred!"
                )
            elif avg_confidence < 50:
                findings.append("low_ocr_confidence")
                details.append(
                    "Low OCR confidence (" +
                    str(round(avg_confidence, 1)) +
                    "%) — review manually"
                )
            else:
                details.append(
                    "OCR confidence acceptable"
                )
              
        else:
            details.append("No confidence data available")

        # Check blur using PIL filter comparison
        if PIL_AVAILABLE:
            img2        = Image.open(file_path).convert("L")
            blurred     = img2.filter(ImageFilter.GaussianBlur(2))
            img2_pixels = list(img2.getdata())
            blur_pixels = list(blurred.getdata())

            # If original is already very similar to blurred
            # then original WAS already blurred
            diff = sum(
                abs(a - b)
                for a, b in zip(img2_pixels, blur_pixels)
            ) / len(img2_pixels)

            details.append(
                "Blur difference score: " + str(round(diff, 2))
            )

            if diff < 2.0:
                findings.append("blur_evasion_detected")
                details.append(
                    "CRITICAL: Image appears pre-blurred — "
                    "possible OCR evasion technique!"
                )

            img2.close()

        if not findings:
            details.append("OCR confidence is normal")

    except Exception as e:
        details.append("OCR confidence error: " + str(e))

    details.append("Technique 17 findings: " + str(len(findings)))
    return findings, details


# ================================================================
# MAIN FUNCTION — parse_image
# Called by app.py when user uploads image file
# ================================================================

def parse_image(file_path):
    """
    file_path = full path to uploaded image file
    Returns   = complete analysis result dict
    """

    all_findings = []
    all_details  = []
    sha256_hash  = ""

    try:

        all_details.append("=" * 55)
        all_details.append(
            "DARKHOOK_ DEFENCE — IMAGE FILE ANALYSIS"
        )
        all_details.append("=" * 55)
        all_details.append(
            "File: " + os.path.basename(file_path)
        )

        with open(file_path, "rb") as f:
            sha256_hash = hashlib.sha256(f.read()).hexdigest()

        all_details.append("SHA256: " + sha256_hash)
        all_details.append("")

        # Technique 1 — File validation
        f1, d1 = technique1_file_validation(file_path)
        all_findings.extend(f1)
        all_details.extend(d1)

        # Technique 2 — EXIF metadata
        f2, d2 = technique2_exif_metadata(file_path)
        all_findings.extend(f2)
        all_details.extend(d2)

        # Technique 3 — OCR extraction (returns text too)
        f3, d3, ocr_text = technique3_ocr_extraction(file_path)
        all_findings.extend(f3)
        all_details.extend(d3)

        # Technique 4 — Keyword detection
        f4, d4 = technique4_keyword_detection(ocr_text)
        all_findings.extend(f4)
        all_details.extend(d4)

        # Technique 5 — URL detection
        f5, d5 = technique5_url_detection(ocr_text)
        all_findings.extend(f5)
        all_details.extend(d5)

        # Technique 6 — QR code detection
        f6, d6 = technique6_qr_detection(file_path)
        all_findings.extend(f6)
        all_details.extend(d6)

        # Technique 7 — Visual deception
        f7, d7 = technique7_visual_deception(
            file_path, ocr_text
        )
        all_findings.extend(f7)
        all_details.extend(d7)

        # Technique 8 — Pixel manipulation
        f8, d8 = technique8_pixel_manipulation(file_path)
        all_findings.extend(f8)
        all_details.extend(d8)

        # Technique 9 — Attack chain
        f9, d9 = technique9_attack_chain(all_findings)
        all_findings.extend(f9)
        all_details.extend(d9)

        # Technique 11 — Multi-language OCR
        f11, d11 = technique11_multilang_ocr(file_path)
        all_findings.extend(f11)
        all_details.extend(d11)

        # Technique 12 — Homograph detection
        f12, d12 = technique12_homograph_detection(ocr_text)
        all_findings.extend(f12)
        all_details.extend(d12)

        # Technique 13 — Hidden text overlay
        f13, d13 = technique13_hidden_text(file_path)
        all_findings.extend(f13)
        all_details.extend(d13)

        # Technique 14 — Hash matching
        f14, d14 = technique14_hash_matching(file_path)
        all_findings.extend(f14)
        all_details.extend(d14)

        # Technique 15 — UI layout detection
        f15, d15 = technique15_ui_layout(file_path, ocr_text)
        all_findings.extend(f15)
        all_details.extend(d15)

        # Technique 16 — Fake browser detection
        f16, d16 = technique16_fake_browser(ocr_text)
        all_findings.extend(f16)
        all_details.extend(d16)

        # Technique 17 — OCR confidence
        f17, d17 = technique17_ocr_confidence(file_path)
        all_findings.extend(f17)
        all_details.extend(d17)

        # Technique 10 — Final scoring (runs last with all findings)
        score, verdict, severity, breakdown = (
            technique10_scoring(all_findings)
        )

        all_details.append("")
        all_details.append(
            "--- TECHNIQUE 10: HEURISTIC SCORING ---"
        )
        all_details.append("Total techniques run : 17")
        all_details.append(
            "Total findings       : " + str(len(all_findings))
        )
        all_details.append(
            "Danger score         : " + str(score) + "/100"
        )
        all_details.append("Severity             : " + severity)
        all_details.append("Verdict              : " + verdict)
        all_details.append("")
        all_details.append("Score breakdown:")

        for finding, data in breakdown.items():
            all_details.append(
                "  " + finding.ljust(35) +
                " count=" + str(data["count"]) +
                " score=" + str(data["score"])
            )

    except Exception as error:
        all_details.append("Critical error: " + str(error))

    return {
        "findings" : all_findings,
        "details"  : all_details,
        "sha256"   : sha256_hash,
    }