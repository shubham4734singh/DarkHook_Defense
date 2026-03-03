# ============================================================
# scorer.py — DarkHOOK_ Defence
# Purpose : Takes findings from all parsers
#           and returns a danger score 0 to 100
# ============================================================


# ----------------------------------------------------------
# SCORING WEIGHTS
# Each type of finding has a danger weight assigned to it.
# Higher weight = more dangerous finding
# ----------------------------------------------------------

WEIGHTS = {
    # General findings
    "suspicious_url"     : 15,   # Suspicious link found
    "malicious_macro"    : 40,   # Dangerous macro in Word/Excel
    "hidden_script"      : 25,   # Hidden script inside file
    "qr_malicious_url"   : 20,   # QR code pointing to bad URL
    "phishing_keyword"   : 10,   # Phishing words like "verify account"
    "suspicious_domain"  : 15,   # Known bad domain found
    "embedded_object"    : 20,   # Suspicious embedded object
    "ocr_phishing_text"  : 10,   # Phishing text found in image
    
    # PDF-specific structural findings
    "javascript_detected"      : 40,  # Embedded JavaScript in PDF
    "openaction_detected"      : 35,  # Auto-execute on open
    "launch_action_detected"   : 35,  # Launch external application
    "embedded_file_detected"   : 30,  # Hidden embedded files
    "high_object_count"        : 15,  # Suspicious number of objects
    "encrypted_object"         : 20,  # Encrypted content
    "acroform_detected"        : 20,  # Forms (credential harvesting)
    "xfa_form_detected"        : 25,  # XFA forms
    
    # PDF content findings
    "urgent_tone_detected"     : 15,  # Urgent/pressure language
    "financial_terms_detected" : 15,  # Banking/payment terms
    "credential_harvesting"    : 20,  # Password/login requests
    
    # PDF URL findings
    "ip_based_url"             : 30,  # IP address instead of domain
    "shortened_url"            : 20,  # URL shorteners
    "suspicious_tld"           : 20,  # Suspicious domain extensions
    "at_symbol_trick"          : 25,  # @ symbol URL obfuscation
    "mismatched_anchor"        : 25,  # Link text doesn't match URL
    "homograph_domain"         : 30,  # Unicode domain spoofing
    
    # PDF image findings
    "single_image_pdf"         : 25,  # PDF with single image only
    "clickable_image_overlay"  : 20,  # Image with hidden link
    
    # PDF behavioral findings
    "base64_payload"           : 35,  # Base64 encoded content
    "hex_payload"              : 30,  # Hex encoded content
    "high_entropy_string"      : 25,  # Random/obfuscated strings
    "powershell_detected"      : 40,  # PowerShell commands
    "external_network_call"    : 30,  # Network connections
    "dropper_pattern"          : 40,  # Malware dropper indicators
    "split_string_concat"      : 20,  # String obfuscation
    "embedded_executable"      : 45,  # Embedded EXE/DLL files
    
    # DOCX-specific file structure findings
    "file_type_mismatch"         : 40,  # File extension doesn't match content
    "corrupted_structure"        : 30,  # Corrupted or malformed structure
    "double_extension"           : 35,  # Double extension trick
    "malformed_zip"              : 25,  # DOCX has bad ZIP structure
    
    # DOCX metadata findings
    "suspicious_metadata"        : 15,  # Suspicious author/creator info
    "wiped_metadata"             : 20,  # Metadata intentionally removed
    "metadata_mismatch"          : 20,  # Metadata inconsistencies
    "suspicious_template"        : 25,  # Suspicious template reference
    
    # DOCX macro findings
    "autoopen_macro"             : 35,  # Auto-execute macro
    "hidden_macro_stream"        : 35,  # Hidden VBA streams
    
    # DOCX VBA behavior findings
    "suspicious_vba_api"         : 30,  # Suspicious API calls in VBA
    "powershell_in_vba"          : 40,  # PowerShell execution from VBA
    "network_call_in_vba"        : 35,  # Network calls from VBA
    "file_system_access"         : 25,  # File system operations
    "registry_access"            : 30,  # Windows registry access
    "process_creation"           : 35,  # Creating new processes
    
    # DOCX obfuscation findings
    "encoded_macro_payload"      : 35,  # Encoded/obfuscated macro code
    "string_obfuscation"         : 25,  # Obfuscated strings
    "junk_code_detected"         : 15,  # Intentional junk/dead code
    
    # DOCX embedded object findings
    "embedded_ole_object"        : 30,  # Embedded OLE objects
    "embedded_script"            : 40,  # Embedded script files
    "double_extension_payload"   : 40,  # Embedded file with double extension
    
    # DOCX external resource findings
    "external_template"          : 35,  # External template loading
    "external_image_tracker"     : 20,  # External image for tracking
    "suspicious_relationship"    : 25,  # Suspicious document relationships
    "hidden_relationship"        : 30,  # Hidden relationship entries
    
    # DOCX content findings
    "enable_macro_lure"          : 35,  # Text trying to trick user to enable macros
    "repeated_cta"               : 15,  # Repeated call-to-action phrases
    "hidden_hyperlink"           : 25,  # Hidden or obfuscated hyperlinks
    
    # DOCX attack chain findings
    "download_execute_pattern"   : 40,  # Download and execute pattern detected
    "multistage_indicator"       : 35,  # Multi-stage attack indicators
    
    # DOCX reputation findings
    "known_malicious_hash"       : 100, # Known malicious file hash
    "known_macro_signature"      : 45,  # Known malicious macro signature
}


# ----------------------------------------------------------
# MAIN SCORING FUNCTION
# This is the function all parsers will call.
# It receives a list of findings and returns final score.
# ----------------------------------------------------------

def calculate_score(findings):
    """
    findings = list of finding types detected by parsers
    Example : ["suspicious_url", "suspicious_url", "malicious_macro"]

    Returns  : score (integer between 0 and 100)
               verdict (string — Safe / Suspicious / Dangerous)
               breakdown (dict — what contributed how much)
    """

    # Start score at zero
    total_score = 0

    # Track what contributed how much
    breakdown = {}

    # Loop through each finding
    for finding in findings:

        # Check if this finding type exists in our weights
        if finding in WEIGHTS:

            # Add its weight to total score
            total_score += WEIGHTS[finding]

            # Track in breakdown
            if finding in breakdown:
                breakdown[finding] += WEIGHTS[finding]
            else:
                breakdown[finding] = WEIGHTS[finding]

    # Cap the score at 100 — cannot go above 100
    if total_score > 100:
        total_score = 100

    # Decide verdict based on score
    verdict = get_verdict(total_score)

    # Return all three things
    return {
        "score"     : total_score,
        "verdict"   : verdict,
        "breakdown" : breakdown
    }


# ----------------------------------------------------------
# VERDICT FUNCTION
# Converts number score into human readable verdict
# ----------------------------------------------------------

def get_verdict(score):
    """
    0  to 25  → Safe
    26 to 55  → Suspicious
    56 to 79  → High Risk
    80 to 100 → Dangerous
    """

    if score <= 25:
        return "Safe ✅"
    elif score <= 55:
        return "Suspicious ⚠️"
    elif score <= 79:
        return "High Risk 🔴"
    else:
        return "Dangerous ☠️"
