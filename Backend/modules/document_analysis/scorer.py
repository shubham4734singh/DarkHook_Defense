# ============================================================
# scorer.py — DarkHOOK_ Defence
# Version  : 2.0 — Updated for ALL parsers
# Purpose  : Central scoring engine for all file parsers
#
# Used by:
#   -> pdf_parser.py
#   -> docx_parser.py
#   -> excel_parser.py
#   -> ppt_parser.py   (coming soon)
#   -> ocr_parser.py   (coming soon)
#
# IMPORTANT RULE:
# Any new finding type added to ANY parser
# MUST also be added here with correct weight.
# ============================================================


# ============================================================
# SCORING WEIGHTS
# Each type of finding has a danger weight assigned to it.
# Higher weight = more dangerous finding
#
# Scale:
# 10-20  = Low danger    (suspicious but common)
# 25-35  = Medium danger (clearly suspicious)
# 40-50  = High danger   (very suspicious)
# 100    = Critical      (confirmed malicious)
# ============================================================

WEIGHTS = {

    # --------------------------------------------------------
    # GENERAL FINDINGS
    # From: all parsers
    # --------------------------------------------------------
    "suspicious_url"             : 15,
    "malicious_macro"            : 40,
    "hidden_script"              : 25,
    "qr_malicious_url"           : 20,
    "phishing_keyword"           : 10,
    "suspicious_domain"          : 15,
    "embedded_object"            : 20,
    "ocr_phishing_text"          : 10,

    # --------------------------------------------------------
    # FILE STRUCTURE FINDINGS
    # From: docx_parser, excel_parser
    # --------------------------------------------------------
    "file_type_mismatch"         : 40,
    "corrupted_structure"        : 30,
    "double_extension"           : 35,
    "malformed_zip"              : 25,
    "xlsm_file"                  : 20,
    "xlsb_file"                  : 25,

    # --------------------------------------------------------
    # METADATA FINDINGS
    # From: docx_parser, excel_parser
    # --------------------------------------------------------
    "suspicious_metadata"        : 15,
    "wiped_metadata"             : 20,
    "metadata_mismatch"          : 20,
    "suspicious_template"        : 25,

    # --------------------------------------------------------
    # MACRO FINDINGS
    # From: docx_parser, excel_parser
    # --------------------------------------------------------
    "autoopen_macro"             : 35,
    "hidden_macro_stream"        : 35,

    # --------------------------------------------------------
    # VBA BEHAVIOR FINDINGS
    # From: docx_parser, excel_parser
    # --------------------------------------------------------
    "suspicious_vba_api"         : 30,
    "powershell_in_vba"          : 40,
    "network_call_in_vba"        : 35,
    "file_system_access"         : 25,
    "registry_access"            : 30,
    "process_creation"           : 35,

    # --------------------------------------------------------
    # OBFUSCATION FINDINGS
    # From: docx_parser, excel_parser, pdf_parser
    # --------------------------------------------------------
    "encoded_macro_payload"      : 35,
    "high_entropy_string"        : 25,
    "string_obfuscation"         : 25,
    "junk_code_detected"         : 15,

    # --------------------------------------------------------
    # EMBEDDED OBJECT FINDINGS
    # From: docx_parser, excel_parser
    # --------------------------------------------------------
    "embedded_ole_object"        : 30,
    "embedded_executable"        : 45,
    "embedded_script"            : 40,
    "double_extension_payload"   : 40,

    # --------------------------------------------------------
    # EXTERNAL RESOURCE FINDINGS
    # From: docx_parser, excel_parser
    # --------------------------------------------------------
    "external_template"          : 35,
    "external_image_tracker"     : 20,
    "suspicious_relationship"    : 25,
    "hidden_relationship"        : 30,
    "dde_attack"                 : 45,

    # --------------------------------------------------------
    # PDF SPECIFIC FINDINGS
    # From: pdf_parser
    # --------------------------------------------------------
    "javascript_detected"        : 40,
    "openaction_detected"        : 35,
    "openaction_trigger"         : 35,
    "launch_action_detected"     : 35,
    "launch_action"              : 40,
    "embedded_file_detected"     : 30,
    "embedded_file_in_pdf"       : 35,
    "high_object_count"          : 15,
    "encrypted_object"           : 20,
    "acroform_detected"          : 20,
    "xfa_form_detected"          : 25,
    "embedded_executable_pdf"    : 45,
    "object_stream"              : 20,
    "powershell_in_pdf"          : 40,
    "dropper_in_pdf"             : 40,
    "base64_in_pdf"              : 30,
    "base64_payload"             : 35,
    "hex_in_pdf"                 : 25,
    "hex_payload"                : 30,
    "high_entropy_pdf"           : 25,
    "nearly_empty_page"          : 20,
    "single_image_pdf"           : 25,
    "clickable_image_overlay"    : 25,
    "missing_metadata_pdf"       : 15,
    "powershell_detected"        : 40,
    "external_network_call"      : 30,
    "split_string_concat"        : 20,

    # --------------------------------------------------------
    # CONTENT FINDINGS
    # From: all parsers
    # --------------------------------------------------------
    "urgent_tone_detected"       : 15,
    "financial_terms_detected"   : 15,
    "credential_harvesting"      : 20,
    "enable_macro_lure"          : 35,
    "repeated_cta"               : 15,

    # --------------------------------------------------------
    # URL FINDINGS
    # From: all parsers
    # --------------------------------------------------------
    "ip_based_url"               : 30,
    "shortened_url"              : 20,
    "suspicious_tld"             : 20,
    "at_symbol_trick"            : 25,
    "hidden_hyperlink"           : 25,
    "mismatched_anchor"          : 25,
    "homograph_domain"           : 30,

    # --------------------------------------------------------
    # ATTACK CHAIN FINDINGS
    # From: all parsers
    # --------------------------------------------------------
    "dropper_pattern"            : 40,
    "download_execute_pattern"   : 40,
    "multistage_indicator"       : 35,

    # --------------------------------------------------------
    # REPUTATION FINDINGS
    # From: all parsers
    # --------------------------------------------------------
    "known_malicious_hash"       : 100,
    "known_macro_signature"      : 45,

    # --------------------------------------------------------
    # XLM MACRO FINDINGS — NEW
    # From: excel_parser
    # --------------------------------------------------------
    "xlm_macro_detected"         : 40,
    "xlm_exec_command"           : 45,
    "xlm_run_command"            : 40,
    "xlm_call_command"           : 40,

    # --------------------------------------------------------
    # HIDDEN SHEET FINDINGS — NEW
    # From: excel_parser
    # --------------------------------------------------------
    "hidden_sheet"               : 25,
    "very_hidden_sheet"          : 40,

    # --------------------------------------------------------
    # FORMULA INJECTION FINDINGS — NEW
    # From: excel_parser
    # --------------------------------------------------------
    "formula_hyperlink_injection": 35,
    "webservice_formula"         : 45,
    "formula_obfuscation"        : 30,
    "char_concat_formula"        : 25,

    # --------------------------------------------------------
    # POWER QUERY FINDINGS — NEW
    # From: excel_parser
    # --------------------------------------------------------
    "power_query_connection"     : 35,
    "suspicious_connection"      : 40,
    "ole_db_connection"          : 30,
    "external_data_connection"   : 30,
}


# ============================================================
# VERDICT FUNCTION
# Converts number score into human readable verdict
# ============================================================

def get_verdict(score):
    """
    0  to 25  -> Safe
    26 to 55  -> Suspicious
    56 to 79  -> High Risk
    80 to 100 -> Dangerous
    """
    if score <= 25:
        return "Safe"
    elif score <= 55:
        return "Suspicious"
    elif score <= 79:
        return "High Risk"
    else:
        return "Dangerous — Likely Phishing"


# ============================================================
# MAIN SCORING FUNCTION
# Called by every parser after scanning is complete.
#
# How to call from any parser:
#   from modules.document_analysis.scorer import calculate_score
#   result  = calculate_score(findings)
#   score   = result["score"]
#   verdict = result["verdict"]
# ============================================================

def calculate_score(findings):
    """
    findings = list of finding strings from any parser
    Example  : ["malicious_macro", "autoopen_macro"]

    Returns dictionary with:
        score     = danger number 0 to 100
        verdict   = text like Safe or Dangerous
        severity  = text like LOW or CRITICAL
        breakdown = dict showing each finding and its points
    """

    total_score = 0
    breakdown   = {}

    for finding in findings:

        # Look up weight — default 5 if not found
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

    # Cap at 100
    total_score = min(total_score, 100)

    # Get verdict
    verdict = get_verdict(total_score)

    # Get severity label
    if total_score <= 25:
        severity = "LOW"
    elif total_score <= 55:
        severity = "MEDIUM"
    elif total_score <= 79:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    return {
        "score"     : total_score,
        "verdict"   : verdict,
        "severity"  : severity,
        "breakdown" : breakdown,
    }