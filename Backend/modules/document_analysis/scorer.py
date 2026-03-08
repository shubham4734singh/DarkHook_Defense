"""
Centralized scoring for document-analysis parsers.

Any new finding key added in a parser should be assigned a weight here.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable

# ============================================================
# SCORING WEIGHTS
# ============================================================

DEFAULT_UNKNOWN_FINDING_WEIGHT = 5

WEIGHTS: Dict[str, int] = {
    # GENERAL FINDINGS
    "suspicious_url": 15,
    "malicious_macro": 40,
    "hidden_script": 25,
    "qr_malicious_url": 40,
    "phishing_keyword": 10,
    "suspicious_domain": 15,
    "embedded_object": 20,
    "ocr_phishing_text": 10,

    # FILE STRUCTURE FINDINGS
    "file_type_mismatch": 40,
    "corrupted_structure": 30,
    "double_extension": 35,
    "malformed_zip": 25,
    "xlsm_file": 20,
    "xlsb_file": 25,

    # METADATA FINDINGS
    "suspicious_metadata": 15,
    "wiped_metadata": 20,
    "metadata_mismatch": 20,
    "suspicious_template": 25,

    # MACRO FINDINGS
    "autoopen_macro": 35,
    "hidden_macro_stream": 35,

    # VBA BEHAVIOR FINDINGS
    "suspicious_vba_api": 30,
    "powershell_in_vba": 40,
    "network_call_in_vba": 35,
    "file_system_access": 25,
    "registry_access": 30,
    "process_creation": 35,

    # OBFUSCATION FINDINGS
    "encoded_macro_payload": 35,
    "high_entropy_string": 25,
    "string_obfuscation": 25,
    "junk_code_detected": 15,

    # EMBEDDED OBJECT FINDINGS
    "embedded_ole_object": 30,
    "embedded_executable": 45,
    "embedded_script": 40,
    "double_extension_payload": 40,

    # EXTERNAL RESOURCE FINDINGS
    "external_template": 35,
    "external_image_tracker": 20,
    "suspicious_relationship": 25,
    "hidden_relationship": 30,
    "dde_attack": 45,

    # PDF SPECIFIC FINDINGS
    "javascript_detected": 40,
    "openaction_detected": 35,
    "openaction_trigger": 35,
    "launch_action_detected": 35,
    "launch_action": 40,
    "embedded_file_detected": 30,
    "embedded_file_in_pdf": 35,
    "high_object_count": 15,
    "encrypted_object": 20,
    "acroform_detected": 20,
    "xfa_form_detected": 25,
    "embedded_executable_pdf": 45,
    "object_stream": 20,
    "powershell_in_pdf": 40,
    "dropper_in_pdf": 40,
    "base64_in_pdf": 30,
    "base64_payload": 35,
    "hex_in_pdf": 25,
    "hex_payload": 30,
    "high_entropy_pdf": 25,
    "nearly_empty_page": 20,
    "single_image_pdf": 25,
    "clickable_image_overlay": 25,
    "missing_metadata_pdf": 15,
    "powershell_detected": 40,
    "external_network_call": 30,
    "split_string_concat": 20,

    # CONTENT FINDINGS
    "urgent_tone_detected": 15,
    "financial_terms_detected": 15,
    "credential_harvesting": 20,
    "enable_macro_lure": 35,
    "repeated_cta": 15,

    # URL FINDINGS
    "ip_based_url": 30,
    "shortened_url": 20,
    "suspicious_tld": 20,
    "at_symbol_trick": 25,
    "hidden_hyperlink": 25,
    "mismatched_anchor": 25,
    "homograph_domain": 30,

    # ATTACK CHAIN FINDINGS
    "dropper_pattern": 40,
    "download_execute_pattern": 40,
    "multistage_indicator": 35,

    # REPUTATION FINDINGS
    "known_malicious_hash": 100,
    "known_macro_signature": 45,

    # XLM MACRO FINDINGS
    "xlm_macro_detected": 40,
    "xlm_exec_command": 45,
    "xlm_run_command": 40,
    "xlm_call_command": 40,

    # HIDDEN SHEET FINDINGS
    "hidden_sheet": 25,
    "very_hidden_sheet": 40,

    # FORMULA INJECTION FINDINGS
    "formula_hyperlink_injection": 35,
    "webservice_formula": 45,
    "formula_obfuscation": 30,
    "char_concat_formula": 25,

    # POWER QUERY FINDINGS
    "power_query_connection": 35,
    "suspicious_connection": 40,
    "ole_db_connection": 30,
    "external_data_connection": 30,

    # OCR / IMAGE FINDINGS
    "invalid_image_format": 30,
    "suspicious_exif": 15,
    "wiped_exif": 5,
    "edited_image": 15,
    "ocr_failed": 10,
    "low_text_density": 15,
    "single_image_content": 20,
    "qr_code_detected": 15,
    "qr_suspicious_url": 25,
    "fake_login_page": 35,
    "blurred_image": 20,
    "high_entropy_image": 25,
    "suspicious_file_size": 20,
    "steganography_indicator": 35,
    "multilang_phishing_text": 25,
    "hindi_phishing_detected": 25,
    "mixed_script_detected": 20,
    "lookalike_domain": 30,
    "char_substitution": 25,
    "hidden_text_overlay": 40,
    "low_contrast_text": 30,
    "transparent_layer": 35,
    "known_phishing_template": 45,
    "template_reuse_detected": 40,
    "fake_login_form_detected": 40,
    "password_field_detected": 30,
    "fake_submit_button": 25,
    "fake_browser_ui": 35,
    "fake_address_bar": 40,
    "fake_padlock_detected": 30,
    "low_ocr_confidence": 20,
    "very_low_ocr_confidence": 30,
    "blur_evasion_detected": 30,
    "credential_theft_chain": 40,
    "qr_phishing_chain": 40,
    "impersonation_chain": 35,

    # PPT FINDINGS
    "invalid_ppt_format": 30,
    "pps_file": 20,
    "suspicious_author": 15,
    "low_revision_count": 10,
    "vba_macro_detected": 30,
    "autorun_macro": 40,
    "ppt_autoopen": 40,
    "shell_command": 40,
    "suspicious_animation": 30,
    "cmd_trigger_found": 40,
    "zero_delay_trigger": 25,
    "mouseover_trigger": 20,
    "package_object": 35,
    "mz_header_found": 45,
    "external_relationship": 25,
    "suspicious_external_url": 30,
    "ip_based_external": 35,
    "template_injection": 40,
    "image_tracker": 20,
    "hidden_slide": 25,
    "hidden_slide_with_content": 35,
    "char_concat_obfuscation": 25,
    "string_split_obfuscation": 25,
    "action_button_found": 20,
    "run_program_action": 45,
    "macro_action_button": 40,
    "mouseover_action": 30,
    "invisible_button": 35,
    "suspicious_media_file": 25,
    "media_type_mismatch": 35,
    "large_media_file": 15,
    "high_entropy_media": 25,
    "remote_template_attack": 40,
    "social_engineering_chain": 35,
    "hidden_payload_chain": 40,
    "click_execute_chain": 40,
}


def get_verdict(score: int) -> str:
    """
    0 to 39   -> Safe
    40 to 69  -> Suspicious
    70 to 100 -> Phishing
    """
    if score <= 39:
        return "Safe"
    if score <= 69:
        return "Suspicious"
    return "Phishing"


def calculate_score(findings: Iterable[str]) -> Dict[str, Any]:
    """
    Returns:
      - score (0-100)
      - verdict
      - severity (LOW/MEDIUM/HIGH/CRITICAL)
      - breakdown: {finding_key: {count, score}}
    """
    total_score = 0
    breakdown: Dict[str, Dict[str, int]] = {}

    for finding in findings:
        weight = WEIGHTS.get(finding, DEFAULT_UNKNOWN_FINDING_WEIGHT)
        total_score += weight

        if finding in breakdown:
            breakdown[finding]["count"] += 1
            breakdown[finding]["score"] += weight
        else:
            breakdown[finding] = {"count": 1, "score": weight}

    total_score = min(total_score, 100)
    verdict = get_verdict(total_score)

    if total_score <= 39:
        severity = "LOW"
    elif total_score <= 69:
        severity = "MEDIUM"
    else:
        severity = "CRITICAL"

    return {
        "score": total_score,
        "verdict": verdict,
        "severity": severity,
        "breakdown": breakdown,
    }
