"""
Centralized scoring for document-analysis parsers.

Any new finding key added in a parser should be assigned a weight here.
Provides MITRE ATT&CK framework mapping for enterprise SOC visibility.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

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
    "suspicious_zip_bomb": 45,
    "xlsm_file": 20,
    "xlsb_file": 25,
    "docm_file": 20,

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
    "powershell_encoded_command": 45,
    "network_call_in_vba": 35,
    "file_system_access": 25,
    "registry_access": 30,
    "process_creation": 35,

    # OBFUSCATION FINDINGS
    "encoded_macro_payload": 35,
    "high_entropy_string": 25,
    "string_obfuscation": 25,
    "junk_code_detected": 15,
    "chr_obfuscation_detected": 30,
    "reverse_string_obfuscation": 30,
    "deobfuscated_malicious_url": 40,
    "deobfuscated_powershell_payload": 45,
    "deobfuscated_executable_drop": 40,

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


# ============================================================
# MITRE ATT&CK MATRIX MAPPINGS
# ============================================================

MITRE_MAP: Dict[str, Dict[str, str]] = {
    # Execution
    "malicious_macro": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Embedded macro designed to execute malicious code on user trigger."
    },
    "autoopen_macro": {
        "id": "T1059.005",
        "name": "Visual Basic for Applications",
        "tactic": "Execution",
        "description": "Macro hooks Document_Open or AutoOpen to execute code automatically."
    },
    "ppt_autoopen": {
        "id": "T1059.005",
        "name": "Visual Basic for Applications",
        "tactic": "Execution",
        "description": "Slide show configured to run VBA on launch."
    },
    "autorun_macro": {
        "id": "T1059.005",
        "name": "Visual Basic for Applications",
        "tactic": "Execution",
        "description": "Automated execution handler detected in Office presentation."
    },
    "vba_macro_detected": {
        "id": "T1059.005",
        "name": "Visual Basic for Applications",
        "tactic": "Execution",
        "description": "VBA macro project detected in Office document."
    },
    "powershell_in_vba": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "VBA macro spawns PowerShell interpreter to run script commands."
    },
    "powershell_detected": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Embedded PowerShell invocation string found in file contents."
    },
    "powershell_in_pdf": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "PDF payload executes PowerShell via launch action or JavaScript."
    },
    "powershell_encoded_command": {
        "id": "T1059.001",
        "name": "PowerShell: Encoded Command",
        "tactic": "Execution",
        "description": "Obfuscated/Base64 encoded PowerShell command line execution."
    },
    "shell_command": {
        "id": "T1059.003",
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "description": "Executes cmd.exe or command shell subprocess directly."
    },
    "process_creation": {
        "id": "T1106",
        "name": "Native API",
        "tactic": "Execution",
        "description": "Uses CreateProcess/ShellExecute APIs to launch background processes."
    },
    "dde_attack": {
        "id": "T1559.001",
        "name": "Dynamic Data Exchange",
        "tactic": "Execution",
        "description": "Exploits Dynamic Data Exchange (DDE) formulas to run arbitrary binaries."
    },
    "xlm_macro_detected": {
        "id": "T1059.005",
        "name": "Excel 4.0 Macros (XLM)",
        "tactic": "Execution",
        "description": "Legacy Excel 4.0 XLM macro sheets used to evade VBA inspection."
    },
    "xlm_exec_command": {
        "id": "T1059.005",
        "name": "Excel 4.0 Macro Execution",
        "tactic": "Execution",
        "description": "XLM macro invokes EXEC/RUN function to spawn external programs."
    },
    "javascript_detected": {
        "id": "T1059.007",
        "name": "JavaScript in Document",
        "tactic": "Execution",
        "description": "Embedded JavaScript action within PDF or document."
    },
    "openaction_detected": {
        "id": "T1204.002",
        "name": "Automated PDF Action Trigger",
        "tactic": "Execution",
        "description": "PDF /OpenAction triggers script execution immediately upon viewing."
    },
    "openaction_trigger": {
        "id": "T1204.002",
        "name": "Automated PDF Action Trigger",
        "tactic": "Execution",
        "description": "PDF /OpenAction triggers script execution immediately upon viewing."
    },
    "launch_action_detected": {
        "id": "T1204.002",
        "name": "PDF Launch Action",
        "tactic": "Execution",
        "description": "PDF /Launch action instructs reader application to execute an external program."
    },
    "launch_action": {
        "id": "T1204.002",
        "name": "PDF Launch Action",
        "tactic": "Execution",
        "description": "PDF /Launch action instructs reader application to execute an external program."
    },
    "cmd_trigger_found": {
        "id": "T1059.003",
        "name": "Command Shell Trigger",
        "tactic": "Execution",
        "description": "Interactive trigger configured to launch cmd.exe."
    },
    "run_program_action": {
        "id": "T1204.002",
        "name": "Run Program Action",
        "tactic": "Execution",
        "description": "Presentation action button configured to execute program on click/hover."
    },

    # Initial Access
    "suspicious_url": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Document contains external hyperlink pointing to suspicious destination."
    },
    "qr_malicious_url": {
        "id": "T1566.002",
        "name": "Spearphishing Link: Quishing",
        "tactic": "Initial Access",
        "description": "QR code containing malicious URL for mobile-targeted quishing attack."
    },
    "qr_phishing_chain": {
        "id": "T1566.002",
        "name": "Spearphishing Link: Quishing",
        "tactic": "Initial Access",
        "description": "Multi-stage quishing attack chain detected."
    },
    "formula_hyperlink_injection": {
        "id": "T1566.002",
        "name": "Spearphishing Link: Formula Injection",
        "tactic": "Initial Access",
        "description": "Spreadsheet formula constructed to mask a phishing hyperlink."
    },
    "enable_macro_lure": {
        "id": "T1204.002",
        "name": "User Execution: Social Engineering Lure",
        "tactic": "Initial Access",
        "description": "Social engineering graphic/text coercing user into enabling macros."
    },

    # Defense Evasion
    "encoded_macro_payload": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Payload obscured with Base64, XOR, or custom encoding."
    },
    "chr_obfuscation_detected": {
        "id": "T1027",
        "name": "Obfuscated Files: Chr() Concatenation",
        "tactic": "Defense Evasion",
        "description": "Strings assembled dynamically via Chr()/Asc() to evade signature detection."
    },
    "reverse_string_obfuscation": {
        "id": "T1027",
        "name": "Obfuscated Files: StrReverse",
        "tactic": "Defense Evasion",
        "description": "Strings reversed at rest and unmasked at runtime."
    },
    "string_obfuscation": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Macro uses string manipulation tricks to mask C2 URLs and binaries."
    },
    "external_template": {
        "id": "T1221",
        "name": "Template Injection",
        "tactic": "Defense Evasion",
        "description": "Word/Office document dynamically pulls a malicious remote .dotm template."
    },
    "template_injection": {
        "id": "T1221",
        "name": "Template Injection",
        "tactic": "Defense Evasion",
        "description": "Presentation dynamically loads a remote macro template."
    },
    "remote_template_attack": {
        "id": "T1221",
        "name": "Template Injection",
        "tactic": "Defense Evasion",
        "description": "Full remote template injection exploit chain identified."
    },
    "embedded_executable": {
        "id": "T1027.009",
        "name": "Embedded Payloads",
        "tactic": "Defense Evasion",
        "description": "Executable binary (MZ/PE header) embedded directly inside document."
    },
    "mz_header_found": {
        "id": "T1027.009",
        "name": "Embedded Payloads (MZ Header)",
        "tactic": "Defense Evasion",
        "description": "Raw Windows executable header (MZ) detected in embedded stream."
    },
    "embedded_ole_object": {
        "id": "T1027.009",
        "name": "Embedded Payloads: OLE Object",
        "tactic": "Defense Evasion",
        "description": "OLE stream payload or embedded package found inside document archive."
    },
    "file_type_mismatch": {
        "id": "T1036.008",
        "name": "Masquerading: File Type Mismatch",
        "tactic": "Defense Evasion",
        "description": "Declared file extension does not match actual internal file magic bytes."
    },
    "double_extension": {
        "id": "T1036.007",
        "name": "Masquerading: Double Extension",
        "tactic": "Defense Evasion",
        "description": "File employs double extension trick (e.g. invoice.pdf.exe) to trick victims."
    },
    "hidden_sheet": {
        "id": "T1564.004",
        "name": "Hide Artifacts: Hidden Sheets",
        "tactic": "Defense Evasion",
        "description": "Spreadsheet hides malicious formulas or macros in hidden worksheets."
    },
    "very_hidden_sheet": {
        "id": "T1564.004",
        "name": "Hide Artifacts: xlSheetVeryHidden",
        "tactic": "Defense Evasion",
        "description": "Worksheet visibility set to xlSheetVeryHidden, invisible to normal Excel UI."
    },
    "hidden_slide": {
        "id": "T1564",
        "name": "Hide Artifacts: Hidden Presentation Slide",
        "tactic": "Defense Evasion",
        "description": "Slide containing payload or phishing lure configured as hidden."
    },
    "hidden_text_overlay": {
        "id": "T1564",
        "name": "Hide Artifacts: Invisible Text Layer",
        "tactic": "Defense Evasion",
        "description": "Invisible or low-contrast text layer used to evade visual security scanners."
    },

    # Credential Access
    "credential_harvesting": {
        "id": "T1056",
        "name": "Input Capture: Credential Phishing",
        "tactic": "Credential Access",
        "description": "Document contains fake login forms or prompts designed to steal passwords."
    },
    "fake_login_page": {
        "id": "T1056",
        "name": "Input Capture: Fake Login UI",
        "tactic": "Credential Access",
        "description": "Visual layout mimics legitimate corporate login interfaces (Microsoft/Google)."
    },
    "fake_login_form_detected": {
        "id": "T1056",
        "name": "Input Capture: Fake Login Form",
        "tactic": "Credential Access",
        "description": "Image contains rendered username and password credential input fields."
    },

    # Command and Control
    "webservice_formula": {
        "id": "T1105",
        "name": "Ingress Tool Transfer: WEBSERVICE",
        "tactic": "Command and Control",
        "description": "Excel WEBSERVICE formula fetches remote data or stage-2 payloads from C2."
    },
    "power_query_connection": {
        "id": "T1105",
        "name": "Ingress Tool Transfer: Power Query",
        "tactic": "Command and Control",
        "description": "External data connection configured to retrieve remote payloads on open."
    },
    "network_call_in_vba": {
        "id": "T1105",
        "name": "Ingress Tool Transfer: VBA Network Request",
        "tactic": "Command and Control",
        "description": "VBA macro makes outbound HTTP/Socket calls to remote server."
    },
    "deobfuscated_malicious_url": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Unmasked C2 download/staging URL extracted from obfuscated macro code."
    },
    "dropper_pattern": {
        "id": "T1105",
        "name": "Ingress Tool Transfer: Dropper Chain",
        "tactic": "Command and Control",
        "description": "Attack pattern indicates file serves as a dropper for next-stage malware."
    },
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
      - mitre_techniques: [{id, name, tactic, description}]
    """
    total_score = 0
    breakdown: Dict[str, Dict[str, int]] = {}
    seen_mitre_ids: set[str] = set()
    mitre_techniques: List[Dict[str, str]] = []

    for finding in findings:
        weight = WEIGHTS.get(finding, DEFAULT_UNKNOWN_FINDING_WEIGHT)
        total_score += weight

        if finding in breakdown:
            breakdown[finding]["count"] += 1
            breakdown[finding]["score"] += weight
        else:
            breakdown[finding] = {"count": 1, "score": weight}

        mitre_info = MITRE_MAP.get(finding)
        if mitre_info and mitre_info["id"] not in seen_mitre_ids:
            seen_mitre_ids.add(mitre_info["id"])
            mitre_techniques.append(mitre_info)

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
        "mitre_techniques": mitre_techniques,
    }
