# ================================================================
# test_docx_parser.py — DarkHOOK_ Defence
# Purpose  : Runs docx_parser.py and displays output
#            in organized readable format
# ================================================================

import sys
import os
import time

# Add parent directory to path to import Backend modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from Backend.modules.document_analysis.docx_parser import parse_docx
from Backend.modules.document_analysis.scorer import calculate_score


# ================================================================
# PUT YOUR WORD FILE PATH HERE (or pass as command-line argument)
# Usage: python test_docx_parser.py <path_to_docx>
# ================================================================

DOCX_PATH = sys.argv[1] if len(sys.argv) > 1 else None
if not DOCX_PATH:
    print("Usage: python test_docx_parser.py <path_to_docx_file>")
    print("Example: python test_docx_parser.py C:\\Users\\user\\Documents\\test.docx")
    sys.exit(1)
if not os.path.isfile(DOCX_PATH):
    print(f"Error: File not found: {DOCX_PATH}")
    sys.exit(1)


# ================================================================
# HELPER FUNCTIONS — For drawing organized output
# ================================================================

def line(char="═", width=62):
    """Prints a full separator line"""
    print(char * width)


def box_line(text, width=62):
    """Prints text inside box borders"""
    print(f"║  {text:<{width-4}}║")


def section(title):
    """Prints a section header"""
    print()
    line()
    print(f"  {title}")
    line()


def print_progress_bar(score, width=40):
    """
    Prints a visual progress bar for danger score.
    Example: [████████████░░░░░░░░░░░░░░░░]  45/100
    """
    filled = int((score / 100) * width)
    empty  = width - filled
    bar    = "█" * filled + "░" * empty
    print(f"  [{bar}]  {score} / 100")


def severity_color(score):
    """Returns severity label based on score"""
    if score < 30:
        return "✅ SAFE"
    elif score < 60:
        return "⚠️  MEDIUM RISK"
    elif score < 80:
        return "🔴 HIGH RISK"
    else:
        return "☠️  CRITICAL"


def technique_status(findings_list, technique_keywords):
    """
    Checks if any finding matches technique keywords.
    Returns FAIL, WARN or PASS based on findings.
    """
    matched = [
        f for f in findings_list
        if any(kw in f for kw in technique_keywords)
    ]
    if not matched:
        return "✅ PASS", "Clean"
    critical_keywords = [
        "macro", "autoopen", "powershell",
        "executable", "template", "dropper",
        "javascript", "launch", "embed"
    ]
    if any(kw in f for f in matched for kw in critical_keywords):
        return "🚨 FAIL", f"{len(matched)} issues"
    return "⚠️  WARN", f"{len(matched)} issues"


# ================================================================
# OUTPUT SECTIONS
# ================================================================

def print_header(file_path, sha256, scan_time):
    """Prints top header box"""
    print()
    print("╔" + "═" * 62 + "╗")
    box_line("🛡️  DARKHOOK_ DEFENCE — DOCUMENT SCANNER")
    box_line("    Word Document Phishing Detection Engine")
    print("╚" + "═" * 62 + "╝")
    print()
    import os
    filename = os.path.basename(file_path)
    print(f"  📄 File      : {filename}")
    print(f"  🔑 SHA256    : {sha256[:42]}...")
    print(f"  ⏱️  Scan Time : {scan_time} seconds")


def print_danger_score(score):
    """Prints visual danger score section"""
    section("📊 DANGER SCORE")
    print()
    print_progress_bar(score)
    print()
    print("   0         25        50        75       100")
    print("   SAFE      LOW      MED      HIGH    CRITICAL")
    print()
    label = severity_color(score)
    print(f"  VERDICT → {label}")


def print_technique_table(findings):
    """
    Prints 14 technique results as a clean table.
    Each technique shows PASS / WARN / FAIL.
    """
    section("🔬 14 TECHNIQUE SCAN RESULTS")

    # Each technique → (name, keywords to check in findings)
    techniques = [
        ("01", "File Validation",
         ["file_type", "double_ext", "corrupted", "malformed"]),
        ("02", "Metadata Analysis",
         ["metadata", "wiped", "suspicious_meta", "template"]),
        ("03", "Macro Detection",
         ["malicious_macro"]),
        ("04", "Auto-Execution",
         ["autoopen"]),
        ("05", "VBA Behavior",
         ["vba_api", "powershell", "network_call",
          "file_system", "registry", "process"]),
        ("06", "Obfuscation",
         ["encoded", "entropy", "obfuscation", "junk"]),
        ("07", "Embedded Objects",
         ["embedded", "ole", "executable", "script"]),
        ("08", "External Resources",
         ["external_template", "external_image",
          "relationship", "hidden_rel"]),
        ("09", "Keyword Analysis",
         ["phishing_keyword", "urgency", "financial",
          "credential", "enable_macro", "cta"]),
        ("10", "URL Analysis",
         ["url", "ip_based", "shortened",
          "suspicious_tld", "at_symbol", "anchor"]),
        ("11", "Attack Chain",
         ["dropper", "download_exec", "multistage"]),
        ("12", "Entropy Analysis",
         ["entropy", "encoded_macro"]),
        ("13", "Reputation Check",
         ["known_macro", "known_malicious"]),
        ("14", "Heuristic Scoring",
         ["score"]),
    ]

    print()
    print("  ┌" + "─" * 58 + "┐")
    print(
        f"  │  {'#':<4} {'Technique':<26} "
        f"{'Status':<12} {'Findings':<10}  │"
    )
    print("  ├" + "─" * 58 + "┤")

    pass_count = 0
    warn_count = 0
    fail_count = 0

    for num, name, keywords in techniques:
        status, result = technique_status(findings, keywords)

        if "PASS" in status:
            pass_count += 1
        elif "WARN" in status:
            warn_count += 1
        else:
            fail_count += 1

        print(
            f"  │  {num:<4} {name:<26} "
            f"{status:<14} {result:<10}  │"
        )

    print("  └" + "─" * 58 + "┘")
    print()
    print(
        f"  Summary → "
        f"🚨 FAIL: {fail_count}  │  "
        f"⚠️  WARN: {warn_count}  │  "
        f"✅ PASS: {pass_count}"
    )


def print_critical_findings(details):
    """
    Prints only CRITICAL findings from details list.
    Filters lines that start with 🚨
    """
    section("🚨 CRITICAL FINDINGS")

    critical_lines = [
        line for line in details
        if "🚨" in line
    ]

    if not critical_lines:
        print("  ✅ No critical findings detected")
        return

    # Group by technique
    current_group = ""
    for line_text in critical_lines:
        # Detect technique tag like [T01] [T03]
        tag = ""
        if "TECHNIQUE 1" in line_text or "T01" in line_text:
            tag = "[T01]"
        elif "TECHNIQUE 2" in line_text or "T02" in line_text:
            tag = "[T02]"

        clean = line_text.replace(
            "🚨 CRITICAL:", "🚨"
        ).replace(
            "🚨 HIGH:", "🚨"
        ).strip()

        print(f"  {clean}")


def print_high_findings(details):
    """Prints WARNING level findings"""
    section("⚠️  HIGH FINDINGS")

    warn_lines = [
        line for line in details
        if "⚠️" in line and "🚨" not in line
    ]

    if not warn_lines:
        print("  ✅ No high-level warnings")
        return

    for line_text in warn_lines:
        clean = line_text.strip()
        print(f"  {clean}")


def print_keywords_table(details):
    """
    Extracts phishing keywords from details
    and prints them in a clean table.
    """
    section("📋 PHISHING CONTENT DETECTED")

    # Extract keyword lines
    keyword_lines = [
        line for line in details
        if "×" in line and "[" in line
    ]

    if not keyword_lines:
        print("  ✅ No phishing keywords detected")
        return

    print()
    print("  KEYWORDS FOUND")
    print("  ┌" + "─" * 56 + "┐")
    print(
        f"  │  {'Category':<22} "
        f"{'Keyword':<24} {'Count':<5}  │"
    )
    print("  ├" + "─" * 56 + "┤")

    for line_text in keyword_lines:
        # Parse: ⚠️ [category] 'keyword' ×count
        try:
            # Extract category
            cat_start = line_text.index("[") + 1
            cat_end   = line_text.index("]")
            category  = line_text[cat_start:cat_end]

            # Extract keyword
            kw_start  = line_text.index("'") + 1
            kw_end    = line_text.rindex("'")
            keyword   = line_text[kw_start:kw_end]

            # Extract count
            count_part = line_text.split("×")[-1].strip()

            # Truncate long text
            category = category[:20]
            keyword  = keyword[:22]

            print(
                f"  │  {category:<22} "
                f"{keyword:<24} ×{count_part:<4}  │"
            )
        except Exception:
            pass

    print("  └" + "─" * 56 + "┘")

    # Print category summary
    print()
    print("  CATEGORY SUMMARY")

    summary_keywords = [
        "Urgency tone",
        "Financial targeting",
        "Credential harvesting",
        "Enable macro lure",
        "Repeated",
    ]

    for line_text in details:
        for kw in summary_keywords:
            if kw.lower() in line_text.lower():
                icon = "🚨" if "🚨" in line_text else "⚠️ "
                clean = line_text.strip()
                print(f"  → {clean}")
                break


def print_urls(details):
    """Prints all suspicious URLs found"""
    section("🔗 SUSPICIOUS URLS FOUND")

    url_lines = [
        line for line in details
        if ("http" in line.lower() and
            ("🚨" in line or "⚠️" in line) and
            "→" in line)
    ]

    if not url_lines:
        print("  ✅ No suspicious URLs detected")
        return

    print()
    for i, line_text in enumerate(url_lines, 1):
        clean = line_text.strip()
        print(f"  {i:02d}. {clean}")


def print_attack_chains(details):
    """Prints attack chains in step by step format"""
    section("⛓️  ATTACK CHAINS DETECTED")

    chain_lines = [
        line for line in details
        if "ATTACK CHAIN" in line
    ]

    if not chain_lines:
        print("  ✅ No attack chains identified")
        return

    print()
    for i, line_text in enumerate(chain_lines, 1):
        # Extract chain description after colon
        if ":" in line_text:
            chain_desc = line_text.split(":", 1)[1].strip()
        else:
            chain_desc = line_text.strip()

        # Split steps by →
        steps = chain_desc.split("→")

        print(f"  Chain {i}")
        for j, step in enumerate(steps, 1):
            step = step.strip()
            if step:
                if j == 1:
                    print(f"  → {step}")
                elif j == len(steps):
                    print(f"    └─ {step}")
                else:
                    print(f"    ├─ {step}")
        print()


def print_score_breakdown(findings):
    """Prints score breakdown table"""
    section("📊 SCORE BREAKDOWN")

    # Weights — same as docx_parser.py
    WEIGHTS = {
        "file_type_mismatch"      : 40,
        "corrupted_structure"     : 30,
        "double_extension"        : 35,
        "malformed_zip"           : 25,
        "suspicious_metadata"     : 15,
        "wiped_metadata"          : 20,
        "metadata_mismatch"       : 20,
        "suspicious_template"     : 25,
        "malicious_macro"         : 40,
        "autoopen_macro"          : 35,
        "hidden_macro_stream"     : 35,
        "suspicious_vba_api"      : 30,
        "powershell_in_vba"       : 40,
        "network_call_in_vba"     : 35,
        "file_system_access"      : 25,
        "registry_access"         : 30,
        "process_creation"        : 35,
        "encoded_macro_payload"   : 35,
        "high_entropy_string"     : 25,
        "string_obfuscation"      : 25,
        "embedded_ole_object"     : 30,
        "embedded_executable"     : 45,
        "embedded_script"         : 40,
        "external_template"       : 35,
        "external_image_tracker"  : 20,
        "suspicious_relationship" : 25,
        "phishing_keyword"        : 10,
        "urgent_tone_detected"    : 15,
        "financial_terms_detected": 15,
        "credential_harvesting"   : 20,
        "enable_macro_lure"       : 35,
        "repeated_cta"            : 15,
        "suspicious_url"          : 15,
        "ip_based_url"            : 30,
        "shortened_url"           : 20,
        "suspicious_tld"          : 20,
        "at_symbol_trick"         : 25,
        "mismatched_anchor"       : 25,
        "dropper_pattern"         : 40,
        "download_execute_pattern": 40,
        "multistage_indicator"    : 35,
        "known_macro_signature"   : 45,
    }

    # Count findings
    from collections import Counter
    finding_counts = Counter(findings)

    print()
    print("  ┌" + "─" * 56 + "┐")
    print(
        f"  │  {'Finding Type':<32} "
        f"{'Count':<7} {'Points':<10}  │"
    )
    print("  ├" + "─" * 56 + "┤")

    total_points = 0
    total_count  = 0

    for finding, count in finding_counts.items():
        weight = WEIGHTS.get(finding, 5)
        points = weight * count
        total_points += points
        total_count  += count

        print(
            f"  │  {finding:<32} "
            f"×{count:<6} +{points:<9}  │"
        )

    print("  ├" + "─" * 56 + "┤")
    capped = min(total_points, 100)
    print(
        f"  │  {'TOTAL':<32} "
        f"×{total_count:<6} {capped}/100{'':5}  │"
    )
    print("  └" + "─" * 56 + "┘")


def print_reputation(sha256, details):
    """Prints reputation and hash section"""
    section("🔍 REPUTATION CHECK")

    print()
    print(f"  SHA256  : {sha256}")

    sig_lines = [
        line for line in details
        if "Known" in line and "🚨" in line
    ]

    if sig_lines:
        for line_text in sig_lines:
            print(f"  {line_text.strip()}")
    else:
        print("  ✅ No known malicious signatures matched")

    print()
    print(
        "  ℹ️  Manual check → https://www.virustotal.com"
    )


def print_final_verdict(file_path, findings,
                        score, scan_time, sha256):
    """Prints final summary and verdict box"""
    import os
    section("✅ FINAL SUMMARY")

    filename = os.path.basename(file_path)
    label    = severity_color(score)

    print()
    print(f"  📄 File           : {filename}")
    print(f"  🔢 Total Findings : {len(findings)}")
    print(f"  📊 Danger Score   : {score} / 100")
    print(f"  🔴 Severity       : {label}")
    print(f"  ⏱️  Scan Time      : {scan_time} seconds")
    print()
    print_progress_bar(score)
    print()

    # Final verdict box
    if score < 30:
        msg1 = "✅  VERDICT : LOW RISK — File appears safe"
        msg2 = "This document passed all safety checks."
    elif score < 60:
        msg1 = "⚠️   VERDICT : MEDIUM RISK — Review manually"
        msg2 = "This document has some suspicious elements."
    elif score < 80:
        msg1 = "🔴  VERDICT : HIGH RISK — Likely phishing"
        msg2 = "Do not open this file without expert review."
    else:
        msg1 = "☠️   VERDICT : CRITICAL — DO NOT OPEN !!!"
        msg2 = "Active malware detected. Opening may compromise system."

    print("╔" + "═" * 62 + "╗")
    box_line(msg1)
    box_line(msg2)
    box_line(f"Score: {score}/100  │  SHA256: {sha256[:30]}...")
    print("╚" + "═" * 62 + "╝")
    print()


# ================================================================
# MAIN — Run everything
# ================================================================

def main():

    # -------------------------------------------------------
    # STEP 1 — Run the scan
    # -------------------------------------------------------

    print()
    print("╔" + "═" * 62 + "╗")
    box_line("🛡️  DARKHOOK_ DEFENCE — DOCUMENT SCANNER")
    box_line("    Word Document Phishing Detection Engine")
    print("╚" + "═" * 62 + "╝")
    print()
    print(f"  Scanning : {DOCX_PATH}")
    print(f"  Please wait — running 14 techniques...")
    print()

    start_time = time.time()
    result     = parse_docx(DOCX_PATH)
    scan_time  = round(time.time() - start_time, 2)

    findings = result["findings"]
    details  = result["details"]
    sha256   = result["sha256"]

    # -------------------------------------------------------
    # STEP 2 — Calculate score
    # -------------------------------------------------------

    score_result = calculate_score(findings)
    score        = score_result["score"]

    # -------------------------------------------------------
    # STEP 3 — Print all sections in order
    # -------------------------------------------------------

    # Section 1 — Header
    print_header(DOCX_PATH, sha256, scan_time)

    # Section 2 — Danger score
    print_danger_score(score)

    # Section 3 — Technique table
    print_technique_table(findings)

    # Section 4 — Critical findings
    print_critical_findings(details)

    # Section 5 — High findings
    print_high_findings(details)

    # Section 6 — Phishing keywords table
    print_keywords_table(details)

    # Section 7 — Suspicious URLs
    print_urls(details)

    # Section 8 — Attack chains
    print_attack_chains(details)

    # Section 9 — Score breakdown
    print_score_breakdown(findings)

    # Section 10 — Reputation
    print_reputation(sha256, details)

    # Section 11 — Final verdict
    print_final_verdict(
        DOCX_PATH, findings,
        score, scan_time, sha256
    )


# Run main
main()



