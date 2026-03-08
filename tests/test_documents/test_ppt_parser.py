# ================================================================
# test_ppt_parser.py — DarkHOOK_ Defence
# ================================================================

import sys
import os

# Add Backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'Backend'))

# Set UTF-8 encoding for Windows console
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import time
from modules.document_analysis.ppt_parser import parse_ppt
from modules.document_analysis.scorer import calculate_score

# PUT YOUR PPT FILE PATH HERE (or pass as command-line argument)
# Usage: python test_ppt_parser.py <path_to_ppt>
PPT_PATH = sys.argv[1] if len(sys.argv) > 1 else None
if not PPT_PATH:
    print("Usage: python test_ppt_parser.py <path_to_ppt_file>")
    print("Example: python test_ppt_parser.py C:\\Users\\user\\Downloads\\test.pptx")
    sys.exit(1)
if not os.path.isfile(PPT_PATH):
    print(f"Error: File not found: {PPT_PATH}")
    sys.exit(1)


def separator(char="=", width=62):
    print(char * width)


def section(title):
    print()
    separator()
    print("  " + title)
    separator()


def print_progress_bar(score, width=40):
    filled = int((score / 100) * width)
    empty  = width - filled
    bar    = "=" * filled + "-" * empty
    print("  [" + bar + "]  " + str(score) + " / 100")


def main():
    print()
    separator("=")
    print("  DARKHOOK_ DEFENCE -- PPT FILE SCANNER")
    print("  Enterprise Grade -- 14 Technique Detection")
    separator("=")
    print()
    print("  Scanning  :", PPT_PATH)
    print("  Please wait -- running 14 techniques...")
    print()

    start        = time.time()
    result       = parse_ppt(PPT_PATH)
    taken        = round(time.time() - start, 2)
    findings     = result["findings"]
    details      = result["details"]
    sha256       = result["sha256"]
    score_result = calculate_score(findings)
    score        = score_result["score"]
    severity     = score_result["severity"]
    breakdown    = score_result["breakdown"]
    filename     = os.path.basename(PPT_PATH)

    section("FILE INFORMATION")
    print("  File      : " + filename)
    print("  SHA256    : " + sha256[:42] + "...")
    print("  Scan Time : " + str(taken) + " seconds")

    section("DANGER SCORE")
    print()
    print_progress_bar(score)
    print()
    print("  0         25        50        75       100")
    print("  SAFE      LOW      MED      HIGH    CRITICAL")

    section("14 TECHNIQUE SCAN RESULTS")
    print()
    for line in details:
        print("  " + line)

    section("FINDINGS LIST")
    print()
    if findings:
        for i, f in enumerate(findings, 1):
            print("  " + str(i).zfill(2) + ". " + f)
    else:
        print("  No findings -- file appears safe!")

    section("SCORE BREAKDOWN")
    print()
    print("  " + "Finding Type".ljust(35) +
          "Count".ljust(8) + "Points")
    print("  " + "-" * 55)
    if breakdown:
        for finding, data in breakdown.items():
            print(
                "  " + finding.ljust(35) +
                ("x" + str(data["count"])).ljust(8) +
                "+" + str(data["score"]) + " pts"
            )
        print("  " + "-" * 55)
        print(
            "  " + "TOTAL".ljust(35) +
            str(len(findings)).ljust(8) +
            str(score) + "/100"
        )
    else:
        print("  No findings -- score is 0")

    print()
    separator("=")
    print("  FINAL VERDICT")
    separator("=")
    print()
    print("  File           : " + filename)
    print("  Total Findings : " + str(len(findings)))
    print("  Danger Score   : " + str(score) + " / 100")
    print("  Severity       : " + severity)
    print("  Scan Time      : " + str(taken) + " seconds")
    print()
    print_progress_bar(score)
    print()

    if score <= 25:
        print("  ** LOW RISK -- File appears safe **")
    elif score <= 55:
        print("  ** MEDIUM RISK -- Review manually **")
    elif score <= 79:
        print("  ** HIGH RISK -- Likely phishing **")
    else:
        print("  !! CRITICAL -- DO NOT OPEN THIS FILE !!")

    print("  Score: " + str(score) + "/100")
    separator("=")
    print()


main()