# ================================================================
# test_ocr_parser.py — DarkHOOK_ Defence
# ================================================================

import sys
import os

# Add parent directory to path for module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import time
from Backend.modules.document_analysis.ocr_parser import parse_image
from Backend.modules.document_analysis.scorer import calculate_score

# PUT YOUR IMAGE FILE PATH HERE
IMAGE_PATH = r"C:\Users\sonip\Downloads\Untitled.png"

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
    print("  DARKHOOK_ DEFENCE -- IMAGE FILE SCANNER")
    print("  Enterprise Grade -- 17 Technique Detection")
    separator("=")
    print()
    print("  Scanning  :", IMAGE_PATH)
    print("  Please wait -- running 17 techniques...")
    print()

    start  = time.time()
    result = parse_image(IMAGE_PATH)
    taken  = round(time.time() - start, 2)

    findings     = result["findings"]
    details      = result["details"]
    sha256       = result["sha256"]
    score_result = calculate_score(findings)
    score        = score_result["score"]
    severity     = score_result["severity"]
    breakdown    = score_result["breakdown"]
    filename     = os.path.basename(IMAGE_PATH)

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

    section("17 TECHNIQUE SCAN RESULTS")
    print()
    for line in details:
        print("  " + line)

    section("FINDINGS LIST")
    print()
    if findings:
        for i, f in enumerate(findings, 1):
            print("  " + str(i).zfill(2) + ". " + f)
    else:
        print("  No findings -- image appears safe!")

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
        print("  ** LOW RISK -- Image appears safe **")
    elif score <= 55:
        print("  ** MEDIUM RISK -- Review manually **")
    elif score <= 79:
        print("  ** HIGH RISK -- Likely phishing image **")
    else:
        print("  !! CRITICAL -- DO NOT USE THIS IMAGE !!")

    print("  Score: " + str(score) + "/100")
    separator("=")
    print()


main()
