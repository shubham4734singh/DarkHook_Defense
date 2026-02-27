# ============================================================
# test_pdf_parser.py
# Purpose : Tests all features of advanced pdf_parser.py
# ============================================================

import sys
import os

# Add Backend directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'Backend'))

from modules.document_analysis.pdf_parser import parse_pdf
from modules.document_analysis.scorer import calculate_score

print()
print("=" * 60)
print("   DARKHOOK DEFENCE - PDF PARSER TEST")
print("=" * 60)


# ----------------------------------------------------------
# TEST 1 - Phishing PDF (should find many issues)
# ----------------------------------------------------------

print()
print("TEST 1 - SCANNING PHISHING PDF")
print("-" * 60)

result = parse_pdf(r"C:\Users\sonip\Desktop\6th sem\DFIR\UNIT 1.pdf")

print("FINDINGS DETECTED:")
print(result["findings"])
print()
print("DETAILED REPORT:")
for detail in result["details"]:
    print(f"  {detail}")

# Send findings to scorer
score_result = calculate_score(result["findings"])
print()
print("DANGER SCORE:")
print(f"  Score   : {score_result['score']} / 100")
print(f"  Verdict : {score_result['verdict']}")
print(f"  Breakdown: {score_result['breakdown']}")

print()
print("=" * 60)
print(f"TOTAL FINDINGS : {len(result['findings'])}")
print(f"FINAL VERDICT  : {score_result['verdict']}")
print("=" * 60)
