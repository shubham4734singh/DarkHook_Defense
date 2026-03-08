# ============================================================
# test_pdf_parser.py — Complete test for pdf_parser.py
# ============================================================

import sys
import os

# Add parent directory to path for module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import time
from Backend.modules.document_analysis.pdf_parser import parse_pdf
from Backend.modules.document_analysis.scorer import calculate_score

# ============================================================
# PUT YOUR PDF PATH HERE (or pass as command-line argument)
# Usage: python test_pdf_parser.py <path_to_pdf>
# ============================================================

PDF_PATH = sys.argv[1] if len(sys.argv) > 1 else None
if not PDF_PATH:
    print("Usage: python test_pdf_parser.py <path_to_pdf_file>")
    print("Example: python test_pdf_parser.py C:\\Users\\user\\Downloads\\test.pdf")
    sys.exit(1)
if not os.path.isfile(PDF_PATH):
    print(f"Error: File not found: {PDF_PATH}")
    sys.exit(1)

# ============================================================
# RUN THE SCAN
# ============================================================

print()
print("=" * 60)
print("   🛡️  DARKHOOK_ DEFENCE")
print("   PDF PHISHING DETECTION ENGINE")
print("=" * 60)
print(f"Scanning: {PDF_PATH}")
print("Please wait...")
print()

# Start timer
start_time = time.time()

# Run parser
result = parse_pdf(PDF_PATH)

# End timer
end_time   = time.time()
scan_time  = round(end_time - start_time, 2)

# ============================================================
# PRINT FULL DETAILED REPORT
# ============================================================

print("=" * 60)
print("FULL ANALYSIS REPORT")
print("=" * 60)
for line in result["details"]:
    print(line)

# ============================================================
# PRINT FINDINGS LIST
# ============================================================

print()
print("=" * 60)
print("FINDINGS LIST (raw)")
print("=" * 60)

if result["findings"]:
    for i, finding in enumerate(result["findings"], 1):
        print(f"  {i}. {finding}")
else:
    print("  No findings detected ✅")

# ============================================================
# CALCULATE AND PRINT DANGER SCORE
# ============================================================

score_result = calculate_score(result["findings"])

print()
print("=" * 60)
print("DANGER SCORE SUMMARY")
print("=" * 60)
print(f"  SHA256         : {result['sha256'][:40]}...")
print(f"  Total Findings : {len(result['findings'])}")
print(f"  Danger Score   : {score_result['score']} / 100")
print(f"  Verdict        : {score_result['verdict']}")
print(f"  Scan Time      : {scan_time} seconds")

# ============================================================
# PRINT SCORE BREAKDOWN
# ============================================================

print()
print("=" * 60)
print("SCORE BREAKDOWN — What caused the score")
print("=" * 60)

if score_result["breakdown"]:
    for finding_type, points in score_result["breakdown"].items():
        print(f"  {finding_type:<30} → +{points} points")
else:
    print("  No suspicious findings — file appears safe ✅")

# ============================================================
# FINAL VERDICT BOX
# ============================================================

print()
print("=" * 60)

score = score_result["score"]

if score < 30:
    print("  ✅  VERDICT: LOW RISK — File appears safe")
elif score < 60:
    print("  ⚠️   VERDICT: MEDIUM RISK — Review manually")
elif score < 80:
    print("  🔴  VERDICT: HIGH RISK — Likely phishing")
else:
    print("  ☠️   VERDICT: CRITICAL — Do NOT open this file!")

print(f"  Score: {score}/100")
print("=" * 60)
print()

