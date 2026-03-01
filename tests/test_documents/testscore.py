# This file is just for testing scorer.py
# Delete this file after testing is done

import sys
import os

# Add Backend directory to Python path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'Backend'))

from modules.document_analysis.scorer import calculate_score

# TEST 1 — Safe file (no findings)
result1 = calculate_score([])
print("TEST 1 — No findings:")
print(result1)
print()

# TEST 2 — Suspicious file
result2 = calculate_score(["suspicious_url", "phishing_keyword"])
print("TEST 2 — Suspicious findings:")
print(result2)
print()

# TEST 3 — Dangerous file
result3 = calculate_score(["malicious_macro", "hidden_script", "suspicious_url", "qr_malicious_url"])
print("TEST 3 — Dangerous findings:")
print(result3)
print()