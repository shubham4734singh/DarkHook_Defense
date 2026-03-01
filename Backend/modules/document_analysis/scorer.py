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
    "suspicious_url"     : 15,   # Suspicious link found
    "malicious_macro"    : 30,   # Dangerous macro in Word/Excel
    "hidden_script"      : 25,   # Hidden script inside file
    "qr_malicious_url"   : 20,   # QR code pointing to bad URL
    "phishing_keyword"   : 5,    # Phishing words like "verify account"
    "suspicious_domain"  : 15,   # Known bad domain found
    "embedded_object"    : 20,   # Suspicious embedded object
    "ocr_phishing_text"  : 10,   # Phishing text found in image
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
