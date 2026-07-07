from urllib.parse import urlparse
import re

# Suspicious words commonly used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "security",
    "account",
    "bank",
    "paypal",
    "update",
    "signin",
    "confirm",
    "password",
    "wallet",
    "invoice",
    "billing",
    "payment"
]


def analyze_url(url):

    score = 0
    reasons = []

    # Add http:// if the user forgets it
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    # ----------------------------
    # HTTPS Check
    # ----------------------------
    if parsed.scheme != "https":
        score += 20
        reasons.append("HTTPS is NOT enabled.")

    # ----------------------------
    # Keyword Detection
    # ----------------------------
    url_lower = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            score += 10
            reasons.append(f"Suspicious keyword detected: {keyword}")

    # ----------------------------
    # IP Address Detection
    # ----------------------------
    ip_pattern = r"^\d+\.\d+\.\d+\.\d+$"

    if re.match(ip_pattern, parsed.netloc):
        score += 25
        reasons.append("Uses an IP address instead of a domain name.")

    # ----------------------------
    # Long URL Detection
    # ----------------------------
    if len(url) > 75:
        score += 10
        reasons.append("Very long URL.")

    # ----------------------------
    # Too Many Subdomains
    # ----------------------------
    domain_parts = parsed.netloc.split(".")

    if len(domain_parts) > 3:
        score += 15
        reasons.append("Too many subdomains.")

    # ----------------------------
    # @ Symbol Detection
    # ----------------------------
    if "@" in url:
        score += 20
        reasons.append("Contains '@' symbol.")

    # ----------------------------
    # Hyphen Detection
    # ----------------------------
    if "-" in parsed.netloc:
        score += 10
        reasons.append("Hyphen detected in domain.")

    # ----------------------------
    # Limit score
    # ----------------------------
    score = min(score, 100)

    # ----------------------------
    # Verdict
    # ----------------------------
    if score >= 70:
        verdict = "Dangerous"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    if len(reasons) == 0:
        reasons.append("No suspicious indicators detected.")

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }