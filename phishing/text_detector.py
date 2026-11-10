"""Simple rule-based phishing text detector.

This module looks for common phishing patterns in a text message:

- urgency words (e.g. "urgent", "immediately", "suspended", "blocked")
- credential-related words (e.g. "password", "OTP", "login", "bank details")
- suspicious links (IP addresses, short links, unusual domains)
- prize / lottery wording

It returns a risk score from 0 to 100, a result of "Safe", "Suspicious" or
"High Risk", and a list of reasons explaining the score.

Safety notes:
- Only Python's standard library is used.
- Links are never visited and nothing is downloaded.
- No passwords or credentials are collected or stored.
- This is a heuristic helper, not a guarantee. A "Safe" result does not
  prove that a message is trustworthy.

Example:
    from phishing.text_detector import analyze_text

    result = analyze_text("URGENT: your account is suspended, verify your password")
    print(result["score"])    # risk score (0-100)
    print(result["result"])   # "High Risk"
    print(result["reasons"])  # list of explanations
"""

import re

# ---------------------------------------------------------------------------
# Word lists used by the rules
# ---------------------------------------------------------------------------

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "suspended",
    "blocked",
    "act now",
    "verify now",
    "final warning",
    "expires today",
    "last chance",
    "time is running out",
]

CREDENTIAL_WORDS = [
    "password",
    "otp",
    "login",
    "log in",
    "bank details",
    "pin",
    "account number",
    "card number",
    "username",
    "verify your account",
    "confirm your identity",
    "social security",
]

PRIZE_WORDS = [
    "winner",
    "you won",
    "you have won",
    "prize",
    "lottery",
    "claim now",
    "free gift",
    "cash reward",
    "congratulations",
    "you are selected",
    "gift card",
    "cash prize",
]

# Domains often used to hide the real destination of a link.
SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
]

# Domain endings that are popular in phishing campaigns.
SUSPICIOUS_TLDS = [
    ".zip",
    ".xyz",
    ".top",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".click",
    ".link",
    ".work",
    ".loan",
]

# Matches "https://...", "http://..." or "www....".
URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s]+", re.IGNORECASE)

# Simple IPv4 pattern (e.g. 192.168.1.10).
IP_PATTERN = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _find_keywords(text, keywords):
    """Return the keywords from ``keywords`` that appear in ``text``.

    ``text`` must already be lowercase. Single words are matched on word
    boundaries so that e.g. "pin" does not match "spinning".
    """
    found = []
    for keyword in keywords:
        if " " in keyword:
            # Multi-word phrases are matched as plain text.
            if keyword in text:
                found.append(keyword)
        else:
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, text):
                found.append(keyword)
    return found


def _check_link(link):
    """Return a list of reasons why a single link looks suspicious."""
    reasons = []
    link_lower = link.lower()

    # Remove "http://" or "www." to get the domain part.
    domain = re.sub(r"^https?://", "", link_lower)
    domain = domain.split("/")[0]

    if IP_PATTERN.match(link_lower):
        reasons.append("Link uses a raw IP address instead of a domain: " + link)

    for shortener in SHORTENER_DOMAINS:
        if domain.endswith(shortener):
            reasons.append("Link uses a link-shortening service: " + link)
            break

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append("Link uses an unusual domain ending (" + tld + "): " + link)
            break

    if "@" in link:
        reasons.append("Link contains an '@' symbol, which can hide the real domain: " + link)

    if len(link) > 75:
        reasons.append("Link is unusually long: " + link)

    return reasons


def _score_to_result(score):
    """Convert a numeric risk score into a result label."""
    if score >= 60:
        return "High Risk"
    if score >= 30:
        return "Suspicious"
    return "Safe"


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------


def analyze_text(message):
    """Analyze a message and return a risk score, result and reasons.

    Args:
        message: The text to analyze (should be a string).

    Returns:
        A dictionary with:
        - "score": integer risk score from 0 to 100
        - "result": "Safe", "Suspicious" or "High Risk"
        - "reasons": list of human-readable explanations
    """
    if not isinstance(message, str) or not message.strip():
        return {
            "score": 0,
            "result": "Safe",
            "reasons": ["No message text to analyze."],
        }

    text = message.lower()
    score = 0
    reasons = []

    # Rule 1: urgency words.
    urgency_matches = _find_keywords(text, URGENCY_WORDS)
    if urgency_matches:
        score += min(12 * len(urgency_matches), 36)
        reasons.append("Uses urgency language: " + ", ".join(urgency_matches))

    # Rule 2: credential-related words.
    credential_matches = _find_keywords(text, CREDENTIAL_WORDS)
    if credential_matches:
        score += min(12 * len(credential_matches), 36)
        reasons.append(
            "Mentions credentials or account details: " + ", ".join(credential_matches)
        )

    # Rule 3: prize / lottery wording.
    prize_matches = _find_keywords(text, PRIZE_WORDS)
    if prize_matches:
        score += min(10 * len(prize_matches), 20)
        reasons.append("Mentions prizes or rewards: " + ", ".join(prize_matches))

    # Rule 4: links.
    links = URL_PATTERN.findall(message)
    if links:
        score += 10
        reasons.append("Contains link(s): " + ", ".join(links[:3]))
        for link in links:
            for link_reason in _check_link(link):
                score += 10
                reasons.append(link_reason)

    # Keep the score inside the 0-100 range.
    score = min(score, 100)

    if not reasons:
        reasons.append("No common phishing indicators were found.")

    return {
        "score": score,
        "result": _score_to_result(score),
        "reasons": reasons,
    }


# Quick manual test when the file is run directly.
if __name__ == "__main__":
    sample = input("Enter a message to analyze: ")
    analysis = analyze_text(sample)
    print("Score:", analysis["score"])
    print("Result:", analysis["result"])
    print("Reasons:")
    for reason in analysis["reasons"]:
        print("-", reason)
