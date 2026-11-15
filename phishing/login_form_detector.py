"""Login form analysis for the phishing detection engine.

This module inspects HTML content (pasted or uploaded) and looks for
risky login-form patterns. It uses only the Python standard library.

What it looks for:

- credential fields: password, email, username, PIN and OTP inputs
- form actions that submit to absolute external destinations
- insecure HTTP form submissions
- hidden credential-related fields
- forms that use GET while collecting a password (credentials may appear
  in the URL)
- suspicious action URLs (raw IP addresses, '@' tricks, risky TLDs,
  link shorteners, javascript:/data: URLs)

Safety notes:
- Forms are NEVER submitted and no data is sent anywhere.
- URLs found in the HTML are never visited.
- Values of input fields are not read or stored; only attribute names
  (name/id/placeholder) are inspected.
- Uploaded HTML is processed in memory only.

A low score does not prove a form is legitimate. Always verify the site
address and certificate before typing credentials.
"""

import re
from html.parser import HTMLParser
from urllib.parse import urlparse

# Maximum accepted HTML size: 2 MB of text.
MAX_HTML_BYTES = 2 * 1024 * 1024

# Domain endings often used in phishing campaigns.
SUSPICIOUS_TLDS = (
    ".zip", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".click", ".link", ".work", ".loan",
)

# Very small list of common link-shortening services.
SHORTENER_DOMAINS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "cutt.ly", "shorturl.at", "rb.gy",
)

# Keywords used to classify input fields.
FIELD_KEYWORDS = {
    "otp": [
        "otp", "one-time", "one time", "onetime", "verification code",
        "verification_code", "2fa", "mfa", "auth code", "security code",
        "sms code",
    ],
    "pin": ["pin", "passcode"],
    "password": ["password", "passwd", "pwd", "pass"],
    "email": ["email", "e-mail", "mail"],
    "username": ["username", "user", "login", "account", "uname"],
}

# Risk thresholds (same scale used by the text detector).
HIGH_RISK_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30


class LoginFormValidationError(ValueError):
    """Raised when the provided HTML is empty, too large or not HTML."""


class _LoginFormParser(HTMLParser):
    """Collect form structure and input attributes from HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attributes = {}
        for key, value in attrs:
            attributes[key.lower()] = value if value is not None else ""

        tag = tag.lower()

        if tag == "form":
            self._current = {
                "action": attributes.get("action", ""),
                "method": (attributes.get("method") or "get").lower(),
                "fields": [],
                "formactions": [],
            }
            return

        if self._current is None:
            return

        if tag in ("input", "button", "textarea"):
            self._current["fields"].append(
                {
                    "tag": tag,
                    "type": (
                        attributes.get("type")
                        or ("text" if tag == "input" else "")
                    ).lower(),
                    "name": attributes.get("name", ""),
                    "id": attributes.get("id", ""),
                    "placeholder": attributes.get("placeholder", ""),
                }
            )
            formaction = attributes.get("formaction")
            if formaction:
                self._current["formactions"].append(formaction)

    def handle_startendtag(self, tag, attrs):
        # Handles self-closing tags such as <input />.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self):
        super().close()
        # Keep a form that was never closed properly.
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _normalize_words(text):
    """Lowercase text and turn separators into spaces.

    This lets names such as ``backup_password`` or ``user-email`` match the
    same keywords as plain words.
    """
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _contains_keyword(text, keyword):
    """Check for a keyword inside already-normalized text."""
    pattern = r"\b" + re.escape(_normalize_words(keyword)) + r"\b"
    return re.search(pattern, text) is not None


def _classify_field(field):
    """Return the credential category of an input field, or None."""
    field_type = field["type"]

    if field_type == "password":
        return "password"
    if field_type == "email":
        return "email"

    text = _normalize_words(
        " ".join([field["name"], field["id"], field["placeholder"]])
    )

    if not text:
        return None

    for category in ("otp", "pin", "password", "email", "username"):
        for keyword in FIELD_KEYWORDS[category]:
            if _contains_keyword(text, keyword):
                return category

    return None


def _analyze_action(action):
    """Return (score, reasons) for a form action or formaction value."""
    value = (action or "").strip()

    if not value or value == "#":
        return 0, []

    lowered = value.lower()

    if lowered.startswith(("javascript:", "data:")):
        return 20, [
            "Form action uses a script or data URL instead of a normal "
            "address: " + value
        ]

    parsed = urlparse(lowered)
    score = 0
    reasons = []
    host = ""

    if parsed.scheme in ("http", "https"):
        host = parsed.hostname or ""
        if parsed.scheme == "http":
            score += 30
            reasons.append("Form submits over insecure HTTP: " + value)
        else:
            score += 15
            reasons.append(
                "Form submits to an absolute external URL: " + value
            )
    elif value.startswith("//") and parsed.netloc:
        host = parsed.hostname or ""
        score += 20
        reasons.append(
            "Form submits to an external URL without a scheme: " + value
        )
    else:
        # Relative actions stay on the same site; nothing to flag here.
        return 0, []

    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host or ""):
        score += 15
        reasons.append("Form action uses a raw IP address: " + host)

    host_part = value.split("//", 1)[-1].split("/")[0]
    if "@" in host_part:
        score += 10
        reasons.append(
            "Form action contains an '@' symbol that can hide the real "
            "domain: " + value
        )

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 10
            reasons.append(
                "Form action uses an unusual domain ending (" + tld + "): "
                + value
            )
            break

    for shortener in SHORTENER_DOMAINS:
        if host.endswith(shortener):
            score += 10
            reasons.append(
                "Form action uses a link-shortening service: " + value
            )
            break

    return score, reasons


def _risk_level(score):
    if score >= HIGH_RISK_THRESHOLD:
        return "High Risk"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"


def analyze_login_form(html_text):
    """Analyze HTML for suspicious login-form patterns.

    Args:
        html_text: HTML source code as a string.

    Returns:
        A dictionary with:
        - "score": risk score from 0 to 100
        - "risk_level": "Safe", "Suspicious" or "High Risk"
        - "forms_found": number of <form> elements
        - "fields": counts of password/email/username/pin/otp fields
        - "reasons": list of explanations

    Raises:
        LoginFormValidationError: if the text is empty, too large or does
            not look like HTML.
    """
    if not isinstance(html_text, str) or not html_text.strip():
        raise LoginFormValidationError("HTML content is required.")

    if len(html_text.encode("utf-8", errors="replace")) > MAX_HTML_BYTES:
        raise LoginFormValidationError(
            "HTML content is too large. The maximum size is 2 MB."
        )

    if not re.search(r"<\s*[a-zA-Z!/]", html_text):
        raise LoginFormValidationError(
            "The provided content does not look like HTML."
        )

    parser = _LoginFormParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:
        raise LoginFormValidationError(
            "The provided HTML could not be parsed."
        ) from exc

    forms = parser.forms
    field_counts = {category: 0 for category in FIELD_KEYWORDS}
    hidden_fields = []
    reasons = []
    score = 0

    for form in forms:
        form_has_password = False

        for field in form["fields"]:
            category = _classify_field(field)

            if category is not None:
                field_counts[category] += 1
                if category == "password":
                    form_has_password = True

            if (
                field["type"] == "hidden"
                and category in ("password", "pin", "otp")
            ):
                label = field["name"] or field["id"] or "(unnamed)"
                hidden_fields.append(label)

        action_score, action_reasons = _analyze_action(form["action"])
        score += action_score
        reasons.extend(action_reasons)

        if form["method"] == "get" and form_has_password:
            score += 20
            reasons.append(
                "Form uses the GET method with a password field, so "
                "credentials may appear in the URL."
            )

        for formaction in form["formactions"]:
            extra_score, extra_reasons = _analyze_action(formaction)
            if extra_score > 0:
                score += 10
                reasons.append(
                    "A submit button overrides the form action with: "
                    + formaction
                )
                reasons.extend(extra_reasons)

    # Field-based points (counted once per page).
    if field_counts["password"]:
        score += 15
        reasons.append(
            "Contains password input field(s): %d" % field_counts["password"]
        )
    if field_counts["email"]:
        score += 5
        reasons.append(
            "Contains email input field(s): %d" % field_counts["email"]
        )
    if field_counts["username"]:
        score += 5
        reasons.append(
            "Contains username/login input field(s): %d"
            % field_counts["username"]
        )
    if field_counts["pin"]:
        score += 10
        reasons.append(
            "Contains PIN input field(s): %d" % field_counts["pin"]
        )
    if field_counts["otp"]:
        score += 10
        reasons.append(
            "Contains OTP/verification-code input field(s): %d"
            % field_counts["otp"]
        )

    if hidden_fields:
        score += 15
        reasons.append(
            "Hidden credential-related field(s) detected: "
            + ", ".join(sorted(set(hidden_fields)))
        )

    if not forms:
        reasons.append("No HTML <form> elements were found.")
    elif not any(field_counts.values()):
        reasons.append(
            "No password, email, username, PIN or OTP fields were found."
        )

    # Remove duplicate reasons while keeping their order.
    seen = set()
    unique_reasons = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)

    score = min(score, 100)

    return {
        "score": score,
        "risk_level": _risk_level(score),
        "forms_found": len(forms),
        "fields": field_counts,
        "reasons": unique_reasons,
    }
