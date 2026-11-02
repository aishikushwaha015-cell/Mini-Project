"""Safe URL-based feature extraction for the phishing detection engine.

The features in this module are computed heuristically from the raw submitted
URL string using only Python's standard library (``urllib.parse``, ``re``).

IMPORTANT: These are APPROXIMATE heuristic implementations and do NOT
necessarily reproduce the precomputed UCI PhiUSIIL Phishing URL dataset
features (several dataset features were derived from webpage source code,
not from the URL string alone).

Do not treat model outputs produced from these values as equivalent to the
published dataset evaluation.

Features that cannot be computed safely are marked as ``None``.
"""

import json
import re
from pathlib import Path
from urllib.parse import urlparse

FEATURES_FILE = Path(__file__).resolve().parent / "models" / "url_features.json"

_FALLBACK_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]

_SAFE_CHARS = frozenset("-._~:/?#[]@!$&'()*+,;=%")


def _load_feature_names() -> list:
    """Load ordered feature names from url_features.json (fallback to defaults)."""
    try:
        with open(FEATURES_FILE, "r", encoding="utf-8") as fh:
            names = json.load(fh)
        if isinstance(names, list) and len(names) > 0:
            return [str(n) for n in names]
    except Exception:
        pass
    return list(_FALLBACK_FEATURES)


def _ratio(num, den) -> float:
    if not den:
        return 0.0
    return float(num) / float(den)


def _is_ip(host: str) -> bool:
    if not host:
        return False
    try:
        import ipaddress

        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def extract_features(url: str, names: list = None) -> list:
    """Extract heuristic phishing URL features.

    Args:
        url: Submitted URL string.
        names: Optional ordered feature names. Defaults to those loaded from
            ``models/url_features.json``.

    Returns:
        List of feature values aligned with ``names`` order. Features that
        cannot be computed safely are ``None``.
    """
    feature_names = list(names) if names is not None else _load_feature_names()
    u = (url or "").strip()
    if not u:
        return [None] * len(feature_names)

    parsed = urlparse(u if "://" in u else "//" + u)
    scheme = parsed.scheme or ""
    host = parsed.hostname or ""
    url_len = len(u)
    labels = [l for l in host.split(".") if l]
    tld = labels[-1] if len(labels) > 1 else ""
    obfuscated_count = len(re.findall(r"%[0-9A-Fa-f]{2}", u))
    letters_count = sum(1 for c in u if c.isalpha())
    digits_count = sum(1 for c in u if c.isdigit())
    special_chars = [c for c in u if not c.isalnum() and c not in _SAFE_CHARS]

    values = {
        "URLLength": float(url_len),
        "DomainLength": float(len(host)),
        "IsDomainIP": 1.0 if _is_ip(host) else 0.0,
        "TLDLength": float(len(tld)),
        "NoOfSubDomain": float(max(len(labels) - 2, 0)),
        "HasObfuscation": 1.0 if obfuscated_count > 0 else 0.0,
        "NoOfObfuscatedChar": float(obfuscated_count),
        "ObfuscationRatio": _ratio(obfuscated_count, url_len),
        "NoOfLettersInURL": float(letters_count),
        "LetterRatioInURL": _ratio(letters_count, url_len),
        "NoOfDegitsInURL": float(digits_count),
        "DegitRatioInURL": _ratio(digits_count, url_len),
        "NoOfEqualsInURL": float(u.count("=")),
        "NoOfQMarkInURL": float(u.count("?")),
        "NoOfAmpersandInURL": float(u.count("&")),
        "NoOfOtherSpecialCharsInURL": float(len(special_chars)),
        "SpacialCharRatioInURL": _ratio(len(special_chars), url_len),
        "IsHTTPS": 1.0 if scheme.lower() == "https" else 0.0,
    }

    return [values.get(name) for name in feature_names]
