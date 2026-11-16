"""Combined risk assessment across all detection modules.

This module takes the JSON results produced by the five detectors:

- URL Analysis        (phishing.detector.detect)
- Text Analysis       (phishing.text_detector.analyze_text)
- Image OCR           (phishing.image_detector.analyze_image)
- Brand Logo Analysis (phishing.brand_detector.analyze_brand)
- Login Form Analysis (phishing.login_form_detector.analyze_login_form)

and produces one overall phishing risk assessment.

Scoring approach (transparent, fixed weights):

1. Every module result is converted to a risk value from 0 to 100.
2. Text and Image OCR are correlated - OCR text is scored by the same text
   rules - so they are combined with max() instead of being added together.
3. Primary signals use these weights (renormalized over what is available):
       URL Analysis      0.40
       Text / OCR        0.30
       Login Form        0.20
4. Brand similarity is SUPPORTING evidence only. It adds at most 10 points
   and can never make a result High Risk on its own.
5. Missing modules are not treated as safe; they are reported as
   "not analyzed" and simply left out of the weighted average.

Safety notes:
- This module only processes results that were already computed locally.
- It never visits URLs, submits forms, stores files or asks for credentials.
"""

MODULE_KEYS = ("url", "text", "ocr", "brand", "login_form")

MODULE_LABELS = {
    "url": "URL Analysis",
    "text": "Text Analysis",
    "ocr": "Image OCR",
    "brand": "Brand Logo",
    "login_form": "Login Form",
}

# Weights for the primary (independent) signals.
PRIMARY_WEIGHTS = {
    "url": 0.40,
    "content": 0.30,
    "login_form": 0.20,
}

# Brand similarity is a supporting signal only.
BRAND_WEIGHT = 0.10
BRAND_POINT_CAP = 10.0

HIGH_RISK_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30

DISCLAIMER = (
    "Combined scores are heuristic and do not prove that a message, file or "
    "website is safe or malicious. Always verify through official channels."
)


class RiskAssessmentError(ValueError):
    """Raised when the supplied module results are invalid."""


def _clamp(value):
    """Keep a numeric value inside the 0-100 range."""
    return max(0.0, min(100.0, float(value)))


def _coerce_score(value, module_label):
    """Validate and clamp a module score."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RiskAssessmentError(
            module_label + " result has an invalid 'score'."
        )
    if value != value:  # NaN check
        raise RiskAssessmentError(
            module_label + " result has an invalid 'score'."
        )
    return _clamp(value)


def _scored_risk(result, module_label):
    """Get a 0-100 risk value from a text/OCR/login result."""
    score = result.get("score")

    if score is None:
        verdict = result.get("risk_level") or result.get("result")
        if isinstance(verdict, str):
            fallback = {
                "safe": 0.0,
                "suspicious": 45.0,
                "high risk": 80.0,
            }
            key = verdict.strip().lower()
            if key in fallback:
                return fallback[key]
        raise RiskAssessmentError(
            module_label + " result is missing a valid 'score'."
        )

    return _coerce_score(score, module_label)


def _url_risk(result):
    """Map the URL detector output to a risk value (or None)."""
    label = result.get("label")
    if label == "Phishing":
        return 90.0, "URL Analysis classified the URL as Phishing."
    if label == "Legitimate":
        return 5.0, "URL Analysis classified the URL as Legitimate."

    prediction = result.get("prediction")
    if prediction == 0:
        return 90.0, "URL Analysis predicted Phishing (0)."
    if prediction == 1:
        return 5.0, "URL Analysis predicted Legitimate (1)."

    return None, None


def _brand_similarity(result):
    """Return (similarity, summary) for a brand result, or (None, None)."""
    verdict = (result.get("result") or "").strip()
    score = result.get("score")

    if verdict.lower() == "unknown":
        return None, None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None, None
    if score != score:  # NaN
        return None, None

    return _clamp(score), (verdict or "similarity")


def _risk_level(score):
    if score >= HIGH_RISK_THRESHOLD:
        return "High Risk"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"


def _recommended_actions(risk_level, has_missing):
    if risk_level == "High Risk":
        actions = [
            "Do not enter passwords, OTPs or personal information.",
            "Do not click links or download attachments from this source.",
            "Verify the sender or website through a channel you find yourself.",
            "Report the message or page to your IT/security team.",
        ]
    elif risk_level == "Suspicious":
        actions = [
            "Verify the sender or website independently before acting.",
            "Avoid entering credentials until the request is confirmed.",
            "Check the URL carefully; prefer typing it manually.",
        ]
    else:
        actions = [
            "No strong phishing indicators were found, but stay cautious.",
            "Verify unexpected requests before sharing information.",
        ]

    if has_missing:
        actions.append(
            "Some modules were not analyzed; check them for a fuller picture."
        )

    return actions


def assess_risk(results):
    """Combine module results into one overall phishing risk assessment.

    Args:
        results: dictionary that may contain any of the keys
            "url", "text", "ocr", "brand", "login_form". Each value should
            be the JSON output of that module, or None/omitted when the
            module was not used.

    Returns:
        A dictionary with overall_score, risk_level, modules,
        missing_modules, inconclusive_modules, reasons,
        recommended_actions, weights and disclaimer.

    Raises:
        RiskAssessmentError: if the input is not a dictionary, a module
            value is not an object, a score is invalid, or no module
            results were supplied.
    """
    if not isinstance(results, dict):
        raise RiskAssessmentError(
            "Module results must be provided as a JSON object."
        )

    supplied = {key: results.get(key) for key in MODULE_KEYS}

    for key, value in supplied.items():
        if value is not None and not isinstance(value, dict):
            raise RiskAssessmentError(
                "'" + key + "' result must be a JSON object."
            )

    if all(value is None for value in supplied.values()):
        raise RiskAssessmentError("At least one module result is required.")

    modules = {}
    reasons = []
    seen_reasons = set()

    def add_reason(prefix, text):
        key = text.strip().lower()
        if not key or key in seen_reasons:
            return
        seen_reasons.add(key)
        if prefix:
            reasons.append(prefix + ": " + text)
        else:
            reasons.append(text)

    # --- URL -----------------------------------------------------------
    url_risk = None
    if supplied["url"] is not None:
        url_risk, url_reason = _url_risk(supplied["url"])
        if url_risk is None:
            modules["url"] = {"available": False, "status": "inconclusive"}
            add_reason("", "URL Analysis returned no usable result.")
        else:
            label = supplied["url"].get("label")
            modules["url"] = {
                "available": True,
                "risk_score": int(round(url_risk)),
                "summary": label if label else "prediction " + str(
                    supplied["url"].get("prediction")
                ),
            }
            add_reason("", url_reason)
    else:
        modules["url"] = {"available": False, "status": "not_provided"}

    # --- Text ----------------------------------------------------------
    text_risk = None
    if supplied["text"] is not None:
        text_risk = _scored_risk(supplied["text"], "Text Analysis")
        modules["text"] = {
            "available": True,
            "risk_score": int(round(text_risk)),
            "summary": supplied["text"].get("result") or "scored",
        }
        text_reasons = supplied["text"].get("reasons")
        if isinstance(text_reasons, list):
            for reason in text_reasons:
                if isinstance(reason, str):
                    add_reason("Text Analysis", reason)
    else:
        modules["text"] = {"available": False, "status": "not_provided"}

    # --- OCR -----------------------------------------------------------
    ocr_risk = None
    if supplied["ocr"] is not None:
        ocr_risk = _scored_risk(supplied["ocr"], "Image OCR")
        modules["ocr"] = {
            "available": True,
            "risk_score": int(round(ocr_risk)),
            "summary": supplied["ocr"].get("result") or "scored",
        }
        ocr_reasons = supplied["ocr"].get("reasons")
        if isinstance(ocr_reasons, list):
            for reason in ocr_reasons:
                if isinstance(reason, str):
                    add_reason("Image OCR", reason)
    else:
        modules["ocr"] = {"available": False, "status": "not_provided"}

    # --- Brand ---------------------------------------------------------
    brand_similarity = None
    if supplied["brand"] is not None:
        brand_similarity, brand_summary = _brand_similarity(supplied["brand"])
        if brand_similarity is None:
            modules["brand"] = {"available": False, "status": "inconclusive"}
            add_reason(
                "", "Brand Logo analysis returned no usable similarity score."
            )
        else:
            best = supplied["brand"].get("best_match")
            modules["brand"] = {
                "available": True,
                "risk_score": int(round(brand_similarity)),
                "summary": brand_summary,
                "best_match": best,
            }
            message = "Brand Logo similarity was %d/100" % round(brand_similarity)
            if best:
                message += " for '" + str(best) + "'"
            message += (
                "; brand similarity is supporting evidence only and cannot "
                "prove phishing or authenticity."
            )
            add_reason("", message)
    else:
        modules["brand"] = {"available": False, "status": "not_provided"}

    # --- Login form ----------------------------------------------------
    login_risk = None
    if supplied["login_form"] is not None:
        login_risk = _scored_risk(supplied["login_form"], "Login Form Analysis")
        modules["login_form"] = {
            "available": True,
            "risk_score": int(round(login_risk)),
            "summary": supplied["login_form"].get("risk_level") or "scored",
        }
        login_reasons = supplied["login_form"].get("reasons")
        if isinstance(login_reasons, list):
            for reason in login_reasons:
                if isinstance(reason, str):
                    add_reason("Login Form", reason)
    else:
        modules["login_form"] = {"available": False, "status": "not_provided"}

    # --- Combine primary signals --------------------------------------
    primary = []
    if url_risk is not None:
        primary.append((PRIMARY_WEIGHTS["url"], url_risk))

    content_risk = None
    if text_risk is not None:
        content_risk = text_risk
    if ocr_risk is not None:
        if content_risk is None:
            content_risk = ocr_risk
        else:
            content_risk = max(content_risk, ocr_risk)
    if content_risk is not None:
        primary.append((PRIMARY_WEIGHTS["content"], content_risk))

    if login_risk is not None:
        primary.append((PRIMARY_WEIGHTS["login_form"], login_risk))

    if text_risk is not None and ocr_risk is not None:
        add_reason(
            "",
            "Text and Image OCR results were combined using the higher score "
            "to avoid double counting the same content.",
        )

    # --- Brand support points -----------------------------------------
    brand_points = 0.0
    if brand_similarity is not None:
        brand_points = min(BRAND_POINT_CAP, brand_similarity * BRAND_WEIGHT)

    if not primary:
        # Brand similarity alone must not prove phishing.
        final_score = int(round(brand_points))
        add_reason(
            "",
            "Only brand similarity was available; the score is capped at 10 "
            "because brand similarity is supporting evidence only.",
        )
    else:
        total_weight = sum(weight for weight, _ in primary)
        weighted = sum(weight * risk for weight, risk in primary) / total_weight
        final_score = int(round(weighted + brand_points))

    final_score = int(max(0, min(100, final_score)))
    risk_level = _risk_level(final_score)

    # --- Report missing / inconclusive modules ------------------------
    missing = [
        key for key in MODULE_KEYS
        if modules[key].get("status") == "not_provided"
    ]
    inconclusive = [
        key for key in MODULE_KEYS
        if modules[key].get("status") == "inconclusive"
    ]

    for key in missing:
        add_reason("", "Not analyzed: " + MODULE_LABELS[key] + ".")

    return {
        "overall_score": final_score,
        "risk_level": risk_level,
        "modules": modules,
        "missing_modules": missing,
        "inconclusive_modules": inconclusive,
        "reasons": reasons,
        "recommended_actions": _recommended_actions(
            risk_level, bool(missing or inconclusive)
        ),
        "weights": {
            "url": PRIMARY_WEIGHTS["url"],
            "text_or_ocr": PRIMARY_WEIGHTS["content"],
            "login_form": PRIMARY_WEIGHTS["login_form"],
            "brand_support_max_points": BRAND_POINT_CAP,
            "note": (
                "Primary weights are renormalized over the available modules. "
                "Brand similarity adds at most 10 points."
            ),
        },
        "disclaimer": DISCLAIMER,
    }
