"""Core phishing detection engine for URL-based phishing detection.

Loads the trained Random Forest model from ``phishing/models/`` and maps its
output to a clear label: ``1 = Legitimate``, ``0 = Phishing``.

Safety:
- Submitted URLs are NEVER visited.
- No passwords or credentials are collected or handled.
"""

import json
from pathlib import Path

import joblib
import pandas as pd

from .features import extract_features

MODEL_PATH = Path(__file__).resolve().parent / "models" / "url_phishing_model.pkl"
FEATURES_PATH = Path(__file__).resolve().parent / "models" / "url_features.json"

_model = None
_model_load_error = None
_feature_names = None


def _load_model():
    global _model, _model_load_error
    if _model_load_error is not None:
        return None
    if _model is None:
        try:
            _model = joblib.load(str(MODEL_PATH))
        except Exception as exc:
            _model_load_error = f"Failed to load phishing model: {exc}"
            _model = None
    return _model


def _get_feature_names() -> list:
    global _feature_names
    if _feature_names is None:
        names = []
        try:
            with open(FEATURES_PATH, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, list) and len(loaded) > 0:
                names = [str(n) for n in loaded]
        except Exception:
            names = []
        _feature_names = names
    return _feature_names


def detect(url: str) -> dict:
    """Detect phishing for a submitted URL.

    Returns:
        - ``label``: ``"Legitimate"`` (prediction ``1``) or ``"Phishing"``
          (prediction ``0``) on success.
        - ``label``: ``"Unknown"`` with an explicit ``error`` if the model
          cannot be loaded or the extracted features fail validation. Never
          guesses in that case.

    Safety:
        - Submitted URLs are never visited.
        - No passwords or credentials are collected or handled.
    """
    url = url.strip() if isinstance(url, str) else ""
    names = _get_feature_names()
    features = extract_features(url, names=names)

    if len(features) != len(names) or any(f is None for f in features):
        return {
            "url": url,
            "label": "Unknown",
            "prediction": None,
            "error": "Feature validation failed: unable to extract all required URL features.",
        }

    model = _load_model()
    if model is None:
        return {
            "url": url,
            "label": "Unknown",
            "prediction": None,
            "error": _model_load_error or "Failed to load phishing model.",
        }

    try:
        n_expected = int(getattr(model, "n_features_in_", len(features)))
    except Exception:
        n_expected = len(features)

    if n_expected != len(features):
        return {
            "url": url,
            "label": "Unknown",
            "prediction": None,
            "error": (
                f"Feature mismatch: model expects {n_expected} features, "
                f"received {len(features)}."
            ),
        }

    try:
        X = pd.DataFrame([features], columns=names)
        prediction = int(model.predict(X)[0])
    except Exception as exc:
        return {
            "url": url,
            "label": "Unknown",
            "prediction": None,
            "error": f"Model prediction failed: {exc}",
        }

    label = "Legitimate" if prediction == 1 else "Phishing"

    return {
        "url": url,
        "label": label,
        "prediction": prediction,
        "warning": (
            "URL features were computed heuristically from the raw submitted URL "
            "and are approximations of the precomputed UCI dataset features; "
            "predictions are approximate and should not be treated as equivalent "
            "to the dataset evaluation."
        ),
    }
