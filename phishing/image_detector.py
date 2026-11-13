"""Image OCR analysis for the phishing detection engine.

This module extracts readable text from an uploaded screenshot or image using
Pillow + pytesseract, then reuses the existing rule-based text detector
(``phishing.text_detector.analyze_text``) to score the extracted text.

Safety notes:
- Images are processed in memory only; nothing is written to disk.
- Links found in images are never visited or downloaded.
- No passwords or credentials are collected.
- OCR requires the Tesseract engine to be installed on the machine.
"""

import io
import os

import pytesseract
from PIL import Image, UnidentifiedImageError

from phishing.text_detector import analyze_text

# Maximum accepted upload size: 5 MB.
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024

# Pillow reports "JPEG" for both .jpg and .jpeg files.
ALLOWED_FORMATS = {"PNG", "JPEG"}

# On Windows the Tesseract installer does not always update PATH.
# Use the default installation folder when it exists.
_WINDOWS_TESSERACT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.name == "nt" and os.path.exists(_WINDOWS_TESSERACT_PATH):
    pytesseract.pytesseract.tesseract_cmd = _WINDOWS_TESSERACT_PATH


class ImageValidationError(ValueError):
    """Raised when the uploaded file is empty, invalid or unsupported."""


class OCRUnavailableError(RuntimeError):
    """Raised when the Tesseract OCR engine is not installed."""


def _check_tesseract():
    """Make sure the Tesseract engine is available.

    Raises:
        OCRUnavailableError: if the engine is missing or not on PATH.
    """
    try:
        pytesseract.get_tesseract_version()
    except pytesseract.TesseractNotFoundError as exc:
        raise OCRUnavailableError(
            "Tesseract OCR is not installed. Install it from "
            "https://github.com/UB-Mannheim/tesseract/wiki "
            "(or run: winget install UB-Mannheim.TesseractOCR)."
        ) from exc


def analyze_image(image_bytes):
    """Extract text from an image and run the phishing text analysis.

    Args:
        image_bytes: raw bytes of the uploaded image.

    Returns:
        A dictionary with:
        - "extracted_text": text found in the image (may be empty)
        - "score": risk score from 0 to 100
        - "result": "Safe", "Suspicious" or "High Risk"
        - "reasons": list of explanations

    Raises:
        ImageValidationError: if the file is empty, too large, unreadable
            or not a supported PNG/JPG/JPEG image.
        OCRUnavailableError: if the Tesseract engine is not installed.
    """
    # --- Basic validation -------------------------------------------------
    if not isinstance(image_bytes, (bytes, bytearray)) or len(image_bytes) == 0:
        raise ImageValidationError("The uploaded image is empty.")

    if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
        raise ImageValidationError("Image is too large. The maximum size is 5 MB.")

    # --- Open and verify the image ---------------------------------------
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()  # forces Pillow to read the whole file now
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ImageValidationError(
            "The uploaded file is not a readable image."
        ) from exc

    if image.format not in ALLOWED_FORMATS:
        raise ImageValidationError(
            "Unsupported image format. Please upload a PNG, JPG or JPEG file."
        )

    # --- OCR ---------------------------------------------------------------
    _check_tesseract()

    # Tesseract expects RGB or grayscale images.
    if image.mode not in ("RGB", "L"):
        image = image.convert("RGB")

    try:
        extracted_text = pytesseract.image_to_string(image).strip()
    except pytesseract.TesseractNotFoundError as exc:
        raise OCRUnavailableError(
            "Tesseract OCR is not installed. Install it from "
            "https://github.com/UB-Mannheim/tesseract/wiki."
        ) from exc
    except Exception as exc:
        raise ImageValidationError("Could not read text from the image.") from exc

    # --- Reuse the existing text rules ------------------------------------
    if not extracted_text:
        analysis = {
            "score": 0,
            "result": "Safe",
            "reasons": ["No readable text was found in the image."],
        }
    else:
        analysis = analyze_text(extracted_text)

    return {
        "extracted_text": extracted_text,
        "score": analysis["score"],
        "result": analysis["result"],
        "reasons": analysis["reasons"],
    }
