"""Brand logo similarity analysis for the phishing detection engine.

The module compares an uploaded logo image against a small local collection
of reference logos and returns a visual similarity score.

Reference logos are NOT downloaded automatically. Place your own image files
in ``phishing/brand_references/`` (PNG, JPG or JPEG). The file name becomes
the brand name, e.g. ``google.png`` -> brand "google".

How the score works (all in-memory, Pillow + NumPy only):

1. The uploaded image is converted to grayscale.
2. A small 9x8 version is used to build a "difference hash" (dHash), which
   captures the rough structure of the image.
3. A 32-bin grayscale histogram captures brightness/colour distribution.
4. The final score is 60% hash similarity + 40% histogram similarity
   (0-100).

Important: a high similarity score does NOT prove that a logo is authentic.
Real logos can be copied, redrawn or imitated. Treat the result as a hint
only.

Safety notes:
- Only local files are read; nothing is downloaded.
- No URLs are visited.
- Uploaded images are processed in memory and never saved.
"""

import io
from pathlib import Path

import numpy as np
from PIL import Image, UnidentifiedImageError

# Maximum accepted upload size: 5 MB.
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024

# Pillow reports "JPEG" for both .jpg and .jpeg files.
ALLOWED_FORMATS = {"PNG", "JPEG"}

# Reference logos are looked up here.
REFERENCE_DIR = Path(__file__).resolve().parent / "brand_references"
SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg"}

# Size used for the difference hash.
HASH_WIDTH = 9
HASH_HEIGHT = 8

# Scores at or above this value are reported as "Possible Match".
MATCH_THRESHOLD = 80

WARNING_TEXT = (
    "Similarity compares visual appearance only and is NOT proof of "
    "authenticity. Logos can be copied, redrawn or imitated."
)


class BrandValidationError(ValueError):
    """Raised when the uploaded file is empty, invalid or unsupported."""


def _load_upload(image_bytes):
    """Open and validate the uploaded image bytes."""
    if not isinstance(image_bytes, (bytes, bytearray)) or len(image_bytes) == 0:
        raise BrandValidationError("The uploaded logo image is empty.")

    if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
        raise BrandValidationError("Image is too large. The maximum size is 5 MB.")

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise BrandValidationError(
            "The uploaded file is not a readable image."
        ) from exc

    if image.format not in ALLOWED_FORMATS:
        raise BrandValidationError(
            "Unsupported image format. Please upload a PNG, JPG or JPEG file."
        )

    return image


def _to_gray(image):
    """Convert an image to grayscale, flattening transparency on white."""
    has_alpha = image.mode in ("RGBA", "LA") or (
        image.mode == "P" and "transparency" in image.info
    )
    if has_alpha:
        background = Image.new("RGB", image.size, "white")
        rgba = image.convert("RGBA")
        background.paste(rgba, mask=rgba.split()[-1])
        image = background
    return image.convert("L")


def _difference_hash(gray_image):
    """Build a 64-bit difference hash from a grayscale image."""
    small = gray_image.resize((HASH_WIDTH, HASH_HEIGHT), Image.LANCZOS)
    pixels = np.asarray(small, dtype=np.int16)
    # Compare each pixel with its right-hand neighbour: 8 x 8 = 64 bits.
    return pixels[:, 1:] > pixels[:, :-1]


def _hash_similarity(hash_a, hash_b):
    """Return the percentage of equal bits (0-100)."""
    return float(np.mean(hash_a == hash_b) * 100.0)


def _gray_histogram(gray_image):
    """Return a normalized 32-bin histogram of a grayscale image."""
    histogram, _ = np.histogram(np.asarray(gray_image), bins=32, range=(0, 256))
    histogram = histogram.astype(np.float64)
    norm = np.linalg.norm(histogram)
    if norm == 0:
        return histogram
    return histogram / norm


def _histogram_similarity(hist_a, hist_b):
    """Cosine similarity of two normalized histograms (0-100)."""
    return float(np.dot(hist_a, hist_b) * 100.0)


def _compare_images(image_a, image_b):
    """Return a combined similarity score (0-100) for two images."""
    gray_a = _to_gray(image_a)
    gray_b = _to_gray(image_b)

    hash_score = _hash_similarity(
        _difference_hash(gray_a), _difference_hash(gray_b)
    )
    histogram_score = _histogram_similarity(
        _gray_histogram(gray_a), _gray_histogram(gray_b)
    )

    return 0.6 * hash_score + 0.4 * histogram_score


def _load_references(reference_dir=None):
    """Load all readable reference logos from the reference folder.

    Returns:
        A list of (brand_name, PIL image) tuples. Broken or unsupported
        files are skipped instead of raising errors.
    """
    directory = Path(reference_dir) if reference_dir is not None else REFERENCE_DIR

    if not directory.is_dir():
        return []

    references = []
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            with open(path, "rb") as file_handle:
                data = file_handle.read()
            image = Image.open(io.BytesIO(data))
            image.load()
            if image.format not in ALLOWED_FORMATS:
                continue
            references.append((path.stem, image))
        except Exception:
            # Skip corrupt or unreadable reference files safely.
            continue

    return references


def analyze_brand(image_bytes, reference_dir=None):
    """Compare an uploaded logo with the local reference collection.

    Args:
        image_bytes: raw bytes of the uploaded logo image.
        reference_dir: optional folder of reference logos (defaults to
            ``phishing/brand_references``). Mainly useful for testing.

    Returns:
        A dictionary with:
        - "result": "Possible Match", "Low Similarity" or "Unknown"
        - "score": best similarity score (int) or None
        - "best_match": brand name of the closest reference, or None
        - "references_checked": number of reference logos compared
        - "matches": list of {"brand": ..., "score": ...} sorted best first
        - "warning": reminder that similarity is not proof of authenticity

    Raises:
        BrandValidationError: if the uploaded file is empty, too large,
            unreadable or not a PNG/JPG/JPEG image.
    """
    image = _load_upload(image_bytes)
    references = _load_references(reference_dir)

    if not references:
        return {
            "result": "Unknown",
            "score": None,
            "best_match": None,
            "references_checked": 0,
            "matches": [],
            "warning": WARNING_TEXT,
        }

    matches = []
    for brand_name, reference_image in references:
        similarity = _compare_images(image, reference_image)
        matches.append({"brand": brand_name, "score": int(round(similarity))})

    matches.sort(key=lambda item: item["score"], reverse=True)
    best = matches[0]

    if best["score"] >= MATCH_THRESHOLD:
        result = "Possible Match"
    else:
        result = "Low Similarity"

    return {
        "result": result,
        "score": best["score"],
        "best_match": best["brand"],
        "references_checked": len(matches),
        "matches": matches,
        "warning": WARNING_TEXT,
    }
