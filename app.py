"""Flask application entry point for DRISHTI AI.

Digital Risk Identification & Security Through Intelligent AI.
"""

from pathlib import Path
from urllib.parse import urlencode

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_cors import CORS

from phishing import history
from phishing.detector import detect
from phishing.brand_detector import BrandValidationError, analyze_brand
from phishing.image_detector import (
    MAX_IMAGE_SIZE_BYTES,
    ImageValidationError,
    OCRUnavailableError,
    analyze_image,
)
from phishing.login_form_detector import (
    MAX_HTML_BYTES,
    LoginFormValidationError,
    analyze_login_form,
)
from phishing.risk_assessment import (
    BRAND_POINT_CAP,
    HIGH_RISK_THRESHOLD,
    PRIMARY_WEIGHTS,
    SUSPICIOUS_THRESHOLD,
    RiskAssessmentError,
    assess_risk,
)
from phishing.text_detector import analyze_text

app = Flask(__name__)
CORS(app)


def _empty_statistics():
    return {
        "total": 0,
        "safe": 0,
        "suspicious": 0,
        "high_risk": 0,
        "inconclusive": 0,
    }


def _empty_page():
    return {
        "items": [],
        "total": 0,
        "page": 1,
        "per_page": 10,
        "pages": 0,
        "has_prev": False,
        "has_next": False,
    }


def _filter_args():
    """Whitelisted filter values echoed back through redirects and links."""
    def value(name, default=""):
        if name in request.args:
            return request.args.get(name, default)
        return request.form.get(name, default)

    module = value("module")
    risk = value("risk")
    query = value("q")
    page = value("page", "1")

    args = {}
    if module in history.MODULE_KEYS:
        args["module"] = module
    if risk in history.RISK_LEVELS:
        args["risk"] = risk
    if query:
        args["q"] = query[: history.MAX_QUERY_LENGTH]
    try:
        page_number = int(page)
    except (TypeError, ValueError):
        page_number = 1
    if page_number > 1:
        args["page"] = page_number
    return args


def _pager(endpoint, filters, page, pages):
    """Build pagination links for a page of records."""
    if pages <= 1:
        return {"links": [], "page": 1, "pages": pages}

    if pages <= 7:
        numbers = list(range(1, pages + 1))
    else:
        window = {1, 2, pages - 1, pages, page - 1, page, page + 1}
        numbers = sorted(number for number in window if 1 <= number <= pages)

    links = []
    previous = None
    for number in numbers:
        if previous is not None and number - previous > 1:
            links.append({"ellipsis": True})
        links.append(
            {
                "number": number,
                "current": number == page,
                "url": url_for(endpoint, **dict(filters, page=number)),
                "ellipsis": False,
            }
        )
        previous = number

    return {
        "links": links,
        "page": page,
        "pages": pages,
        "prev_url": url_for(endpoint, **dict(filters, page=page - 1)) if page > 1 else None,
        "next_url": url_for(endpoint, **dict(filters, page=page + 1)) if page < pages else None,
    }


@app.route("/")
def index():
    try:
        stats = history.get_statistics()
        latest_combined = history.get_latest_combined()
        recent_scans = history.get_recent_scans(6)
        history_error = None
    except Exception:
        stats = _empty_statistics()
        latest_combined = None
        recent_scans = []
        history_error = (
            "Scan history is temporarily unavailable. Detection modules still work."
        )

    return render_template(
        "index.html",
        active_page="overview",
        stats=stats,
        latest_combined=latest_combined,
        recent_scans=recent_scans,
        history_error=history_error,
    )


@app.route("/history")
def history_page():
    filters = _filter_args()
    try:
        result = history.list_scans(
            module=filters.get("module"),
            risk_level=filters.get("risk"),
            query=filters.get("q"),
            page=filters.get("page", 1),
            per_page=10,
        )
        history_error = None
    except Exception:
        result = _empty_page()
        history_error = "Scan history is temporarily unavailable."

    notice = None
    if request.args.get("deleted"):
        notice = "The scan record was deleted."
    elif request.args.get("cleared"):
        notice = "Scan history was cleared."
    elif request.args.get("delete_failed") or request.args.get("clear_failed"):
        history_error = "The history database could not be updated."

    return render_template(
        "history.html",
        active_page="history",
        filters=filters,
        result=result,
        pager=_pager("history_page", filters, result["page"], result["pages"]),
        notice=notice,
        history_error=history_error,
        module_options=[
            (key, history.MODULE_LABELS[key]) for key in history.MODULE_KEYS
        ],
        risk_options=[
            (key, history.RISK_LABELS[key])
            for key in ("safe", "suspicious", "high_risk", "inconclusive")
        ],
    )


@app.route("/history/<int:scan_id>/delete", methods=["POST"])
def delete_history_scan(scan_id):
    try:
        history.delete_scan(scan_id)
        flag = "deleted"
    except Exception:
        flag = "delete_failed"
    return redirect(url_for("history_page", **dict(_filter_args(), **{flag: 1})))


@app.route("/history/clear", methods=["POST"])
def clear_history():
    try:
        history.clear_scans()
        return redirect(url_for("history_page", cleared=1))
    except Exception:
        return redirect(url_for("history_page", clear_failed=1))


@app.route("/reports")
def reports_page():
    try:
        page = int(request.args.get("page", 1))
    except (TypeError, ValueError):
        page = 1
    page = max(1, page)

    try:
        result = history.list_scans(page=page, per_page=10)
        history_error = None
    except Exception:
        result = _empty_page()
        history_error = "Scan reports are temporarily unavailable."

    return render_template(
        "reports.html",
        active_page="reports",
        result=result,
        pager=_pager("reports_page", {}, result["page"], result["pages"]),
        history_error=history_error,
    )


@app.route("/reports/<int:scan_id>")
def report_detail(scan_id):
    try:
        record = history.get_scan(scan_id)
    except Exception:
        abort(404)
    if record is None:
        abort(404)

    return render_template(
        "report_detail.html",
        active_page="reports",
        record=record,
        recommendations=history.recommendations_for(record["risk_level_key"]),
        count_rows=history.display_counts(record),
        breakdown=history.display_breakdown(record),
    )


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html", active_page=""), 404


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        app.static_folder, "favicon.ico", mimetype="image/x-icon"
    )


@app.route("/settings")
def settings_page():
    try:
        stats = history.get_statistics()
        history_error = None
    except Exception:
        stats = _empty_statistics()
        history_error = "Scan history is temporarily unavailable."

    notice = None
    if request.args.get("cleared"):
        notice = "Scan history was cleared."
    elif request.args.get("clear_failed"):
        history_error = "The history database could not be updated."

    database_path = Path(history.get_database_path())
    try:
        database_exists = database_path.exists()
        database_size = database_path.stat().st_size if database_exists else 0
    except OSError:
        database_exists = False
        database_size = 0

    return render_template(
        "settings.html",
        active_page="settings",
        stats=stats,
        notice=notice,
        history_error=history_error,
        database_path=str(database_path),
        database_exists=database_exists,
        database_size=database_size,
        engine_version=history.ENGINE_VERSION,
        schema_version=history.SCHEMA_VERSION,
        suspicious_threshold=SUSPICIOUS_THRESHOLD,
        high_risk_threshold=HIGH_RISK_THRESHOLD,
        weights=PRIMARY_WEIGHTS,
        brand_cap=int(BRAND_POINT_CAP),
        module_count=len(history.MODULE_KEYS),
    )


@app.route("/settings/history/clear", methods=["POST"])
def settings_clear_history():
    try:
        history.clear_scans()
        return redirect(url_for("settings_page", cleared=1))
    except Exception:
        return redirect(url_for("settings_page", clear_failed=1))


@app.route("/about")
def about_page():
    return render_template(
        "about.html",
        active_page="about",
        engine_version=history.ENGINE_VERSION,
        schema_version=history.SCHEMA_VERSION,
    )


@app.route("/analysis")
def analysis_hub():
    return render_template("analysis/hub.html", active_page="new_analysis")


@app.route("/analysis/url")
def analysis_url():
    return render_template("analysis/url.html", active_page="url")


@app.route("/analysis/text")
def analysis_text():
    return render_template("analysis/text.html", active_page="text")


@app.route("/analysis/image-brand")
def analysis_image_brand():
    return render_template("analysis/image_brand.html", active_page="image_brand")


@app.route("/analysis/ocr")
def analysis_ocr():
    return render_template("analysis/ocr.html", active_page="ocr")


@app.route("/analysis/login-form")
def analysis_login_form():
    return render_template("analysis/login_form.html", active_page="login_form")


@app.route("/analysis/combined")
def analysis_combined():
    return render_template("analysis/combined.html", active_page="combined")


@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(silent=True)
    url = payload.get("url") if isinstance(payload, dict) else None

    # Validate: missing / empty / non-string URL -> 400
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "A non-empty 'url' string is required."}), 400

    result = detect(url)
    history.safe_record("url", result)
    return jsonify(result), 200


@app.route("/detect-text", methods=["POST"])
def detect_text():
    payload = request.get_json(silent=True)
    text = payload.get("text") if isinstance(payload, dict) else None

    # Validate: missing / empty / non-string text -> 400
    if not isinstance(text, str) or not text.strip():
        return jsonify({"error": "A non-empty 'text' string is required."}), 400

    result = analyze_text(text)
    history.safe_record("text", result)
    return jsonify(result), 200


@app.route("/analyze-image", methods=["POST"])
def analyze_image_route():
    uploaded = request.files.get("image")

    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "No image file was uploaded. Use the 'image' form field."}), 400

    image_bytes = uploaded.read()

    if not image_bytes:
        return jsonify({"error": "The uploaded image is empty."}), 400

    if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
        return jsonify({"error": "Image is too large. The maximum size is 5 MB."}), 413

    try:
        result = analyze_image(image_bytes)
    except ImageValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except OCRUnavailableError as exc:
        return jsonify({"error": str(exc)}), 503

    history.safe_record("ocr", result)
    return jsonify(result), 200


@app.route("/analyze-brand", methods=["POST"])
def analyze_brand_route():
    uploaded = request.files.get("image")

    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "No logo image was uploaded. Use the 'image' form field."}), 400

    image_bytes = uploaded.read()

    if not image_bytes:
        return jsonify({"error": "The uploaded image is empty."}), 400

    if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
        return jsonify({"error": "Image is too large. The maximum size is 5 MB."}), 413

    try:
        result = analyze_brand(image_bytes)
    except BrandValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    history.safe_record("brand", result)
    return jsonify(result), 200


@app.route("/analyze-login-form", methods=["POST"])
def analyze_login_form_route():
    uploaded = request.files.get("file")
    html_text = None

    if uploaded is not None and uploaded.filename:
        raw = uploaded.read()
        if not raw:
            return jsonify({"error": "The uploaded HTML file is empty."}), 400
        if len(raw) > MAX_HTML_BYTES:
            return jsonify({"error": "HTML content is too large. The maximum size is 2 MB."}), 413
        html_text = raw.decode("utf-8", errors="replace")
    else:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            html_text = payload.get("html")
        if isinstance(html_text, str):
            if len(html_text.encode("utf-8", errors="replace")) > MAX_HTML_BYTES:
                return jsonify({"error": "HTML content is too large. The maximum size is 2 MB."}), 413

    if not isinstance(html_text, str) or not html_text.strip():
        return jsonify({
            "error": "A non-empty 'html' string or an uploaded .html file is required."
        }), 400

    try:
        result = analyze_login_form(html_text)
    except LoginFormValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    history.safe_record("login_form", result)
    return jsonify(result), 200


@app.route("/assess-risk", methods=["POST"])
def assess_risk_route():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({
            "error": "A JSON object containing module results is required."
        }), 400

    try:
        result = assess_risk(payload)
    except RiskAssessmentError as exc:
        return jsonify({"error": str(exc)}), 400

    history.safe_record("combined", result)
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
