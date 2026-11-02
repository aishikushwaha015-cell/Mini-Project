"""Flask application entry point for the Multimodal AI Brand Spoofing
& Credential Harvesting Phishing Detection Engine.
"""

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from phishing.detector import detect

app = Flask(__name__)
CORS(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(silent=True)
    url = payload.get("url") if isinstance(payload, dict) else None

    # Validate: missing / empty / non-string URL -> 400
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "A non-empty 'url' string is required."}), 400

    result = detect(url)
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
