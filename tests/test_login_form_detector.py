"""Tests for the login form detector and its Flask route.

Run from the project root:

    .venv\\Scripts\\python -m unittest discover -s tests -v
"""

import io
import unittest

from app import app
from phishing.login_form_detector import (
    MAX_HTML_BYTES,
    LoginFormValidationError,
    analyze_login_form,
)

NORMAL_FORM = """
<html><body>
  <form action="/session" method="post">
    <input type="email" name="email" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Sign in</button>
  </form>
</body></html>
"""

SUSPICIOUS_FORM = """
<html><body>
  <form action="http://198.51.100.7/collect" method="get">
    <input type="email" name="email">
    <input type="password" name="password">
    <input type="hidden" name="backup_password">
  </form>
</body></html>
"""

EXTERNAL_FORM = """
<html><body>
  <form action="https://login.example-verify.xyz/collect" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
  </form>
</body></html>
"""

HTTP_FORM = """
<html><body>
  <form action="http://example.com/login" method="post">
    <input type="password" name="password">
  </form>
</body></html>
"""

OTP_PIN_FORM = """
<html><body>
  <form action="/verify" method="post">
    <input type="text" name="otp" placeholder="Enter OTP">
    <input type="text" name="pin" placeholder="PIN">
  </form>
</body></html>
"""


class TestAnalyzeLoginForm(unittest.TestCase):
    def test_normal_form_is_safe(self):
        result = analyze_login_form(NORMAL_FORM)
        self.assertEqual(result["risk_level"], "Safe")
        self.assertLess(result["score"], 30)
        self.assertEqual(result["forms_found"], 1)
        self.assertEqual(result["fields"]["password"], 1)
        self.assertEqual(result["fields"]["email"], 1)

    def test_suspicious_form_is_high_risk(self):
        result = analyze_login_form(SUSPICIOUS_FORM)
        self.assertEqual(result["risk_level"], "High Risk")
        self.assertGreaterEqual(result["score"], 60)
        text = " ".join(result["reasons"]).lower()
        self.assertIn("hidden credential", text)
        self.assertIn("insecure http", text)
        self.assertIn("raw ip", text)

    def test_external_https_action_flagged(self):
        result = analyze_login_form(EXTERNAL_FORM)
        self.assertEqual(result["risk_level"], "Suspicious")
        self.assertGreaterEqual(result["score"], 30)
        self.assertIn("external url", " ".join(result["reasons"]).lower())

    def test_http_submission_flagged(self):
        result = analyze_login_form(HTTP_FORM)
        self.assertIn("insecure http", " ".join(result["reasons"]).lower())
        self.assertGreaterEqual(result["score"], 30)

    def test_otp_and_pin_fields_detected(self):
        result = analyze_login_form(OTP_PIN_FORM)
        self.assertEqual(result["fields"]["otp"], 1)
        self.assertEqual(result["fields"]["pin"], 1)

    def test_html_without_forms_is_safe(self):
        result = analyze_login_form("<html><body><p>Hello</p></body></html>")
        self.assertEqual(result["risk_level"], "Safe")
        self.assertEqual(result["forms_found"], 0)
        self.assertIn("no html <form>", " ".join(result["reasons"]).lower())

    def test_plain_text_is_rejected(self):
        with self.assertRaises(LoginFormValidationError):
            analyze_login_form("this is not html at all")

    def test_empty_input_is_rejected(self):
        with self.assertRaises(LoginFormValidationError):
            analyze_login_form("   ")

    def test_oversized_html_is_rejected(self):
        with self.assertRaises(LoginFormValidationError):
            analyze_login_form("<form>" + ("x" * (MAX_HTML_BYTES + 1)))


class TestLoginFormRoute(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_page_contains_login_form_card(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        # Stage 1 overview links to the dedicated login-form module page.
        self.assertIn('href="/analysis/login-form"', html)
        self.assertIn("Login Form Analysis", html)

    def test_json_html_accepted(self):
        response = self.client.post("/analyze-login-form", json={"html": NORMAL_FORM})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["risk_level"], "Safe")

    def test_uploaded_html_file_accepted(self):
        response = self.client.post(
            "/analyze-login-form",
            data={"file": (io.BytesIO(NORMAL_FORM.encode("utf-8")), "login.html")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["risk_level"], "Safe")

    def test_missing_input_returns_400(self):
        response = self.client.post("/analyze-login-form", json={})
        self.assertEqual(response.status_code, 400)

    def test_invalid_html_returns_400(self):
        response = self.client.post("/analyze-login-form", json={"html": "plain text"})
        self.assertEqual(response.status_code, 400)

    def test_oversized_json_returns_413(self):
        big = "<form>" + ("x" * (MAX_HTML_BYTES + 10))
        response = self.client.post("/analyze-login-form", json={"html": big})
        self.assertEqual(response.status_code, 413)

    def test_empty_upload_returns_400(self):
        response = self.client.post(
            "/analyze-login-form",
            data={"file": (io.BytesIO(b""), "empty.html")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_existing_routes_still_work(self):
        url_response = self.client.post(
            "/predict", json={"url": "https://www.example.com/login"}
        )
        text_response = self.client.post(
            "/detect-text", json={"text": "URGENT: verify your password"}
        )
        self.assertEqual(url_response.status_code, 200)
        self.assertEqual(text_response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
