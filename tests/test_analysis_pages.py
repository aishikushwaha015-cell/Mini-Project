"""Tests for the Stage 2 analysis pages and their wiring.

Run from the project root:

    .venv\\Scripts\\python -m unittest discover -s tests -v
"""

import unittest

from app import app


PAGES = [
    ("/analysis", "hub", "New Analysis"),
    ("/analysis/url", "url", "URL Analysis"),
    ("/analysis/text", "text", "Text Analysis"),
    ("/analysis/ocr", "ocr", "OCR Analysis"),
    ("/analysis/image-brand", "image_brand", "Image &amp; Brand Analysis"),
    ("/analysis/login-form", "login_form", "Login Form Analysis"),
    ("/analysis/combined", "combined", "Combined Risk Assessment"),
]


class TestAnalysisPages(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_all_pages_return_200(self):
        for path, _, heading in PAGES:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(heading, response.get_data(as_text=True))

    def test_pages_use_shared_shell_and_assets(self):
        for path, page_id, _ in PAGES:
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True)
                self.assertIn('id="sidebar"', html)
                self.assertIn("css/app.css", html)
                self.assertIn("css/analysis.css", html)
                self.assertIn("js/analysis.js", html)
                self.assertIn('data-page="%s"' % page_id, html)

    def test_module_pages_declare_their_existing_api(self):
        expected = {
            "/analysis/url": 'data-api="/predict"',
            "/analysis/text": 'data-api="/detect-text"',
            "/analysis/ocr": 'data-api="/analyze-image"',
            "/analysis/image-brand": 'data-api="/analyze-brand"',
            "/analysis/login-form": 'data-api="/analyze-login-form"',
        }
        for path, marker in expected.items():
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True)
                self.assertIn(marker, html)

    def test_hub_links_all_six_modules(self):
        html = self.client.get("/analysis").get_data(as_text=True)
        for path in (
            "/analysis/url",
            "/analysis/text",
            "/analysis/image-brand",
            "/analysis/ocr",
            "/analysis/login-form",
            "/analysis/combined",
        ):
            self.assertIn('href="%s"' % path, html)
        self.assertEqual(html.count('class="module-card"'), 6)

    def test_active_navigation_matches_each_page(self):
        for path, _, _ in PAGES:
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True)
                self.assertIn('aria-current="page"', html)

    def test_no_chart_or_analytics_markup(self):
        forbidden = ("<canvas", "chart.js", "donut", "sparkline")
        for path, _, _ in PAGES:
            with self.subTest(path=path):
                html = self.client.get(path).get_data(as_text=True).lower()
                for token in forbidden:
                    self.assertNotIn(token, html)

    def test_analysis_script_references_all_existing_apis(self):
        script = self.client.get("/static/js/analysis.js")
        self.assertEqual(script.status_code, 200)
        text = script.get_data(as_text=True)
        script.close()
        for endpoint in (
            "/predict",
            "/detect-text",
            "/analyze-image",
            "/analyze-brand",
            "/analyze-login-form",
            "/assess-risk",
        ):
            self.assertIn(endpoint, text)

    def test_login_form_page_supports_paste_and_upload(self):
        html = self.client.get("/analysis/login-form").get_data(as_text=True)
        self.assertIn('id="panel-paste"', html)
        self.assertIn('id="panel-upload"', html)
        self.assertIn('name="html"', html)
        self.assertIn('name="file"', html)

    def test_upload_fields_and_limits_are_documented(self):
        ocr = self.client.get("/analysis/ocr").get_data(as_text=True)
        brand = self.client.get("/analysis/image-brand").get_data(as_text=True)
        self.assertIn('name="image"', ocr)
        self.assertIn('name="image"', brand)
        self.assertIn("5 MB", ocr)
        self.assertIn("2 MB", self.client.get("/analysis/login-form").get_data(as_text=True))

    def test_privacy_copy_is_present(self):
        hub = self.client.get("/analysis").get_data(as_text=True)
        self.assertIn("never written to disk", hub)
        self.assertIn("credentials are never stored", hub)
        ocr = self.client.get("/analysis/ocr").get_data(as_text=True)
        self.assertIn("never saved", ocr)


if __name__ == "__main__":
    unittest.main()
