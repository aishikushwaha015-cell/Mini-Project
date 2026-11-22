"""Stage 4 page tests: settings, about, favicon and responsive tables.

Run from the project root:

    .venv\\Scripts\\python -m unittest discover -s tests -v
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import app
from phishing import history


def url_result(label="Phishing", prediction=0):
    return {"url": "https://sentinel-raw.example/login", "label": label,
            "prediction": prediction}


def text_result(score=92, label="High Risk"):
    return {"score": score, "result": label, "reasons": ["reason"]}


class StageFourTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.tmp = Path(tempfile.mkdtemp(prefix="phishguard-stage4-"))
        history.set_database_path(self.tmp / "history.db")
        self.addCleanup(history.set_database_path, None)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def get(self, path):
        response = self.client.get(path)
        return response, response.get_data(as_text=True)

    def seed(self):
        return [
            history.record_analysis("url", url_result()),
            history.record_analysis("url", url_result("Legitimate", 1)),
            history.record_analysis("text", text_result()),
            history.record_analysis("text", text_result(18, "Safe")),
        ]


class TestSettingsPage(StageFourTestCase):
    def test_page_renders_shared_shell_and_active_navigation(self):
        response, html = self.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn("css/records.css", html)
        self.assertIn("js/records.js", html)
        self.assertIn('data-page="settings"', html)
        self.assertIn('id="sidebar"', html)
        self.assertIn('href="/settings"', html)
        self.assertIn('aria-current="page"', html)
        self.assertIn("Settings", html)

    def test_shows_database_location_and_versions(self):
        _, html = self.get("/settings")
        self.assertIn("Project database location", html)
        self.assertIn(str(self.tmp / "history.db"), html)
        self.assertIn(history.ENGINE_VERSION, html)
        self.assertIn("schema v%d" % history.SCHEMA_VERSION, html)

    def test_explains_stored_and_never_stored_data(self):
        _, html = self.get("/settings")
        self.assertIn("Stored metadata", html)
        self.assertIn("Never stored", html)
        self.assertIn("Raw URLs, hostnames or query strings", html)
        self.assertIn("Messages, OCR text or document contents", html)
        self.assertIn("Passwords, OTPs, tokens or credentials", html)
        self.assertIn("Uploaded images, logos or filenames", html)
        self.assertIn("Sanitized numeric counts", html)

    def test_shows_read_only_configuration(self):
        _, html = self.get("/settings")
        self.assertIn("Dashboard configuration", html)
        self.assertIn("Read only", html)
        self.assertIn("Detection modules", html)
        self.assertIn("Risk thresholds", html)
        self.assertIn("Combined weights", html)
        self.assertIn("Midnight Navy", html)
        self.assertIn("#00E5FF", html)

    def test_aggregate_summary_uses_real_counts_without_duplicating_table(self):
        self.seed()
        _, html = self.get("/settings")
        self.assertIn("Scan history management", html)
        self.assertIn(">4<", html)
        self.assertIn("Manage individual records", html)
        self.assertIn('href="/history"', html)
        self.assertNotIn('class="data-table', html)
        self.assertNotIn("No scans recorded yet", html)

    def test_clear_all_uses_shared_confirmation_dialog(self):
        self.seed()
        _, html = self.get("/settings")
        self.assertIn('id="confirm-dialog"', html)
        self.assertIn("data-confirm", html)
        self.assertIn('data-confirm-title="Clear all scan history?"', html)
        self.assertIn('action="/settings/history/clear"', html)

    def test_empty_history_disables_clear_button(self):
        _, html = self.get("/settings")
        self.assertIn("History already empty", html)
        self.assertNotIn("Clear all scan history", html)

    def test_clear_all_history_success(self):
        self.seed()
        response = self.client.post("/settings/history/clear", follow_redirects=True)
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Scan history was cleared.", html)
        self.assertEqual(history.get_statistics()["total"], 0)
        self.assertIn("History already empty", html)

    def test_clear_all_history_failure_is_reported(self):
        self.seed()
        with mock.patch.object(
            history, "clear_scans", side_effect=history.HistoryError("boom")
        ):
            response = self.client.post(
                "/settings/history/clear", follow_redirects=True
            )
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("The history database could not be updated.", html)
        self.assertEqual(history.get_statistics()["total"], 4)

    def test_database_read_failure_is_reported_without_crashing(self):
        with mock.patch.object(
            history, "get_statistics", side_effect=history.HistoryError("boom")
        ):
            response, html = self.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Scan history is temporarily unavailable.", html)

    def test_no_charts_on_settings(self):
        _, html = self.get("/settings")
        lowered = html.lower()
        for token in ("<canvas", "chart.js", "donut", "sparkline"):
            self.assertNotIn(token, lowered)


class TestAboutPage(StageFourTestCase):
    def test_page_renders_and_has_active_navigation(self):
        response, html = self.get("/about")
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-page="about"', html)
        self.assertIn('id="sidebar"', html)
        self.assertIn('aria-current="page"', html)
        self.assertIn("About DRISHTI AI", html)

    def test_required_sections_are_present(self):
        _, html = self.get("/about")
        required = [
            "Project introduction",
            "Problem statement",
            "Project objectives",
            "Detection modules",
            "Technology stack",
            "Architecture &amp; detection workflow",
            "Limitations &amp; future scope",
            "Project information",
        ]
        for heading in required:
            with self.subTest(heading=heading):
                self.assertIn(heading, html)

    def test_all_six_detection_modules_are_explained(self):
        _, html = self.get("/about")
        modules = [
            "URL Analysis",
            "Text Analysis",
            "OCR Analysis",
            "Image &amp; Brand Analysis",
            "Login Form Analysis",
            "Combined Risk Assessment",
        ]
        for module in modules:
            with self.subTest(module=module):
                self.assertIn(module, html)
        self.assertEqual(html.count('class="about-card"'), 6)

    def test_technology_stack_is_described(self):
        _, html = self.get("/about")
        for technology in (
            "Python",
            "Flask",
            "Jinja templates",
            "HTML, CSS &amp; vanilla JavaScript",
            "scikit-learn &amp; joblib",
            "pandas &amp; NumPy",
            "Pillow &amp; pytesseract",
            "SQLite",
        ):
            with self.subTest(technology=technology):
                self.assertIn(technology, html)

    def test_workflow_has_numbered_steps(self):
        _, html = self.get("/about")
        self.assertEqual(html.count('class="workflow-step"'), 6)
        self.assertIn("Local module analysis", html)
        self.assertIn("Sanitized persistence", html)
        self.assertIn("History and reports", html)

    def test_unavailable_team_details_are_marked_as_placeholders(self):
        _, html = self.get("/about")
        self.assertEqual(html.count("Not specified in the project files"), 3)
        self.assertIn("Developer / team", html)
        self.assertIn("Institution / course", html)
        self.assertIn("License", html)

    def test_no_unsupported_accuracy_claim(self):
        _, html = self.get("/about")
        self.assertIn("No accuracy, precision or recall figures are claimed", html)
        lowered = html.lower()
        self.assertNotIn("99% accuracy", lowered)
        self.assertNotIn("98% accuracy", lowered)

    def test_no_charts_on_about(self):
        _, html = self.get("/about")
        lowered = html.lower()
        for token in ("<canvas", "chart.js", "donut", "sparkline"):
            self.assertNotIn(token, lowered)


class TestFaviconAndNavigation(StageFourTestCase):
    def test_favicon_ico_is_served(self):
        response = self.client.get("/favicon.ico")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"\x00\x00\x01\x00"))
        response.close()

    def test_favicon_svg_is_served(self):
        response = self.client.get("/static/favicon.svg")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<svg", response.data)
        response.close()

    def test_base_template_links_both_icons(self):
        _, html = self.get("/")
        self.assertIn('rel="icon"', html)
        self.assertIn("favicon.svg", html)
        self.assertIn("favicon.ico", html)

    def test_every_sidebar_link_has_a_working_page(self):
        _, html = self.get("/")
        paths = [
            "/",
            "/analysis",
            "/analysis/url",
            "/analysis/text",
            "/analysis/image-brand",
            "/analysis/ocr",
            "/analysis/login-form",
            "/analysis/combined",
            "/history",
            "/reports",
            "/settings",
            "/about",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertIn('href="%s"' % path, html)
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                response.close()

    def test_settings_and_about_are_not_four_oh_four(self):
        for path in ("/settings", "/about"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn("could not be found", response.get_data(as_text=True))
                response.close()


class TestResponsiveTables(StageFourTestCase):
    def test_history_table_supports_stacked_mobile_layout(self):
        self.seed()
        _, html = self.get("/history")
        self.assertIn('class="data-table stack-mobile"', html)
        for label in ("Date (UTC)", "Module", "Result", "Risk", "Score", "Status",
                      "Actions"):
            with self.subTest(label=label):
                self.assertIn('data-label="%s"' % label, html)

    def test_reports_table_supports_stacked_mobile_layout(self):
        self.seed()
        _, html = self.get("/reports")
        self.assertIn('class="data-table stack-mobile"', html)
        for label in ("Date (UTC)", "Report", "Module", "Risk", "Score", "Status"):
            with self.subTest(label=label):
                self.assertIn('data-label="%s"' % label, html)

    def test_mobile_table_css_is_shipped(self):
        response = self.client.get("/static/css/records.css")
        css = response.get_data(as_text=True)
        response.close()
        self.assertIn(".data-table.stack-mobile", css)
        self.assertIn("@media (max-width: 640px)", css)
        self.assertIn("content: attr(data-label)", css)


if __name__ == "__main__":
    unittest.main()
