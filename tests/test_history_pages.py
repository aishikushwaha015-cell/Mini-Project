"""Stage 3 page tests: history, reports, overview and failure handling.

Run from the project root:

    .venv\\Scripts\\python -m unittest discover -s tests -v
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from app import app
from phishing import history

SENTINEL = "SENTINEL-RAW-INPUT-7c1f"
SENTINEL_HTML = (
    '<form action="https://sentinel-raw.example/collect">'
    '<input type="password" name="SENTINEL-RAW-INPUT-7c1f"></form>'
)


def url_result(label="Phishing", prediction=0):
    return {"url": "https://sentinel-raw.example/login?token=" + SENTINEL,
            "label": label, "prediction": prediction}


def text_result(score=92, label="High Risk"):
    return {
        "score": score,
        "result": label,
        "reasons": ["SENTINEL reason that must never be stored", SENTINEL],
    }


def brand_result():
    return {
        "result": "Possible Match",
        "score": 81,
        "best_match": SENTINEL,
        "references_checked": 2,
        "matches": [{"brand": SENTINEL, "score": 81}],
    }


def login_result():
    return {
        "score": 70,
        "risk_level": "High Risk",
        "forms_found": 1,
        "fields": {"password": 1, "email": 1, "otp": 0},
        "reasons": [SENTINEL, SENTINEL_HTML],
    }


def combined_result():
    return {
        "overall_score": 87,
        "risk_level": "High Risk",
        "modules": {
            "url": {"available": True, "risk_score": 90},
            "text": {"available": True, "risk_score": 92},
            "ocr": {"available": False, "status": "not_provided"},
            "brand": {"available": True, "risk_score": 81},
            "login_form": {"available": False, "status": "inconclusive"},
        },
        "missing_modules": ["ocr"],
        "inconclusive_modules": ["login_form"],
        "reasons": [SENTINEL],
        "recommended_actions": [SENTINEL_HTML],
    }


class PageTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.tmp = Path(tempfile.mkdtemp(prefix="phishguard-pages-"))
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
            history.record_analysis("login_form", login_result()),
            history.record_analysis("brand", brand_result()),
            history.record_analysis("combined", combined_result()),
        ]


class TestHistoryPage(PageTestCase):
    def test_empty_state(self):
        response, html = self.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No scans recorded yet", html)
        self.assertIn("Results are added automatically", html)
        self.assertNotIn("Clear all history", html)

    def test_shared_shell_and_assets(self):
        _, html = self.get("/history")
        self.assertIn('id="sidebar"', html)
        self.assertIn("css/records.css", html)
        self.assertIn("js/records.js", html)
        self.assertIn('data-page="history"', html)
        self.assertIn('aria-current="page"', html)

    def test_lists_sanitized_records(self):
        self.seed()
        _, html = self.get("/history")
        self.assertIn("URL Analysis", html)
        self.assertIn("Combined Risk Assessment", html)
        self.assertIn(">Phishing<", html)
        self.assertIn(">High Risk<", html)
        self.assertIn("92/100", html)
        self.assertIn("6</strong> records", html)
        self.assertIn("Clear all history", html)

    def test_module_filter_limits_rows(self):
        self.seed()
        _, html = self.get("/history?module=url")
        self.assertEqual(html.count('class="type-pill"'), 2)
        self.assertIn("All modules", html)

    def test_risk_filter_limits_rows(self):
        self.seed()
        _, html = self.get("/history?risk=inconclusive")
        self.assertEqual(html.count('class="type-pill"'), 1)

    def test_search_filter_matches_allowed_fields(self):
        self.seed()
        _, html = self.get("/history?q=login")
        self.assertEqual(html.count('class="type-pill"'), 1)
        _, none = self.get("/history?q=" + SENTINEL)
        self.assertIn("No scans match these filters", none)

    def test_invalid_filter_values_are_ignored(self):
        self.seed()
        response, html = self.get("/history?module=bogus&risk=evil&page=abc")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(html.count('class="type-pill"'), 6)

    def test_pagination_and_preserved_filters(self):
        for _ in range(12):
            history.record_analysis("text", text_result())
        response, html = self.get("/history?module=text&page=2")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Page 2 of 2", html)
        self.assertIn('aria-current="page">2</span>', html)
        self.assertEqual(html.count('class="type-pill"'), 2)
        self.assertIn("module=text&amp;page=1", html)

    def test_delete_individual_record(self):
        ids = self.seed()
        response = self.client.post(
            "/history/%d/delete" % ids[0], follow_redirects=True
        )
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("The scan record was deleted.", html)
        self.assertEqual(history.get_statistics()["total"], 5)
        self.assertIsNone(history.get_scan(ids[0]))

    def test_delete_keeps_active_filters(self):
        ids = self.seed()
        response = self.client.post(
            "/history/%d/delete" % ids[5],
            data={"module": "combined", "risk": "high_risk", "q": "risk"},
        )
        self.assertEqual(response.status_code, 302)
        location = response.headers["Location"]
        self.assertIn("module=combined", location)
        self.assertIn("risk=high_risk", location)
        self.assertIn("deleted=1", location)

    def test_delete_missing_record_does_not_error(self):
        response = self.client.post("/history/99999/delete", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("The scan record was deleted.", response.get_data(as_text=True))

    def test_clear_all_history(self):
        self.seed()
        response = self.client.post("/history/clear", follow_redirects=True)
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Scan history was cleared.", html)
        self.assertEqual(history.get_statistics()["total"], 0)
        self.assertIn("No scans recorded yet", html)

    def test_confirmation_dialog_present(self):
        self.seed()
        _, html = self.get("/history")
        self.assertIn('id="confirm-dialog"', html)
        self.assertIn("data-confirm", html)
        self.assertIn('data-confirm-title="Clear all scan history?"', html)

    def test_no_chart_or_analytics_markup(self):
        self.seed()
        _, html = self.get("/history")
        lowered = html.lower()
        for token in ("<canvas", "chart.js", "donut", "sparkline"):
            self.assertNotIn(token, lowered)


class TestReports(PageTestCase):
    def test_reports_list_and_empty_state(self):
        response, html = self.get("/reports")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No reports yet", html)
        self.assertIn("metadata only", html)

        self.seed()
        _, html = self.get("/reports")
        self.assertIn("Combined Risk Assessment", html)
        self.assertIn("6</strong> reports", html)
        self.assertIn("View report", html)

    def test_report_detail_shows_metadata_and_static_advice(self):
        ids = self.seed()
        response, html = self.get("/reports/%d" % ids[5])
        self.assertEqual(response.status_code, 200)
        self.assertIn("Report #%d" % ids[5], html)
        self.assertIn("High Risk", html)
        self.assertIn("87", html)
        self.assertIn("Combined Risk Assessment", html)
        self.assertIn("Sanitized module breakdown", html)
        self.assertIn("Not analyzed", html)
        self.assertIn("Inconclusive", html)
        self.assertIn("General safety recommendations", html)
        self.assertIn("Do not enter passwords", html)
        self.assertIn("data-print", html)
        self.assertIn("sanitized metadata only", html)

    def test_single_module_report_has_no_breakdown(self):
        ids = self.seed()
        _, html = self.get("/reports/%d" % ids[2])
        self.assertIn("Text Analysis", html)
        self.assertIn("General safety recommendations", html)
        self.assertNotIn("Sanitized module breakdown", html)

    def test_missing_report_returns_themed_404(self):
        for path in ("/reports/99999", "/reports/not-a-number"):
            with self.subTest(path=path):
                response, html = self.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertIn("could not be found", html)
                self.assertIn('id="sidebar"', html)

    def test_reports_do_not_render_charts(self):
        self.seed()
        for path in ("/reports", "/reports/6"):
            with self.subTest(path=path):
                _, html = self.get(path)
                lowered = html.lower()
                for token in ("<canvas", "chart.js", "donut", "sparkline"):
                    self.assertNotIn(token, lowered)


class TestOverview(PageTestCase):
    def test_overview_uses_real_statistics(self):
        self.seed()
        response, html = self.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(html.count('class="stat-card"'), 5)
        self.assertIn("Total Scans", html)
        self.assertIn("Safe Scans", html)
        self.assertIn("Suspicious Scans", html)
        self.assertIn("High Risk Scans", html)
        self.assertIn("Inconclusive Scans", html)
        self.assertIn(">6</p>", html)
        self.assertIn(">1</p>", html)

    def test_overview_links_latest_combined_report(self):
        ids = self.seed()
        _, html = self.get("/")
        self.assertIn("Latest Combined Risk", html)
        self.assertIn(">87</span>", html)
        self.assertIn('href="/reports/%d"' % ids[5], html)

    def test_overview_empty_history(self):
        _, html = self.get("/")
        self.assertIn("No scans recorded yet", html)
        self.assertIn("No combined assessment has been recorded yet", html)
        self.assertNotIn("View latest report", html)

    def test_overview_recent_history_columns(self):
        self.seed()
        _, html = self.get("/")
        for column in ("Date (UTC)", "Module", "Result", "Risk", "Score", "Status"):
            self.assertIn(column, html)


class TestDatabaseFailures(PageTestCase):
    def break_database(self):
        broken = self.tmp / "not-a-database"
        broken.mkdir()
        history.set_database_path(broken)

    def test_pages_degrade_gracefully(self):
        self.break_database()
        cases = {
            "/": "Scan history is temporarily unavailable",
            "/history": "Scan history is temporarily unavailable",
            "/reports": "Scan reports are temporarily unavailable",
        }
        for path, message in cases.items():
            with self.subTest(path=path):
                response, html = self.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(message, html)

        response, html = self.get("/reports/1")
        self.assertEqual(response.status_code, 404)
        self.assertIn("could not be found", html)

    def test_detection_apis_still_succeed(self):
        self.break_database()
        text_response = self.client.post(
            "/detect-text", json={"text": "URGENT: verify your password now"}
        )
        self.assertEqual(text_response.status_code, 200)
        payload = text_response.get_json()
        self.assertEqual(set(payload), {"score", "result", "reasons"})

        risk_response = self.client.post(
            "/assess-risk",
            json={"text": {"score": 92, "result": "High Risk", "reasons": []}},
        )
        self.assertEqual(risk_response.status_code, 200)
        self.assertEqual(risk_response.get_json()["risk_level"], "High Risk")

        login_response = self.client.post(
            "/analyze-login-form",
            json={"html": '<form><input type="password" name="p"></form>'},
        )
        self.assertEqual(login_response.status_code, 200)

    def test_delete_and_clear_report_failure_without_crashing(self):
        self.break_database()
        response = self.client.post("/history/1/delete", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("database could not be updated", response.get_data(as_text=True))

        response = self.client.post("/history/clear", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("database could not be updated", response.get_data(as_text=True))


class TestPrivacyAcrossPages(PageTestCase):
    def test_raw_inputs_never_render_in_any_view(self):
        ids = self.seed()
        paths = (
            "/",
            "/history",
            "/history?q=login",
            "/reports",
            "/reports/%d" % ids[0],
            "/reports/%d" % ids[3],
            "/reports/%d" % ids[5],
        )
        for path in paths:
            with self.subTest(path=path):
                response, html = self.get(path)
                self.assertIn(response.status_code, (200, 404))
                self.assertNotIn(SENTINEL, html)
                self.assertNotIn("sentinel-raw.example", html)
                self.assertNotIn("SENTINEL reason", html)
                self.assertNotIn("<input type=\"password\" name=\"SENTINEL", html)


if __name__ == "__main__":
    unittest.main()
