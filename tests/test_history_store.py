"""Stage 3 storage tests: sanitization, persistence, queries and failures.

Run from the project root:

    .venv\\Scripts\\python -m unittest discover -s tests -v
"""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from phishing import history

SENTINEL_URL = "https://sentinel-host.example/verify?token=SECRET-TOKEN-9f3a"
SENTINEL_MESSAGE = "SENTINEL MESSAGE: confirm your password and OTP 483920"
SENTINEL_HTML = (
    '<form action="https://sentinel-host.example/collect" method="post">'
    '<input type="password" name="sentinel-password-field"></form>'
)
SENTINEL_TEXT = "SENTINEL OCR TEXT account suspended login now"
SENTINEL_BRAND = "Sentinel Brand Logistics"
SENTINEL_REASON = "SENTINEL REASON: credential harvesting detected"


def url_result(label="Phishing", prediction=0):
    return {
        "url": SENTINEL_URL,
        "label": label,
        "prediction": prediction,
        "warning": SENTINEL_URL,
        "error": SENTINEL_URL,
    }


def text_result():
    return {
        "score": 92,
        "result": "High Risk",
        "reasons": [SENTINEL_REASON, SENTINEL_MESSAGE],
        "message": SENTINEL_MESSAGE,
    }


def ocr_result(text=SENTINEL_TEXT):
    return {
        "extracted_text": text,
        "score": 88,
        "result": "High Risk",
        "reasons": [SENTINEL_REASON],
    }


def brand_result():
    return {
        "result": "Possible Match",
        "score": 84,
        "best_match": SENTINEL_BRAND,
        "references_checked": 3,
        "matches": [{"brand": SENTINEL_BRAND, "score": 84}],
        "warning": SENTINEL_REASON,
    }


def login_result():
    return {
        "score": 75,
        "risk_level": "High Risk",
        "forms_found": 1,
        "fields": {
            "password": 1,
            "email": 1,
            "username": 0,
            "pin": 0,
            "otp": 2,
        },
        "reasons": [SENTINEL_REASON, SENTINEL_HTML],
    }


def combined_result():
    return {
        "overall_score": 87,
        "risk_level": "High Risk",
        "modules": {
            "url": {"available": True, "risk_score": 90},
            "text": {"available": True, "risk_score": 92},
            "ocr": {"available": False, "status": "not_provided"},
            "brand": {"available": True, "risk_score": 84, "summary": SENTINEL_BRAND},
            "login_form": {"available": False, "status": "inconclusive"},
        },
        "missing_modules": ["ocr"],
        "inconclusive_modules": ["login_form"],
        "reasons": [SENTINEL_REASON],
        "recommended_actions": [SENTINEL_MESSAGE],
        "disclaimer": SENTINEL_URL,
    }


class HistoryTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="phishguard-test-"))
        self.db_path = self.tmp / "history.db"
        history.set_database_path(self.db_path)
        self.addCleanup(history.set_database_path, None)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def all_column_text(self):
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT * FROM scans").fetchall()
        finally:
            connection.close()
        return "\n".join(str(value) for row in rows for value in tuple(row))


class TestSanitizedRecordBuilding(HistoryTestCase):
    def test_url_record_keeps_only_verdict_metadata(self):
        record = history.build_record("url", url_result())
        payload = json.dumps(record)
        self.assertEqual(record["module"], "url")
        self.assertEqual(record["label"], "Phishing")
        self.assertEqual(record["risk_level"], "high_risk")
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["counts"], {"prediction": 0})
        self.assertNotIn("sentinel", payload.lower())
        self.assertNotIn("token", payload.lower())

    def test_text_record_stores_indicator_count_not_reasons(self):
        record = history.build_record("text", text_result())
        payload = json.dumps(record)
        self.assertEqual(record["label"], "High Risk")
        self.assertEqual(record["risk_level"], "high_risk")
        self.assertEqual(record["score"], 92)
        self.assertEqual(record["counts"]["indicators"], 2)
        self.assertNotIn("SENTINEL", payload)
        self.assertNotIn("password", payload.lower())

    def test_ocr_record_stores_character_count_not_text(self):
        record = history.build_record("ocr", ocr_result())
        payload = json.dumps(record)
        self.assertEqual(record["counts"]["characters"], len(SENTINEL_TEXT))
        self.assertEqual(record["risk_level"], "high_risk")
        self.assertNotIn("SENTINEL", payload)
        self.assertNotIn("suspended", payload.lower())

    def test_ocr_without_extracted_text_is_inconclusive(self):
        record = history.build_record("ocr", ocr_result(text=""))
        self.assertEqual(record["counts"]["characters"], 0)
        self.assertEqual(record["risk_level"], "inconclusive")
        self.assertEqual(record["status"], "inconclusive")

    def test_brand_similarity_is_never_a_verdict(self):
        record = history.build_record("brand", brand_result())
        payload = json.dumps(record)
        self.assertEqual(record["label"], "Possible Match")
        self.assertEqual(record["risk_level"], "inconclusive")
        self.assertEqual(record["status"], "inconclusive")
        self.assertEqual(record["counts"]["references_checked"], 3)
        self.assertEqual(record["counts"]["matches"], 1)
        self.assertNotIn("Sentinel", payload)
        self.assertNotIn("best_match", payload)

    def test_login_form_drops_html_and_field_names(self):
        record = history.build_record("login_form", login_result())
        payload = json.dumps(record)
        self.assertEqual(record["label"], "High Risk")
        self.assertEqual(record["risk_level"], "high_risk")
        self.assertEqual(
            record["counts"],
            {
                "forms": 1,
                "password_fields": 1,
                "email_fields": 1,
                "username_fields": 0,
                "pin_fields": 0,
                "otp_fields": 2,
                "indicators": 2,
            },
        )
        self.assertNotIn("<form", payload.lower())
        self.assertNotIn("sentinel", payload.lower())
        self.assertNotIn("collect", payload.lower())

    def test_combined_breakdown_is_numeric_and_enumerated_only(self):
        record = history.build_record("combined", combined_result())
        payload = json.dumps(record)
        modules = record["counts"]["modules"]
        self.assertEqual(record["label"], "High Risk")
        self.assertEqual(record["score"], 87)
        self.assertEqual(record["risk_level"], "high_risk")
        self.assertEqual(
            set(modules),
            {"url", "text", "ocr", "brand", "login_form"},
        )
        self.assertEqual(modules["ocr"], {"available": False, "state": "not_provided"})
        self.assertEqual(
            modules["login_form"], {"available": False, "state": "inconclusive"}
        )
        self.assertEqual(modules["brand"]["score"], 84)
        self.assertNotIn("SENTINEL", payload)
        self.assertNotIn("summary", payload)
        self.assertNotIn("best_match", payload)

    def test_unknown_labels_are_replaced(self):
        record = history.build_record(
            "text",
            {"score": 50, "result": "SENTINEL custom verdict", "reasons": []},
        )
        self.assertEqual(record["label"], "Unknown")
        self.assertEqual(record["risk_level"], "inconclusive")
        self.assertNotIn("SENTINEL", json.dumps(record))

    def test_out_of_range_and_boolean_scores_rejected(self):
        for score in (150, -5, True, "90", float("nan")):
            with self.subTest(score=score):
                record = history.build_record(
                    "text", {"score": score, "result": "Safe", "reasons": []}
                )
                self.assertIsNone(record["score"])

    def test_unsafe_counts_rejected(self):
        record = history.build_record(
            "login_form",
            {
                "score": 10,
                "risk_level": "Safe",
                "forms_found": "many",
                "fields": {"password": True, "email": -1, "otp": 999999999999},
                "reasons": "not a list",
            },
        )
        self.assertEqual(record["counts"], {})

    def test_unknown_module_rejected(self):
        with self.assertRaises(ValueError):
            history.build_record("sentinel", {})

    def test_recommendations_are_static_per_risk_level(self):
        for level in ("safe", "suspicious", "high_risk", "inconclusive"):
            with self.subTest(level=level):
                items = history.recommendations_for(level)
                self.assertTrue(items)
                for item in items:
                    self.assertIsInstance(item, str)
                    self.assertNotIn("SENTINEL", item)
        self.assertIn("passwords", " ".join(history.recommendations_for("high_risk")))


class TestPersistenceAndPrivacy(HistoryTestCase):
    def test_schema_stores_only_whitelisted_columns(self):
        history.record_analysis("url", url_result())
        connection = sqlite3.connect(str(self.db_path))
        try:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(scans)")
            }
        finally:
            connection.close()
        self.assertEqual(
            columns,
            {
                "scan_id",
                "created_at",
                "module",
                "label",
                "risk_level",
                "risk_score",
                "completion_status",
                "counts_json",
                "version",
                "schema_version",
            },
        )

    def test_raw_inputs_and_reasons_never_reach_the_database(self):
        samples = [
            ("url", url_result()),
            ("text", text_result()),
            ("ocr", ocr_result()),
            ("brand", brand_result()),
            ("login_form", login_result()),
            ("combined", combined_result()),
        ]
        for module, result in samples:
            with self.subTest(module=module):
                history.record_analysis(module, result)

        stored = self.all_column_text()
        self.assertNotIn("sentinel", stored.lower())
        self.assertNotIn("secret-token", stored.lower())
        self.assertNotIn("<form", stored.lower())
        self.assertNotIn("suspended", stored.lower())
        self.assertNotIn("SENTINEL REASON", stored)

    def test_counts_json_only_uses_whitelisted_keys(self):
        for module, result in (
            ("combined", combined_result()),
            ("login_form", login_result()),
        ):
            history.record_analysis(module, result)

        connection = sqlite3.connect(str(self.db_path))
        try:
            rows = connection.execute("SELECT counts_json FROM scans").fetchall()
        finally:
            connection.close()

        for (payload,) in rows:
            counts = json.loads(payload)
            for key, value in counts.items():
                if key == "modules":
                    for entry in value.values():
                        self.assertLessEqual(set(entry), {"available", "score", "state"})
                        self.assertIsInstance(entry["available"], bool)
                        if "state" in entry:
                            self.assertIn(entry["state"], history.MODULE_STATES)
                else:
                    self.assertIn(key, history.COUNT_KEYS)
                    self.assertIsInstance(value, int)

    def test_version_marker_and_utc_timestamp_stored(self):
        scan_id = history.record_analysis("text", text_result())
        record = history.get_scan(scan_id)
        self.assertEqual(record["version"], history.ENGINE_VERSION)
        self.assertEqual(record["schema_version"], history.SCHEMA_VERSION)
        self.assertTrue(record["created_at"].endswith("UTC"))
        self.assertRegex(
            record["created_at_iso"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
        )

    def test_get_scan_handles_missing_and_invalid_ids(self):
        history.record_analysis("text", text_result())
        self.assertIsNone(history.get_scan(99999))
        self.assertIsNone(history.get_scan("not-an-id"))
        self.assertIsNone(history.get_scan(None))

    def test_safe_record_never_raises(self):
        broken = self.tmp / "broken"
        broken.mkdir()
        history.set_database_path(broken)
        self.assertIsNone(history.safe_record("text", text_result()))
        with self.assertRaises(history.HistoryError):
            history.record_analysis("text", text_result())
        with self.assertRaises(history.HistoryError):
            history.get_statistics()
        with self.assertRaises(history.HistoryError):
            history.list_scans()


class TestQueries(HistoryTestCase):
    def seed(self):
        return [
            history.record_analysis("url", url_result()),
            history.record_analysis("url", url_result("Legitimate", 1)),
            history.record_analysis("text", text_result()),
            history.record_analysis("login_form", login_result()),
            history.record_analysis("brand", brand_result()),
            history.record_analysis("combined", combined_result()),
        ]

    def test_statistics_count_every_risk_level(self):
        self.seed()
        stats = history.get_statistics()
        self.assertEqual(
            stats,
            {
                "total": 6,
                "safe": 1,
                "suspicious": 0,
                "high_risk": 4,
                "inconclusive": 1,
            },
        )

    def test_latest_combined_returns_newest_combined_only(self):
        self.seed()
        second = history.record_analysis(
            "combined",
            dict(combined_result(), overall_score=41, risk_level="Suspicious"),
        )
        latest = history.get_latest_combined()
        self.assertEqual(latest["scan_id"], second)
        self.assertEqual(latest["risk_level"], "Suspicious")
        self.assertEqual(latest["risk_score"], 41)

    def test_latest_combined_none_when_absent(self):
        history.record_analysis("text", text_result())
        self.assertIsNone(history.get_latest_combined())

    def test_recent_scans_are_newest_first_with_limit(self):
        ids = self.seed()
        recent = history.get_recent_scans(3)
        self.assertEqual(len(recent), 3)
        self.assertEqual([item["scan_id"] for item in recent], ids[::-1][:3])

    def test_list_scans_paginates(self):
        for _ in range(12):
            history.record_analysis("text", text_result())
        first = history.list_scans(per_page=5)
        second = history.list_scans(page=2, per_page=5)
        last = history.list_scans(page=3, per_page=5)
        self.assertEqual((first["total"], first["pages"]), (12, 3))
        self.assertEqual(len(first["items"]), 5)
        self.assertTrue(first["has_next"])
        self.assertFalse(first["has_prev"])
        self.assertEqual(second["page"], 2)
        self.assertEqual(len(last["items"]), 2)
        self.assertFalse(last["has_next"])

    def test_page_beyond_last_clamps(self):
        history.record_analysis("text", text_result())
        page = history.list_scans(page=99)
        self.assertEqual(page["page"], 1)
        self.assertEqual(len(page["items"]), 1)

    def test_module_and_risk_filters(self):
        self.seed()
        url_scans = history.list_scans(module="url")
        self.assertEqual(url_scans["total"], 2)
        self.assertTrue(all(item["module"] == "url" for item in url_scans["items"]))

        high = history.list_scans(risk_level="high_risk")
        self.assertEqual(high["total"], 4)
        self.assertTrue(
            all(item["risk_level_key"] == "high_risk" for item in high["items"])
        )

        combined = history.list_scans(module="url", risk_level="safe")
        self.assertEqual(combined["total"], 1)
        self.assertEqual(combined["items"][0]["label"], "Legitimate")

    def test_query_search_matches_whitelisted_fields_only(self):
        self.seed()
        self.assertEqual(history.list_scans(query="legitimate")["total"], 1)
        self.assertEqual(history.list_scans(query="login form")["total"], 1)
        self.assertEqual(history.list_scans(query="high risk")["total"], 4)
        self.assertEqual(history.list_scans(query="SENTINEL")["total"], 0)
        self.assertEqual(history.list_scans(query="%")["total"], 0)

    def test_query_length_is_capped(self):
        self.seed()
        long_query = "a" * 500
        self.assertEqual(history.list_scans(query=long_query)["total"], 0)

    def test_delete_scan_removes_one_record(self):
        ids = self.seed()
        self.assertTrue(history.delete_scan(ids[0]))
        self.assertFalse(history.delete_scan(ids[0]))
        self.assertEqual(history.get_statistics()["total"], 5)
        self.assertIsNone(history.get_scan(ids[0]))

    def test_clear_scans_removes_everything(self):
        self.seed()
        self.assertEqual(history.clear_scans(), 6)
        self.assertEqual(history.get_statistics()["total"], 0)
        self.assertEqual(history.list_scans()["items"], [])


class TestDisplayHelpers(HistoryTestCase):
    def test_display_counts_are_ordered_and_labeled(self):
        scan_id = history.record_analysis("login_form", login_result())
        record = history.get_scan(scan_id)
        rows = history.display_counts(record)
        labels = [row["label"] for row in rows]
        self.assertIn("Forms found", labels)
        self.assertIn("OTP / verification-code fields", labels)
        self.assertEqual(len(labels), 7)

    def test_display_breakdown_covers_all_modules(self):
        scan_id = history.record_analysis("combined", combined_result())
        rows = history.display_breakdown(history.get_scan(scan_id))
        self.assertEqual(len(rows), 5)
        by_module = {row["module"]: row for row in rows}
        self.assertEqual(by_module["ocr"]["status"], "Not analyzed")
        self.assertEqual(by_module["login_form"]["status"], "Inconclusive")
        self.assertEqual(by_module["url"]["score"], 90)

    def test_display_helpers_tolerate_missing_counts(self):
        self.assertEqual(history.display_counts({"counts": {}}), [])
        self.assertEqual(history.display_breakdown({"counts": {}}), [])


if __name__ == "__main__":
    unittest.main()
