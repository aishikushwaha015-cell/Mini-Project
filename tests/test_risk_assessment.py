"""Tests for the combined risk assessment engine and its Flask route.

Run from the project root:

    .venv\\Scripts\\python -m unittest discover -s tests -v
"""

import unittest

from app import app
from phishing.risk_assessment import RiskAssessmentError, assess_risk


LOW_RESULTS = {
    "url": {"label": "Legitimate", "prediction": 1},
    "text": {"score": 5, "result": "Safe", "reasons": []},
    "ocr": {"score": 5, "result": "Safe", "reasons": []},
    "brand": {"result": "Low Similarity", "score": 10},
    "login_form": {"score": 5, "risk_level": "Safe", "reasons": []},
}

HIGH_RESULTS = {
    "url": {"label": "Phishing", "prediction": 0},
    "text": {"score": 90, "result": "High Risk", "reasons": ["Urgent request"]},
    "ocr": {"score": 85, "result": "High Risk", "reasons": []},
    "brand": {"result": "Possible Match", "score": 95, "best_match": "Example"},
    "login_form": {"score": 80, "risk_level": "High Risk", "reasons": []},
}


class TestAssessRisk(unittest.TestCase):
    def test_all_modules_low_risk(self):
        result = assess_risk(LOW_RESULTS)
        self.assertEqual(result["overall_score"], 6)
        self.assertEqual(result["risk_level"], "Safe")
        self.assertEqual(result["missing_modules"], [])
        self.assertEqual(result["inconclusive_modules"], [])
        for key in ("url", "text", "ocr", "brand", "login_form"):
            self.assertTrue(result["modules"][key]["available"])

    def test_multiple_modules_high_risk(self):
        result = assess_risk(HIGH_RESULTS)
        self.assertEqual(result["risk_level"], "High Risk")
        self.assertGreaterEqual(result["overall_score"], 60)
        self.assertLessEqual(result["overall_score"], 100)

    def test_only_one_module_available(self):
        result = assess_risk(
            {"login_form": {"score": 80, "risk_level": "High Risk", "reasons": []}}
        )
        # A single module keeps its own score because weights renormalize.
        self.assertEqual(result["overall_score"], 80)
        self.assertEqual(result["risk_level"], "High Risk")
        self.assertEqual(result["modules"]["login_form"]["risk_score"], 80)
        self.assertIn("url", result["missing_modules"])
        self.assertIn("text", result["missing_modules"])
        self.assertIn("ocr", result["missing_modules"])
        self.assertIn("brand", result["missing_modules"])

    def test_missing_modules_are_flagged_not_treated_as_safe(self):
        result = assess_risk(
            {
                "url": {"label": "Phishing", "prediction": 0},
                "text": {"score": 70, "result": "High Risk"},
            }
        )
        self.assertEqual(result["risk_level"], "High Risk")
        self.assertGreaterEqual(result["overall_score"], 60)
        self.assertEqual(
            sorted(result["missing_modules"]),
            ["brand", "login_form", "ocr"],
        )
        self.assertIn(
            "Not analyzed: Image OCR.",
            result["reasons"],
        )

    def test_unknown_url_is_inconclusive_not_safe(self):
        result = assess_risk(
            {
                "url": {"label": "Unknown", "prediction": None},
                "text": {"score": 40, "result": "Suspicious"},
            }
        )
        self.assertFalse(result["modules"]["url"]["available"])
        self.assertEqual(result["modules"]["url"]["status"], "inconclusive")
        self.assertIn("url", result["inconclusive_modules"])
        self.assertEqual(result["overall_score"], 40)
        self.assertEqual(result["risk_level"], "Suspicious")

    def test_text_and_ocr_are_not_double_counted(self):
        base = {
            "url": {"label": "Legitimate", "prediction": 1},
            "text": {"score": 90, "result": "High Risk"},
            "login_form": {"score": 0, "risk_level": "Safe"},
        }
        with_duplicate_ocr = dict(base)
        with_duplicate_ocr["ocr"] = {"score": 90, "result": "High Risk"}

        base_result = assess_risk(base)
        duplicate_result = assess_risk(with_duplicate_ocr)

        self.assertEqual(
            base_result["overall_score"],
            duplicate_result["overall_score"],
        )

    def test_score_boundaries_zero_and_hundred(self):
        zero = assess_risk(
            {
                "text": {"score": 0, "result": "Safe"},
                "ocr": {"score": 0, "result": "Safe"},
                "login_form": {"score": 0, "risk_level": "Safe"},
            }
        )
        self.assertEqual(zero["overall_score"], 0)
        self.assertEqual(zero["risk_level"], "Safe")

        hundred = assess_risk(
            {
                "url": {"label": "Phishing", "prediction": 0},
                "text": {"score": 100, "result": "High Risk"},
                "ocr": {"score": 100, "result": "High Risk"},
                "brand": {"result": "Possible Match", "score": 100},
                "login_form": {"score": 100, "risk_level": "High Risk"},
            }
        )
        self.assertEqual(hundred["overall_score"], 100)
        self.assertEqual(hundred["risk_level"], "High Risk")

    def test_brand_similarity_alone_cannot_prove_phishing(self):
        result = assess_risk(
            {"brand": {"result": "Possible Match", "score": 100, "best_match": "Example"}}
        )
        self.assertLessEqual(result["overall_score"], 10)
        self.assertEqual(result["risk_level"], "Safe")
        self.assertTrue(
            any(
                "supporting evidence only" in reason
                for reason in result["reasons"]
            )
        )

    def test_brand_similarity_only_adds_supporting_points(self):
        no_brand = assess_risk(
            {
                "url": {"label": "Legitimate", "prediction": 1},
                "text": {"score": 20, "result": "Safe"},
                "login_form": {"score": 20, "risk_level": "Safe"},
            }
        )
        with_brand = assess_risk(
            {
                "url": {"label": "Legitimate", "prediction": 1},
                "text": {"score": 20, "result": "Safe"},
                "brand": {"result": "Possible Match", "score": 100},
                "login_form": {"score": 20, "risk_level": "Safe"},
            }
        )
        self.assertLessEqual(
            with_brand["overall_score"] - no_brand["overall_score"], 10
        )
        self.assertEqual(with_brand["risk_level"], "Safe")

    def test_output_contains_required_sections(self):
        result = assess_risk(LOW_RESULTS)
        for key in (
            "overall_score",
            "risk_level",
            "modules",
            "missing_modules",
            "inconclusive_modules",
            "reasons",
            "recommended_actions",
            "weights",
            "disclaimer",
        ):
            self.assertIn(key, result)
        self.assertIsInstance(result["reasons"], list)
        self.assertIsInstance(result["recommended_actions"], list)
        self.assertTrue(result["recommended_actions"])


class TestAssessRiskInvalidInput(unittest.TestCase):
    def test_non_object_input_rejected(self):
        with self.assertRaises(RiskAssessmentError):
            assess_risk("not an object")
        with self.assertRaises(RiskAssessmentError):
            assess_risk(None)
        with self.assertRaises(RiskAssessmentError):
            assess_risk([LOW_RESULTS])

    def test_empty_results_rejected(self):
        with self.assertRaises(RiskAssessmentError):
            assess_risk({})

    def test_all_none_results_rejected(self):
        with self.assertRaises(RiskAssessmentError):
            assess_risk(
                {"url": None, "text": None, "ocr": None, "brand": None, "login_form": None}
            )

    def test_non_object_module_result_rejected(self):
        with self.assertRaises(RiskAssessmentError):
            assess_risk({"url": "https://example.com"})

    def test_invalid_scores_rejected(self):
        for bad_score in ("high", True, float("nan")):
            with self.subTest(score=bad_score):
                with self.assertRaises(RiskAssessmentError):
                    assess_risk({"text": {"score": bad_score}})

    def test_missing_score_and_verdict_rejected(self):
        with self.assertRaises(RiskAssessmentError):
            assess_risk({"text": {"reasons": []}})


class TestAssessRiskRoute(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_page_contains_combined_card(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        # Stage 1 overview highlights the latest combined result and links
        # to the dedicated combined-assessment page.
        self.assertIn("Latest Combined Risk", html)
        self.assertIn('href="/analysis/combined"', html)

    def test_valid_results_return_200(self):
        response = self.client.post("/assess-risk", json=HIGH_RESULTS)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["risk_level"], "High Risk")
        self.assertIn("overall_score", data)

    def test_brand_only_returns_safe(self):
        response = self.client.post(
            "/assess-risk",
            json={"brand": {"result": "Possible Match", "score": 100}},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["risk_level"], "Safe")

    def test_empty_payload_returns_400(self):
        response = self.client.post("/assess-risk", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_non_object_payload_returns_400(self):
        response = self.client.post("/assess-risk", json=[LOW_RESULTS])
        self.assertEqual(response.status_code, 400)

    def test_invalid_module_score_returns_400(self):
        response = self.client.post(
            "/assess-risk", json={"text": {"score": "not a number"}}
        )
        self.assertEqual(response.status_code, 400)

    def test_missing_json_returns_400(self):
        response = self.client.post("/assess-risk")
        self.assertEqual(response.status_code, 400)

    def test_existing_routes_still_work(self):
        self.assertEqual(
            self.client.post(
                "/predict", json={"url": "https://www.example.com/login"}
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/detect-text", json={"text": "URGENT: verify your password"}
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/analyze-login-form",
                json={
                    "html": (
                        '<form action="/session" method="post">'
                        '<input type="password" name="password">'
                        "</form>"
                    )
                },
            ).status_code,
            200,
        )


if __name__ == "__main__":
    unittest.main()
