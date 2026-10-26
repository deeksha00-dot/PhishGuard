"""API tests using Flask's test client and a temporary database."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app(os.path.join(self.tmp, "test.db"))
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def analyze(self, text="Share your OTP at http://bit.ly/abc", **extra):
        return self.client.post("/api/analyze", json={"text": text, **extra})

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_index_page_loads(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_successful_analysis(self):
        r = self.analyze()
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        for key in ("id", "risk_score", "risk_level", "detected_indicators", "suspicious_phrases",
                    "detected_urls", "recommendations", "input_type", "summary"):
            self.assertIn(key, data)
        self.assertTrue(0 <= data["risk_score"] <= 100)

    def test_different_inputs_give_different_scores(self):
        a = self.analyze("Lunch tomorrow?").get_json()["risk_score"]
        b = self.analyze("Share your OTP at http://bit.ly/abc").get_json()["risk_score"]
        self.assertLess(a, b)

    def test_empty_text_rejected(self):
        for payload in ({"text": ""}, {"text": "   "}, {}):
            r = self.client.post("/api/analyze", json=payload)
            self.assertEqual(r.status_code, 400)
            self.assertIn("error", r.get_json())

    def test_invalid_json_and_types_rejected(self):
        r = self.client.post("/api/analyze", data="not json", content_type="application/json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", json={"text": 123}).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", json=["a"]).status_code, 400)
        self.assertEqual(self.analyze(input_type="bogus").status_code, 400)

    def test_too_long_rejected(self):
        self.assertEqual(self.analyze("a" * 10_001).status_code, 413)

    def test_history_list_newest_first(self):
        self.analyze("first message")
        second_id = self.analyze("second message").get_json()["id"]
        r = self.client.get("/api/history")
        self.assertEqual(r.status_code, 200)
        items = r.get_json()["history"]
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["id"], second_id)
        self.assertEqual(items[0]["preview"], "second message")

    def test_history_limited_to_20(self):
        for i in range(25):
            self.analyze(f"message {i}")
        self.assertEqual(len(self.client.get("/api/history").get_json()["history"]), 20)

    def test_single_history_record(self):
        saved = self.analyze().get_json()
        r = self.client.get(f"/api/history/{saved['id']}")
        self.assertEqual(r.status_code, 200)
        item = r.get_json()
        self.assertEqual(item["risk_score"], saved["risk_score"])
        self.assertEqual(item["submitted_text"], "Share your OTP at http://bit.ly/abc")
        self.assertEqual(self.client.get("/api/history/9999").status_code, 404)

    def test_clear_history(self):
        self.analyze()
        r = self.client.delete("/api/history")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["deleted"], 1)
        self.assertEqual(self.client.get("/api/history").get_json()["history"], [])

    def test_history_persists_across_app_restarts(self):
        self.analyze()
        again = create_app(self.app.config["DB_PATH"]).test_client()
        self.assertEqual(len(again.get("/api/history").get_json()["history"]), 1)

    def test_sql_injection_text_is_stored_safely(self):
        self.analyze("'); DROP TABLE analyses; --")
        self.assertEqual(len(self.client.get("/api/history").get_json()["history"]), 1)

    def test_unknown_api_route_is_json_404(self):
        r = self.client.get("/api/nope")
        self.assertEqual(r.status_code, 404)
        self.assertIn("error", r.get_json())


if __name__ == "__main__":
    unittest.main()
