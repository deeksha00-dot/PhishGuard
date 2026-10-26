"""Unit tests for detector.py (no network access needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detector import analyze_content, get_risk_level, extract_urls  # noqa: E402


def ids(result):
    return {i["id"] for i in result["detected_indicators"]}


class DetectorTests(unittest.TestCase):
    def test_harmless_message_is_low(self):
        r = analyze_content("Hi Sam, are we still meeting for lunch tomorrow at 1pm?")
        self.assertEqual(r["risk_level"], "Low")
        self.assertEqual(r["risk_score"], 0)
        self.assertEqual(r["detected_indicators"], [])

    def test_otp_request_detected(self):
        r = analyze_content("Please share your OTP to verify your account.")
        self.assertIn("otp_request", ids(r))
        self.assertGreaterEqual(r["risk_score"], 25)

    def test_urgency_with_suspicious_url_scores_higher(self):
        text = "Your account will be suspended within 24 hours. Verify now at http://192.168.1.5/login"
        r = analyze_content(text)
        self.assertIn("account_threat", ids(r))
        self.assertIn("url_ip_host", ids(r))
        self.assertGreaterEqual(r["risk_score"], 25)
        self.assertGreater(r["risk_score"], analyze_content("Your account will be suspended within 24 hours.")["risk_score"])

    def test_shortened_url_detected(self):
        r = analyze_content("Check this out: https://bit.ly/3abcXYZ")
        self.assertIn("url_shortened", ids(r))
        self.assertEqual(r["detected_urls"][0]["host"], "bit.ly")

    def test_empty_message(self):
        r = analyze_content("   ")
        self.assertEqual(r["risk_score"], 0)
        self.assertEqual(r["risk_level"], "Low")
        self.assertEqual(r["detected_indicators"], [])

    def test_repeated_words_do_not_inflate_score(self):
        once = analyze_content("Act now!")
        many = analyze_content("Act now! act now! ACT NOW! act now! act now! act now!")
        self.assertEqual(once["risk_score"], many["risk_score"])

    def test_legitimate_bank_message_stays_low(self):
        r = analyze_content("I went to the bank today. The statement will be ready on Monday, want to grab lunch?")
        self.assertEqual(r["risk_level"], "Low")

    def test_real_otp_notice_with_safety_advice_is_low(self):
        r = analyze_content("Your OTP for the card payment of Rs 499 is 482913. Never share it with anyone, including bank staff.")
        self.assertNotIn("otp_request", ids(r))
        self.assertEqual(r["risk_level"], "Low")

    def test_http_url_is_weak_signal_only(self):
        r = analyze_content("Our documentation is at http://example.com/help")
        self.assertIn("url_http", ids(r))
        self.assertEqual(r["risk_level"], "Low")
        self.assertLess(r["risk_score"], 10)

    def test_brand_lookalike_url(self):
        r = analyze_content("http://paypal.account-verify.xyz/login")
        self.assertIn("url_brand_mismatch", ids(r))
        r2 = analyze_content("https://www.paypal.com/signin")
        self.assertNotIn("url_brand_mismatch", ids(r2))

    def test_scam_message_is_critical(self):
        r = analyze_content("URGENT action required. Your account will be blocked within 24 hours. Share your OTP at http://bit.ly/x1")
        self.assertEqual(r["risk_level"], "Critical")

    def test_score_range_and_level_thresholds(self):
        for score, level in [(0, "Low"), (24, "Low"), (25, "Medium"), (49, "Medium"), (50, "High"), (74, "High"), (75, "Critical"), (100, "Critical")]:
            self.assertEqual(get_risk_level(score), level)
        r = analyze_content("Urgent action required! You have won the lottery! Send money, keep this secret. Share your password and OTP at http://1.2.3.4/a http://bit.ly/b")
        self.assertTrue(0 <= r["risk_score"] <= 100)
        self.assertEqual(r["risk_level"], get_risk_level(r["risk_score"]))

    def test_deterministic(self):
        text = "Share your OTP now at http://bit.ly/abc"
        self.assertEqual(analyze_content(text), analyze_content(text))

    def test_url_extraction_ignores_email_addresses(self):
        self.assertEqual(extract_urls("write to help@example.com please"), [])
        self.assertEqual(extract_urls("see https://example.com/a, then www.test.org."), ["https://example.com/a", "www.test.org"])

    def test_invalid_arguments(self):
        with self.assertRaises(ValueError):
            analyze_content("hello", "bogus")
        with self.assertRaises(TypeError):
            analyze_content(None)


if __name__ == "__main__":
    unittest.main()
