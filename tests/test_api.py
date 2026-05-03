import unittest
from unittest.mock import patch

from fastapi import HTTPException

import api
from api import ScanRequest, VirusTotalScanRequest, health, scan, scan_virustotal


class ApiTests(unittest.TestCase):
    def test_health_returns_ok(self):
        response = self.run_async(health())

        self.assertEqual(response, {"ok": True})

    def test_scan_returns_local_scan_result(self):
        response = self.run_async(
            scan(ScanRequest(url="https://example.com/private/path", initData="query=data"))
        )

        self.assertTrue(response["ok"])
        self.assertEqual(response["url"], "https://example.com/...")
        self.assertIn("risk_score", response["scan"])
        self.assertIn("signals", response["scan"])
        self.assertIn("expert_analysis", response["scan"])
        self.assertIn("recommendation", response["scan"]["expert_analysis"])

    def test_scan_requires_init_data(self):
        with self.assertRaises(HTTPException) as context:
            self.run_async(scan(ScanRequest(url="https://example.com", initData="   ")))

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "initData is required")

    def test_scan_rejects_invalid_url(self):
        with self.assertRaises(HTTPException) as context:
            self.run_async(scan(ScanRequest(url="not-a-url", initData="query=data")))

        self.assertEqual(context.exception.status_code, 400)
        self.assertEqual(context.exception.detail, "url must be a valid http(s) URL")

    def test_scan_accepts_www_url(self):
        response = self.run_async(
            scan(ScanRequest(url="www.example.com/path", initData="query=data"))
        )

        self.assertEqual(response["url"], "https://www.example.com/...")

    def test_scan_accepts_full_message_with_link_context(self):
        response = self.run_async(
            scan(
                ScanRequest(
                    url="عاجل تحقق من حسابك الآن https://paypa1-secure-login.example.com/verify",
                    initData="query=data",
                )
            )
        )

        self.assertTrue(response["ok"])
        self.assertEqual(response["url"], "https://paypa1-secure-login.example.com/...")
        self.assertIn("message_analysis", response["scan"])
        self.assertGreaterEqual(response["scan"]["risk_score"], 60)

    def test_virustotal_scan_requires_server_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(HTTPException) as context:
                self.run_async(
                    scan(
                        ScanRequest(
                            url="https://example.com",
                            initData="query=data",
                            advanced=True,
                        )
                    )
                )

        self.assertEqual(context.exception.status_code, 503)
        self.assertEqual(context.exception.detail, "vt api key missing")

    def test_virustotal_scan_returns_summary_without_exposing_api_key(self):
        summary = {
            "status": "ready",
            "level": "low",
            "title": "لا توجد مؤشرات متقدمة واضحة",
            "message": "لم ترصد VirusTotal مؤشرات خطر واضحة.",
            "stats": {"total": 10},
            "cached": False,
        }

        with patch.dict("os.environ", {"VT_API_KEY": "server-secret"}):
            with patch("api.get_vt_summary", return_value=summary) as mocked_summary:
                response = self.run_async(
                    scan(
                        ScanRequest(
                            url="https://example.com/private/path",
                            initData="query=data",
                            advanced=True,
                        )
                    )
                )

        self.assertTrue(response["ok"])
        self.assertEqual(response["url"], "https://example.com/...")
        self.assertEqual(response["vt"], summary)
        mocked_summary.assert_called_once_with("https://example.com/private/path", "server-secret")

    def test_legacy_virustotal_endpoint_still_works(self):
        summary = {
            "status": "ready",
            "level": "low",
            "title": "لا توجد مؤشرات متقدمة واضحة",
            "message": "لم ترصد VirusTotal مؤشرات خطر واضحة.",
            "stats": {"total": 10},
            "cached": False,
        }

        with patch.dict("os.environ", {"VT_API_KEY": "server-secret"}):
            with patch("api.get_vt_summary", return_value=summary):
                response = self.run_async(
                    scan_virustotal(
                        VirusTotalScanRequest(
                            url="https://example.com/private/path",
                            initData="query=data",
                        )
                    )
                )

        self.assertTrue(response["ok"])
        self.assertEqual(response["vt"], summary)

    def test_virustotal_summary_uses_24h_cache(self):
        api.vt_cache.clear()
        report = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 4,
                        "undetected": 2,
                    }
                }
            }
        }

        with patch("api.vt_request", return_value=report) as mocked_request:
            first = api.get_vt_summary("https://example.com", "server-secret")
            second = api.get_vt_summary("https://example.com", "server-secret")

        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(second["level"], "high")
        mocked_request.assert_called_once()
        api.vt_cache.clear()

    def test_virustotal_rate_limit_is_reported(self):
        api.vt_cache.clear()

        with patch(
            "api.vt_request",
            side_effect=HTTPException(status_code=429, detail="vt rate limit reached"),
        ):
            with self.assertRaises(HTTPException) as context:
                api.get_vt_summary("https://example.com", "server-secret")

        self.assertEqual(context.exception.status_code, 429)
        self.assertEqual(context.exception.detail, "vt rate limit reached")

    def run_async(self, awaitable):
        import asyncio

        return asyncio.run(awaitable)


if __name__ == "__main__":
    unittest.main()
