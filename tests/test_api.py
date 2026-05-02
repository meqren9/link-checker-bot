import unittest

from fastapi import HTTPException

from api import ScanRequest, health, scan


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

    def run_async(self, awaitable):
        import asyncio

        return asyncio.run(awaitable)


if __name__ == "__main__":
    unittest.main()
