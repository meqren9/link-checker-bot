import json
import tempfile
import unittest
from pathlib import Path

import community_reports


class CommunityReportsTests(unittest.TestCase):
    def test_reports_store_domain_key_without_full_url(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            community_reports.REPORTS_FILE = Path(temp_dir) / "reports.json"

            report = community_reports.add_report(
                "https://example.com/private/path?token=secret",
                reporter_id=123,
            )

            data = json.loads(community_reports.REPORTS_FILE.read_text(encoding="utf-8"))

        self.assertEqual(report["key_type"], "domain")
        self.assertEqual(report["label"], "example.com")
        self.assertNotIn("private", str(data))
        self.assertNotIn("secret", str(data))

    def test_report_reaches_community_threshold(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            community_reports.REPORTS_FILE = Path(temp_dir) / "reports.json"

            for reporter_id in range(community_reports.REPORT_THRESHOLD):
                report = community_reports.add_report(
                    "https://reported-example.test/path",
                    reporter_id=reporter_id,
                )

        self.assertTrue(report["community_suspicious"])
        self.assertEqual(report["count"], community_reports.REPORT_THRESHOLD)

    def test_list_reports_and_clear_domain_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            community_reports.REPORTS_FILE = Path(temp_dir) / "reports.json"
            community_reports.add_report("https://example.com/a", reporter_id=1)
            community_reports.add_report("https://example.com/b", reporter_id=2)

            reports = community_reports.list_reports()
            clear_result = community_reports.clear_domain_report("example.com")
            status = community_reports.get_report_status("https://example.com/a")

        self.assertEqual(reports[0]["label"], "example.com")
        self.assertEqual(reports[0]["count"], 2)
        self.assertTrue(clear_result["cleared"])
        self.assertEqual(status["count"], 0)


if __name__ == "__main__":
    unittest.main()
