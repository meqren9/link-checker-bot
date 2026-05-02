import unittest
from types import SimpleNamespace
from unittest.mock import patch

import main


class MainRateLimitTests(unittest.TestCase):
    def setUp(self):
        main.user_scan_times.clear()
        main.ADMIN_USER_IDS.clear()

    def test_normal_user_limited_to_three_scans_per_minute(self):
        with patch("main.time.time", return_value=1000):
            self.assertTrue(main.can_scan_for_user(111))
            self.assertTrue(main.can_scan_for_user(111))
            self.assertTrue(main.can_scan_for_user(111))
            self.assertFalse(main.can_scan_for_user(111))

    def test_admin_user_bypasses_rate_limit(self):
        main.ADMIN_USER_IDS.add(222)

        with patch("main.time.time", return_value=1000):
            for _ in range(10):
                self.assertTrue(main.can_scan_for_user(222))

        self.assertNotIn(222, main.user_scan_times)

    def test_format_user_identity_includes_id_and_username(self):
        user = SimpleNamespace(id=333, username="meqren10")

        response = main.format_user_identity(user)

        self.assertIn("333", response)
        self.assertIn("@meqren10", response)


if __name__ == "__main__":
    unittest.main()
