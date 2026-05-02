import unittest

from scanner import check_url, clean_url, local_scan_url, normalize_url, safe_url_label


class ScannerTests(unittest.TestCase):
    def test_clean_url_removes_wrapping_punctuation(self):
        self.assertEqual(clean_url("(https://example.com),"), "https://example.com")

    def test_normalize_url_adds_https_for_www(self):
        self.assertEqual(normalize_url("www.example.com"), "https://www.example.com")

    def test_safe_url_label_hides_path(self):
        self.assertEqual(
            safe_url_label("https://example.com/private/path"),
            "https://example.com/...",
        )

    def test_local_scan_flags_http_ip_login_url(self):
        result = local_scan_url("http://192.168.1.10/login")

        self.assertGreaterEqual(result["risk_score"], 55)
        self.assertIn("الرابط لا يستخدم HTTPS.", result["signals"])
        self.assertIn("الرابط يستخدم عنوان IP بدل اسم نطاق.", result["signals"])
        self.assertIn("يحتوي الرابط كلمات شائعة في روابط التصيد.", result["signals"])

    def test_check_url_returns_arabic_result_text(self):
        result = check_url("https://example.com")

        self.assertIn("درجة الخطورة:", result)
        self.assertIn("الفحص المحلي:", result)


if __name__ == "__main__":
    unittest.main()
