import unittest

from scanner import check_url, clean_url, extract_urls, local_scan_url, normalize_url, safe_url_label


class ScannerTests(unittest.TestCase):
    def test_clean_url_removes_wrapping_punctuation(self):
        self.assertEqual(clean_url("(https://example.com),"), "https://example.com")

    def test_normalize_url_adds_https_for_www(self):
        self.assertEqual(normalize_url("www.example.com"), "https://www.example.com")

    def test_extract_urls_finds_link_inside_full_message(self):
        urls = extract_urls("عاجل تحقق من حسابك الآن https://example.com/login.")

        self.assertEqual(urls, ["https://example.com/login"])

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
        self.assertIn("expert_analysis", result)

    def test_local_scan_expert_analysis_flags_required_indicators(self):
        result = local_scan_url(
            "http://paypal-login.example-account-verification-top-domain-name-that-is-long.xyz/update.exe"
        )

        indicators = "\n".join(result["expert_analysis"]["indicators"])
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertIn("التصيد", indicators)
        self.assertIn("تقمص علامة تجارية", indicators)
        self.assertIn(".xyz", indicators)
        self.assertIn("طويل", indicators)
        self.assertIn(".exe", indicators)

    def test_local_scan_expert_analysis_flags_shortener_and_misleading_subdomain(self):
        result = local_scan_url("https://paypal.bit.ly/verify")

        indicators = "\n".join(result["expert_analysis"]["indicators"])
        self.assertIn("النطاق الفرعي", indicators)
        self.assertIn("اختصار", indicators)

    def test_local_scan_does_not_flag_official_brand_domain_as_impersonation(self):
        result = local_scan_url("https://paypal.com/login")

        self.assertNotIn("قد يحاول الرابط تقمص علامة تجارية في نطاق غير رسمي.", result["signals"])

    def test_local_scan_uses_full_message_context(self):
        message = "عاجل! ربحت جائزة. تحقق من حسابك خلال 24 ساعة: https://example.com/prize"

        result = local_scan_url("https://example.com/prize", message_text=message)

        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertIn("نص الرسالة يحتوي عبارات شائعة في رسائل التصيد.", result["signals"])
        indicators = "\n".join(result["message_analysis"]["indicators"])
        self.assertIn("استعجال", indicators)
        self.assertIn("جائزة", indicators)

    def test_local_scan_detects_typo_brand_impersonation_and_real_domain(self):
        result = local_scan_url("https://paypa1-secure-login.example.com/verify")

        indicators = "\n".join(result["expert_analysis"]["indicators"])
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertIn("paypal", indicators)
        self.assertIn("paypal.com", indicators)
        self.assertIn("secure-login", indicators)

    def test_check_url_returns_arabic_result_text(self):
        result = check_url("https://example.com")

        self.assertIn("درجة الخطورة:", result)
        self.assertIn("الفحص المحلي:", result)
        self.assertIn("🧠 تحليل خبير الأمن", result)
        self.assertIn("🧭 ماذا تفعل الآن؟", result)


if __name__ == "__main__":
    unittest.main()
