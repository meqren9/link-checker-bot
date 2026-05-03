import unittest
import tempfile
from pathlib import Path

from scanner import check_url, clean_url, extract_urls, is_url_shortener, local_scan_url, normalize_url, safe_url_label


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

    def test_shortener_detection_handles_common_services(self):
        for hostname in ("bit.ly", "www.tinyurl.com", "t.co", "cutt.ly"):
            with self.subTest(hostname=hostname):
                self.assertTrue(is_url_shortener(hostname))

    def test_local_scan_marks_shortened_url_with_safe_advice(self):
        result = local_scan_url("https://cutt.ly/example")

        self.assertTrue(result["is_shortened_url"])
        self.assertEqual(result["shortener_domain"], "cutt.ly")
        self.assertEqual(result["shortener_advice"], "تحقق من الوجهة قبل الفتح")
        self.assertIn("هذا رابط مختصر عبر cutt.ly.", result["signals"])
        self.assertIn("تحقق من الوجهة قبل الفتح", result["signals"])

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

    def test_local_scan_flags_community_suspicious_after_five_reports(self):
        import community_reports

        with tempfile.TemporaryDirectory() as temp_dir:
            community_reports.REPORTS_FILE = Path(temp_dir) / "reports.json"

            for reporter_id in range(5):
                community_reports.add_report(
                    "https://reported-example.test/private/path?token=secret",
                    reporter_id=reporter_id,
                )

            result = local_scan_url("https://reported-example.test/private/path?token=secret")

        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertTrue(result["community_report"]["community_suspicious"])
        self.assertIn("تم الإبلاغ عنه من المجتمع عدة مرات كرابط مشبوه.", result["signals"])

    def test_formatted_result_shows_existing_community_reports(self):
        import community_reports

        with tempfile.TemporaryDirectory() as temp_dir:
            community_reports.REPORTS_FILE = Path(temp_dir) / "reports.json"
            community_reports.add_report("https://example.com/private/path", reporter_id=1)

            result = check_url("https://example.com/private/path")

        self.assertIn("بلاغات المجتمع:", result)
        self.assertIn("1/5", result)
        self.assertNotIn("private", result)

    def test_local_scan_detects_typo_brand_impersonation_and_real_domain(self):
        result = local_scan_url("https://paypa1-secure-login.example.com/verify")

        indicators = "\n".join(result["expert_analysis"]["indicators"])
        self.assertGreaterEqual(result["risk_score"], 30)
        self.assertIn("paypal", indicators)
        self.assertIn("paypal.com", indicators)
        self.assertIn("secure-login", indicators)

    def test_local_scan_flags_saudi_trusted_brand_on_unofficial_domain_as_high_risk(self):
        cases = (
            ("Absher", "https://absher-login.example.com/verify", "أبشر"),
            ("Al Rajhi", "https://example.com/pay", "مصرف الراجحي"),
            ("STC", "https://mystc-bill.example.net/pay", "stc"),
            ("SPL", "https://delivery.example.net/track", "البريد السعودي SPL"),
            ("Nafath", "https://example.org/login", "سجل دخول عبر نفاذ"),
            ("Qiwa", "https://example.org/contract", "منصة قوى"),
            ("Mudad", "https://example.org/wages", "منصة مدد"),
        )

        for brand, url, message in cases:
            with self.subTest(brand=brand):
                result = local_scan_url(url, message_text=message)
                indicators = "\n".join(result["expert_analysis"]["indicators"])

                self.assertGreaterEqual(result["risk_score"], 60)
                self.assertIn(
                    "ظهر اسم جهة سعودية موثوقة، لكن النطاق ليس ضمن القائمة الرسمية الصغيرة.",
                    result["signals"],
                )
                self.assertIn("احتمال تقمص جهة سعودية موثوقة", indicators)
                self.assertIn("لا يثبت الاحتيال وحده", indicators)

    def test_local_scan_does_not_flag_saudi_trusted_brand_on_official_domains(self):
        cases = (
            ("https://www.absher.sa/wps/portal/individuals", "أبشر"),
            ("https://www.alrajhibank.com/login", "مصرف الراجحي"),
            ("https://www.stc.com.sa/content/stc/sa/ar", "stc"),
            ("https://splonline.com.sa/en/", "البريد السعودي SPL"),
            ("https://www.iam.gov.sa/policy.html", "نفاذ"),
            ("https://auth.qiwa.sa/", "منصة قوى"),
            ("https://mudad.com.sa/system-selection", "مدد"),
        )

        for url, message in cases:
            with self.subTest(url=url):
                result = local_scan_url(url, message_text=message)

                self.assertNotIn(
                    "ظهر اسم جهة سعودية موثوقة، لكن النطاق ليس ضمن القائمة الرسمية الصغيرة.",
                    result["signals"],
                )

    def test_check_url_returns_arabic_result_text(self):
        result = check_url("https://example.com")

        self.assertIn("درجة الخطورة:", result)
        self.assertIn("الفحص المحلي:", result)
        self.assertIn("🧠 تحليل خبير الأمن", result)
        self.assertIn("🧭 ماذا تفعل الآن؟", result)

    def test_check_url_explains_shortened_link_without_opening_it(self):
        result = check_url("https://bit.ly/example")

        self.assertIn("الرابط المختصر:", result)
        self.assertIn("هذا رابط مختصر عبر bit.ly.", result)
        self.assertIn("تحقق من الوجهة قبل الفتح", result)
        self.assertIn("لا أفتح الروابط غير الآمنة تلقائيًا.", result)


if __name__ == "__main__":
    unittest.main()
