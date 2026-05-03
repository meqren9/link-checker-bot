import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

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

    def test_parse_admin_user_ids_accepts_comma_separated_numeric_ids(self):
        self.assertEqual(main.parse_admin_user_ids("111, 222,333"), {111, 222, 333})

    def test_parse_admin_user_ids_ignores_usernames(self):
        with self.assertLogs("main", level="WARNING"):
            admin_ids = main.parse_admin_user_ids("111, @adminuser, adminuser")

        self.assertEqual(admin_ids, {111})

    def test_format_user_identity_includes_id_and_username(self):
        user = SimpleNamespace(id=333, username="meqren10")

        response = main.format_user_identity(user)

        self.assertIn("333", response)
        self.assertIn("@meqren10", response)

    def test_report_token_stores_report_key_not_full_url(self):
        main.pending_report_tokens.clear()

        token = main.report_token_for_url("https://example.com/private/path?token=secret")
        pending = main.pending_report_tokens[token]

        self.assertEqual(pending["report_key"]["key"], "domain:example.com")
        self.assertNotIn("private", str(pending))
        self.assertNotIn("secret", str(pending))

    def test_report_button_uses_requested_label(self):
        keyboard = main.link_actions_keyboard("https://example.com/path")

        self.assertEqual(keyboard.inline_keyboard[0][0].text, "🚩 بلّغ عن رابط")

    def test_group_warning_matches_required_text(self):
        self.assertEqual(
            main.group_warning_text(),
            "⚠️ تحذير:\n"
            "هذا الرابط تم تصنيفه كمشبوه/خطير\n"
            "يرجى الحذر قبل فتحه",
        )

    def test_group_delete_notice_matches_required_text(self):
        self.assertEqual(
            main.group_delete_notice_text(),
            "🛡️ تم حذف رابط مشبوه لحماية المجموعة",
        )

    def test_group_safety_only_flags_high_confidence_cases(self):
        medium_risk = {
            "risk_score": 30,
            "community_report": {"count": 0, "threshold": 5},
        }
        high_risk = {
            "risk_score": 60,
            "community_report": {"count": 0, "threshold": 5},
        }
        reported = {
            "risk_score": 10,
            "community_report": {"count": 5, "threshold": 5},
        }

        self.assertFalse(main.is_high_confidence_group_risk(medium_risk))
        self.assertTrue(main.is_high_confidence_group_risk(high_risk))
        self.assertTrue(main.is_high_confidence_group_risk(reported))

    def test_parse_bool_env_defaults_to_false(self):
        self.assertFalse(main.parse_bool_env(""))
        self.assertFalse(main.parse_bool_env("false"))
        self.assertTrue(main.parse_bool_env("true"))
        self.assertTrue(main.parse_bool_env("1"))


class MainGroupSafetyTests(unittest.IsolatedAsyncioTestCase):
    def make_group_update(self):
        message = SimpleNamespace(
            text="https://example.com/login",
            reply_text=AsyncMock(),
            delete=AsyncMock(),
        )
        return SimpleNamespace(
            effective_chat=SimpleNamespace(id=-100, type="supergroup"),
            message=message,
        )

    async def test_group_safety_warns_without_deleting_by_default(self):
        update = self.make_group_update()
        result = {
            "risk_score": 65,
            "community_report": {"count": 0, "threshold": 5},
        }
        context = SimpleNamespace(bot=SimpleNamespace(send_message=AsyncMock()))

        with patch("main.DELETE_SUSPICIOUS", False), patch("main.link_actions_keyboard", return_value=None):
            handled = await main.handle_group_safety_action(
                update,
                context,
                "https://example.com/login",
                result,
            )

        self.assertTrue(handled)
        update.message.delete.assert_not_awaited()
        update.message.reply_text.assert_awaited_once_with(
            main.group_warning_text(),
            reply_markup=None,
        )

    async def test_group_safety_deletes_when_enabled_and_bot_is_admin(self):
        update = self.make_group_update()
        result = {
            "risk_score": 65,
            "community_report": {"count": 0, "threshold": 5},
        }
        context = SimpleNamespace(bot=SimpleNamespace(send_message=AsyncMock()))

        with patch("main.DELETE_SUSPICIOUS", True), patch("main.bot_is_admin", new=AsyncMock(return_value=True)):
            handled = await main.handle_group_safety_action(
                update,
                context,
                "https://example.com/login",
                result,
            )

        self.assertTrue(handled)
        update.message.delete.assert_awaited_once()
        update.message.reply_text.assert_not_awaited()
        context.bot.send_message.assert_awaited_once_with(
            chat_id=-100,
            text=main.group_delete_notice_text(),
        )

    async def test_group_safety_ignores_medium_risk_links(self):
        update = self.make_group_update()
        result = {
            "risk_score": 30,
            "community_report": {"count": 0, "threshold": 5},
        }
        context = SimpleNamespace(bot=SimpleNamespace(send_message=AsyncMock()))

        handled = await main.handle_group_safety_action(
            update,
            context,
            "https://example.com/login",
            result,
        )

        self.assertFalse(handled)
        update.message.delete.assert_not_awaited()
        update.message.reply_text.assert_not_awaited()


class MainAdminReportCommandTests(unittest.IsolatedAsyncioTestCase):
    def make_update(self, user_id=111):
        return SimpleNamespace(
            effective_user=SimpleNamespace(id=user_id),
            message=SimpleNamespace(reply_text=AsyncMock()),
        )

    async def test_reports_command_rejects_non_admin(self):
        update = self.make_update(user_id=111)
        context = SimpleNamespace(args=[])

        with patch("main.ADMIN_USER_IDS", set()):
            await main.reports_command(update, context)

        update.message.reply_text.assert_awaited_once_with("هذا الأمر متاح للمشرفين فقط.")

    async def test_reports_command_lists_reports_for_admin(self):
        update = self.make_update(user_id=222)
        context = SimpleNamespace(args=[])
        reports = [{
            "key_type": "domain",
            "label": "example.com",
            "count": 3,
            "threshold": 5,
            "community_suspicious": False,
        }]

        with patch("main.ADMIN_USER_IDS", {222}), patch("main.list_reports", return_value=reports):
            await main.reports_command(update, context)

        message = update.message.reply_text.await_args.args[0]
        self.assertIn("example.com", message)
        self.assertIn("3/5", message)

    async def test_clearreport_command_clears_domain_for_admin(self):
        update = self.make_update(user_id=222)
        context = SimpleNamespace(args=["example.com"])

        with patch("main.ADMIN_USER_IDS", {222}), patch(
            "main.clear_domain_report",
            return_value={"cleared": True, "label": "example.com", "reason": ""},
        ) as clear_report:
            await main.clearreport_command(update, context)

        clear_report.assert_called_once_with("example.com")
        update.message.reply_text.assert_awaited_once_with("تم حذف بلاغات النطاق: example.com")


if __name__ == "__main__":
    unittest.main()
