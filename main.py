import os
import logging
import time
import threading
import uuid
from collections import defaultdict, deque
from dotenv import load_dotenv
from urllib.parse import quote
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update, WebAppInfo
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
import uvicorn
from community_reports import add_report_for_key, url_report_key
from scanner import extract_urls, format_local_scan_result, local_scan_url, normalize_url, safe_url_label

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
WEBAPP_URL = os.getenv("WEBAPP_URL", "").strip()

USER_SCAN_LIMIT = 3
USER_SCAN_WINDOW_SECONDS = 60
MAX_MESSAGE_LENGTH = 2000
MAX_URL_LENGTH = 2048

logger = logging.getLogger(__name__)
user_scan_times = defaultdict(deque)
pending_report_tokens = {}

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)


def parse_admin_user_ids(value: str) -> set[int]:
    admin_ids = set()

    for raw_user_id in value.split(","):
        user_id = raw_user_id.strip()

        if not user_id:
            continue

        if not user_id.isdigit():
            logger.warning(
                "Ignoring invalid ADMIN_USER_IDS entry %r. Use numeric Telegram user IDs, not usernames.",
                user_id,
            )
            continue

        admin_ids.add(int(user_id))

    return admin_ids


ADMIN_USER_IDS = parse_admin_user_ids(os.getenv("ADMIN_USER_IDS", ""))


def run_api_server():
    port = int(os.getenv("PORT", "8000"))
    config = uvicorn.Config("api:app", host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    server.run()


def report_token_for_url(url: str) -> str:
    token = uuid.uuid4().hex[:16]
    pending_report_tokens[token] = {
        "created_at": time.time(),
        "report_key": url_report_key(url),
    }

    if len(pending_report_tokens) > 500:
        oldest_tokens = sorted(
            pending_report_tokens,
            key=lambda item: pending_report_tokens[item]["created_at"],
        )
        for old_token in oldest_tokens[:100]:
            pending_report_tokens.pop(old_token, None)

    return token


def link_actions_keyboard(url: str) -> InlineKeyboardMarkup:
    share_text = quote("افحص أي رابط قبل فتحه عبر @SafeLiinkBot")
    share_url = f"https://t.me/share/url?text={share_text}"
    token = report_token_for_url(url)

    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🚩 بلّغ عن رابط مشبوه", callback_data=f"report:{token}")],
        [InlineKeyboardButton("📤 مشاركة البوت", url=share_url)],
    ])


def start_keyboard() -> InlineKeyboardMarkup | None:
    if not WEBAPP_URL:
        return None

    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔎 فتح الفحص", web_app=WebAppInfo(url=WEBAPP_URL))]
    ])


def is_admin_user(user_id: int) -> bool:
    return user_id in ADMIN_USER_IDS


def can_scan_for_user(user_id: int) -> bool:
    if is_admin_user(user_id):
        return True

    now = time.time()
    scan_times = user_scan_times[user_id]

    while scan_times and now - scan_times[0] >= USER_SCAN_WINDOW_SECONDS:
        scan_times.popleft()

    if len(scan_times) >= USER_SCAN_LIMIT:
        return False

    scan_times.append(now)
    return True


def format_user_identity(user) -> str:
    username = f"@{user.username}" if user and user.username else "لا يوجد اسم مستخدم"
    user_id = user.id if user else "غير معروف"
    return f"معرّفك في Telegram:\n{user_id}\n\nاسم المستخدم:\n{username}"


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "مرحبًا 👋\n\n"
        "أرسل لي رابطًا وسأفحصه محليًا بمؤشرات بسيطة.\n"
        "يمكنك إرسال حتى 3 روابط في الرسالة الواحدة.\n\n"
        "مثال:\n"
        "https://google.com",
        reply_markup=start_keyboard(),
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "الأوامر:\n\n"
        "/start - تشغيل البوت\n"
        "/help - المساعدة\n\n"
        "/myid - عرض معرّفك واسم المستخدم\n\n"
        "/privacy - الخصوصية والبلاغات\n\n"
        "أرسل رابطًا يبدأ بـ https:// أو www وسأفحصه لك.\n"
        "الفحص الحالي محلي وإرشادي فقط.\n"
        "لن أعرض الرابط كاملًا في الرد حفاظًا على الخصوصية."
    )


async def myid_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(format_user_identity(update.effective_user))


async def privacy_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "الخصوصية والبلاغات:\n\n"
        "- لا يعرض البوت الرابط كاملًا في الردود.\n"
        "- عند البلاغ عن رابط، نحفظ مفتاحًا مختصرًا فقط: النطاق المسجل مثل example.com أو بصمة SHA-256 للرابط عند الحاجة.\n"
        "- لا نحفظ المسار أو الاستعلام الكامل للرابط ضمن البلاغات.\n"
        "- نستخدم بصمة مرتبطة بمفتاح البلاغ لمنع تكرار البلاغ من نفس الحساب، ولا نحفظ المعرّف الخام داخل سجل البلاغات.\n"
        "- عند وصول رابط أو نطاق إلى 5 بلاغات، يظهر كمشبوه من المجتمع في الفحص.\n"
        "- في المجموعات يرسل البوت تحذيرًا عند الروابط المشبوهة أو عالية الخطورة، ولا يحذف الرسائل حاليًا."
    )


def is_group_chat(update: Update) -> bool:
    return bool(update.effective_chat and update.effective_chat.type in {"group", "supergroup"})


def group_warning_text(url: str, result: dict) -> str:
    return (
        "⚠️ تحذير رابط مشبوه في المجموعة\n\n"
        f"الرابط:\n{safe_url_label(url)}\n\n"
        f"درجة الخطورة: {result['risk_score']}/100\n"
        f"{result['explanation']}\n\n"
        "لم أحذف الرسالة. تحققوا من المصدر قبل فتح الرابط أو إدخال أي بيانات."
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""

    if len(text) > MAX_MESSAGE_LENGTH:
        await update.message.reply_text(
            "الرسالة طويلة جدًا.\n"
            "أرسل رسالة أقصر تحتوي على الروابط التي تريد فحصها فقط."
        )
        return

    urls = extract_urls(text)

    if not urls:
        await update.message.reply_text(
            "لم أجد رابطًا واضحًا في رسالتك.\n"
            "أرسل رابطًا يبدأ بـ https:// أو www."
        )
        return

    await update.message.reply_text("🔍 جاري فحص الروابط...")

    for url in urls[:3]:
        user_id = update.effective_user.id if update.effective_user else update.effective_chat.id

        if len(normalize_url(url)) > MAX_URL_LENGTH:
            await update.message.reply_text(
                "تجاوز أحد الروابط الحد الأقصى للطول، لذلك لم أقم بفحصه."
            )
            continue

        if not can_scan_for_user(user_id):
            await update.message.reply_text(
                "وصلت للحد المؤقت للفحص.\n"
                "يمكنك فحص حتى 3 روابط في الدقيقة. جرّب بعد قليل."
            )
            break

        result = local_scan_url(url, message_text=text)

        if is_group_chat(update) and result["risk_score"] >= 30:
            await update.message.reply_text(
                group_warning_text(url, result),
                reply_markup=link_actions_keyboard(url),
            )
            continue

        await update.message.reply_text(
            f"🔗 الرابط:\n{safe_url_label(url)}\n\n{format_local_scan_result(result)}",
            reply_markup=link_actions_keyboard(url),
        )

    if len(urls) > 3:
        await update.message.reply_text("فحصت أول 3 روابط فقط حتى لا تطول العملية.")


async def report_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data or ""
    if not data.startswith("report:"):
        return

    token = data.removeprefix("report:")
    pending = pending_report_tokens.get(token)

    if not pending:
        await query.message.reply_text("تعذر تسجيل البلاغ. افحص الرابط مرة أخرى ثم أعد البلاغ.")
        return

    reporter_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    report = add_report_for_key(pending["report_key"], reporter_id=reporter_id)

    if report["duplicate"]:
        await query.message.reply_text("تم تسجيل بلاغك سابقًا لهذا الرابط أو النطاق.")
        return

    if report["community_suspicious"]:
        await query.message.reply_text(
            "تم تسجيل البلاغ. وصل هذا الرابط أو النطاق إلى حد البلاغات وسيظهر كمشبوه من المجتمع."
        )
        return

    await query.message.reply_text(
        f"تم تسجيل البلاغ. عدد البلاغات الحالي: {report['count']}/{report['threshold']}."
    )


def main():
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN غير موجود. أضفه في Railway Variables")

    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()
    logger.info("FastAPI server is running")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("myid", myid_command))
    app.add_handler(CommandHandler("privacy", privacy_command))
    app.add_handler(CallbackQueryHandler(report_callback, pattern=r"^report:"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot is running")
    app.run_polling()


if __name__ == "__main__":
    main()
