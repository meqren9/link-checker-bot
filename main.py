import os
import re
import logging
import time
import threading
from collections import defaultdict, deque
from dotenv import load_dotenv
from urllib.parse import quote
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
import uvicorn
from scanner import URL_REGEX, check_url, clean_url, normalize_url, safe_url_label

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

USER_SCAN_LIMIT = 3
USER_SCAN_WINDOW_SECONDS = 60
MAX_MESSAGE_LENGTH = 2000
MAX_URL_LENGTH = 2048
ADMIN_USER_IDS = {
    int(user_id.strip())
    for user_id in os.getenv("ADMIN_USER_IDS", "").split(",")
    if user_id.strip().isdigit()
}

logger = logging.getLogger(__name__)
user_scan_times = defaultdict(deque)

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)


def run_api_server():
    port = int(os.getenv("PORT", "8000"))
    config = uvicorn.Config("api:app", host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(config)
    server.run()


def share_bot_keyboard() -> InlineKeyboardMarkup:
    share_text = quote("افحص أي رابط قبل فتحه عبر @SafeLiinkBot")
    share_url = f"https://t.me/share/url?text={share_text}"

    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📤 مشاركة البوت", url=share_url)]
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
        "https://google.com"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "الأوامر:\n\n"
        "/start - تشغيل البوت\n"
        "/help - المساعدة\n\n"
        "/myid - عرض معرّفك واسم المستخدم\n\n"
        "أرسل رابطًا يبدأ بـ https:// أو www وسأفحصه لك.\n"
        "الفحص الحالي محلي وإرشادي فقط.\n"
        "لن أعرض الرابط كاملًا في الرد حفاظًا على الخصوصية."
    )


async def myid_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(format_user_identity(update.effective_user))


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""

    if len(text) > MAX_MESSAGE_LENGTH:
        await update.message.reply_text(
            "الرسالة طويلة جدًا.\n"
            "أرسل رسالة أقصر تحتوي على الروابط التي تريد فحصها فقط."
        )
        return

    urls = [clean_url(url) for url in re.findall(URL_REGEX, text)]
    urls = [url for url in urls if url]

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

        result = check_url(url)
        await update.message.reply_text(
            f"🔗 الرابط:\n{safe_url_label(url)}\n\n{result}",
            reply_markup=share_bot_keyboard(),
        )

    if len(urls) > 3:
        await update.message.reply_text("فحصت أول 3 روابط فقط حتى لا تطول العملية.")


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
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot is running")
    app.run_polling()


if __name__ == "__main__":
    main()
