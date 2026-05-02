import os
import re
import logging
import time
from collections import defaultdict, deque
from dotenv import load_dotenv
from urllib.parse import quote, urlsplit
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+)"
TRAILING_URL_CHARS = ".,;:!?)]}>'\"،؛؟"
LEADING_URL_CHARS = "([<{\"'"
USER_SCAN_LIMIT = 5
USER_SCAN_WINDOW_SECONDS = 60
MAX_MESSAGE_LENGTH = 2000
MAX_URL_LENGTH = 2048

logger = logging.getLogger(__name__)
user_scan_times = defaultdict(deque)

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)


def share_bot_keyboard() -> InlineKeyboardMarkup:
    share_text = quote("افحص أي رابط قبل فتحه عبر @SafeLiinkBot")
    share_url = f"https://t.me/share/url?text={share_text}"

    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📤 مشاركة البوت", url=share_url)]
    ])


def normalize_url(url: str) -> str:
    url = clean_url(url)
    if url.startswith("www."):
        url = "https://" + url
    return url


def clean_url(url: str) -> str:
    return url.strip().strip(LEADING_URL_CHARS).rstrip(TRAILING_URL_CHARS)


def safe_url_label(url: str) -> str:
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)

    if parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/..."

    return "رابط غير صالح"


def local_scan_url(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""
    risk_score = 0
    signals = []

    if not parsed.scheme or not parsed.netloc:
        risk_score += 40
        signals.append("صيغة الرابط غير واضحة.")

    if parsed.scheme != "https":
        risk_score += 15
        signals.append("الرابط لا يستخدم HTTPS.")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        risk_score += 25
        signals.append("الرابط يستخدم عنوان IP بدل اسم نطاق.")

    if "xn--" in hostname:
        risk_score += 20
        signals.append("النطاق قد يحتوي أحرفًا شبيهة أو دولية.")

    if len(normalized) > 120:
        risk_score += 10
        signals.append("الرابط طويل وقد يخفي تفاصيل مهمة.")

    suspicious_words = ("login", "verify", "secure", "account", "update", "gift")
    if any(word in normalized.lower() for word in suspicious_words):
        risk_score += 15
        signals.append("يحتوي الرابط كلمات شائعة في روابط التصيد.")

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        verdict = "🚨 التقييم الحالي: خطر محتمل"
        explanation = "الفحص المحلي وجد عدة مؤشرات تستدعي تجنب الرابط."
    elif risk_score >= 30:
        verdict = "⚠️ التقييم الحالي: مشبوه"
        explanation = "الفحص المحلي وجد مؤشرات تحتاج حذرًا قبل فتح الرابط."
    else:
        verdict = "✅ التقييم الحالي: لا توجد مؤشرات خطر واضحة"
        explanation = "الفحص المحلي لم يجد علامات خطرة واضحة."

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "explanation": explanation,
        "signals": signals,
    }


def format_local_scan_result(result: dict) -> str:
    signals = result["signals"] or ["لا توجد مؤشرات محلية واضحة."]
    signal_lines = "\n".join(f"- {signal}" for signal in signals[:3])

    return (
        f"{result['verdict']}\n"
        f"درجة الخطورة: {result['risk_score']}/100\n\n"
        f"{result['explanation']}\n\n"
        "الفحص المحلي:\n"
        f"{signal_lines}\n\n"
        "تنبيه: حتى إذا ظهرت النتيجة آمنة، فهذا لا يضمن الأمان بنسبة 100%.\n\n"
        "ساعد غيرك على فحص الروابط بمشاركة البوت: @SafeLiinkBot"
    )


def check_url(url: str) -> str:
    url = normalize_url(url)
    return format_local_scan_result(local_scan_url(url))


def can_scan_for_user(user_id: int) -> bool:
    now = time.time()
    scan_times = user_scan_times[user_id]

    while scan_times and now - scan_times[0] >= USER_SCAN_WINDOW_SECONDS:
        scan_times.popleft()

    if len(scan_times) >= USER_SCAN_LIMIT:
        return False

    scan_times.append(now)
    return True


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
        "أرسل رابطًا يبدأ بـ https:// أو www وسأفحصه لك.\n"
        "الفحص الحالي محلي وإرشادي فقط.\n"
        "لن أعرض الرابط كاملًا في الرد حفاظًا على الخصوصية."
    )


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
                "يمكنك فحص حتى 5 روابط في الدقيقة. جرّب بعد قليل."
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

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot is running")
    app.run_polling()


if __name__ == "__main__":
    main()
