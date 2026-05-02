import os
import re
import base64
import logging
import requests
from dotenv import load_dotenv
from urllib.parse import urlsplit
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+)"
TRAILING_URL_CHARS = ".,;:!?)]}>'\"،؛؟"
LEADING_URL_CHARS = "([<{\"'"

logger = logging.getLogger(__name__)

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)


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


def get_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.strip("=")


def format_scan_result(stats: dict) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        verdict = "🚨 النتيجة: خطر"
        explanation = "وجدت بعض محركات الفحص أن الرابط ضار. لا تفتحه."
    elif suspicious > 0:
        verdict = "⚠️ النتيجة: مشبوه"
        explanation = "لم يتم تأكيد أنه ضار، لكن توجد مؤشرات تستدعي الحذر."
    elif harmless > 0:
        verdict = "✅ النتيجة: لا توجد مؤشرات خطر واضحة"
        explanation = "لم ترصد محركات الفحص المتاحة علامات خطرة على الرابط."
    else:
        verdict = "ℹ️ النتيجة: غير كافية"
        explanation = "لا توجد بيانات كافية للحكم على الرابط بثقة."

    return (
        f"{verdict}\n"
        f"{explanation}\n\n"
        "تفاصيل الفحص من VirusTotal:\n"
        f"🔴 ضار: {malicious}\n"
        f"🟠 مشبوه: {suspicious}\n"
        f"🟢 سليم: {harmless}\n"
        f"⚪ غير معروف: {undetected}\n\n"
        "ملاحظة: نتيجة الفحص تساعدك على التقييم لكنها لا تضمن الأمان بنسبة 100%."
    )


def check_url(url: str) -> str:
    url = normalize_url(url)

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        url_id = get_url_id(url)
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(api_url, headers=headers, timeout=15)

        if response.status_code == 404:
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15,
            )

            if submit.status_code in (200, 201):
                return (
                    "⏳ الرابط غير موجود في قاعدة البيانات.\n"
                    "تم إرساله للفحص.\n"
                    "أرسل الرابط مرة أخرى بعد دقيقة."
                )

            return f"❌ فشل إرسال الرابط للفحص. الكود: {submit.status_code}"

        if response.status_code == 401:
            return "❌ مفتاح VirusTotal غير صحيح."

        if response.status_code == 429:
            return "⚠️ وصلت للحد المسموح في VirusTotal. جرّب لاحقًا."

        if response.status_code != 200:
            return f"❌ حدث خطأ أثناء الفحص. الكود: {response.status_code}"

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return format_scan_result(stats)

    except requests.exceptions.Timeout:
        return "⏱️ انتهت مهلة الاتصال. جرّب مرة ثانية."

    except requests.exceptions.RequestException as exc:
        logger.warning(
            "VirusTotal request failed for %s: %s",
            safe_url_label(url),
            exc.__class__.__name__,
        )
        return "❌ حدث خطأ في الاتصال بخدمة الفحص. جرّب مرة أخرى لاحقًا."

    except Exception as exc:
        logger.error(
            "Unexpected error while checking %s: %s",
            safe_url_label(url),
            exc.__class__.__name__,
        )
        return "❌ حدث خطأ غير متوقع أثناء الفحص."


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "مرحبًا 👋\n\n"
        "أرسل لي رابطًا وسأفحصه عبر VirusTotal.\n"
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
        "لن أعرض الرابط كاملًا في الرد حفاظًا على الخصوصية."
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
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
        result = check_url(url)
        await update.message.reply_text(
            f"🔗 الرابط:\n{safe_url_label(url)}\n\n{result}"
        )

    if len(urls) > 3:
        await update.message.reply_text("فحصت أول 3 روابط فقط حتى لا تطول العملية.")


def main():
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN غير موجود. أضفه في Railway Variables")

    if not VT_API_KEY:
        raise ValueError("VT_API_KEY غير موجود. أضفه في Railway Variables")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot is running")
    app.run_polling()


if __name__ == "__main__":
    main()
