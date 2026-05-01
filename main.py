import os
import re
import base64
import logging
import requests
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+)"

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)


def normalize_url(url: str) -> str:
    url = url.strip()
    if url.startswith("www."):
        url = "https://" + url
    return url


def get_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.strip("=")


def check_url(url: str) -> str:
    url = normalize_url(url)

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        url_id = get_url_id(url)
        report_api = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(report_api, headers=headers, timeout=15)

        if response.status_code == 404:
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )

            if submit_response.status_code in (200, 201):
                return (
                    "⏳ لم أجد نتيجة قديمة لهذا الرابط.\n"
                    "تم إرسال الرابط للفحص.\n"
                    "أرسل الرابط مرة أخرى بعد دقيقة."
                )

            return f"❌ فشل إرسال الرابط للفحص. كود الخطأ: {submit_response.status_code}"

        if response.status_code == 401:
            return "❌ مفتاح VirusTotal غير صحيح."

        if response.status_code == 429:
            return "⚠️ وصلت للحد المسموح في VirusTotal. جرّب لاحقًا."

        if response.status_code != 200:
            return f"❌ حدث خطأ أثناء الفحص. كود الخطأ: {response.status_code}"

        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total_bad = malicious + suspicious

        if total_bad > 0:
            verdict = "⚠️ الرابط مشبوه أو خطر"
        else:
            verdict = "✅ الرابط يبدو آمنًا"

        return (
            f"{verdict}\n\n"
            f"🔴 خطير: {malicious}\n"
            f"🟠 مشبوه: {suspicious}\n"
            f"🟢 آمن: {harmless}\n"
            f"⚪ غير معروف: {undetected}"
        )

    except requests.exceptions.Timeout:
        return "⏱️ انتهت مهلة الاتصال. جرّب مرة أخرى."

    except requests.exceptions.RequestException:
        return "❌ حدث خطأ في الاتصال بـ VirusTotal."

    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return "❌ حدث خطأ غير متوقع أثناء الفحص."


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "مرحبًا 👋\n\n"
        "أنا بوت فحص الروابط.\n"
        "أرسل أي رابط وسأفحصه لك عبر VirusTotal.\n\n"
        "مثال:\n"
        "https://google.com"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "الأوامر المتاحة:\n\n"
        "/start - تشغيل البوت\n"
        "/help - المساعدة\n\n"
        "أرسل رابطًا مباشرًا مثل:\n"
        "https://example.com"
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    urls = re.findall(URL_REGEX, text)

    if not urls:
        await update.message.reply_text("لم أجد أي رابط في رسالتك.")
        return

    urls = urls[:3]

    await update.message.reply_text("🔍 جاري فحص الرابط...")

    for url in urls:
        result = check_url(url)
        await update.message.reply_text(
            f"🔗 الرابط:\n{url}\n\n{result}"
        )


def main():
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN غير موجود داخل ملف .env")

    if not VT_API_KEY:
        raise ValueError("VT_API_KEY غير موجود داخل ملف .env")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
