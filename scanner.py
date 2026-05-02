import re
from urllib.parse import urlsplit


URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+)"
TRAILING_URL_CHARS = ".,;:!?)]}>'\"،؛؟"
LEADING_URL_CHARS = "([<{\"'"


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
