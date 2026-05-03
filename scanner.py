import re
from urllib.parse import urlsplit


URL_REGEX = r"(https?://[^\s]+|www\.[^\s]+)"
TRAILING_URL_CHARS = ".,;:!?)]}>'\"،؛؟"
LEADING_URL_CHARS = "([<{\"'"
PHISHING_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "gift",
    "wallet",
    "password",
    "confirm",
    "signin",
    "banking",
    "support",
)
KNOWN_BRANDS = (
    "apple",
    "google",
    "microsoft",
    "paypal",
    "amazon",
    "netflix",
    "meta",
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "binance",
    "stc",
    "alrajhi",
    "snb",
)
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "lnkd.in",
}
SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
    "work",
    "rest",
    "support",
}
RISKY_FILE_EXTENSIONS = {
    ".apk",
    ".app",
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".js",
    ".msi",
    ".scr",
    ".vbs",
    ".wsf",
}
BRAND_DOMAIN_HINTS = {
    "apple": ("apple.com",),
    "google": ("google.com",),
    "microsoft": ("microsoft.com", "office.com", "live.com"),
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com",),
    "netflix": ("netflix.com",),
    "meta": ("meta.com", "facebook.com", "instagram.com"),
    "facebook": ("facebook.com",),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "telegram": ("telegram.org", "t.me"),
    "binance": ("binance.com",),
    "stc": ("stc.com.sa",),
    "alrajhi": ("alrajhibank.com.sa",),
    "snb": ("alahli.com",),
}


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


def registered_domain(hostname: str) -> str:
    parts = [part for part in hostname.lower().split(".") if part]

    if len(parts) <= 2:
        return ".".join(parts)

    return ".".join(parts[-2:])


def hostname_tld(hostname: str) -> str:
    parts = [part for part in hostname.lower().split(".") if part]
    return parts[-1] if parts else ""


def has_ip_hostname(hostname: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname))


def has_risky_file_extension(path: str) -> str:
    lowered_path = path.lower()

    for extension in RISKY_FILE_EXTENSIONS:
        if lowered_path.endswith(extension):
            return extension

    return ""


def find_brand_impersonation(hostname: str) -> list[str]:
    lowered_hostname = hostname.lower()
    normalized_hostname = lowered_hostname.replace("-", "")
    root_domain = registered_domain(lowered_hostname)
    found = []

    for brand, official_domains in BRAND_DOMAIN_HINTS.items():
        brand_in_host = brand in normalized_hostname
        official_match = any(
            lowered_hostname == official
            or root_domain == official
            or lowered_hostname.endswith(f".{official}")
            for official in official_domains
        )

        if brand_in_host and not official_match:
            found.append(brand)

    return found


def has_misleading_subdomain(hostname: str) -> bool:
    parts = [part for part in hostname.lower().split(".") if part]

    if len(parts) < 3:
        return False

    subdomain = ".".join(parts[:-2])
    return any(brand in subdomain.replace("-", "") for brand in KNOWN_BRANDS)


def build_expert_analysis(normalized_url: str, risk_score: int, signals: list[str]) -> dict:
    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname or ""
    lowered_url = normalized_url.lower()
    root_domain = registered_domain(hostname)
    tld = hostname_tld(hostname)
    risky_extension = has_risky_file_extension(parsed.path)
    phishing_keywords = [word for word in PHISHING_KEYWORDS if word in lowered_url]
    impersonated_brands = find_brand_impersonation(hostname)
    indicators = []

    if phishing_keywords:
        indicators.append(
            "كلمات مرتبطة غالبًا بالتصيد أو الاستعجال: "
            + "، ".join(phishing_keywords[:5])
        )

    if impersonated_brands:
        indicators.append(
            "احتمال تقمص علامة تجارية داخل نطاق غير رسمي: "
            + "، ".join(impersonated_brands[:3])
        )

    if tld in SUSPICIOUS_TLDS:
        indicators.append(f"امتداد النطاق .{tld} يظهر كثيرًا في حملات روابط منخفضة الثقة.")

    if len(root_domain) > 30:
        indicators.append("اسم النطاق طويل نسبيًا وقد يصعّب ملاحظة النطاق الحقيقي.")

    if has_misleading_subdomain(hostname):
        indicators.append("يوجد اسم علامة أو خدمة في النطاق الفرعي وليس في النطاق الأساسي.")

    if has_ip_hostname(hostname):
        indicators.append("الرابط يستخدم عنوان IP بدل نطاق واضح يمكن التحقق من هويته.")

    if root_domain in URL_SHORTENERS:
        indicators.append("الرابط يستخدم خدمة اختصار، وهذا يخفي الوجهة النهائية قبل الفتح.")

    if risky_extension:
        indicators.append(f"الرابط يشير إلى ملف بامتداد عالي المخاطر: {risky_extension}")

    if "xn--" in hostname:
        indicators.append("النطاق يحتوي ترميزًا قد يشير إلى أحرف شبيهة بأحرف علامات معروفة.")

    if not indicators and signals:
        indicators.extend(signals[:3])

    if risk_score >= 60:
        summary = "الرابط يبدو خطيرًا أو عالي الاشتباه بسبب اجتماع عدة مؤشرات خطر."
        recommendation = "لا تفتح الرابط ولا تدخل بياناتك. تحقّق من الجهة عبر التطبيق أو الموقع الرسمي مباشرة."
    elif risk_score >= 30:
        summary = "الرابط يبدو مشبوهًا ويحتاج تحققًا إضافيًا قبل فتحه."
        recommendation = "تجنب إدخال كلمات مرور أو بيانات دفع، وافتح الخدمة من عنوانها الرسمي بدل هذا الرابط."
    else:
        summary = "لا توجد مؤشرات خطر واضحة في الفحص المحلي، لكن ذلك لا يعني أن الرابط آمن بنسبة 100%."
        recommendation = "افتح الرابط فقط إذا كنت تثق بالمصدر، ولا تدخل بيانات حساسة إلا بعد التأكد من النطاق."

    return {
        "summary": summary,
        "indicators": indicators or ["لم تظهر مؤشرات خطر واضحة ضمن القواعد المحلية."],
        "recommendation": recommendation,
    }


def local_scan_url(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""
    root_domain = registered_domain(hostname)
    tld = hostname_tld(hostname)
    risk_score = 0
    signals = []

    if not parsed.scheme or not parsed.netloc:
        risk_score += 40
        signals.append("صيغة الرابط غير واضحة.")

    if parsed.scheme != "https":
        risk_score += 15
        signals.append("الرابط لا يستخدم HTTPS.")

    if has_ip_hostname(hostname):
        risk_score += 25
        signals.append("الرابط يستخدم عنوان IP بدل اسم نطاق.")

    if "xn--" in hostname:
        risk_score += 20
        signals.append("النطاق قد يحتوي أحرفًا شبيهة أو دولية.")

    if len(normalized) > 120:
        risk_score += 10
        signals.append("الرابط طويل وقد يخفي تفاصيل مهمة.")

    if any(word in normalized.lower() for word in PHISHING_KEYWORDS):
        risk_score += 15
        signals.append("يحتوي الرابط كلمات شائعة في روابط التصيد.")

    if find_brand_impersonation(hostname):
        risk_score += 25
        signals.append("قد يحاول الرابط تقمص علامة تجارية في نطاق غير رسمي.")

    if tld in SUSPICIOUS_TLDS:
        risk_score += 15
        signals.append("امتداد النطاق مرتبط عادةً بروابط منخفضة الثقة.")

    if len(root_domain) > 30:
        risk_score += 10
        signals.append("اسم النطاق طويل بشكل غير معتاد.")

    if has_misleading_subdomain(hostname):
        risk_score += 20
        signals.append("النطاق الفرعي قد يكون مضللًا ويخفي النطاق الحقيقي.")

    if root_domain in URL_SHORTENERS:
        risk_score += 20
        signals.append("الرابط يستخدم خدمة اختصار تخفي الوجهة النهائية.")

    if has_risky_file_extension(parsed.path):
        risk_score += 25
        signals.append("الرابط يشير إلى ملف قابل للتنفيذ أو امتداد عالي المخاطر.")

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
        "expert_analysis": build_expert_analysis(normalized, risk_score, signals),
    }


def format_local_scan_result(result: dict) -> str:
    signals = result["signals"] or ["لا توجد مؤشرات محلية واضحة."]
    signal_lines = "\n".join(f"- {signal}" for signal in signals[:3])
    expert = result.get("expert_analysis") or {}
    expert_indicators = expert.get("indicators") or ["لم تظهر مؤشرات خطر واضحة ضمن القواعد المحلية."]
    expert_indicator_lines = "\n".join(f"- {indicator}" for indicator in expert_indicators[:5])

    return (
        f"{result['verdict']}\n"
        f"درجة الخطورة: {result['risk_score']}/100\n\n"
        f"{result['explanation']}\n\n"
        "الفحص المحلي:\n"
        f"{signal_lines}\n\n"
        "🧠 تحليل خبير الأمن\n"
        f"{expert.get('summary', 'لا توجد مؤشرات خطر واضحة في الفحص المحلي.')}\n\n"
        "المؤشرات:\n"
        f"{expert_indicator_lines}\n\n"
        "ماذا تفعل:\n"
        f"{expert.get('recommendation', 'افتح الرابط فقط إذا كنت تثق بالمصدر.')}\n\n"
        "تنبيه: حتى إذا ظهرت النتيجة آمنة، فهذا لا يضمن الأمان بنسبة 100%.\n\n"
        "ساعد غيرك على فحص الروابط بمشاركة البوت: @SafeLiinkBot"
    )


def check_url(url: str) -> str:
    url = normalize_url(url)
    return format_local_scan_result(local_scan_url(url))
