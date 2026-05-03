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
MESSAGE_RISK_PATTERNS = {
    "urgency": {
        "score": 15,
        "label": "استعجال أو ضغط زمني",
        "words": (
            "urgent",
            "immediately",
            "now",
            "within 24 hours",
            "expires",
            "last chance",
            "limited time",
            "عاجل",
            "فورًا",
            "فورا",
            "الآن",
            "خلال 24 ساعة",
            "ينتهي",
            "آخر فرصة",
        ),
    },
    "fake_prize": {
        "score": 20,
        "label": "وعد بجائزة أو هدية",
        "words": (
            "winner",
            "won",
            "prize",
            "reward",
            "free gift",
            "airdrop",
            "congratulations",
            "ربحت",
            "فزت",
            "جائزة",
            "هدية",
            "مكافأة",
            "مبروك",
        ),
    },
    "account_warning": {
        "score": 20,
        "label": "تحذير عن الحساب",
        "words": (
            "suspended",
            "locked",
            "blocked",
            "disabled",
            "unusual activity",
            "account warning",
            "تم إيقاف",
            "موقوف",
            "محظور",
            "مقفل",
            "نشاط غير معتاد",
            "تحذير الحساب",
        ),
    },
    "login_update": {
        "score": 20,
        "label": "طلب تسجيل دخول أو تحديث بيانات",
        "words": (
            "login",
            "sign in",
            "verify",
            "update",
            "confirm",
            "password",
            "validate",
            "تسجيل الدخول",
            "سجل دخول",
            "تحقق",
            "حدّث",
            "حدث",
            "تأكيد",
            "كلمة المرور",
            "بياناتك",
        ),
    },
    "payment_security": {
        "score": 15,
        "label": "كلمات دفع أو أمن",
        "words": (
            "payment",
            "card",
            "bank",
            "wallet",
            "security",
            "2fa",
            "otp",
            "دفع",
            "بطاقة",
            "بنك",
            "محفظة",
            "أمان",
            "رمز التحقق",
            "كود التحقق",
        ),
    },
}
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
    "alahli",
    "riyadbank",
    "alinma",
)
SUSPICIOUS_DOMAIN_PHRASES = (
    "secure-login",
    "securelogin",
    "verify-account",
    "verifyaccount",
    "support-update",
    "supportupdate",
    "account-verify",
    "accountverify",
    "login-update",
    "loginupdate",
    "security-check",
    "securitycheck",
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
MULTI_PART_PUBLIC_SUFFIXES = {
    "com.sa",
    "net.sa",
    "org.sa",
    "co.uk",
    "com.au",
    "co.in",
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
    "alahli": ("alahli.com",),
    "riyadbank": ("riyadbank.com",),
    "alinma": ("alinma.com",),
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

    suffix = ".".join(parts[-2:])
    if suffix in MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def extract_urls(text: str) -> list[str]:
    return [clean_url(url) for url in re.findall(URL_REGEX, text or "") if clean_url(url)]


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


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0

    if len(left) < len(right):
        left, right = right, left

    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            insert_cost = current[right_index - 1] + 1
            delete_cost = previous[right_index] + 1
            replace_cost = previous[right_index - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current

    return previous[-1]


def official_domain_for_brand(brand: str) -> str:
    return BRAND_DOMAIN_HINTS.get(brand, (f"{brand}.com",))[0]


def find_brand_impersonation(hostname: str) -> list[dict]:
    lowered_hostname = hostname.lower()
    normalized_hostname = lowered_hostname.replace("-", "")
    root_domain = registered_domain(lowered_hostname)
    root_label = root_domain.split(".")[0] if root_domain else ""
    hostname_labels = [label for label in re.split(r"[.-]", lowered_hostname) if label]
    found = []

    for brand, official_domains in BRAND_DOMAIN_HINTS.items():
        brand_in_host = brand in normalized_hostname
        typo_distance = min(
            [levenshtein_distance(root_label, brand)]
            + [levenshtein_distance(label, brand) for label in hostname_labels]
        )
        typosquat = len(brand) >= 5 and 0 < typo_distance <= 2
        official_match = any(
            lowered_hostname == official
            or root_domain == official
            or lowered_hostname.endswith(f".{official}")
            for official in official_domains
        )

        if not official_match and (brand_in_host or typosquat):
            reason = "اسم العلامة ظاهر داخل نطاق غير رسمي"
            if typosquat and not brand_in_host:
                reason = "اسم النطاق قريب جدًا من اسم العلامة وقد يكون خطأً مقصودًا"

            found.append({
                "brand": brand,
                "official_domain": official_domain_for_brand(brand),
                "reason": reason,
                "domain": root_domain,
            })

    return found


def find_suspicious_domain_phrases(hostname: str) -> list[str]:
    compact_hostname = hostname.lower().replace(".", "-")
    return [phrase for phrase in SUSPICIOUS_DOMAIN_PHRASES if phrase in compact_hostname]


def has_misleading_subdomain(hostname: str) -> bool:
    parts = [part for part in hostname.lower().split(".") if part]

    if len(parts) < 3:
        return False

    subdomain = ".".join(parts[:-2])
    return any(brand in subdomain.replace("-", "") for brand in KNOWN_BRANDS)


def analyze_message_context(message_text: str = "") -> dict:
    lowered_message = (message_text or "").lower()
    indicators = []
    score = 0
    matched_categories = 0

    for pattern in MESSAGE_RISK_PATTERNS.values():
        matches = [word for word in pattern["words"] if word in lowered_message]
        if not matches:
            continue

        matched_categories += 1
        score += pattern["score"]
        indicators.append(
            f"{pattern['label']}: ظهرت عبارات مثل {', '.join(matches[:3])}."
        )

    if matched_categories >= 3:
        score += 10
        indicators.append("اجتماع عدة أساليب في رسالة واحدة يزيد احتمال التصيد.")

    if not indicators:
        summary = "نص الرسالة لا يحتوي مؤشرات تصيد واضحة ضمن القواعد المحلية."
    elif score >= 45:
        summary = "نص الرسالة يرفع مستوى الخطر لأنه يجمع ضغطًا أو وعودًا أو طلب بيانات حساسة."
    else:
        summary = "نص الرسالة يحتوي مؤشرات تستحق الحذر قبل التعامل مع الرابط."

    return {
        "risk_score": min(score, 60),
        "summary": summary,
        "indicators": indicators,
    }


def smart_advice_for_score(risk_score: int) -> str:
    if risk_score >= 60:
        return "لا تفتح الرابط، لا تدخل بياناتك، احذف الرسالة أو بلّغ عنها."

    if risk_score >= 30:
        return "تحقق من المصدر وافتح الموقع الرسمي يدويًا بدل الضغط على الرابط."

    return "لا توجد مؤشرات خطر واضحة، لكن لا تشارك بيانات حساسة إلا من المصدر الرسمي."


def build_expert_analysis(
    normalized_url: str,
    risk_score: int,
    signals: list[str],
    message_analysis: dict | None = None,
) -> dict:
    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname or ""
    lowered_url = normalized_url.lower()
    root_domain = registered_domain(hostname)
    tld = hostname_tld(hostname)
    risky_extension = has_risky_file_extension(parsed.path)
    phishing_keywords = [word for word in PHISHING_KEYWORDS if word in lowered_url]
    impersonated_brands = find_brand_impersonation(hostname)
    suspicious_domain_phrases = find_suspicious_domain_phrases(hostname)
    indicators = []

    if phishing_keywords:
        indicators.append(
            "كلمات مرتبطة غالبًا بالتصيد أو الاستعجال: "
            + "، ".join(phishing_keywords[:5])
        )

    if impersonated_brands:
        for item in impersonated_brands[:3]:
            indicators.append(
                "احتمال تقمص علامة تجارية: "
                f"النطاق {item['domain']} يشبه {item['brand']}، "
                f"والنطاق الرسمي المتوقع هو {item['official_domain']}. "
                f"{item['reason']}."
            )

    if suspicious_domain_phrases:
        indicators.append(
            "اسم النطاق يستخدم عبارات تصيد شائعة مثل: "
            + "، ".join(suspicious_domain_phrases[:3])
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

    if message_analysis:
        indicators.extend(message_analysis.get("indicators", [])[:4])

    if not indicators and signals:
        indicators.extend(signals[:3])

    if risk_score >= 60:
        summary = "الرسالة أو الرابط تبدو خطيرة بسبب اجتماع مؤشرات تصيد، تقمص، أو طلب بيانات حساسة."
    elif risk_score >= 30:
        summary = "الرسالة أو الرابط تبدو مشبوهة وتحتاج تحققًا إضافيًا قبل فتحها."
    else:
        summary = "لا توجد مؤشرات خطر واضحة في النص أو الرابط ضمن الفحص المحلي، لكن ذلك لا يعني الأمان بنسبة 100%."

    return {
        "summary": summary,
        "indicators": indicators or ["لم تظهر مؤشرات خطر واضحة ضمن القواعد المحلية."],
        "recommendation": smart_advice_for_score(risk_score),
        "next_steps_title": "🧭 ماذا تفعل الآن؟",
    }


def local_scan_url(url: str, message_text: str = "") -> dict:
    from community_reports import get_report_status

    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""
    root_domain = registered_domain(hostname)
    tld = hostname_tld(hostname)
    risk_score = 0
    signals = []
    message_analysis = analyze_message_context(message_text)
    community_report = get_report_status(normalized)

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

    if find_suspicious_domain_phrases(hostname):
        risk_score += 15
        signals.append("اسم النطاق يحتوي عبارات مثل تسجيل دخول آمن أو تحقق من الحساب.")

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

    if message_analysis["indicators"]:
        risk_score += message_analysis["risk_score"]
        signals.append("نص الرسالة يحتوي عبارات شائعة في رسائل التصيد.")

    if community_report["community_suspicious"]:
        risk_score += 35
        signals.append("تم الإبلاغ عنه من المجتمع عدة مرات كرابط مشبوه.")

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
        "community_report": community_report,
        "message_analysis": message_analysis,
        "expert_analysis": build_expert_analysis(
            normalized,
            risk_score,
            signals,
            message_analysis,
        ),
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
        f"{expert.get('next_steps_title', '🧭 ماذا تفعل الآن؟')}\n"
        f"{expert.get('recommendation', 'افتح الرابط فقط إذا كنت تثق بالمصدر.')}\n\n"
        "تنبيه: حتى إذا ظهرت النتيجة آمنة، فهذا لا يضمن الأمان بنسبة 100%.\n\n"
        "ساعد غيرك على فحص الروابط بمشاركة البوت: @SafeLiinkBot"
    )


def check_url(url: str, message_text: str = "") -> str:
    url = normalize_url(url)
    return format_local_scan_result(local_scan_url(url, message_text=message_text))
