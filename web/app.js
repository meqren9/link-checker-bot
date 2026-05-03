const telegram = window.Telegram?.WebApp;
const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const button = document.querySelector("#scan-button");
const statusBox = document.querySelector("#status");
const resultBox = document.querySelector("#result");
const ERROR_MESSAGES = {
  "url is required": "أدخل رابطًا للفحص.",
  "initData is required": "تعذر التحقق من جلسة تيليجرام. افتح التطبيق من داخل البوت وحاول مرة أخرى.",
  "url is too long": "الرابط طويل جدًا. جرّب رابطًا أقصر.",
  "url must be a valid http(s) URL": "أدخل رابطًا صحيحًا يبدأ بـ http أو https.",
  "vt api key missing": "الفحص المتقدم غير مفعّل حاليًا.",
  "vt api key invalid": "تعذر تشغيل الفحص المتقدم حاليًا.",
  "vt rate limit reached": "⚠️ فحص VirusTotal غير متاح حالياً",
  "vt request failed": "تعذر الاتصال بخدمة الفحص المتقدم. حاول لاحقًا.",
};
let lastScannedUrl = "";
let advancedButton;
let advancedBox;
let reportButton;

if (telegram) {
  telegram.ready();
  telegram.expand();
}

function cleanPastedUrl(value) {
  return value
    .trim()
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/^<(.+)>$/s, "$1")
    .replace(/^["'“”‘’]+|["'“”‘’]+$/g, "");
}

function translateError(message) {
  return ERROR_MESSAGES[message] || message || "حدث خطأ غير متوقع. حاول مرة أخرى.";
}

function setStatus(message, { isError = false, isLoading = false } = {}) {
  statusBox.replaceChildren();
  statusBox.classList.toggle("error", isError);

  if (!message) {
    return;
  }

  const content = document.createElement("div");
  content.className = "status-content";

  if (isLoading) {
    const spinner = document.createElement("span");
    spinner.className = "spinner";
    spinner.setAttribute("aria-hidden", "true");
    content.append(spinner);
  }

  const text = document.createElement("span");
  text.textContent = message;
  content.append(text);
  statusBox.append(content);
}

function riskClass(score) {
  if (score >= 70) {
    return "high";
  }

  if (score >= 35) {
    return "medium";
  }

  return "";
}

function riskLabel(score) {
  if (score >= 70) {
    return "خطر مرتفع";
  }

  if (score >= 35) {
    return "خطر متوسط";
  }

  return "خطر منخفض";
}

function vtLevelClass(level) {
  if (level === "high") {
    return "high";
  }

  if (level === "medium") {
    return "medium";
  }

  return "";
}

function renderResult(response) {
  const scan = response.scan || {};
  const score = Number(scan.risk_score || 0);
  const signals = Array.isArray(scan.signals) ? scan.signals : [];
  const expert = scan.expert_analysis || {};
  const expertIndicators = Array.isArray(expert.indicators) ? expert.indicators : [];
  const messageAnalysis = scan.message_analysis || {};

  resultBox.hidden = false;
  resultBox.replaceChildren();

  const card = document.createElement("article");
  card.className = "result-card";

  const top = document.createElement("div");
  top.className = "result-top";

  const title = document.createElement("h2");
  title.className = "result-title";
  title.textContent = "نتيجة الفحص";

  const risk = document.createElement("div");
  risk.className = `risk ${riskClass(score)}`.trim();
  risk.textContent = `${riskLabel(score)} · ${score}`;

  const url = document.createElement("div");
  url.className = "result-url";
  url.textContent = response.url || "";

  const signalsCard = document.createElement("div");
  signalsCard.className = "signals-card";

  const signalsTitle = document.createElement("h3");
  signalsTitle.className = "signals-title";
  signalsTitle.textContent = "المؤشرات";

  const list = document.createElement("ul");
  list.className = "signals";

  if (signals.length === 0) {
    const item = document.createElement("li");
    item.textContent = "لم تظهر مؤشرات خطر واضحة في الفحص المحلي.";
    list.append(item);
  } else {
    for (const signal of signals) {
      const item = document.createElement("li");
      item.textContent = signal;
      list.append(item);
    }
  }

  const expertCard = document.createElement("section");
  expertCard.className = "expert-card";

  const expertTitle = document.createElement("h3");
  expertTitle.className = "signals-title";
  expertTitle.textContent = "🧠 تحليل خبير الأمن";

  const expertSummary = document.createElement("p");
  expertSummary.className = "expert-summary";
  expertSummary.textContent =
    expert.summary || "لا توجد مؤشرات خطر واضحة في الفحص المحلي، لكن هذا لا يعني أن الرابط آمن بنسبة 100%.";

  const expertList = document.createElement("ul");
  expertList.className = "signals";

  const indicators = expertIndicators.length
    ? expertIndicators
    : ["لم تظهر مؤشرات خطر واضحة ضمن القواعد المحلية."];

  for (const indicator of indicators) {
    const item = document.createElement("li");
    item.textContent = indicator;
    expertList.append(item);
  }

  const expertRecommendation = document.createElement("p");
  expertRecommendation.className = "expert-recommendation";
  expertRecommendation.textContent =
    expert.recommendation || "افتح الرابط فقط إذا كنت تثق بالمصدر، ولا تدخل بيانات حساسة إلا بعد التأكد من النطاق.";

  const adviceTitle = document.createElement("h3");
  adviceTitle.className = "signals-title";
  adviceTitle.textContent = expert.next_steps_title || "🧭 ماذا تفعل الآن؟";

  expertCard.append(expertTitle, expertSummary, expertList, adviceTitle, expertRecommendation);

  let messageCard;
  if (messageAnalysis.summary) {
    messageCard = document.createElement("section");
    messageCard.className = "expert-card";

    const messageTitle = document.createElement("h3");
    messageTitle.className = "signals-title";
    messageTitle.textContent = "تحليل نص الرسالة";

    const messageSummary = document.createElement("p");
    messageSummary.className = "expert-summary";
    messageSummary.textContent = messageAnalysis.summary;
    messageCard.append(messageTitle, messageSummary);
  }

  top.append(title, risk);
  signalsCard.append(signalsTitle, list);
  card.append(top, url, signalsCard);
  if (messageCard) {
    card.append(messageCard);
  }
  card.append(expertCard);

  const actions = document.createElement("div");
  actions.className = "result-actions";

  advancedButton = document.createElement("button");
  advancedButton.className = "advanced-button";
  advancedButton.type = "button";
  advancedButton.textContent = "🔬 فحص متقدم";
  advancedButton.addEventListener("click", runAdvancedScan);

  reportButton = document.createElement("button");
  reportButton.className = "report-button";
  reportButton.type = "button";
  reportButton.textContent = "🚩 بلّغ عن رابط مشبوه";
  reportButton.addEventListener("click", reportSuspiciousLink);

  advancedBox = document.createElement("section");
  advancedBox.className = "advanced-result";
  advancedBox.hidden = true;
  advancedBox.setAttribute("aria-live", "polite");

  actions.append(reportButton, advancedButton);
  resultBox.append(card, actions, advancedBox);
}

function renderAdvancedResult(summary) {
  if (!advancedBox) {
    return;
  }

  const stats = summary.stats || {};
  const cachedText = summary.cached ? "نتيجة محفوظة خلال آخر 24 ساعة" : "نتيجة جديدة";

  advancedBox.hidden = false;
  advancedBox.replaceChildren();

  const card = document.createElement("article");
  card.className = "vt-card";

  const top = document.createElement("div");
  top.className = "result-top";

  const title = document.createElement("h2");
  title.className = "result-title";
  title.textContent = "🔬 نتيجة VirusTotal";

  const badge = document.createElement("div");
  badge.className = `risk ${vtLevelClass(summary.level)}`.trim();
  badge.textContent = cachedText;

  const message = document.createElement("p");
  message.className = "vt-message";
  message.textContent = summary.message || "لا توجد تفاصيل إضافية.";

  top.append(title, badge);
  card.append(top, message);

  const statsList = document.createElement("dl");
  statsList.className = "vt-stats";

  const items = [
    ["خطر", stats.malicious || 0],
    ["مشبوه", stats.suspicious || 0],
    ["آمن", stats.harmless || 0],
  ];

  for (const [label, value] of items) {
    const item = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    item.append(term, description);
    statsList.append(item);
  }

  card.append(statsList);
  advancedBox.append(card);
}

input.addEventListener("blur", () => {
  input.value = cleanPastedUrl(input.value);
});

input.addEventListener("paste", () => {
  window.setTimeout(() => {
    input.value = cleanPastedUrl(input.value);
  }, 0);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = cleanPastedUrl(input.value);
  input.value = url;

  if (!url) {
    setStatus("أدخل رابطًا للفحص.", { isError: true });
    return;
  }

  button.disabled = true;
  resultBox.hidden = true;
  lastScannedUrl = url;
  setStatus("جاري الفحص...", { isLoading: true });

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
        initData: telegram?.initData || "",
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(translateError(data.detail || "تعذر فحص الرابط."));
    }

    setStatus("");
    renderResult(data);
  } catch (error) {
    setStatus(translateError(error.message), { isError: true });
  } finally {
    button.disabled = false;
  }
});

async function runAdvancedScan() {
  const url = cleanPastedUrl(lastScannedUrl || input.value);
  if (!url) {
    setStatus("أدخل رابطًا للفحص.", { isError: true });
    return;
  }

  advancedButton.disabled = true;
  advancedBox.hidden = false;
  advancedBox.replaceChildren();
  setStatus("جاري الفحص المتقدم...", { isLoading: true });

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
        initData: telegram?.initData || "",
        advanced: true,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(translateError(data.detail || "تعذر الفحص المتقدم."));
    }

    setStatus("");
    renderAdvancedResult(data.vt || {});
  } catch (error) {
    setStatus(translateError(error.message), { isError: true });
  } finally {
    advancedButton.disabled = false;
  }
}

async function reportSuspiciousLink() {
  const url = cleanPastedUrl(lastScannedUrl || input.value);
  if (!url) {
    setStatus("أدخل رابطًا للفحص.", { isError: true });
    return;
  }

  reportButton.disabled = true;
  setStatus("جاري تسجيل البلاغ...", { isLoading: true });

  try {
    const response = await fetch("/api/report", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
        initData: telegram?.initData || "",
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(translateError(data.detail || "تعذر تسجيل البلاغ."));
    }

    const report = data.report || {};
    if (report.duplicate) {
      setStatus("تم تسجيل بلاغك سابقًا لهذا الرابط أو النطاق.");
    } else if (report.community_suspicious) {
      setStatus("تم تسجيل البلاغ. وصل الرابط أو النطاق إلى حد البلاغات وسيظهر كمشبوه من المجتمع.");
    } else {
      setStatus(`تم تسجيل البلاغ. عدد البلاغات الحالي: ${report.count}/${report.threshold}.`);
    }
  } catch (error) {
    setStatus(translateError(error.message), { isError: true });
  } finally {
    reportButton.disabled = false;
  }
}
