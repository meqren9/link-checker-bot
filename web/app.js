const telegram = window.Telegram?.WebApp;
const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const button = document.querySelector("#scan-button");
const clearButton = document.querySelector("#clear-input");
const pasteButton = document.querySelector("#paste-input");
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

function resizeInput() {
  input.style.height = "auto";
  input.style.height = `${input.scrollHeight}px`;
}

function updateInputTools() {
  clearButton.hidden = input.value.length === 0;
  resizeInput();
}

async function enablePasteButton() {
  if (!navigator.clipboard?.readText) {
    return;
  }

  try {
    const permission = await navigator.permissions?.query({ name: "clipboard-read" });
    if (permission && permission.state === "denied") {
      return;
    }
  } catch {
    // Browsers that do not expose clipboard permissions can still allow readText on click.
  }

  pasteButton.hidden = false;
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
    return "خطر عالي";
  }

  if (score >= 35) {
    return "تنبيه";
  }

  return "آمن غالبًا";
}

function resultAdvice(score) {
  if (score >= 70) {
    return "لا تفتح الرابط ولا تدخل بياناتك.";
  }

  if (score >= 35) {
    return "افتحه فقط إذا كنت تثق بالمصدر.";
  }

  return "لا توجد مؤشرات واضحة. ابقَ حذرًا.";
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
  const communityReport = scan.community_report || {};
  const isShortenedUrl = Boolean(scan.is_shortened_url);
  const shortenerAdvice = scan.shortener_advice || "تحقق من الوجهة قبل الفتح";

  resultBox.hidden = false;
  resultBox.replaceChildren();

  const card = document.createElement("article");
  card.className = "result-card";

  const statusPanel = document.createElement("section");
  statusPanel.className = `result-status ${riskClass(score)}`.trim();

  const statusText = document.createElement("div");
  statusText.className = "result-status-text";

  const statusLabel = document.createElement("h2");
  statusLabel.className = "result-status-label";
  statusLabel.textContent = riskLabel(score);

  const statusAdvice = document.createElement("p");
  statusAdvice.className = "result-status-advice";
  statusAdvice.textContent = isShortenedUrl ? shortenerAdvice : resultAdvice(score);

  const scoreBadge = document.createElement("div");
  scoreBadge.className = "score-badge";
  scoreBadge.setAttribute("aria-label", `درجة الخطر ${score} من 100`);
  scoreBadge.textContent = score;

  statusText.append(statusLabel, statusAdvice);
  statusPanel.append(statusText, scoreBadge);

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
  expertRecommendation.textContent = resultAdvice(score);

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

  signalsCard.append(signalsTitle, list);
  card.append(statusPanel, url, signalsCard);

  if (isShortenedUrl) {
    const shortenerCard = document.createElement("section");
    shortenerCard.className = "expert-card";

    const shortenerTitle = document.createElement("h3");
    shortenerTitle.className = "signals-title";
    shortenerTitle.textContent = "رابط مختصر";

    const shortenerSummary = document.createElement("p");
    shortenerSummary.className = "expert-summary";
    shortenerSummary.textContent = `هذا رابط مختصر عبر ${scan.shortener_domain || "خدمة اختصار"}.`;

    const shortenerRecommendation = document.createElement("p");
    shortenerRecommendation.className = "expert-recommendation";
    shortenerRecommendation.textContent = `${shortenerAdvice}. لا أفتح الروابط غير الآمنة تلقائيًا.`;

    shortenerCard.append(shortenerTitle, shortenerSummary, shortenerRecommendation);
    card.append(shortenerCard);
  }

  if (messageCard) {
    card.append(messageCard);
  }

  if (Number(communityReport.count || 0) > 0) {
    const communityCard = document.createElement("section");
    communityCard.className = "expert-card";

    const communityTitle = document.createElement("h3");
    communityTitle.className = "signals-title";
    communityTitle.textContent = "بلاغات المجتمع";

    const communitySummary = document.createElement("p");
    communitySummary.className = "expert-summary";
    communitySummary.textContent = communityReport.community_suspicious
      ? `مصنف كمشبوه من المجتمع: ${communityReport.count}/${communityReport.threshold}`
      : `بلاغات موجودة: ${communityReport.count}/${communityReport.threshold}`;

    communityCard.append(communityTitle, communitySummary);
    card.append(communityCard);
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
  reportButton.textContent = "🚩 بلّغ عن رابط";
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
  updateInputTools();
});

input.addEventListener("input", updateInputTools);

clearButton.addEventListener("click", () => {
  input.value = "";
  updateInputTools();
  input.focus();
});

pasteButton.addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (!text) {
      return;
    }

    input.value = cleanPastedUrl(text);
    updateInputTools();
    input.focus();
  } catch {
    // Clipboard access depends on browser and Telegram container permissions.
  }
});

input.addEventListener("paste", () => {
  window.setTimeout(() => {
    input.value = cleanPastedUrl(input.value);
    updateInputTools();
  }, 0);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = cleanPastedUrl(input.value);
  input.value = url;
  updateInputTools();

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

updateInputTools();
enablePasteButton();

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
