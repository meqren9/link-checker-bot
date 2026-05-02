const telegram = window.Telegram?.WebApp;
const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const button = document.querySelector("#scan-button");
const statusBox = document.querySelector("#status");
const resultBox = document.querySelector("#result");

if (telegram) {
  telegram.ready();
  telegram.expand();
}

function setStatus(message, isError = false) {
  statusBox.textContent = message;
  statusBox.classList.toggle("error", isError);
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

function renderResult(response) {
  const scan = response.scan || {};
  const score = Number(scan.risk_score || 0);
  const signals = Array.isArray(scan.signals) ? scan.signals : [];

  resultBox.hidden = false;
  resultBox.replaceChildren();

  const risk = document.createElement("div");
  risk.className = `risk ${riskClass(score)}`.trim();
  risk.textContent = `درجة الخطورة: ${score}`;

  const url = document.createElement("div");
  url.className = "result-url";
  url.textContent = response.url || "";

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

  resultBox.append(risk, url, list);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = input.value.trim();
  if (!url) {
    setStatus("أدخل رابطًا للفحص.", true);
    return;
  }

  button.disabled = true;
  resultBox.hidden = true;
  setStatus("جاري الفحص...");

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
      throw new Error(data.detail || "تعذر فحص الرابط.");
    }

    setStatus("");
    renderResult(data);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
});
