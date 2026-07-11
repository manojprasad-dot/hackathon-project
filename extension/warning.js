// PhishGuard v4.0 -- warning.js
// Reads URL params and populates the redesigned warning page

const params     = new URLSearchParams(window.location.search);
const url        = params.get("url")        || "Unknown";
const confidence = parseFloat(params.get("confidence") || "0");
const risk       = (params.get("risk")      || "high").toLowerCase();
const reasons    = params.get("reasons")    || "";

// -- Blocked URL
document.getElementById("blocked-url").textContent =
  url.length > 60 ? url.slice(0, 57) + "…" : url;

// -- Risk level badge
const RISK_LABELS = { high: "⚠ HIGH RISK", medium: "⚡ MEDIUM RISK", low: "• LOW RISK" };
const riskEl = document.getElementById("risk-level");
if (riskEl) riskEl.textContent = RISK_LABELS[risk] || "HIGH RISK";

// -- Confidence value + animated bar (delay so CSS transition fires)
const pct = Math.round(confidence * 100);
document.getElementById("confidence").textContent = pct + "%";
setTimeout(() => {
  document.getElementById("conf-bar").style.width = pct + "%";
}, 80);

// -- Reasons list (animated stagger)
if (reasons) {
  const list = reasons.split("|").filter(r => r.trim());
  if (list.length > 0) {
    document.getElementById("reasons-section").style.display = "block";
    document.getElementById("reasons-list").innerHTML = list.map((r, i) => `
      <div class="reason-item" style="animation-delay:${i * 70}ms">
        <div class="reason-dot"></div>
        <div class="reason-text">${escHtml(r)}</div>
      </div>
    `).join("");
  }
}

// -- Navigation buttons
document.getElementById("go-back").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "https://www.google.com";
  }
});

document.getElementById("proceed").addEventListener("click", () => {
  // Report user proceeded to feedback
  try {
    chrome.runtime.sendMessage({
      type: "USER_FEEDBACK",
      feedback: { url, verdict: "user_proceeded", timestamp: new Date().toISOString() },
    });
  } catch { /* extension context may not be available */ }
  window.location.href = url;
});

function escHtml(s) {
  return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
