// PhishGuard v4.0 -- popup.js
// Drives the redesigned popup with arc confidence meter,
// risk card, collapsible explanation panel, and stats.

document.addEventListener("DOMContentLoaded", async () => {
  await loadTab();
  await loadStats();
  await loadAlerts();
  await loadFeedback();

  // -- Tab switching -------------------------------------------------------
  document.querySelectorAll(".tab").forEach(t => {
    t.onclick = () => {
      document.querySelectorAll(".tab,.panel").forEach(el => el.classList.remove("active"));
      t.classList.add("active");
      document.getElementById(`panel-${t.dataset.panel}`).classList.add("active");
    };
  });

  // -- Explanation panel toggle --------------------------------------------
  const explainWrap   = document.getElementById("explain-wrap");
  const toggleBtn     = document.getElementById("toggle-btn");
  let explanationOpen = false;

  document.getElementById("explain-toggle").addEventListener("click", () => {
    explanationOpen = !explanationOpen;
    explainWrap.classList.toggle("open", explanationOpen);
    toggleBtn.textContent = explanationOpen ? "Hide ▴" : "Show ▾";
  });

  // -- Clear history -------------------------------------------------------
  document.getElementById("btn-clear").onclick = async () => {
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" });
    await loadStats(); await loadAlerts(); await loadFeedback();
    // Reset risk card to neutral
    setRiskCard({ scanning: true, url: null });
  };

  // -- Report Website button -----------------------------------------------
  document.getElementById("btn-report").onclick = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      document.getElementById("report-url").textContent = new URL(tab.url).hostname;
      document.getElementById("report-modal").style.display = "flex";
    }
  };
  document.getElementById("report-cancel").onclick = () => {
    document.getElementById("report-modal").style.display = "none";
  };
  document.getElementById("report-submit").onclick = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const reason = document.getElementById("report-reason").value;
    const notes  = document.getElementById("report-notes").value;
    chrome.runtime.sendMessage({
      type: "REPORT_WEBSITE",
      url: tab.url,
      reason: `${reason}${notes ? ": " + notes : ""}`,
    });
    document.getElementById("report-modal").style.display = "none";
    document.getElementById("report-notes").value = "";
    const btn = document.getElementById("btn-report");
    const orig = btn.innerHTML;
    btn.innerHTML = "✓ Reported!";
    btn.style.background = "rgba(52,199,89,.15)";
    btn.style.color = "#34C759";
    setTimeout(() => { btn.innerHTML = orig; btn.style.background = ""; btn.style.color = ""; }, 2000);
  };

  // -- Quick Scan button ---------------------------------------------------
  document.getElementById("btn-quickscan").onclick = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || !tab.url.startsWith("http")) return;
    const btn = document.getElementById("btn-quickscan");
    btn.innerHTML = "⟳ Scanning…";
    setRiskCard({ scanning: true, url: tab.url });
    chrome.runtime.sendMessage({ type: "QUICK_SCAN", tabId: tab.id, url: tab.url });
    setTimeout(() => window.close(), 800);
  };

  // -- Email Scanner button ------------------------------------------------
  document.getElementById("btn-email-scanner").onclick = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("email_scanner.html") });
  };
});

// ══ RISK CARD RENDERER ════════════════════════════════════════════════════

/**
 * Update the risk card (arc meter, verdict text, risk badge, explanation panel).
 *
 * @param {Object} opts
 * @param {boolean} [opts.scanning]     - Show scanning state
 * @param {string}  [opts.url]          - URL string
 * @param {boolean} [opts.isPhishing]   - Is phishing?
 * @param {number}  [opts.confidence]   - 0-1 confidence value
 * @param {string}  [opts.risk_level]   - "high"|"medium"|"low"|"safe"
 * @param {string[]}[opts.reasons]      - Explanation strings
 */
function setRiskCard(opts = {}) {
  const card      = document.getElementById("risk-card");
  const arcFill   = document.getElementById("arc-fill");
  const arcPct    = document.getElementById("arc-pct");
  const arcWrap   = document.getElementById("arc-wrap");
  const verdictEl = document.getElementById("risk-verdict");
  const icoEl     = document.getElementById("verdict-ico");
  const txtEl     = document.getElementById("verdict-txt");
  const badgeEl   = document.getElementById("risk-badge");
  const urlEl     = document.getElementById("cur-url");
  const exSection = document.getElementById("explain-section");
  const reasonEl  = document.getElementById("reason-list");

  // URL
  if (opts.url) {
    try {
      const u = new URL(opts.url);
      urlEl.textContent = u.hostname + (u.pathname.length > 30 ? u.pathname.slice(0, 30) + "…" : u.pathname);
    } catch {
      urlEl.textContent = opts.url;
    }
  }

  if (opts.scanning) {
    // Scanning state
    card.className = "risk-card scanning";
    arcWrap.classList.add("arc-scanning");
    arcFill.style.stroke = "#0A84FF";
    arcFill.style.strokeDashoffset = "122";  // ~25% filled, pulsing
    arcPct.textContent = "…";
    arcPct.style.color = "#0A84FF";
    icoEl.textContent = "⟳";
    txtEl.textContent = "Scanning page…";
    badgeEl.className = "risk-badge scanning";
    badgeEl.textContent = "Analyzing";
    exSection.style.display = "none";
    return;
  }

  arcWrap.classList.remove("arc-scanning");

  const conf   = Math.round((opts.confidence || 0) * 100);
  const risk   = opts.risk_level || (opts.isPhishing ? "high" : "safe");

  // Arc progress: dashoffset = 163 × (1 - confidence)
  const offset = Math.round(163 * (1 - (opts.confidence || 0)));
  arcFill.style.strokeDashoffset = offset;

  // Colors by risk level
  const COLORS = {
    high:   { arc: "#FF3B30", glow: "rgba(255,59,48,0.5)",  pct: "#FF3B30" },
    medium: { arc: "#FF9F0A", glow: "rgba(255,159,10,0.5)", pct: "#FF9F0A" },
    low:    { arc: "#0A84FF", glow: "rgba(10,132,255,0.5)", pct: "#0A84FF" },
    safe:   { arc: "#34C759", glow: "rgba(52,199,89,0.5)",  pct: "#34C759" },
  };
  const col = COLORS[risk] || COLORS.safe;

  arcFill.style.stroke = col.arc;
  document.querySelector(".arc-svg").style.filter = `drop-shadow(0 0 6px ${col.glow})`;
  arcPct.textContent = opts.isPhishing ? conf + "%" : "OK";
  arcPct.style.color = col.pct;
  arcPct.style.fontSize = opts.isPhishing ? "18px" : "14px";

  // Card background
  card.className = `risk-card ${opts.isPhishing ? "phishing" : "safe"}`;

  // Verdict
  if (opts.isPhishing) {
    icoEl.textContent = "⚠";
    icoEl.style.color = "#FF3B30";
    txtEl.textContent = "Phishing Detected";
    txtEl.style.color = "#FF3B30";
  } else {
    icoEl.textContent = "✓";
    icoEl.style.color = "#34C759";
    txtEl.textContent = "Page Looks Safe";
    txtEl.style.color = "#34C759";
  }

  // Risk badge
  const BADGE_LABELS = { high: "⚠ High Risk", medium: "⚡ Medium Risk", low: "• Low Risk", safe: "✓ Safe" };
  badgeEl.className = `risk-badge ${risk}`;
  badgeEl.textContent = BADGE_LABELS[risk] || "Safe";

  // Explanation panel
  const reasons = opts.reasons || [];
  if (opts.isPhishing && reasons.length > 0) {
    exSection.style.display = "block";
    reasonEl.innerHTML = reasons.map((r, i) => `
      <div class="reason-item" style="animation-delay:${i * 60}ms">
        <div class="reason-dot"></div>
        <div class="reason-txt">${escHtml(r)}</div>
      </div>
    `).join("");
  } else if (!opts.isPhishing) {
    exSection.style.display = "block";
    reasonEl.innerHTML = `<div class="no-reasons">✓ No suspicious signals detected for this page.</div>`;
  } else {
    exSection.style.display = "none";
  }
}

// ══ DATA LOADERS ══════════════════════════════════════════════════════════

async function loadTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  if (!tab.url || !tab.url.startsWith("http")) {
    setRiskCard({ url: tab.url, isPhishing: false, confidence: 0, risk_level: "safe", reasons: [] });
    document.getElementById("cur-url").textContent = "Internal page — not scanned";
    return;
  }

  // Check if this URL has been scanned
  const { alerts = [] } = await chrome.storage.local.get(["alerts"]);
  const hit = alerts.find(a => a.url === tab.url);

  if (hit) {
    const isPhish = hit.is_phishing || hit.result === "phishing";
    setRiskCard({
      url:        tab.url,
      isPhishing: isPhish,
      confidence: hit.confidence || 0,
      risk_level: hit.risk_level || (isPhish ? "high" : "safe"),
      reasons:    hit.reasons    || [],
    });
  } else {
    setRiskCard({ scanning: true, url: tab.url });
  }
}

async function loadStats() {
  const { stats = {} } = await chrome.storage.local.get(["stats"]);
  animateCount("s-total", stats.totalScanned    || 0);
  animateCount("s-phish", stats.phishingDetected || 0);
  animateCount("s-safe",  stats.safeDetected     || 0);
}

async function loadAlerts() {
  const { alerts = [] } = await chrome.storage.local.get(["alerts"]);
  const el = document.getElementById("al-list");
  if (!alerts.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ico">🛡️</div>No activity yet.<br>Browse to start scanning.</div>`;
    return;
  }
  el.innerHTML = alerts.map(a => {
    const host    = safeHost(a.url);
    const isPhish = a.is_phishing || a.result === "phishing";
    const cls     = isPhish ? "p" : "s";
    const lbl     = isPhish ? "Phishing" : "Safe";
    const conf    = a.confidence ? Math.round(a.confidence * 100) + "%" : "";
    return `<div class="al">
      <div class="aldot ${cls}"></div>
      <div class="al-info">
        <div class="al-host" title="${escHtml(a.url)}">${escHtml(host)}</div>
        <div class="al-time">${ago(a.timestamp)}${conf ? `<span class="al-conf">${conf}</span>` : ""}</div>
      </div>
      <div class="albadge ${cls}">${lbl}</div>
    </div>`;
  }).join("");
}

async function loadFeedback() {
  const { feedbackLog = [] } = await chrome.storage.local.get(["feedbackLog"]);
  const el = document.getElementById("fb-list");
  if (!feedbackLog.length) {
    el.innerHTML = `<div class="empty"><div class="empty-ico">💬</div>No feedback submitted yet.</div>`;
    return;
  }
  el.innerHTML = feedbackLog.map(f => {
    const labels = { safe: "Safe", phishing: "Phishing", user_proceeded: "Proceeded" };
    return `<div class="fb">
      <div class="fb-info" style="flex:1;overflow:hidden">
        <div style="font-size:11px;color:#999;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escHtml(safeHost(f.url))}</div>
        <div style="font-size:10px;color:#555">${ago(f.timestamp)}</div>
      </div>
      <div class="fb-verdict ${f.verdict}">${labels[f.verdict] || f.verdict}</div>
    </div>`;
  }).join("");
}

// ══ UTILITIES ═════════════════════════════════════════════════════════════

function animateCount(id, target) {
  const el = document.getElementById(id);
  const start = parseInt(el.textContent) || 0;
  if (start === target) return;
  const duration = 400;
  const startTime = performance.now();
  const tick = (now) => {
    const progress = Math.min((now - startTime) / duration, 1);
    el.textContent = Math.round(start + (target - start) * easeOut(progress));
    if (progress < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function easeOut(t) { return 1 - Math.pow(1 - t, 3); }
function safeHost(u) { try { return new URL(u).hostname; } catch { return u; } }
function ago(ts) {
  const s = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}
function escHtml(s) {
  return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
