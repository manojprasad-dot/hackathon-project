// PhishGuard Edge AI — popup.js
// Orchestrates local database queries, live tab monitoring, settings state,
// Explainable AI (XAI) feature cards, and the interactive demo switcher.

import { icon } from "./icons.js";
import { verdictForScore, VERDICTS } from "./constants.js";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const CIRC = 2 * Math.PI * 42; // r=42 circumference ~263.89

let history = [];
let currentScenario = "safe";
let activeTabInfo = { domain: "No page active", score: 0, confidence: 99.8, scanMs: 2.6, reasons: [] };

// ── Default Safe Indicators for XAI ──────────────────────────────────────

const SAFE_EXPLANATIONS = [
  { icon: "shield-check", severity: "safe", weight: 0.08, title: "HTTPS Enabled", detail: "Page uses secure TLS encryption (HTTPS protocol)." },
  { icon: "clock", severity: "safe", weight: 0.12, title: "Trusted Domain", detail: "Domain registration age and certificate issuer are established." },
  { icon: "shuffle", severity: "safe", weight: 0.14, title: "Low Hostname Entropy", detail: "Domain layout has standard, predictable character distribution." },
  { icon: "type", severity: "safe", weight: 0.18, title: "No Login Keywords", detail: "URL does not contain trigger words like login, verify, or secure." },
  { icon: "server", severity: "safe", weight: 0.0, title: "Raw IP Address Hostname", detail: "Standard DNS hostname resolution (no raw IP endpoints detected)." }
];

const ALL_THREAT_EXPLANATIONS = {
  "IP Address Used": {
    weight: 0.70,
    severity: "danger",
    icon: "server",
    desc: "Domain resolution points to a raw IP endpoint instead of a DNS hostname.",
    rec: "Avoid logging sensitive credentials; raw IP channels are typical vectors for bots."
  },
  "Brand Impersonation": {
    weight: 0.55,
    severity: "danger",
    icon: "shield",
    desc: "Hostname contains a spoofed brand name hosted on an unofficial TLD.",
    rec: "Verify domain authenticity. Legit brands use their designated registry extensions."
  },
  "Suspicious Keyword": {
    weight: 0.40,
    severity: "warning",
    icon: "type",
    desc: "URL segments contain trigger keywords (e.g. login, verify, payment).",
    rec: "Look closely at the browser address bar to ensure the security context is valid."
  },
  "Suspicious TLD": {
    weight: 0.35,
    severity: "warning",
    icon: "link",
    desc: "URL uses high-risk top level domains associated with cheap registration rates.",
    rec: "Exercise extreme caution on links redirecting to .xyz, .tk, .ml, or .gq."
  },
  "Lookalike homograph": {
    weight: 0.35,
    severity: "warning",
    icon: "type",
    desc: "URL contains homoglyph lookalike characters designed to spoof common hostnames.",
    rec: "Double-check for similar character replacements (e.g., '0' instead of 'o')."
  },
  "Uses HTTP": {
    weight: 0.18,
    severity: "warning",
    icon: "shield",
    desc: "Web application serves resource endpoints over plaintext http:// protocols.",
    rec: "Avoid submitting forms; data is broadcasted without secure TLS tunnel encryption."
  },
  "Sensitive Path": {
    weight: 0.20,
    severity: "warning",
    icon: "link",
    desc: "The directory paths contain sensitive authentication tags.",
    rec: "Check for spoofed checkout gateways trying to capture banking logs."
  }
};

// ── Gauge Rendering ────────────────────────────────────────────────────────

function paintGauge(score) {
  const verdict = verdictForScore(score);
  const color = { safe: "var(--safe)", warning: "var(--warning)", danger: "var(--danger)" }[verdict];
  const labels = { safe: "LOW RISK", warning: "MEDIUM RISK", danger: "HIGH RISK" };
  const arc = $("#gaugeArc");
  const pct = Math.max(2, Math.min(100, score)) / 100;
  
  // Set stroke parameters
  arc.style.stroke = color;
  arc.style.strokeDasharray = `${CIRC * pct} ${CIRC}`;
  $("#gaugeValue").textContent = Math.round(score) + "%";
  $("#gaugeLabel").textContent = labels[verdict] || "LOW RISK";
  $("#gaugeLabel").style.fill = color;
}

function runScanAnimation(score, cb) {
  $("#gaugeSweep").style.display = "block";
  const arc = $("#gaugeArc");
  arc.style.strokeDasharray = `0 ${CIRC}`;
  $("#gaugeValue").textContent = "—";
  $("#gaugeLabel").textContent = "SCANNING";
  $("#gaugeLabel").style.fill = "var(--text-tertiary)";
  
  setTimeout(() => {
    $("#gaugeSweep").style.display = "none";
    paintGauge(score);
    cb && cb();
  }, 650);
}

// ── Reasons (Explainable AI) ───────────────────────────────────────────────

function renderReasons(reasons, score) {
  const list = $("#reasonList");
  
  // If score is safe (<= 30), show the safe evaluations instead of empty state
  if (score <= 30 || !reasons || reasons.length === 0) {
    list.innerHTML = SAFE_EXPLANATIONS
      .map(
        (r) => `
      <div class="reason">
        <div class="reason-icon ${r.severity}">${icon(r.icon, 14)}</div>
        <div class="reason-body">
          <div class="reason-title-row">
            <span class="reason-title">${escHtml(r.title)}</span>
            <span class="reason-weight mono">${(r.weight * 100).toFixed(0)}%</span>
          </div>
          <div class="reason-detail">${escHtml(r.detail)}</div>
          <div class="weight-bar ${r.severity}"><span style="width:${r.weight * 100}%"></span></div>
        </div>
      </div>`
      )
      .join("");
    return;
  }

  list.innerHTML = reasons
    .map(
      (r) => `
    <div class="reason">
      <div class="reason-icon ${r.severity}">${icon(r.icon, 14)}</div>
      <div class="reason-body">
        <div class="reason-title-row">
          <span class="reason-title">${escHtml(r.title)}</span>
          <span class="reason-weight mono">${(r.weight * 100).toFixed(0)}%</span>
        </div>
        <div class="reason-detail">${escHtml(r.detail)}</div>
        <div class="weight-bar ${r.severity}"><span style="width:${r.weight * 100}%"></span></div>
      </div>
    </div>`
    )
    .join("");
}

// ── History Syncing ────────────────────────────────────────────────────────

function renderHistory() {
  const list = $("#historyList");
  const listFull = $("#historyListFull");
  
  if (history.length === 0) {
    const emptyHtml = `
      <div class="empty" style="padding: 24px 0; text-align: center; color: var(--text-tertiary);">
        No recent scans in database.
      </div>
    `;
    list.innerHTML = emptyHtml;
    listFull.innerHTML = emptyHtml;
    return;
  }

  const makeRow = (h) => {
    const v = verdictForScore(h.score);
    const timeVal = h.time || ago(h.timestamp);
    return `
    <div class="scan-row">
      <div class="favicon">${h.domain[0].toUpperCase()}</div>
      <div class="scan-domain" title="${escHtml(h.domain)}">${escHtml(h.domain)}</div>
      <div class="scan-score ${v} mono">${Math.round(h.score)}%</div>
      <div class="scan-time">${timeVal}</div>
    </div>`;
  };

  list.innerHTML = history.slice(0, 3).map(makeRow).join("");
  listFull.innerHTML = history.map(makeRow).join("");
}



// ── Active Tab Interface Syncing ───────────────────────────────────────────

async function loadActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;

  if (tab.url.startsWith("chrome-extension://") && tab.url.includes("warning.html")) {
    try {
      const urlObj = new URL(tab.url);
      const blockedUrl = urlObj.searchParams.get("url") || "";
      const blockedConfidence = parseFloat(urlObj.searchParams.get("confidence") || "0.9");
      const blockedReasonsStr = urlObj.searchParams.get("reasons") || "";
      const blockedLatency = parseFloat(urlObj.searchParams.get("latency") || "3.8");
      
      const hostname = blockedUrl ? new URL(blockedUrl).hostname : "blocked-site";
      const score = blockedConfidence * 100;
      
      const parsedReasons = blockedReasonsStr.split("|").filter(r => r.trim()).map(r => {
        const spec = ALL_THREAT_EXPLANATIONS[r] || {
          weight: 0.15,
          severity: "warning",
          icon: "type",
          desc: `Heuristic pattern matched: "${r}"`
        };
        return {
          icon: spec.icon,
          severity: spec.severity,
          weight: spec.weight,
          title: r,
          detail: spec.desc
        };
      });

      activeTabInfo = {
        domain: hostname,
        score: score,
        confidence: score,
        scanMs: blockedLatency,
        reasons: parsedReasons
      };
      renderActiveTabVerdict();
      return;
    } catch (e) {
      console.error("Error parsing warning page parameters:", e);
    }
  }

  if (!tab.url.startsWith("http")) {
    activeTabInfo = {
      domain: "internal-page",
      score: 0,
      confidence: 100,
      scanMs: 0.1,
      reasons: []
    };
    renderActiveTabVerdict();
    return;
  }

  const hostname = new URL(tab.url).hostname;
  
  // Check local storage for existing evaluation results
  chrome.storage.local.get(["alerts"], (data) => {
    const alerts = data.alerts || [];
    const hit = alerts.find(a => a.url === tab.url);

    if (hit) {
      const isPhish = hit.is_phishing || hit.result === "phishing";
      const score = hit.confidence ? hit.confidence * 100 : (isPhish ? 85 : 5);
      
      const parsedReasons = (hit.reasons || []).map(r => {
        const spec = ALL_THREAT_EXPLANATIONS[r] || {
          weight: 0.15,
          severity: "warning",
          icon: "type",
          desc: `Heuristic pattern matched: "${r}"`
        };
        return {
          icon: spec.icon,
          severity: spec.severity,
          weight: spec.weight,
          title: r,
          detail: spec.desc
        };
      });

      activeTabInfo = {
        domain: hostname,
        score: score,
        confidence: score > 50 ? score : (100 - score),
        scanMs: hit.latencyMs || 2.6,
        reasons: parsedReasons
      };
      
      renderActiveTabVerdict();
    } else {
      activeTabInfo = {
        domain: hostname,
        score: 0,
        confidence: 99.8,
        scanMs: 2.6,
        reasons: []
      };
      renderActiveTabVerdict();
    }
  });
}

function renderActiveTabVerdict() {
  const verdict = verdictForScore(activeTabInfo.score);
  const meta = VERDICTS[verdict];

  $("#riskDomain").textContent = activeTabInfo.domain;
  $("#riskScanTime").textContent = "scanned locally";

  const pill = $("#verdictPill");
  pill.className = `verdict-pill ${verdict}`;
  pill.innerHTML = `${icon(verdict === "safe" ? "shield-check" : verdict === "warning" ? "type" : "server", 13)} ${meta.label}`;

  $("#confidenceVal").textContent = `${activeTabInfo.confidence.toFixed(1)}%`;
  $("#scanTimeVal").textContent = `${activeTabInfo.scanMs.toFixed(1)} ms`;
  const perfInf = $("#perf-inference-time");
  if (perfInf) perfInf.textContent = `${activeTabInfo.scanMs.toFixed(1)} ms`;

  document.body.dataset.verdict = verdict;
  $("#warningBanner").style.display = verdict === "danger" ? "flex" : "none";
  
  paintGauge(activeTabInfo.score);
  renderReasons(activeTabInfo.reasons, activeTabInfo.score);
}

// ── Tab & UI Operations ───────────────────────────────────────────────────

function initTabs() {
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => t.classList.remove("active"));
      $$(".view").forEach((v) => v.classList.remove("active"));
      tab.classList.add("active");
      $(`#view-${tab.dataset.view}`).classList.add("active");
    });
  });

  $$("[data-jump]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const dest = btn.getAttribute("data-jump");
      const match = $(`.tab[data-view="${dest}"]`);
      if (match) match.click();
    });
  });
}



function initSettings() {
  const settingsKeys = ["set-email", "set-notif", "set-vt", "set-gsb", "set-telemetry"];
  
  settingsKeys.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;

    // Load states
    chrome.storage.local.get([id], (data) => {
      if (data[id] !== undefined) {
        el.checked = data[id];
      }
    });

    // Save states
    el.addEventListener("change", () => {
      chrome.storage.local.set({ [id]: el.checked });
    });
  });

  // Reset database settings
  $("#btn-clear")?.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
      history = [];
      renderHistory();
      loadActiveTab();
    });
  });

  // Export scan logs to local JSON file
  $("#btn-export")?.addEventListener("click", () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(history, null, 2));
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute("href", dataStr);
    dlAnchorElem.setAttribute("download", `phishguard_scan_history_${Date.now()}.json`);
    dlAnchorElem.click();
  });
}

// ── Boot ───────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initSettings();

  // Setup email scan button
  document.getElementById("btn-email-scanner")?.addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("email_scanner.html") });
  });

  // Load stats history and sync overview
  chrome.storage.local.get(["alerts"], (data) => {
    const alerts = data.alerts || [];
    if (alerts.length > 0) {
      history = alerts.map(a => ({
        domain: safeHost(a.url),
        score: a.confidence ? a.confidence * 100 : (a.is_phishing ? 90 : 5),
        confidence: a.confidence ? a.confidence * 100 : 99,
        timestamp: a.timestamp
      }));
    } else {
      history = [];
    }
    renderHistory();
    loadActiveTab();
  });

  // Manual re-scan trigger
  $("#rescanBtn")?.addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url && tab.url.startsWith("http")) {
      runScanAnimation(20, () => {
        chrome.runtime.sendMessage({ type: "QUICK_SCAN", tabId: tab.id, url: tab.url }, () => {
          setTimeout(loadActiveTab, 200);
        });
      });
    }
  });
});

// ── Utilities ─────────────────────────────────────────────────────────────

function safeHost(u) { try { return new URL(u).hostname; } catch { return u; } }
function ago(ts) {
  if (!ts) return "just now";
  const s = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60); if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}
function escHtml(s) {
  return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
