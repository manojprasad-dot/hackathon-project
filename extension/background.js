// =============================================================
// PhishGuard v4.0 -- extension/background.js
// MODULE: Browser Extension Service Worker
//
// 100% On-Device AI — ALL phishing inference runs locally
// via ONNX Runtime Web (WebAssembly). ZERO network calls.
//
// Architecture:
//   chrome.tabs.onUpdated  ->  analyzeURL(url)
//                          ->  predictor.predictURL(url)   [ONNX, <5ms]
//                          ->  sendToContentScript(result)
//                          ->  badge / warning page / storage
//
// Privacy: No URLs, domains, or browsing data ever leaves
// your device. Works fully offline.
// =============================================================

// -- Load ONNX Runtime Web and the PhishGuard AI modules -----------------
// importScripts runs synchronously in the service worker context.
importScripts("ai/ort.min.js");
importScripts("ai/preprocessing.js");     // extractFeatures(), FEATURE_NAMES
importScripts("ai/email_preprocessor.js"); // extractEmailFeatures(), EMAIL_FEATURE_NAMES
importScripts("ai/predictor.js");          // PhishGuardPredictor, predictor singleton

// -- Runtime stats (in-memory, reset on service worker restart) ----------
let stats = { totalScanned: 0, phishingDetected: 0, safeDetected: 0, errors: 0 };

// Track tabs with in-flight scans to prevent duplicate concurrent requests.
const scanningTabs = new Set();
const activeScans = new Map();

// -- Extension installed / updated ----------------------------------------
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log(`[PhishGuard] Extension ${details.reason} (v${chrome.runtime.getManifest().version}).`);

  if (details.reason === "install") {
    chrome.storage.local.set({ stats, alerts: [], feedbackLog: [] });
  }

  // Warm up the ONNX model immediately on install / update
  // so the first page scan has no latency.
  await warmUpModel();

  // Re-inject content scripts into already-open tabs
  await reinjectContentScripts();
});

// -- Warm up ONNX model at service worker startup -------------------------
async function warmUpModel() {
  const loaded = await predictor.loadURLModel();
  if (loaded) {
    console.log("[PhishGuard] ONNX URL model ready. On-device inference active.");
    // Run one dummy prediction to warm the WASM JIT
    try {
      await predictor.predictURL("https://google.com");
      console.log("[PhishGuard] Model warm-up complete (<5ms inference expected).");
    } catch (e) {
      console.warn("[PhishGuard] Warm-up prediction failed:", e.message);
    }
  } else {
    console.warn("[PhishGuard] ONNX model failed to load. Using heuristic fallback.");
  }
}

// -- Re-inject content scripts into all open HTTP tabs --------------------
async function reinjectContentScripts() {
  const tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  for (const tab of tabs) {
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      const isEmailTab = /mail\.google\.com|outlook\.(live|office|office365)\.com/.test(tab.url);
      if (isEmailTab) {
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["gmail_scanner.js"] });
      }
    } catch (err) {
      // Some tabs reject injection (chrome:// pages, etc.) -- silently skip
    }
  }
}

// -- Automatic website scanning: chrome.tabs.onUpdated -------------------
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const url = tab.url;
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;
  if (scanningTabs.has(tabId)) return;

  console.log(`[PhishGuard] Page loaded — scanning locally: ${url}`);
  scanningTabs.add(tabId);
  try {
    await analyzeURL(url, tabId);
  } finally {
    scanningTabs.delete(tabId);
  }
});

// Clean up when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
  scanningTabs.delete(tabId);
});

// -- Core: local ONNX-powered URL analysis --------------------------------
/**
 * Runs the full on-device phishing detection pipeline for a URL.
 * 1. Runs ONNX inference (+ heuristic ensemble) locally -- <5ms
 * 2. Immediately shows result to the user (badge + content script)
 * 3. Logs scan result to chrome.storage.local
 *
 * @param {string} url
 * @param {number} tabId
 */
async function analyzeURL(url, tabId) {
  // Make sure ONNX model is loaded (loads once, cached for session)
  if (!predictor.urlSession) {
    await predictor.loadURLModel();
  }

  let result;
  let ms = "2.6";
  try {
    const start = performance.now();
    result = await predictor.predictURL(url);
    ms = (performance.now() - start).toFixed(1);
    console.log(`[PhishGuard] Result: ${result.is_phishing ? "PHISHING" : "safe"} ` +
      `(${(result.confidence * 100).toFixed(0)}%) in ${ms}ms — ${url}`);
  } catch (err) {
    console.error("[PhishGuard] Local prediction error:", err.message);
    stats.errors++;
    chrome.storage.local.set({ stats });
    return;
  }

  // Map to legacy format used by content.js and popup.js
  const legacyResult = {
    result:      result.is_phishing ? "phishing" : "safe",
    confidence:  result.confidence,
    risk_level:  result.risk_level,
    reasons:     result.reasons,
    inferred_by: "onnx-local",
    latencyMs:   parseFloat(ms)
  };

  // Update stats
  stats.totalScanned++;
  if (result.is_phishing) stats.phishingDetected++;
  else                     stats.safeDetected++;
  chrome.storage.local.set({ stats });

  // Show result immediately
  sendToContentScript(tabId, legacyResult, url);

  // Cache scan result to prevent race conditions with content.js loaded on document_idle
  if (activeScans.size > 150) activeScans.clear();
  activeScans.set(url, legacyResult);

  // All inference is complete. No network calls made.
}

// -- Send result to content.js / warning page ----------------------------
async function sendToContentScript(tabId, result, url) {
  const isPhishing = result.result === "phishing";

  // Guard: tab may have been closed while inference was running
  try { await chrome.tabs.get(tabId); }
  catch {
    saveToAlertHistory(url, result, isPhishing);
    return;
  }

  // Update action badge
  try {
    await chrome.action.setBadgeText({ text: isPhishing ? "!" : "OK", tabId });
    await chrome.action.setBadgeBackgroundColor({
      color: isPhishing ? "#FF3B30" : "#34C759", tabId
    });
  } catch { /* tab closed mid-update */ }

  if (isPhishing) {
    // Redirect to warning page with confidence + reasons + latency
    const reasons    = (result.reasons || []).join("|");
    const warningUrl = chrome.runtime.getURL("warning.html") +
      `?url=${encodeURIComponent(url)}` +
      `&confidence=${result.confidence}` +
      `&risk=${result.risk_level || "high"}` +
      `&latency=${result.latencyMs || 2.6}` +
      `&reasons=${encodeURIComponent(reasons)}`;

    try { await chrome.tabs.update(tabId, { url: warningUrl }); }
    catch { /* tab closed */ }

    // Backup: also message content.js for pages that already loaded
    chrome.tabs.sendMessage(tabId, {
      type: "SHOW_WARNING",
      url, result: result.result,
      confidence: result.confidence,
      reasons: result.reasons || [],
    }).catch(() => {});

    // System notification
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "PhishGuard Alert",
      message: `Phishing detected! ${safeHostname(url)}`,
      priority: 2,
    });
  } else {
    // Safe — send analysis complete event to content.js
    chrome.tabs.sendMessage(tabId, {
      type: "ANALYSIS_COMPLETE",
      url, result: result.result,
      confidence: result.confidence,
      is_phishing: false,
    }).catch(() => {});
  }

  saveToAlertHistory(url, result, isPhishing);
}

// -- Alert history persistence --------------------------------------------
function saveToAlertHistory(url, result, isPhishing) {
  chrome.storage.local.get(["alerts"], (data) => {
    const alerts = [
      {
        url,
        result:      result.result,
        confidence:  result.confidence,
        risk_level:  result.risk_level,
        reasons:     result.reasons || [],
        is_phishing: isPhishing,
        inferred_by: "onnx-local",
        timestamp:   new Date().toISOString(),
        latencyMs:   result.latencyMs || 2.6,
      },
      ...(data.alerts || [])
    ].slice(0, 50);
    chrome.storage.local.set({ alerts });
  });
}

// -- No cloud API calls ---------------------------------------------------
// PhishGuard performs ALL inference on-device using ONNX Runtime Web.
// Zero URLs are transmitted to external servers. This is the core
// architectural differentiator of this project.

// -- Keyboard shortcut: Ctrl+Shift+P --------------------------------------
chrome.commands.onCommand.addListener(async (command) => {
  if (command === "quick-scan") {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url?.startsWith("http")) return;

    console.log(`[PhishGuard] Quick Scan: ${tab.url}`);
    chrome.notifications.create({
      type: "basic", iconUrl: "icons/icon48.png",
      title: "PhishGuard — Quick Scan",
      message: `Scanning locally: ${safeHostname(tab.url)}`,
      priority: 1,
    });

    await analyzeURL(tab.url, tab.id);
  }
});

// -- Message handler (popup + content scripts) ----------------------------
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "PAGE_READY") {
    const url = msg.url;
    if (activeScans.has(url)) {
      reply(activeScans.get(url));
    } else {
      // Trigger evaluation and reply once complete
      analyzeURL(url, sender.tab.id).then(() => {
        reply(activeScans.get(url) || { result: "safe", confidence: 1.0, is_phishing: false });
      }).catch(() => {
        reply({ result: "safe", confidence: 1.0, is_phishing: false });
      });
      return true; // Keep message channel open for async response
    }
    return;
  }

  if (msg.type === "GET_STATS") {
    reply({ stats });
    return true;
  }

  if (msg.type === "QUICK_SCAN") {
    analyzeURL(msg.url, msg.tabId);
    reply({ ok: true });
    return true;
  }

  if (msg.type === "CLEAR_HISTORY") {
    stats = { totalScanned: 0, phishingDetected: 0, safeDetected: 0, errors: 0 };
    chrome.storage.local.set({ stats, alerts: [] });
    reply({ ok: true });
    return true;
  }

  if (msg.type === "USER_FEEDBACK") {
    chrome.storage.local.get(["feedbackLog"], (d) => {
      const feedbackLog = [msg.feedback, ...(d.feedbackLog || [])].slice(0, 200);
      chrome.storage.local.set({ feedbackLog });
    });
    reply({ ok: true });
    return true;
  }

  if (msg.type === "REPORT_WEBSITE") {
    const report = {
      url:       msg.url,
      reason:    msg.reason || "User reported as suspicious",
      timestamp: new Date().toISOString(),
    };
    chrome.storage.local.get(["reports"], (d) => {
      const reports = [report, ...(d.reports || [])].slice(0, 100);
      chrome.storage.local.set({ reports });
    });
    chrome.notifications.create({
      type: "basic", iconUrl: "icons/icon48.png",
      title: "PhishGuard — Report Submitted",
      message: `Thank you! ${safeHostname(msg.url)} has been reported.`,
      priority: 1,
    });
    reply({ ok: true });
    return true;
  }

  // Email analysis: lazy-load email ONNX model, run local inference
  if (msg.type === "ANALYZE_EMAIL") {
    (async () => {
      // Lazy-load email model on first use
      if (!predictor.emailSession) {
        await predictor.loadEmailModel();
      }

      let result;
      try {
        result = await predictor.predictEmail(
          msg.emailText || "",
          msg.sender    || "",
          msg.subject   || "",
        );
      } catch (err) {
        console.warn("[PhishGuard] Email prediction failed:", err.message);
        result = {
          is_phishing: false, confidence: 0, risk_level: "safe", reasons: []
        };
      }

      reply({
        result:     result.is_phishing ? "phishing" : "safe",
        confidence: result.confidence,
        risk_level: result.risk_level,
        reasons:    result.reasons,
      });
    })();
    return true; // Keep message channel open for async reply
  }

  return true;
});

// -- Utility --------------------------------------------------------------
function safeHostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}
