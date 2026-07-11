/**
 * PhishGuard -- extension/ai/email_preprocessor.js
 * ==================================================
 * JavaScript port of backend/features/email_extractor.py
 *
 * Extracts 28 structured features from email content for on-device
 * ML classification. All computation is local -- no network calls.
 *
 * Feature order (must match email_model.onnx training order):
 *  [0]  has_urgent_language      [14] body_length
 *  [1]  urgent_keyword_count     [15] capitalization_ratio
 *  [2]  has_threat_language      [16] special_char_ratio
 *  [3]  has_reward_language      [17] has_dangerous_attachment
 *  [4]  link_count               [18] spelling_error_score
 *  [5]  has_suspicious_links     [19] url_phishing_score
 *  [6]  suspicious_link_ratio    [20] has_base64_content
 *  [7]  has_html_form            [21] has_javascript
 *  [8]  has_mismatched_url       [22] link_to_text_ratio
 *  [9]  sender_domain_mismatch   [23] has_hidden_text
 *  [10] sender_is_freemail       [24] reply_to_mismatch
 *  [11] has_spoofed_sender       [25] has_tracking_pixel
 *  [12] sender_suspicious_tld    [26] urgency_in_subject
 *  [13] has_generic_greeting     [27] body_entropy
 */

// -- Constants (ported from backend/features/email_extractor.py) -----------

const EMAIL_FEATURE_NAMES = [
  "has_urgent_language","urgent_keyword_count","has_threat_language",
  "has_reward_language","link_count","has_suspicious_links",
  "suspicious_link_ratio","has_html_form","has_mismatched_url",
  "sender_domain_mismatch","sender_is_freemail","has_spoofed_sender",
  "sender_suspicious_tld","has_generic_greeting","body_length",
  "capitalization_ratio","special_char_ratio","has_dangerous_attachment",
  "spelling_error_score","url_phishing_score","has_base64_content",
  "has_javascript","link_to_text_ratio","has_hidden_text",
  "reply_to_mismatch","has_tracking_pixel","urgency_in_subject",
  "body_entropy",
];

const URGENT_PHRASES = [
  "urgent action required","verify your account","verify immediately",
  "confirm your identity","update your information","click here to update",
  "payment failed","account suspended","unauthorized access",
  "unusual activity","security alert","immediate action",
  "within 24 hours","within 48 hours","your account will be",
  "failure to verify","risk of suspension","action required",
  "verify your identity","confirm your payment","expire soon",
  "last warning","final notice","act now","time sensitive",
  "respond immediately","do not ignore","limited time",
  "account will be closed","must verify","expires today",
  "hours remaining","respond now","take action immediately",
  "risk losing","will be terminated","will be permanently",
  "click below immediately","requires your attention",
  "update required","mandatory update","confirm now",
  "verify within","must be completed","failure to respond",
  "your access will be","will be disabled","will be frozen",
];

const THREAT_PHRASES = [
  "suspended","locked","unauthorized","compromised","breach",
  "terminated","disabled","restricted","blocked","frozen",
  "illegal activity","legal action","law enforcement",
  "permanent closure","account closure","identity theft",
  "penalty","fine","prosecution","court order","arrest warrant",
  "federal investigation","criminal charges","tax fraud",
  "money laundering","seized","confiscated","forfeited",
];

const REWARD_PHRASES = [
  "congratulations","winner","prize","free gift","claim your",
  "you have been selected","lottery","million dollars",
  "you have won","limited offer","exclusive offer","act now",
  "cash reward","bonus","free iphone","free money","sweepstakes",
];

const GENERIC_GREETINGS = [
  "dear customer","dear user","dear account holder","dear member",
  "dear valued customer","hello dear","dear sir","dear madam",
  "dear sir/madam","to whom it may concern","dear friend",
  "greetings","attention","dear client",
];

const FREEMAIL_DOMAINS = new Set([
  "gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com",
  "icloud.com","protonmail.com","zoho.com","mail.com","yandex.com",
  "gmx.com","inbox.com","live.com","msn.com","rocketmail.com",
  "qq.com","163.com","126.com","sina.com","sohu.com",
]);

const SUSPICIOUS_EMAIL_TLDS = new Set([
  ".xyz",".top",".tk",".ml",".ga",".cf",".gq",".pw",".buzz",
  ".bid",".click",".link",".win",".download",".stream",".racing",
  ".party",".science",".cricket",".faith",".icu",".cam",".monster",
]);

const DANGEROUS_EXTENSIONS = new Set([
  ".exe",".zip",".rar",".bat",".cmd",".scr",".pif",".com",
  ".vbs",".js",".jar",".msi",".ps1",".docm",".xlsm",".pdf.exe",
]);

const URGENCY_SUBJECT_WORDS = [
  "urgent","important","action required","verify","confirm",
  "alert","warning","suspended","expir","immediately","attention",
  "critical","final notice","last chance","limited time",
];

// -- Helper -----------------------------------------------------------------

function emailShannonEntropy(text) {
  if (!text) return 0;
  const freq = {};
  for (const c of text) freq[c] = (freq[c] || 0) + 1;
  const n = text.length;
  return -Object.values(freq).reduce((s, f) => {
    const p = f / n; return s + p * Math.log2(p);
  }, 0);
}

function extractDomain(emailOrUrl) {
  try {
    if (emailOrUrl.includes("@")) return emailOrUrl.split("@")[1].toLowerCase().trim();
    return new URL(emailOrUrl).hostname.toLowerCase();
  } catch { return ""; }
}

function extractLinks(text) {
  const re = /https?:\/\/[^\s<>"'\)\]]+/gi;
  return [...(text.match(re) || [])];
}

// -- Main extractor ---------------------------------------------------------

/**
 * Extract 28 email features for ONNX inference.
 *
 * @param {string} emailText  - Plain text body of the email
 * @param {string} sender     - Sender address (e.g. "phisher@evil.xyz")
 * @param {string} subject    - Email subject line
 * @param {number} [urlPhishingScore=0] - Pre-computed avg phishing score of links in email
 * @returns {{ features: Object, vector: Float32Array }}
 */
function extractEmailFeatures(emailText, sender = "", subject = "", urlPhishingScore = 0) {
  const f = {};
  const lowerBody    = (emailText || "").toLowerCase();
  const lowerSubject = (subject  || "").toLowerCase();
  const senderLower  = (sender   || "").toLowerCase();

  // -- [0] has_urgent_language -----------------------------------------------
  f.has_urgent_language = URGENT_PHRASES.some(p => lowerBody.includes(p)) ? 1 : 0;

  // -- [1] urgent_keyword_count ----------------------------------------------
  f.urgent_keyword_count = URGENT_PHRASES.filter(p => lowerBody.includes(p)).length;

  // -- [2] has_threat_language -----------------------------------------------
  f.has_threat_language = THREAT_PHRASES.some(p => lowerBody.includes(p)) ? 1 : 0;

  // -- [3] has_reward_language -----------------------------------------------
  f.has_reward_language = REWARD_PHRASES.some(p => lowerBody.includes(p)) ? 1 : 0;

  // -- [4] link_count --------------------------------------------------------
  const links = extractLinks(emailText || "");
  f.link_count = links.length;

  // -- [5] has_suspicious_links (uses SUSPICIOUS_TLDS from preprocessing.js) -
  // (SUSPICIOUS_TLDS is imported from preprocessing.js which is loaded first)
  const suspLinks = links.filter(url => {
    try {
      const host = new URL(url).hostname.toLowerCase();
      return [...SUSPICIOUS_TLDS].some(t => host.endsWith(t));
    } catch { return false; }
  });
  f.has_suspicious_links = suspLinks.length > 0 ? 1 : 0;

  // -- [6] suspicious_link_ratio ---------------------------------------------
  f.suspicious_link_ratio = links.length > 0
    ? parseFloat((suspLinks.length / links.length).toFixed(4)) : 0;

  // -- [7] has_html_form -----------------------------------------------------
  const lowerFull = lowerBody;
  f.has_html_form = (lowerFull.includes("<form") || lowerFull.includes("action=")) ? 1 : 0;

  // -- [8] has_mismatched_url ------------------------------------------------
  // Link text says one domain but href points elsewhere
  const aTagRe = /href=["']([^"']+)["'][^>]*>([^<]+)</gi;
  let hasMismatch = false;
  let m;
  while ((m = aTagRe.exec(emailText || "")) !== null) {
    const hrefDomain = extractDomain(m[1]);
    const textDomain = extractDomain(m[2].trim());
    if (textDomain && hrefDomain && !hrefDomain.includes(textDomain) && !textDomain.includes(hrefDomain)) {
      hasMismatch = true; break;
    }
  }
  f.has_mismatched_url = hasMismatch ? 1 : 0;

  // -- [9] sender_domain_mismatch --------------------------------------------
  const senderDomain = extractDomain(senderLower);
  let bodyDomains = links.map(u => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } });
  const hasOtherDomain = bodyDomains.some(d => d && !d.includes(senderDomain) && senderDomain && !senderDomain.includes(d));
  f.sender_domain_mismatch = hasOtherDomain ? 1 : 0;

  // -- [10] sender_is_freemail -----------------------------------------------
  f.sender_is_freemail = FREEMAIL_DOMAINS.has(senderDomain) ? 1 : 0;

  // -- [11] has_spoofed_sender -----------------------------------------------
  // Sender display name contains brand but actual domain doesn't match
  const senderName = senderLower.replace(/@.*/, "");
  f.has_spoofed_sender = BRAND_NAMES.some(b =>
    senderName.includes(b) && !LEGITIMATE_DOMAINS.has(senderDomain)
  ) ? 1 : 0;

  // -- [12] sender_suspicious_tld --------------------------------------------
  const senderTld = "." + (senderDomain.split(".").pop() || "");
  f.sender_suspicious_tld = SUSPICIOUS_EMAIL_TLDS.has(senderTld) ? 1 : 0;

  // -- [13] has_generic_greeting ---------------------------------------------
  f.has_generic_greeting = GENERIC_GREETINGS.some(g => lowerBody.includes(g)) ? 1 : 0;

  // -- [14] body_length ------------------------------------------------------
  f.body_length = (emailText || "").length;

  // -- [15] capitalization_ratio ---------------------------------------------
  const letters = (emailText || "").replace(/[^a-zA-Z]/g, "");
  f.capitalization_ratio = letters.length > 0
    ? parseFloat((letters.split("").filter(c => c === c.toUpperCase()).length / letters.length).toFixed(4))
    : 0;

  // -- [16] special_char_ratio -----------------------------------------------
  f.special_char_ratio = (emailText || "").length > 0
    ? parseFloat(([...(emailText || "")].filter(c => /[^a-zA-Z0-9\s]/.test(c)).length / emailText.length).toFixed(4))
    : 0;

  // -- [17] has_dangerous_attachment -----------------------------------------
  f.has_dangerous_attachment = [...DANGEROUS_EXTENSIONS].some(ext =>
    lowerBody.includes(ext) || lowerSubject.includes(ext)
  ) ? 1 : 0;

  // -- [18] spelling_error_score ---------------------------------------------
  // Lightweight heuristics: repeated punctuation, ALL CAPS words, etc.
  const allCapsWords = (emailText || "").match(/\b[A-Z]{4,}\b/g) || [];
  const triplePunct  = (emailText || "").match(/[!?.]{3,}/g) || [];
  f.spelling_error_score = Math.min(allCapsWords.length * 0.1 + triplePunct.length * 0.2, 1.0);

  // -- [19] url_phishing_score -----------------------------------------------
  f.url_phishing_score = parseFloat((urlPhishingScore || 0).toFixed(4));

  // -- [20] has_base64_content -----------------------------------------------
  f.has_base64_content = /[A-Za-z0-9+/]{40,}={0,2}/.test(emailText || "") ? 1 : 0;

  // -- [21] has_javascript ---------------------------------------------------
  f.has_javascript = (lowerBody.includes("<script") || lowerBody.includes("javascript:")) ? 1 : 0;

  // -- [22] link_to_text_ratio -----------------------------------------------
  const wordCount = (emailText || "").split(/\s+/).filter(w => w.length > 2).length;
  f.link_to_text_ratio = wordCount > 0
    ? parseFloat((links.length / wordCount).toFixed(4)) : 0;

  // -- [23] has_hidden_text --------------------------------------------------
  f.has_hidden_text = (
    lowerBody.includes("display:none") ||
    lowerBody.includes("visibility:hidden") ||
    lowerBody.includes("font-size:0") ||
    lowerBody.includes("color:white") ||
    lowerBody.includes("opacity:0")
  ) ? 1 : 0;

  // -- [24] reply_to_mismatch ------------------------------------------------
  // If Reply-To header differs from From (simplified: check if both exist in text)
  f.reply_to_mismatch = 0; // Cannot reliably detect from body alone; set 0 by default

  // -- [25] has_tracking_pixel -----------------------------------------------
  f.has_tracking_pixel = (
    lowerBody.includes("width=\"1\"") ||
    lowerBody.includes("height=\"1\"") ||
    lowerBody.includes("width=1 height=1") ||
    /img[^>]+src=["'][^"']+\.gif["'][^>]+width=["']1["']/i.test(emailText || "")
  ) ? 1 : 0;

  // -- [26] urgency_in_subject -----------------------------------------------
  f.urgency_in_subject = URGENCY_SUBJECT_WORDS.filter(w => lowerSubject.includes(w)).length;

  // -- [27] body_entropy -----------------------------------------------------
  f.body_entropy = parseFloat(emailShannonEntropy(emailText || "").toFixed(4));

  // Build Float32Array in exact training order
  const vector = new Float32Array(EMAIL_FEATURE_NAMES.map(name => f[name] || 0));
  return { features: f, vector };
}

if (typeof module !== "undefined") {
  module.exports = { extractEmailFeatures, EMAIL_FEATURE_NAMES };
}
