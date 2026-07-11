/**
 * PhishGuard -- extension/ai/preprocessing.js
 * =============================================
 * JavaScript port of backend/features/extractor.py
 *
 * Extracts the exact 30 features the ONNX model was trained on.
 * Feature order MUST match backend/ml/model.pkl feature_names exactly:
 *
 *   [0]  url_length            [10] num_query_params
 *   [1]  hostname_length       [11] num_special_chars
 *   [2]  path_length           [12] digit_ratio
 *   [3]  query_length          [13] letter_ratio
 *   [4]  path_depth            [14] special_char_ratio
 *   [5]  num_dots              [15] hostname_entropy
 *   [6]  num_hyphens           [16] uses_https
 *   [7]  num_underscores       [17] is_ip_address
 *   [8]  num_digits            [18] is_known_tld_suspicious
 *   [9]  num_subdomains        [19] has_suspicious_keyword
 *  [20]  has_at_symbol         [25] brand_in_hostname
 *  [21]  has_double_slash      [26] brand_hyphenated
 *  [22]  has_redirect_param    [27] has_lookalike_chars
 *  [23]  has_encoded_chars     [28] has_sensitive_path
 *  [24]  is_known_legitimate   [29] is_shortened_url
 */

// -- Constants (ported verbatim from extractor.py) --------------------------

const SUSPICIOUS_KEYWORDS = [
  "paypa1","paypal-","bank-login","secure-login","account-verify",
  "signin-","login-secure","update-account","verify-account",
  "banking-","free-gift","claim-prize","winner-","password-reset-",
  "apple-id","microsoft-verify","google-security","amazon-secure",
  "ebay-support","netflix-confirm","instagram-verify","facebook-login",
  "security-alert","suspended","unauthorized","locked-account",
  "confirm-identity","unusual-activity","verify-payment","update-billing",
  "reset-password","recover-account","unlock-account","validate-account",
  "secure-update","billing-update","tax-refund","irs-refund",
  "crypto-wallet","wallet-verify","coinbase-verify","binance-secure",
  "zelle-payment","venmo-verify","wire-transfer","invoice-payment",
  "delivery-failed","package-held","usps-redelivery","fedex-schedule",
  "dhl-tracking","ups-delivery","customs-fee","shipping-update",
];

const SUSPICIOUS_TLDS = new Set([
  ".xyz",".top",".club",".work",".click",".link",
  ".tk",".ml",".ga",".cf",".gq",".pw",".buzz",
  ".bid",".stream",".download",".racing",".win",
  ".review",".party",".science",".cricket",".faith",
  ".icu",".cam",".monster",".rest",".surf",
  ".loan",".date",".trade",".accountant",".gdn",
  ".men",".kim",".wang",".space",".host",
  ".site",".website",".online",".tech",".store",
  ".fun",".life",".fit",".vip",".pro",
]);

const BRAND_NAMES = [
  "paypal","amazon","netflix","google","apple",
  "microsoft","facebook","instagram","ebay","dropbox",
  "chase","wellsfargo","citibank","dhl","fedex",
  "linkedin","twitter","steam","whatsapp","telegram",
  "yahoo","outlook","icloud","coinbase","binance",
  "uber","venmo","zelle","usps","ups",
  "spotify","discord","tiktok","snapchat","reddit",
  "stripe","shopify","square","docusign","adobe",
  "salesforce","zoom","slack","notion","figma",
  "metamask","opensea","kraken","robinhood","etrade",
  "schwab","fidelity","vanguard","americanexpress","capitalone",
  "discover","usbank","pnc","regions","truist",
];

const BRAND_OWNED_TLDS = new Set([
  ".google",".apple",".microsoft",".amazon",".youtube",
  ".netflix",".facebook",".instagram",".linkedin",
  ".android",".chrome",".gmail",".windows",
]);

const LEGITIMATE_DOMAINS = new Set([
  "google.com","youtube.com","facebook.com","amazon.com","wikipedia.org",
  "twitter.com","x.com","reddit.com","linkedin.com","github.com",
  "stackoverflow.com","microsoft.com","apple.com","paypal.com",
  "netflix.com","spotify.com","instagram.com","tiktok.com","yahoo.com",
  "ebay.com","adobe.com","dropbox.com","zoom.us","slack.com",
  "notion.so","figma.com","medium.com","quora.com","pinterest.com",
  "wordpress.com","cloudflare.com","stripe.com","twitch.tv",
  "discord.com","whatsapp.com","telegram.org","bbc.com","cnn.com",
  "nytimes.com","walmart.com","target.com","chase.com",
  "bankofamerica.com","wellsfargo.com","citibank.com",
  "hulu.com","disneyplus.com","airbnb.com","booking.com","expedia.com",
  "coursera.org","udemy.com","aws.amazon.com","azure.microsoft.com",
  "cloud.google.com","salesforce.com","shopify.com","etsy.com",
  "onrender.com","render.com","vercel.app","netlify.app",
  "herokuapp.com","firebase.google.com","web.app",
  "uber.com","lyft.com","venmo.com","zelle.com","usps.com",
  "ups.com","fedex.com","dhl.com","snapchat.com","signal.org",
  "protonmail.com","tutanota.com","fastmail.com","hey.com",
  "coinbase.com","binance.com","kraken.com","gemini.com",
  "robinhood.com","etrade.com","schwab.com","fidelity.com",
  "vanguard.com","americanexpress.com","capitalone.com","discover.com",
  "usbank.com","pnc.com","ally.com","sofi.com","chime.com",
  "docusign.com","canva.com","grammarly.com",
  "atlassian.com","jira.com","confluence.com","bitbucket.org",
  "gitlab.com","npmjs.com","pypi.org","docker.com",
  "openai.com","anthropic.com","huggingface.co",
  "washingtonpost.com","theguardian.com","reuters.com",
  "bloomberg.com","forbes.com","techcrunch.com","wired.com",
  "producthunt.com","ycombinator.com","dribbble.com","behance.net",
]);

const SENSITIVE_PATH_TERMS = [
  "login","signin","account","secure","verify",
  "banking","update","confirm","password","credential",
  "wallet","payment","billing","auth","token",
  "reset","recover","unlock","validate","checkout",
  "invoice","transfer","wire","withdraw","deposit",
  "2fa","mfa","otp","sso","oauth",
  "admin","dashboard","portal","webmail","cpanel",
  "wp-admin","wp-login","administrator",
];

const SHORTENING_SERVICES = [
  "bit.ly","goo.gl","t.co","tinyurl.com","ow.ly",
  "is.gd","buff.ly","adf.ly","j.mp","tr.im",
  "rb.gy","cutt.ly","shorturl.at",
  "v.gd","clck.ru","tny.im","su.pr","lnkd.in",
  "db.tt","qr.ae","bc.vc","x.co","tiny.cc",
  "s.id","rotf.lol","shorturl.asia",
];

// -- Feature names in exact order (matches model training) ------------------
const FEATURE_NAMES = [
  "url_length","hostname_length","path_length","query_length","path_depth",
  "num_dots","num_hyphens","num_underscores","num_digits","num_subdomains",
  "num_query_params","num_special_chars",
  "digit_ratio","letter_ratio","special_char_ratio","hostname_entropy",
  "uses_https","is_ip_address","is_known_tld_suspicious",
  "has_suspicious_keyword","has_at_symbol","has_double_slash",
  "has_redirect_param","has_encoded_chars","is_known_legitimate",
  "brand_in_hostname","brand_hyphenated","has_lookalike_chars",
  "has_sensitive_path","is_shortened_url",
];

// -- Helper functions -------------------------------------------------------

/** Shannon entropy of a string (higher = more random/suspicious). */
function shannonEntropy(text) {
  if (!text) return 0.0;
  const freq = {};
  for (const c of text) freq[c] = (freq[c] || 0) + 1;
  const len = text.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

/** Ratio of digits in text. */
function ratioDigits(text) {
  if (!text) return 0.0;
  return [...text].filter(c => c >= "0" && c <= "9").length / text.length;
}

/** Ratio of letters in text. */
function ratioLetters(text) {
  if (!text) return 0.0;
  return [...text].filter(c => /[a-zA-Z]/.test(c)).length / text.length;
}

/** Ratio of special chars in text. */
function ratioSpecial(text) {
  if (!text) return 0.0;
  return [...text].filter(c => /[^a-zA-Z0-9]/.test(c)).length / text.length;
}

/** Count non-overlapping occurrences of needle in haystack. */
function countOccurrences(haystack, needle) {
  let count = 0;
  let pos = 0;
  while ((pos = haystack.indexOf(needle, pos)) !== -1) {
    count++;
    pos += needle.length;
  }
  return count;
}

// -- Main extractor ---------------------------------------------------------

/**
 * Extract the 30 URL features the ONNX model was trained on.
 *
 * @param {string} url - The URL to analyze
 * @returns {{ features: Object, vector: Float32Array }}
 *   features  - Named dict of feature values (for heuristic engine)
 *   vector    - Float32Array of length 30, ready for ONNX inference
 */
function extractFeatures(url) {
  const f = {};

  try {
    const lowerUrl = url.toLowerCase();
    let parsed;
    try {
      parsed = new URL(url.startsWith("http") ? url : "https://" + url);
    } catch {
      parsed = new URL("https://invalid.example");
    }

    const hostname = (parsed.hostname || "").toLowerCase();
    const path     = parsed.pathname || "";
    const query    = parsed.search.replace(/^\?/, "") || "";
    const fullUrl  = lowerUrl;
    const parts    = hostname.split(".");
    const rootDomain = parts.length >= 2 ? parts.slice(-2).join(".") : hostname;

    // -- [0-4] Length features -----------------------------------------------
    f.url_length      = url.length;
    f.hostname_length = hostname.length;
    f.path_length     = path.length;
    f.query_length    = query.length;
    f.path_depth      = Math.max(0, (path.match(/\//g) || []).length - 1);

    // -- [5-11] Count features -----------------------------------------------
    f.num_dots         = countOccurrences(fullUrl, ".");
    f.num_hyphens      = countOccurrences(fullUrl, "-");
    f.num_underscores  = countOccurrences(fullUrl, "_");
    f.num_digits       = [...hostname].filter(c => c >= "0" && c <= "9").length;
    f.num_subdomains   = Math.max(0, parts.length - 2);

    // Parse query params
    const qparams = query ? query.split("&").filter(p => p.includes("=")).length : 0;
    f.num_query_params = qparams;
    f.num_special_chars = [...url].filter(c => "@?=&%#~!".includes(c)).length;

    // -- [12-15] Ratio features ----------------------------------------------
    f.digit_ratio       = parseFloat(ratioDigits(hostname).toFixed(4));
    f.letter_ratio      = parseFloat(ratioLetters(hostname).toFixed(4));
    f.special_char_ratio = parseFloat(ratioSpecial(fullUrl).toFixed(4));
    f.hostname_entropy  = parseFloat(shannonEntropy(hostname).toFixed(4));

    // -- [16-24] Boolean flags -----------------------------------------------
    f.uses_https = parsed.protocol === "https:" ? 1 : 0;

    f.is_ip_address = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0;

    f.is_known_tld_suspicious = [...SUSPICIOUS_TLDS].some(t => hostname.endsWith(t)) ? 1 : 0;

    f.has_suspicious_keyword = SUSPICIOUS_KEYWORDS.some(kw => fullUrl.includes(kw)) ? 1 : 0;

    f.has_at_symbol = url.includes("@") ? 1 : 0;

    f.has_double_slash = path.includes("//") ? 1 : 0;

    f.has_redirect_param = (
      fullUrl.includes("redirect=") ||
      fullUrl.includes("url=") ||
      fullUrl.includes("next=")
    ) ? 1 : 0;

    f.has_encoded_chars = (
      fullUrl.includes("%2f") ||
      fullUrl.includes("%40") ||
      fullUrl.includes("%3a") ||
      fullUrl.includes("%3d")
    ) ? 1 : 0;

    const isBrandTld = [...BRAND_OWNED_TLDS].some(t => hostname.endsWith(t));
    f.is_known_legitimate = (LEGITIMATE_DOMAINS.has(rootDomain) || isBrandTld) ? 1 : 0;

    // -- [25-26] Brand impersonation -----------------------------------------
    f.brand_in_hostname = BRAND_NAMES.some(b =>
      hostname.includes(b) &&
      !LEGITIMATE_DOMAINS.has(rootDomain) &&
      !isBrandTld
    ) ? 1 : 0;

    f.brand_hyphenated = BRAND_NAMES.some(b =>
      (hostname.includes(b + "-") || hostname.includes("-" + b)) &&
      !LEGITIMATE_DOMAINS.has(rootDomain) &&
      !isBrandTld
    ) ? 1 : 0;

    // -- [27] Lookalike / homograph chars ------------------------------------
    const LOOKALIKE = ["0", "1", "3", "4", "5", "vv"];
    const LOOKALIKE_TARGETS = { "0":"o","1":"l","3":"e","4":"a","5":"s","vv":"w" };
    f.has_lookalike_chars = LOOKALIKE.some(k => hostname.includes(k)) ? 1 : 0;

    // -- [28] Sensitive path terms -------------------------------------------
    f.has_sensitive_path = SENSITIVE_PATH_TERMS.some(p => path.toLowerCase().includes(p)) ? 1 : 0;

    // -- [29] URL shortening service -----------------------------------------
    f.is_shortened_url = SHORTENING_SERVICES.some(s => fullUrl.includes(s)) ? 1 : 0;

  } catch (err) {
    // On parse failure, return all zeros
    for (const name of FEATURE_NAMES) f[name] = 0;
  }

  // Build Float32Array in exact training order
  const vector = new Float32Array(FEATURE_NAMES.map(name => f[name] || 0));

  return { features: f, vector };
}

// Export for use in background.js and predictor.js
if (typeof module !== "undefined") {
  module.exports = { extractFeatures, FEATURE_NAMES };
}
