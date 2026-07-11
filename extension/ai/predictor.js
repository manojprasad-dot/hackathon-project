/**
 * PhishGuard -- extension/ai/predictor.js
 * =========================================
 * On-device AI inference engine using ONNX Runtime Web.
 *
 * Loads model.onnx and email_model.onnx from the extension bundle.
 * Runs predictions 100% locally — no network calls required.
 *
 * Architecture: Ensemble = ONNX model (75%) + Heuristic rules (25%)
 *   This mirrors the original Python detector.py logic exactly.
 *
 * Usage (in background.js as a service worker module):
 *   importScripts("../ai/ort.min.js");
 *   importScripts("../ai/preprocessing.js");
 *   importScripts("../ai/predictor.js");
 *
 *   const predictor = new PhishGuardPredictor();
 *   await predictor.loadModels();
 *   const result = await predictor.predictURL("https://example.com");
 *   // result: { is_phishing, confidence, risk_level, reasons }
 */

// -- ONNX Runtime WASM Config (for Chrome Extension Service Worker environment)
// Points the runtime to the local extension folder and restricts thread pools to avoid dynamic imports.
const aiFolder = chrome.runtime.getURL("ai/");
ort.env.wasm.numThreads = 1;
ort.env.wasm.simd       = true;
ort.env.wasm.wasmPaths = {
  "ort-wasm.wasm": aiFolder + "ort-wasm.wasm",
  "ort-wasm-simd.wasm": aiFolder + "ort-wasm-simd.wasm"
};

// -- Heuristic engine weights (ported from backend/ml/detector.py) ----------
const FEATURE_WEIGHTS = {
  is_ip_address:           0.70,
  brand_hyphenated:        0.60,
  brand_in_hostname:       0.55,
  has_suspicious_keyword:  0.40,
  is_known_tld_suspicious: 0.35,
  has_at_symbol:           0.40,
  has_lookalike_chars:     0.35,
  has_sensitive_path:      0.20,
  is_shortened_url:        0.35,
  num_subdomains:          0.15,   // per subdomain above 2 (Aligned with local model importances)
  num_dots_penalty:        0.08,   // per dot above 3
  has_encoded_chars:       0.22,
  has_redirect_param:      0.20,
  has_double_slash:        0.20,
  url_length_penalty:      0.12,   // if url_length > 100
  no_https_penalty:        0.18,   // if uses_https === 0
  high_entropy_penalty:    0.18,   // if hostname_entropy > 3.5
  is_known_legitimate:    -1.00,   // hard override (negative weight)
};

const PHISHING_THRESHOLD = 0.50;

class PhishGuardPredictor {
  constructor() {
    this.urlSession   = null;   // ONNX InferenceSession for URL model
    this.emailSession = null;   // ONNX InferenceSession for email model (lazy)
    this._loadingUrl  = false;
    this._loadingEmail = false;
  }

  // ---------------------------------------------------------------------------
  // Model loading
  // ---------------------------------------------------------------------------

  /**
   * Load the URL phishing ONNX model.
   * Called once at service worker startup.
   * @returns {Promise<boolean>} true if loaded successfully
   */
  async loadURLModel() {
    if (this.urlSession) return true;
    if (this._loadingUrl) return false;
    this._loadingUrl = true;

    try {
      const modelPath = chrome.runtime.getURL("ai/model.onnx");
      console.log("[PhishGuard] Loading ONNX URL model from:", modelPath);

      // Configure ORT to use WASM backend
      ort.env.wasm.numThreads = 1;
      ort.env.wasm.simd       = true;

      this.urlSession = await ort.InferenceSession.create(modelPath, {
        executionProviders: ["wasm"],
        graphOptimizationLevel: "all",
      });

      const inputName  = this.urlSession.inputNames[0];
      const outputNames = this.urlSession.outputNames;
      console.log("[PhishGuard] URL model loaded.");
      console.log("  Input :", inputName);
      console.log("  Outputs:", outputNames);
      return true;
    } catch (err) {
      console.error("[PhishGuard] Failed to load URL ONNX model:", err);
      this.urlSession = null;
      return false;
    } finally {
      this._loadingUrl = false;
    }
  }

  /**
   * Load the email phishing ONNX model (lazy — only on first email scan).
   * @returns {Promise<boolean>}
   */
  async loadEmailModel() {
    if (this.emailSession) return true;
    if (this._loadingEmail) return false;
    this._loadingEmail = true;

    try {
      const modelPath = chrome.runtime.getURL("ai/email_model.onnx");
      console.log("[PhishGuard] Loading ONNX Email model from:", modelPath);

      this.emailSession = await ort.InferenceSession.create(modelPath, {
        executionProviders: ["wasm"],
        graphOptimizationLevel: "all",
      });

      console.log("[PhishGuard] Email model loaded.");
      return true;
    } catch (err) {
      console.error("[PhishGuard] Failed to load Email ONNX model:", err);
      this.emailSession = null;
      return false;
    } finally {
      this._loadingEmail = false;
    }
  }

  // ---------------------------------------------------------------------------
  // URL prediction
  // ---------------------------------------------------------------------------

  /**
   * Predict whether a URL is phishing using on-device ONNX inference.
   *
   * Ensemble: ONNX model (75%) + Heuristic rules (25%)
   * Falls back to heuristic-only if ONNX model is unavailable.
   *
   * @param {string} url
   * @returns {Promise<{is_phishing: boolean, confidence: number, risk_level: string, reasons: string[]}>}
   */
  async predictURL(url) {
    // Hard override: known legitimate domain
    const { features, vector } = extractFeatures(url);
    if (features.is_known_legitimate) {
      return this._result(false, 0.01, []);
    }

    // Heuristic prediction (always available, zero latency)
    const hResult = this._heuristicPredict(features);
    const hConf   = hResult.confidence;
    const reasons = hResult.reasons;

    // ONNX prediction (if model is loaded)
    if (this.urlSession) {
      try {
        const mlConf = await this._onnxPredict(this.urlSession, vector);
        return this._combineEnsemble(mlConf, hConf, reasons);
      } catch (err) {
        console.warn("[PhishGuard] ONNX prediction failed, using heuristic:", err.message);
      }
    }

    // Fallback: heuristic only
    return hResult;
  }

  // ---------------------------------------------------------------------------
  // ONNX inference (internal)
  // ---------------------------------------------------------------------------

  /**
   * Run a feature vector through an ONNX InferenceSession.
   * @param {ort.InferenceSession} session
   * @param {Float32Array} vector
   * @returns {Promise<number>} phishing probability (0-1)
   */
  async _onnxPredict(session, vector) {
    const inputName = session.inputNames[0];
    const tensor    = new ort.Tensor("float32", vector, [1, vector.length]);
    const feeds     = { [inputName]: tensor };

    const results   = await session.run(feeds);

    // Output[1] is the probability tensor (shape [1,2]) when zipmap=False
    // Index [0][1] = P(phishing class = 1)
    const probTensor = results[session.outputNames[1]];
    const probData   = probTensor.data;

    // probData is [P(safe), P(phishing)] for the single input row
    return parseFloat(probData[1].toFixed(4));
  }

  // ---------------------------------------------------------------------------
  // Email prediction
  // ---------------------------------------------------------------------------

  /**
   * Predict whether an email is phishing using on-device ONNX inference.
   * Lazily loads the email ONNX model on first call.
   *
   * @param {string} emailText
   * @param {string} sender
   * @param {string} subject
   * @returns {Promise<{is_phishing: boolean, confidence: number, risk_level: string, reasons: string[]}>}
   */
  async predictEmail(emailText, sender = "", subject = "") {
    // Extract 28 email features (email_preprocessor.js must be loaded first)
    const { features, vector } = extractEmailFeatures(emailText, sender, subject);

    // Heuristic email prediction (always available)
    const hResult = this._emailHeuristicPredict(features);
    const hConf   = hResult.confidence;
    const reasons = hResult.reasons;

    // ONNX email prediction (if model is loaded)
    if (this.emailSession) {
      try {
        const mlConf = await this._onnxPredict(this.emailSession, vector);
        return this._combineEnsemble(mlConf, hConf, reasons);
      } catch (err) {
        console.warn("[PhishGuard] Email ONNX failed, using heuristic:", err.message);
      }
    }

    return hResult;
  }

  // ---------------------------------------------------------------------------
  // Heuristic engine (ported from backend/ml/detector.py)
  // ---------------------------------------------------------------------------

  /**
   * Rule-based phishing detection.
   * Mirrors FEATURE_WEIGHTS logic from Python detector.py exactly.
   *
   * @param {Object} f - Feature dict from extractFeatures()
   * @returns {{ is_phishing: boolean, confidence: number, reasons: string[] }}
   */
  _heuristicPredict(f) {
    let score = 0.0;
    const reasons = [];
    let flags = 0;

    if (f.is_ip_address) {
      score += FEATURE_WEIGHTS.is_ip_address;
      reasons.push("Uses raw IP address instead of a domain name");
      flags++;
    }
    if (f.brand_hyphenated) {
      score += FEATURE_WEIGHTS.brand_hyphenated;
      reasons.push("Domain uses a brand name with hyphens (brand spoofing)");
      flags++;
    }
    if (f.brand_in_hostname) {
      score += FEATURE_WEIGHTS.brand_in_hostname;
      reasons.push("Hostname contains a major brand name on a non-official domain");
      flags++;
    }
    if (f.has_suspicious_keyword) {
      score += FEATURE_WEIGHTS.has_suspicious_keyword;
      reasons.push("URL contains phishing-related keywords");
      flags++;
    }
    if (f.is_known_tld_suspicious) {
      score += FEATURE_WEIGHTS.is_known_tld_suspicious;
      reasons.push("Uses a high-risk top-level domain (.xyz, .tk, .ml, etc.)");
      flags++;
    }
    if (f.has_at_symbol) {
      score += FEATURE_WEIGHTS.has_at_symbol;
      reasons.push("URL contains '@' symbol which can obscure the real destination");
      flags++;
    }
    if (f.has_lookalike_chars) {
      score += FEATURE_WEIGHTS.has_lookalike_chars;
      reasons.push("Hostname uses lookalike characters (0→o, 1→l)");
      flags++;
    }
    if (f.has_sensitive_path) {
      score += FEATURE_WEIGHTS.has_sensitive_path;
      reasons.push("URL path contains sensitive terms like 'login', 'account', 'verify'");
      flags++;
    }
    if (f.is_shortened_url) {
      score += FEATURE_WEIGHTS.is_shortened_url;
      reasons.push("URL uses a shortening service to hide the real destination");
      flags++;
    }

    const extraSubdomains = Math.max(0, (f.num_subdomains || 0) - 2);
    if (extraSubdomains > 0) {
      score += FEATURE_WEIGHTS.num_subdomains * extraSubdomains;
      reasons.push(`Excessive subdomain depth (${f.num_subdomains} levels)`);
      flags++;
    }

    const extraDots = Math.max(0, (f.num_dots || 0) - 3);
    if (extraDots > 0) {
      score += FEATURE_WEIGHTS.num_dots_penalty * extraDots;
      reasons.push(`Excessive dot segments count (${f.num_dots} dots) indicating deep obfuscation`);
      flags++;
    }

    if (f.has_encoded_chars) {
      score += FEATURE_WEIGHTS.has_encoded_chars;
      reasons.push("URL contains encoded characters to obfuscate the path");
      flags++;
    }
    if (f.has_redirect_param) {
      score += FEATURE_WEIGHTS.has_redirect_param;
      reasons.push("URL contains redirect parameters");
      flags++;
    }
    if (f.has_double_slash) {
      score += FEATURE_WEIGHTS.has_double_slash;
      reasons.push("URL path contains a double slash redirect technique");
      flags++;
    }
    if ((f.url_length || 0) > 100) {
      score += FEATURE_WEIGHTS.url_length_penalty;
      reasons.push(`Unusually long URL (${f.url_length} characters)`);
      flags++;
    }
    if (!f.uses_https) {
      score += FEATURE_WEIGHTS.no_https_penalty;
      reasons.push("Page served over HTTP (not encrypted HTTPS)");
      flags++;
    }
    if ((f.hostname_entropy || 0) > 3.5) {
      score += FEATURE_WEIGHTS.high_entropy_penalty;
      reasons.push("Hostname has high entropy (randomly generated domain)");
      flags++;
    }

    // Combo boosting: multiple flags = exponentially more suspicious
    if (flags >= 5) {
      score += 0.20;
      reasons.push(`Multi-signal alert: ${flags} suspicious indicators detected`);
    } else if (flags >= 3) {
      score += 0.10;
    }

    const confidence = Math.min(score, 1.0);
    return this._result(confidence >= PHISHING_THRESHOLD, confidence, reasons.slice(0, 6));
  }

  // ---------------------------------------------------------------------------
  // Email heuristic engine (ported from backend/ml/email_detector.py)
  // ---------------------------------------------------------------------------

  /**
   * Rule-based email phishing detection.
   * Mirrors EMAIL_FEATURE_WEIGHTS from email_detector.py.
   */
  _emailHeuristicPredict(f) {
    let score = 0.0;
    const reasons = [];

    if (f.has_urgent_language) {
      score += 0.30;
      reasons.push("Email uses urgency language to pressure the reader");
    }
    if (f.has_threat_language) {
      score += 0.30;
      reasons.push("Email contains threats (suspended, illegal activity, law enforcement)");
    }
    if (f.has_reward_language) {
      score += 0.25;
      reasons.push("Email promises prizes or rewards (lottery, winner, free gift)");
    }
    if (f.has_suspicious_links) {
      score += 0.40;
      reasons.push("Email links point to high-risk domains (.xyz, .tk, .ml, etc.)");
    }
    if (f.has_html_form) {
      score += 0.30;
      reasons.push("Email contains an embedded HTML form (credential harvesting)");
    }
    if (f.has_mismatched_url) {
      score += 0.45;
      reasons.push("Link text and href destination domains do not match");
    }
    if (f.sender_domain_mismatch) {
      score += 0.38;
      reasons.push("Sender domain doesn't match the domains linked in the email");
    }
    if (f.has_spoofed_sender) {
      score += 0.50;
      reasons.push("Sender name contains a brand name but uses an unofficial domain");
    }
    if (f.sender_suspicious_tld) {
      score += 0.35;
      reasons.push("Sender's email domain uses a high-risk TLD");
    }
    if (f.has_dangerous_attachment) {
      score += 0.30;
      reasons.push("Email references a dangerous file type (.exe, .zip, .bat, .scr)");
    }
    if (f.url_phishing_score > 0.5) {
      score += 0.45;
      reasons.push(`Links in email score high on URL phishing model (${(f.url_phishing_score*100).toFixed(0)}%)`);
    }
    if (f.has_base64_content) {
      score += 0.20;
      reasons.push("Email contains Base64-encoded content (obfuscation technique)");
    }
    if (f.has_javascript) {
      score += 0.50;
      reasons.push("Email contains JavaScript (unusual and potentially malicious)");
    }
    if (f.has_hidden_text) {
      score += 0.40;
      reasons.push("Email contains hidden text (display:none, opacity:0)");
    }
    if ((f.urgency_in_subject || 0) >= 2) {
      score += 0.15 * f.urgency_in_subject;
      reasons.push(`Subject line contains ${f.urgency_in_subject} urgency keywords`);
    }
    if ((f.capitalization_ratio || 0) > 0.3) {
      score += 0.12;
      reasons.push("Excessive capitalization in email body (shouting/pressure)");
    }

    const confidence = Math.min(score, 1.0);
    return this._result(confidence >= PHISHING_THRESHOLD, confidence, reasons.slice(0, 6));
  }

  // ---------------------------------------------------------------------------
  // Ensemble combiner
  // ---------------------------------------------------------------------------

  /**
   * Combine ML confidence and heuristic confidence using the same
   * weighted ensemble as the original Python detector.py (75% ML + 25% heuristic).
   */
  _combineEnsemble(mlConf, hConf, reasons) {
    let combined = (mlConf * 0.75) + (hConf * 0.25);

    // If either engine is very confident, boost the score
    if (hConf >= 0.75 || mlConf >= 0.85) {
      combined = Math.max(combined, Math.max(hConf, mlConf));
    }

    // If BOTH agree it's phishing, boost further
    if (hConf >= 0.5 && mlConf >= 0.5) {
      combined = Math.max(combined, (hConf + mlConf) / 2 + 0.05);
    }

    combined = Math.min(combined, 1.0);
    const isPhishing = combined >= PHISHING_THRESHOLD;
    return this._result(isPhishing, parseFloat(combined.toFixed(4)), reasons);
  }

  // ---------------------------------------------------------------------------
  // Result builder
  // ---------------------------------------------------------------------------

  _result(isPhishing, confidence, reasons) {
    let risk;
    if (confidence >= 0.7)      risk = "high";
    else if (confidence >= 0.4) risk = "medium";
    else                        risk = "low";

    if (!isPhishing && confidence < 0.15) risk = "safe";

    return {
      is_phishing: isPhishing,
      confidence:  parseFloat(confidence.toFixed(4)),
      risk_level:  risk,
      reasons:     reasons,
    };
  }
}

// Singleton instance — shared across all calls in the service worker
const predictor = new PhishGuardPredictor();
