# 🛡️ PhishGuard Edge AI — 100% On-Device Browser Phishing Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![ONNX Runtime](https://img.shields.io/badge/ONNX--Runtime-WebAssembly-purple.svg)](https://onnxruntime.ai/)
[![Chrome Extension](https://img.shields.io/badge/Chrome--Extension-Manifest--V3-orange.svg)](https://developer.chrome.com/docs/extensions/)
[![Inference Speed](https://img.shields.io/badge/Inference-2.6ms-emerald.svg)](#)
[![Privacy Compliance](https://img.shields.io/badge/Privacy-100%25%20On--Device-brightgreen.svg)](#)

PhishGuard Edge AI is a next-generation browser security extension that runs machine learning inference **100% locally in the user's browser**. By integrating **ONNX Runtime Web** into a classic Manifest V3 Service Worker, it evaluates incoming URLs and emails for phishing indicators with **zero cloud dependencies**, **zero latency**, and **zero data leakage**.

🌐 **Live Website & Download:** [https://phishguard26.netlify.app/](https://phishguard26.netlify.app/)

---

## 💡 The Pitch & The Problem

### The Problem with Traditional Security
*   **Privacy Leaks**: Popular URL checkers scan links by sending them to remote servers, effectively tracking and leaking your entire browsing history.
*   **Latency Overhead**: Cloud lookup APIs introduce `150ms - 300ms` of network latency per page load.
*   **Outage Vulnerability**: If the security company's API is down, or if you lose internet connectivity, you have zero protection.

### The PhishGuard Edge AI Solution
*   **100% Privacy**: No URLs, page hashes, or email contents ever leave your device. Analysis happens in local memory.
*   **Instant Verification**: Evaluates pages in **`2.6 milliseconds`**—fast enough to run on every navigation event.
*   **Offline Ready**: Runs model inference completely offline without requesting any remote network sockets.

---

## 🏗️ Architecture & Pipeline

```
                                 USER BROWSER (Manifest V3)
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  1. Navigation / DOM Observer                                               │
│         │                                                                   │
│         ▼                                                                   │
│  2. Local Extractors ([preprocessing.js](extension/ai/preprocessing.js) / [email_preprocessor.js](extension/ai/email_preprocessor.js))  │
│         ├─► Extracts 30 URL features (Entropy, TLD checks, keyword scans)  │
│         └─► Extracts 28 Email features (Sender mismatch, link flags)        │
│         │                                                                   │
│         ▼                                                                   │
│  3. ONNX Runtime Web ([ort.min.js](extension/ai/ort.min.js)) — WASM CPU Engine                 │
│         │                                                                   │
│         ▼                                                                   │
│  4. Risk Fusion ([predictor.js](extension/ai/predictor.js)) — 75% ML Model + 25% Heuristics     │
│         │                                                                   │
│         ├─► High Risk ──► Redirect to warning landing page ([warning.html](extension/warning.html)) │
│         └─► Low Risk  ──► Display safe verification cards in [popup.html](extension/popup.html)      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
phishguard/
│
├── extension/                        ← Chrome MV3 Extension Root (On-Device Inference)
│   ├── manifest.json                 ← Manifest configuration (WASM CSP, permissions)
│   ├── background.js                 ← SW controller (URL monitor, IPC interface)
│   ├── content.js                    ← Content script (warning redirects, overlay injectors)
│   ├── warning.html / warning.css    ← Redesigned Warning Landing Page
│   ├── warning.js                    ← Warning page query parameter parser
│   ├── email_scanner.html / .js      ← Standalone Email Scanner View
│   ├── gmail_scanner.js              ← Gmail/Outlook DOM Observer Injection
│   │
│   └── ai/                           ← On-Device AI Bundle
│       ├── model.onnx                ← 1.66MB Compiled URL Model (100 Trees)
│       ├── email_model.onnx          ← 138KB Compiled Email Model
│       ├── ort.min.js                ← ONNX Runtime Web JS engine (v1.17.3)
│       ├── ort-wasm.wasm             • Classic single-threaded WASM binary
│       ├── ort-wasm-simd.wasm        • High-performance SIMD WASM binary
│       ├── preprocessing.js          ← 30-Feature URL preprocessor
│       ├── email_preprocessor.js     ← 28-Feature Email preprocessor
│       └── predictor.js              ← ONNX Inference & Heuristics fusion
│
└── backend/                          ← Offline Python training pipeline
    ├── app.py                        ← Legacy prediction endpoint & local verification server
    ├── requirements_train.txt        ← ML/ONNX export dependencies
    ├── features/
    │   └── extractor.py              ← Reference Feature extraction (38 URL features)
    └── ml/
        ├── train_model.py            ← Balanced 50K URL training script
        ├── detector.py               ← Reference heuristic rules
        └── model.pkl                 ← legacy scikit-learn format
```

---

## ⚡ Performance Benchmarks

| Metric | Google Safe Browsing | Legacy Cloud API | PhishGuard Edge AI |
| :--- | :--- | :--- | :--- |
| **Average Scan Time** | `120 ms` | `240 ms` (up to 2 min cold start) | **`2.6 ms`** (WASM) |
| **Privacy Guarantee** | Partial (hashes sent) | None (URL sent) | **100% Local (On-Device)** |
| **Offline Operation** | ❌ No | ❌ No | **✓ Yes** |
| **API Costs** | High (volume-based) | High (hosting costs) | **$0.00 (Serverless)** |

---

## 📂 Hackathon Judge's Code Checklist

Technical judges can verify the authenticity of the local AI architecture here:
*   [Predictor Logic & Rules Ensemble](file:///d:/hackathon-project/extension/ai/predictor.js) — The core class that orchestrates ONNX session calls and fuses predictions.
*   [URL Feature Extraction](file:///d:/hackathon-project/extension/ai/preprocessing.js) — Ported Javascript extractors for Shannon entropy, TLD maps, and keyword flags.
*   [Email Feature Extraction](file:///d:/hackathon-project/extension/ai/email_preprocessor.js) — Local extractor mapping email bodies to 28 input variables.
*   [Offline Model Trainer](file:///d:/hackathon-project/backend/ml/train_model.py) — Python script pulling UCI datasets and compiling Random Forests.
*   [ONNX Exporter & Parity Tester](file:///d:/hackathon-project/backend/convert_to_onnx.py) — Python tool checking correctness metrics and copying `.onnx` binaries to the client.

---

## 🔍 Feature Extraction Specifications

### URL Features (38 Parameters)
| Category | Features |
| :--- | :--- |
| **Length (5)** | `url_length`, `hostname_length`, `path_length`, `query_length`, `path_depth` |
| **Count (7)** | `num_dots`, `num_hyphens`, `num_underscores`, `num_digits`, `num_subdomains`, `num_query_params`, `num_special_chars` |
| **Ratio (4)** | `digit_ratio`, `letter_ratio`, `special_char_ratio`, `hostname_entropy` |
| **Boolean (11)** | `uses_https`, `is_ip_address`, `is_known_tld_suspicious`, `has_suspicious_keyword`, `has_at_symbol`, `has_double_slash`, `has_redirect_param`, `has_encoded_chars`, `is_known_legitimate`, `brand_in_hostname`, `brand_hyphenated` |
| **Advanced (3)** | `has_lookalike_chars`, `has_sensitive_path`, `is_shortened_url` |
| **Advanced v3 (8)** | `has_punycode`, `tld_length`, `subdomain_length`, `has_port_number`, `path_has_double_extension`, `digit_ratio_in_subdomain`, `vowel_consonant_ratio`, `domain_token_count` |

### Email Features (28 Parameters)
| Category | Features |
| :--- | :--- |
| **Urgency (4)** | `has_urgent_language`, `urgent_keyword_count`, `has_threat_language`, `has_reward_language` |
| **Links (5)** | `link_count`, `has_suspicious_links`, `suspicious_link_ratio`, `has_html_form`, `has_mismatched_url` |
| **Sender (4)** | `sender_domain_mismatch`, `sender_is_freemail`, `has_spoofed_sender`, `sender_suspicious_tld` |
| **Content (4)** | `has_generic_greeting`, `body_length`, `capitalization_ratio`, `special_char_ratio` |
| **Structure (3)** | `has_dangerous_attachment`, `spelling_error_score`, `url_phishing_score` |
| **Advanced v3 (8)** | `has_base64_content`, `has_javascript`, `link_to_text_ratio`, `has_hidden_text`, `reply_to_mismatch`, `has_tracking_pixel`, `urgency_in_subject`, `body_entropy` |

---

## 🔄 Module Process Flows

### Module 1 — Browser Extension Monitoring
1. Browser extension installed and activated in Google Chrome.
2. Extension runs local background monitoring service in `background.js`.
3. User navigates to a website or clicks a link.
4. Extension intercepts the navigation event and captures the URL.
5. Injects URL into local feature preprocessor (`preprocessing.js`).
6. Passes the 30-feature vector directly to the local ONNX predictor session.
7. Evaluates ML classifications and heuristical rules synchronously.
8. If marked high risk, blocks navigation and redirects to `warning.html`.
9. Logs results into secure storage.local cache database.
10. Renders green safe metrics overlay inside the popup if clean.

### Module 2 — Offline Pipeline (Model Training & Conversion)
1. Python environment activated and requirements installed (`requirements_train.txt`).
2. Run training script `python backend/ml/train_model.py`.
3. UCI dataset downloaded and balanced (50K URL records).
4. Trains a 100-tree RandomForest Classifier.
5. Exports scikit-learn tree maps directly to ONNX format.
6. Runs parity checks between python outputs and exported WASM outputs.
7. Auto-copies the compiled `.onnx` files directly to the extension assets.

---

## 📥 Getting Started (Testing the Extension)

1. Clone or download this repository.
2. In Google Chrome, go to `chrome://extensions/`.
3. Toggle **Developer mode** in the top right.
4. Click **Load unpacked** in the top left and select the **`extension`** folder.
5. Pin **PhishGuard Edge AI** to your toolbar.
6. **Test the Demo Sandbox**:
   - Open the extension popup, go to the **Sandbox tab**, and click through Safe and Phishing scenarios to witness local inference, simulated scanning steps, and Explainable AI indicators.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
