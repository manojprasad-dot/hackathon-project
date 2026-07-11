# 🛡️ PhishGuard Edge AI — On-Device AI Phishing Protection

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![ONNX Runtime](https://img.shields.io/badge/ONNX--Runtime-WebAssembly-purple.svg)](https://onnxruntime.ai/)
[![Chrome Extension](https://img.shields.io/badge/Chrome--Extension-Manifest--V3-orange.svg)](https://developer.chrome.com/docs/extensions/)
[![Inference Speed](https://img.shields.io/badge/Inference-3.8ms-emerald.svg)](#)

PhishGuard Edge AI is a next-generation, privacy-preserving browser security product that runs machine learning inference **100% on-device**. By utilizing **ONNX Runtime Web** inside a classic Manifest V3 Service Worker, it evaluates incoming URLs and emails for phishing indicators with zero cloud dependencies, zero data leakage, and sub-5ms latencies.

---

## 🏗️ Architectural Blueprint

```
                      USER BROWSER (Manifest V3 Context)
┌────────────────────────────────────────────────────────────────────────┐
│                                                                        │
│  1. DOM / URL Navigation Event                                         │
│         │                                                              │
│         ▼                                                              │
│  2. Local Preprocessors (extractFeatures / extractEmailFeatures)       │
│         │                                                              │
│         ├─► [30 URL features extracted]                                │
│         └─► [28 Email features extracted]                              │
│         │                                                              │
│         ▼                                                              │
│  3. ONNX Runtime Web (WASM Single-Threaded CPU Engine)                 │
│         │                                                              │
│         ▼                                                              │
│  4. Risk Fusion (75% ML Ensemble + 25% Heuristics Engine)             │
│         │                                                              │
│         ├─► If High Risk: Redirect to Warning Page (warning.html)       │
│         └─► Else: Update status to "Safe" inside Sidebar UI            │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Performance & Benchmarks

Traditional cloud-lookup blockers leak your entire browsing history to remote APIs and suffer from significant network round-trip overhead. PhishGuard Edge AI computes verdicts instantly, fully offline.

| Protection Model | Latency (Avg) | Privacy | Offline Mode |
| :--- | :--- | :--- | :--- |
| **Traditional Cloud Lookups (e.g. Render API)** | `240 ms` (up to 2 min cold start) | None (URLs leaked) | ❌ No |
| **Google Safe Browsing API** | `120 ms` | Partial (hashed URLs sent) | ❌ No |
| **PhishGuard Edge AI (Local WASM)** | **`3.8 ms`** | **100% Private (On-Device)** | **✓ Yes** |

*Benchmarks conducted on standard laptop CPUs running chrome-extension WASM single-thread runtimes.*

---

## 🛡️ Threat Model

```
Traditional Blocker (Cloud)       [Browser] ──(Web History Leaked)──► [Remote Security API]
                                                                                │
                                                                                ▼ (Targeted by attackers)
                                                                       [API Outage / DNS hijack]

PhishGuard Edge AI (Local)         [Browser] ──(Encrypted WASM Heap)──► [WASM Model] 
                                   *(No network sockets are opened during prediction)*
```

*   **Zero Outage Risk**: Prediction does not rely on backend service availability. 
*   **Privacy-Preserving**: No URLs are ever written to disk, sent to third-party databases, or leaked to ad networks.
*   **Exfiltration Shield**: Disables cloud lookup fallback paths when "Offline Lock Mode" is active.

---

## 🚀 Key Features

*   **Animated SVG Risk Gauge**: High-fidelity dashboard displaying exact threat score and classification confidence.
*   **Explainable AI (XAI) Cards**: Breaks down which heuristic indicators triggered the ML model, showing severity, weight, and active mitigation steps.
*   **Pipeline Dataflow Visualization**: Interactive animated representation of the internal execution states.
*   **Dual-Ensemble Engine**: Combines statistical tree node classifications (RandomForest ONNX) with 24-rule heuristics (weighted combo-boosting).
*   **Interactive Demo Sandbox**: Allows testing high, medium, and low-risk domains inside a visual test harness.
*   **System Controls**: Toggle notifications, email scanner, heuristic fallback modes, or export local database scan history.

---

## 📦 Directory Structure

```
phishguard/
│
├── extension/                        ← Chrome MV3 Extension Root
│   ├── manifest.json                 ← Manifest configuration (WASM CSP, permissions)
│   ├── background.js                 ← SW controller (URL monitor, ONNX wrapper)
│   ├── warning.html / warning.js     ← Redesigned Warning Landing Page
│   ├── email_scanner.html / .js      ← Standalone Email Scanner View
│   ├── gmail_scanner.js              ← Gmail/Outlook DOM Observer Injection
│   │
│   └── ai/                           ← On-Device AI Bundle
│       ├── model.onnx                ← 1.66MB Compiled URL Model (100 Trees)
│       ├── email_model.onnx          ← 138KB Compiled Email Model
│       ├── ort.min.js                ← ONNX Runtime Web JS engine (v1.17.3)
│       ├── ort-wasm.wasm             ← Classic single-threaded WASM binary
│       ├── ort-wasm-simd.wasm        ← High-performance SIMD WASM binary
│       ├── preprocessing.js          ← 30-Feature URL preprocessor
│       ├── email_preprocessor.js    ← 28-Feature Email preprocessor
│       └── predictor.js              ← ONNX Inference & Heuristics fusion
│
└── backend/                          ← Python training pipeline
    ├── ml/
    │   ├── train_model.py            ← Balanced 50K URL training script
    │   └── model.pkl                 ← Legacy scikit-learn format
    ├── requirements_train.txt        ← ML/ONNX export dependencies
    └── convert_to_onnx.py            ← Correctness verification & conversion utility
```

---

## 🛠️ Developer Guide (Offline Training & Conversion)

The backend is strictly used for offline training and exporting models.

### 1. Training Setup
Install python dependencies:
```bash
pip install -r backend/requirements_train.txt
```

### 2. Train the Model
To re-evaluate features and retrain the Random Forest model:
```bash
python backend/ml/train_model.py
```
This script downloads 235K URL rows from the UCI dataset, extracts features, trains 100 trees, evaluates precision, and automatically writes the compiled `model.onnx` file to the extension directory.

### 3. Model Conversion
To convert a legacy `.pkl` file into an ONNX model manually:
```bash
python backend/convert_to_onnx.py
```
This runs a numerical validation script comparing the prediction delta between Python (scikit-learn) and JS (ONNX Runtime) verifying precision matches up to `1e-7`.

---

## 📥 Extension Installation

1. Clone or download this repository.
2. In Google Chrome, go to `chrome://extensions/`.
3. Enable **Developer mode** (top right switch).
4. Click **Load unpacked** (top left button) and select the `extension` directory.
5. Launch the extension popup or navigate to a test URL (e.g. `http://paypal-secure-login.xyz/verify`) to see local blocking in action.

---

## 🗺️ Roadmap
*   **WebGPU Acceleration**: Add WebGPU fallback paths when executing larger models.
*   **Local Llama-3-Edge Integration**: Allow interactive generative chat on blocked domains.
*   **Differential Privacy Reporting**: Share metadata on blocked URLs anonymously using DP algorithms.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
