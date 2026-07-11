# PhishGuard Backend — ML pipeline (v4.0 On-Device AI Edition)

The PhishGuard backend is optimized for local, privacy-preserving client inference. Instead of running a live inference server (which introduces network latency, cold starts, and privacy concerns), all active predictions are performed 100% locally inside the user's browser using **ONNX Runtime Web**.

The backend is now solely responsible for **offline training**, **dataset management**, and **ONNX model conversion**.

---

## Architecture Overview

```
[ UCI Dataset / Local CSV ] ──> [ train_model.py ] ──> model.pkl (scikit-learn)
                                       │
                                       └──> [ convert_to_onnx.py ] ──> model.onnx (ONNX)
                                                                            │
                                                                            └──> Copy to extension/ai/
```

- **Inference**: Handled in-browser via `extension/ai/ort.min.js`, `extension/ai/preprocessing.js`, and `extension/ai/predictor.js`.
- **Training**: Executed offline using scikit-learn and the UCI PhiUSIIL dataset.
- **Conversion**: Converts scikit-learn models to ONNX format using `skl2onnx` targeting opset 17.

---

## Getting Started (Training & Conversion)

### 1. Install Training Dependencies
Create a virtual environment and install the required machine learning packages:
```bash
pip install -r requirements_train.txt
```

### 2. Train the URL Model
To train the URL classification model:
```bash
python ml/train_model.py
```
This script will:
1. Download the latest **UCI PhiUSIIL Phishing URL Dataset** (approx. 235K URL records).
2. Balance and sample 50,000 URLs.
3. Extract 30 structured features from each URL matching the browser preprocessor.
4. Train a 100-tree RandomForest Classifier (optimized to keep size under 2MB).
5. Output `ml/model.pkl` and auto-convert it to `ml/model.onnx`.
6. Copy the compiled `model.onnx` directly into `../extension/ai/model.onnx`.

### 3. Convert Existing Models manually
If you have trained models (such as `email_model.pkl`) that you need to re-convert to ONNX:
```bash
python convert_to_onnx.py
```
This converts `model.pkl` and `email_model.pkl` to their corresponding `.onnx` files, verifies numerical correctness (verifying that ONNX matches scikit-learn within `< 1e-4` tolerance), and bundles them inside the browser extension directory.
