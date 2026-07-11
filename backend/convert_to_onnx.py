"""
PhishGuard -- backend/convert_to_onnx.py
=========================================
Converts trained sklearn RandomForest models to ONNX format
for local inference inside the Chrome extension via ONNX Runtime Web.

Models converted:
  backend/ml/model.pkl       -> backend/ml/model.onnx
                             -> extension/ai/model.onnx  (auto-copied)

  backend/ml/email_model.pkl -> backend/ml/email_model.onnx
                             -> extension/ai/email_model.onnx (auto-copied)

Usage:
    cd d:/hackathon-project
    python backend/convert_to_onnx.py

Requirements:
    pip install skl2onnx onnx onnxruntime
"""

import os
import sys
import pickle
import shutil
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(SCRIPT_DIR, "ml")
EXT_AI_DIR = os.path.join(SCRIPT_DIR, "..", "extension", "ai")

URL_PKL = os.path.join(ML_DIR, "model.pkl")
EMAIL_PKL = os.path.join(ML_DIR, "email_model.pkl")
URL_ONNX = os.path.join(ML_DIR, "model.onnx")
EMAIL_ONNX = os.path.join(ML_DIR, "email_model.onnx")


def _load_pkl(path):
    with open(path, "rb") as f:
        data = pickle.load(f)
    if isinstance(data, dict):
        return data["model"], data.get("feature_names", []), data
    return data, [], {}


def _convert(model, n_features, out_path, label):
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    print(f"\n  [{label}] Converting...")
    print(f"    n_estimators   : {model.n_estimators}")
    print(f"    n_features_in_ : {model.n_features_in_}")

    initial_type = [("float_input", FloatTensorType([None, n_features]))]
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=17,
        options={"zipmap": False},
    )
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_kb = os.path.getsize(out_path) / 1024
    print(f"    Saved: {out_path}")
    print(f"    Size : {size_kb:.1f} KB ({size_kb/1024:.2f} MB)")
    return onnx_model


def _verify(sklearn_model, onnx_path, n_features, label):
    import onnxruntime as ort

    print(f"\n  [{label}] Verifying correctness...")
    rng = np.random.RandomState(42)
    X_test = rng.rand(200, n_features).astype(np.float32)

    sk_proba = sklearn_model.predict_proba(X_test)[:, 1]

    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    ort_out = sess.run(None, {input_name: X_test})
    ort_proba = ort_out[1][:, 1]

    max_err = float(np.max(np.abs(sk_proba - ort_proba)))
    print(f"    Max absolute error: {max_err:.2e}")
    if max_err < 1e-4:
        print(f"    OK -- ONNX matches sklearn within tolerance")
    else:
        print(f"    WARN -- error {max_err:.2e} exceeds 1e-4 (may still be acceptable)")


def _copy_to_ext(src, filename):
    os.makedirs(EXT_AI_DIR, exist_ok=True)
    dst = os.path.join(EXT_AI_DIR, filename)
    shutil.copy2(src, dst)
    kb = os.path.getsize(dst) / 1024
    print(f"    Copied to extension/ai/{filename}  ({kb:.1f} KB)")


def convert_url_model():
    print("\n" + "=" * 56)
    print("  [1/2] URL Model (model.pkl)")
    print("=" * 56)
    if not os.path.exists(URL_PKL):
        print(f"  ERROR: {URL_PKL} not found.")
        return False
    model, feature_names, meta = _load_pkl(URL_PKL)
    print(f"  accuracy : {meta.get('accuracy','?')}")
    print(f"  features : {feature_names}")
    _convert(model, model.n_features_in_, URL_ONNX, "URL")
    _verify(model, URL_ONNX, model.n_features_in_, "URL")
    _copy_to_ext(URL_ONNX, "model.onnx")
    return True


def convert_email_model():
    print("\n" + "=" * 56)
    print("  [2/2] Email Model (email_model.pkl)")
    print("=" * 56)
    if not os.path.exists(EMAIL_PKL):
        print(f"  ERROR: {EMAIL_PKL} not found.")
        return False
    model, feature_names, meta = _load_pkl(EMAIL_PKL)
    print(f"  accuracy : {meta.get('accuracy','?')}")
    print(f"  features : {feature_names}")
    _convert(model, model.n_features_in_, EMAIL_ONNX, "Email")
    _verify(model, EMAIL_ONNX, model.n_features_in_, "Email")
    _copy_to_ext(EMAIL_ONNX, "email_model.onnx")
    return True


def print_summary():
    print("\n" + "=" * 56)
    print("  CONVERSION COMPLETE")
    print("=" * 56)
    for label, path in [
        ("backend/ml/model.onnx",          URL_ONNX),
        ("backend/ml/email_model.onnx",    EMAIL_ONNX),
        ("extension/ai/model.onnx",        os.path.join(EXT_AI_DIR, "model.onnx")),
        ("extension/ai/email_model.onnx",  os.path.join(EXT_AI_DIR, "email_model.onnx")),
    ]:
        exists = os.path.exists(path)
        kb = os.path.getsize(path) / 1024 if exists else 0
        mark = "OK" if exists else "MISSING"
        print(f"  {mark}  {label:<42}  {kb:>8.1f} KB")
    print()


def main():
    print("\n" + "=" * 56)
    print("  PhishGuard -- ONNX Conversion Pipeline")
    print("  sklearn RandomForest -> ONNX Runtime Web")
    print("=" * 56)

    try:
        import skl2onnx, onnx, onnxruntime
        print(f"\n  skl2onnx    : {skl2onnx.__version__}")
        print(f"  onnx        : {onnx.__version__}")
        print(f"  onnxruntime : {onnxruntime.__version__}")
    except ImportError as e:
        print(f"  ERROR: {e}")
        print("  Run: pip install skl2onnx onnx onnxruntime")
        sys.exit(1)

    ok1 = convert_url_model()
    ok2 = convert_email_model()

    if ok1 and ok2:
        print_summary()
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
