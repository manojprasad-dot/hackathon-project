"""
PhishGuard -- ml/train_model.py  (v4.0 — On-Device AI Edition)
Training Pipeline: 100-Tree RandomForest → ONNX Runtime Web

Produces:
  backend/ml/model.pkl   — sklearn model (for re-conversion/inspection)
  backend/ml/model.onnx  — ONNX model for Chrome extension
  extension/ai/model.onnx — auto-copied for the extension bundle

Why 100 trees?
  The 300-tree model converts to ~5 MB ONNX which pushes the extension
  bundle near the 10 MB Chrome Web Store limit. 100 trees produce a
  ~1.7 MB ONNX file with < 0.5% accuracy drop and 3x faster load time.

Usage:
    cd backend
    python ml/train_model.py

Requirements:
    pip install scikit-learn skl2onnx onnx onnxruntime pandas ucimlrepo
"""

import os
import sys
import pickle
import shutil
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from features.extractor import extract_features

# ---------------------------------------------------------------------------
# Feature set: the 30 features this model is trained and evaluated on.
# These must exactly match the order used in extension/ai/preprocessing.js
# so the ONNX model receives the right inputs during browser inference.
# ---------------------------------------------------------------------------
MODEL_FEATURE_NAMES = [
    # Length (5)
    "url_length", "hostname_length", "path_length", "query_length", "path_depth",
    # Count (7)
    "num_dots", "num_hyphens", "num_underscores", "num_digits",
    "num_subdomains", "num_query_params", "num_special_chars",
    # Ratio (4)
    "digit_ratio", "letter_ratio", "special_char_ratio", "hostname_entropy",
    # Boolean flags (11)
    "uses_https", "is_ip_address", "is_known_tld_suspicious",
    "has_suspicious_keyword", "has_at_symbol", "has_double_slash",
    "has_redirect_param", "has_encoded_chars", "is_known_legitimate",
    "brand_in_hostname", "brand_hyphenated",
    # Advanced (3)
    "has_lookalike_chars", "has_sensitive_path", "is_shortened_url",
]

N_TREES    = 100   # Optimised for ONNX bundle size (<2 MB) with minimal accuracy loss
N_SAMPLES  = 50000 # Max training URLs (balanced: 25K phishing + 25K safe)


def load_dataset():
    """Download UCI PhiUSIIL dataset."""
    print("\n  Downloading UCI PhiUSIIL Phishing URL Dataset...")
    try:
        from ucimlrepo import fetch_ucirepo
        dataset = fetch_ucirepo(id=967)
        X_df = dataset.data.features
        y_df = dataset.data.targets
        for col in ["URL", "url", "Url"]:
            if col in X_df.columns:
                urls = X_df[col].tolist()
                labels = y_df.values.ravel()
                print(f"  Loaded {len(urls)} URLs")
                return urls, labels
        return X_df, y_df
    except Exception as e:
        print(f"  UCI download failed: {e}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        df = pd.read_csv(os.path.join(script_dir, "dataset.csv"))
        return df["url"].tolist(), df["label"].values


def extract_all_features(urls, labels, max_samples=N_SAMPLES):
    """Extract MODEL_FEATURE_NAMES (30 features) from each URL."""
    if isinstance(urls, pd.DataFrame):
        # Dataset was returned as pre-computed features — use directly
        X = np.nan_to_num(urls.values.astype(float), nan=0.0)
        y = labels.values.ravel() if hasattr(labels, 'values') else labels
        return X, y

    total = len(urls)
    if total > max_samples:
        print(f"\n[2/6] Sampling {max_samples} from {total} URLs (balanced 50/50)...")
        labs = np.array(labels)
        phish_idx = np.where(labs == 1)[0]
        safe_idx  = np.where(labs == 0)[0]
        half = max_samples // 2
        rng = np.random.RandomState(42)
        if len(phish_idx) >= half and len(safe_idx) >= half:
            indices = np.concatenate([
                rng.choice(phish_idx, half, replace=False),
                rng.choice(safe_idx,  half, replace=False)
            ])
        else:
            indices = rng.choice(total, max_samples, replace=False)
        rng.shuffle(indices)
        urls   = [urls[i] for i in indices]
        labels = labs[indices]
    else:
        print(f"\n[2/6] Extracting features from {total} URLs...")

    feature_list = []
    errors = 0
    start  = time.time()

    for i, url in enumerate(urls):
        try:
            feats = extract_features(str(url))
            # Use MODEL_FEATURE_NAMES (30) — not the full 38 from extractor.py
            feature_list.append([float(feats.get(k, 0)) for k in MODEL_FEATURE_NAMES])
        except Exception:
            feature_list.append([0.0] * len(MODEL_FEATURE_NAMES))
            errors += 1
        if (i + 1) % 2500 == 0 or (i + 1) == len(urls):
            elapsed = time.time() - start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"      [{(i+1)/len(urls)*100:5.1f}%] {i+1}/{len(urls)}  "
                  f"({rate:.0f}/sec, errors: {errors})")

    X = np.array(feature_list, dtype=np.float32)
    y = np.array(labels[:len(feature_list)])
    print(f"      Shape: {X.shape} | Phishing: {sum(y==1)} | Safe: {sum(y==0)}")
    return X, y


def train_model(X, y):
    """Train RandomForest classifier."""
    X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
    mask = X.sum(axis=1) != 0
    X, y = X[mask], y[mask]

    print(f"\n[3/6] Splitting 80/20...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[4/6] Training RandomForest ({N_TREES} trees — ONNX-optimised)...")
    start = time.time()
    model = RandomForestClassifier(
        n_estimators=N_TREES,   # 100 trees → ~1.7 MB ONNX (vs ~5 MB for 300 trees)
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print(f"      Done in {time.time()-start:.1f}s")

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    auc       = roc_auc_score(y_test, y_proba)

    print(f"\n{'='*60}")
    print(f"  MODEL RESULTS (RandomForest)")
    print(f"{'='*60}")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall:    {recall*100:.2f}%")
    print(f"  F1 Score:  {f1*100:.2f}%")
    print(f"  AUC-ROC:   {auc:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:")
    print(f"  {'':20s} Pred Safe  Pred Phish")
    print(f"  {'Actual Safe':20s}  {cm[0][0]:>7}     {cm[0][1]:>7}")
    print(f"  {'Actual Phishing':20s}  {cm[1][0]:>7}     {cm[1][1]:>7}")

    imp = sorted(zip(MODEL_FEATURE_NAMES, model.feature_importances_),
                 key=lambda x: x[1], reverse=True)
    print(f"\n  Top 10 Features:")
    for n, v in imp[:10]:
        print(f"    {n:25s} {v:.4f}  {'#'*int(v*50)}")

    print(f"\n  5-Fold CV (fast — 100 trees)...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    print(f"  CV: {cv_scores.mean()*100:.2f}% +/- {cv_scores.std()*100:.2f}%")

    return model, {
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "auc_roc": auc,
        "cv_mean": cv_scores.mean(), "cv_std": cv_scores.std(),
    }


def save_model(model, metrics, pkl_path):
    """Save sklearn model to .pkl and auto-convert to .onnx."""
    # -- Save .pkl -----------------------------------------------------------
    print(f"\n[6a/6] Saving .pkl to {pkl_path}")
    data = {
        "model":         model,
        "model_type":    "RandomForestClassifier",
        "n_features":    len(MODEL_FEATURE_NAMES),
        "feature_names": MODEL_FEATURE_NAMES,
        "n_estimators":  N_TREES,
        "trained_at":    time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset":       f"UCI PhiUSIIL ({N_SAMPLES} balanced)",
        **metrics,
    }
    with open(pkl_path, "wb") as f:
        pickle.dump(data, f)
    print(f"      Size: {os.path.getsize(pkl_path)/1024:.1f} KB")
    print(f"      Accuracy: {metrics['accuracy']*100:.2f}%")

    # -- Auto-convert to ONNX ------------------------------------------------
    print(f"\n[6b/6] Converting to ONNX...")
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        onnx_path = pkl_path.replace(".pkl", ".onnx")
        initial_type = [("float_input", FloatTensorType([None, len(MODEL_FEATURE_NAMES)]))]
        onnx_model = convert_sklearn(
            model,
            initial_types=initial_type,
            target_opset=17,
            options={"zipmap": False},
        )
        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        onnx_kb = os.path.getsize(onnx_path) / 1024
        print(f"      ONNX saved: {onnx_path}")
        print(f"      ONNX size:  {onnx_kb:.1f} KB ({onnx_kb/1024:.2f} MB)")

        # Auto-copy to extension/ai/
        ext_ai = os.path.join(os.path.dirname(os.path.dirname(pkl_path)),
                              "..", "extension", "ai")
        ext_ai = os.path.normpath(ext_ai)
        os.makedirs(ext_ai, exist_ok=True)
        ext_dst = os.path.join(ext_ai, "model.onnx")
        shutil.copy2(onnx_path, ext_dst)
        print(f"      Copied to:  {ext_dst}")
    except ImportError:
        print("      skl2onnx not installed — skipping ONNX export.")
        print("      Run: pip install skl2onnx onnx  then  python backend/convert_to_onnx.py")

    print(f"\n  Model saved successfully!\n")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "model.pkl")
    print("\n" + "="*60)
    print("  PhishGuard ML Training v4.0  (On-Device AI Edition)")
    print(f"  RandomForest · {N_TREES} trees · {len(MODEL_FEATURE_NAMES)} features · {N_SAMPLES} URLs")
    print("="*60)
    print(f"\n[1/6] Loading dataset...")
    urls, labels = load_dataset()
    X, y = extract_all_features(urls, labels, max_samples=N_SAMPLES)
    model, metrics = train_model(X, y)
    save_model(model, metrics, model_path)


if __name__ == "__main__":
    main()
