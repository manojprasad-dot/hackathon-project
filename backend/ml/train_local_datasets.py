"""
PhishGuard -- ml/train_local_datasets.py  (v4.0 — Local Dataset Training)
Combines archive.zip (PhishTank + Tranco) and phiusiil+phishing+url+dataset.zip to train a 100-Tree RandomForest,
converts it to ONNX, and copies it to the extension folder.
"""

import os
import sys
import zipfile
import pandas as pd
import numpy as np
import pickle
import shutil
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import skl2onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from features.extractor import extract_features

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

def load_local_datasets():
    print("\n[1/5] Loading local datasets from zip archives...")
    phish_urls = []
    safe_urls = []

    # 1. Parse archive.zip (verified_online.csv and tranco_6GQGX.csv)
    archive_path = "d:/hackathon-project/archive.zip"
    if os.path.exists(archive_path):
        print(f"  Reading from {archive_path}...")
        try:
            with zipfile.ZipFile(archive_path, 'r') as z:
                # Phishing
                if "verified_online.csv" in z.namelist():
                    with z.open("verified_online.csv") as f:
                        df = pd.read_csv(f)
                        phish_urls.extend(df["url"].dropna().astype(str).tolist())
                        print(f"    Loaded {len(df)} phishing URLs from verified_online.csv")
                # Safe
                if "tranco_6GQGX.csv" in z.namelist():
                    with z.open("tranco_6GQGX.csv") as f:
                        # Tranco has no headers; format: rank,domain
                        df = pd.read_csv(f, header=None)
                        domains = df[1].dropna().astype(str).tolist()
                        # Prepend https://
                        safe_urls.extend([f"https://{d}" for d in domains])
                        print(f"    Loaded {len(domains)} safe URLs from tranco_6GQGX.csv")
        except Exception as e:
            print(f"    Error reading archive.zip: {e}")

    # 2. Parse phiusiil+phishing+url+dataset.zip (PhiUSIIL_Phishing_URL_Dataset.csv)
    phi_path = "d:/hackathon-project/phiusiil+phishing+url+dataset.zip"
    if os.path.exists(phi_path):
        print(f"  Reading from {phi_path}...")
        try:
            with zipfile.ZipFile(phi_path, 'r') as z:
                if "PhiUSIIL_Phishing_URL_Dataset.csv" in z.namelist():
                    with z.open("PhiUSIIL_Phishing_URL_Dataset.csv") as f:
                        df = pd.read_csv(f, encoding='utf-8-sig')
                        # Extract URL column and label column
                        df_phish = df[df["label"] == 1]
                        df_safe = df[df["label"] == 0]
                        phish_urls.extend(df_phish["URL"].dropna().astype(str).tolist())
                        safe_urls.extend(df_safe["URL"].dropna().astype(str).tolist())
                        print(f"    Loaded {len(df_phish)} phishing and {len(df_safe)} safe URLs from PhiUSIIL")
        except Exception as e:
            print(f"    Error reading PhiUSIIL zip: {e}")

    # Remove duplicates
    phish_urls = list(set(phish_urls))
    safe_urls = list(set(safe_urls))
    print(f"  Unique Phishing URLs count: {len(phish_urls)}")
    print(f"  Unique Safe URLs count:     {len(safe_urls)}")

    # Balance 50/50 dataset to N_SAMPLES
    n_samples = min(30000, len(phish_urls), len(safe_urls))
    print(f"  Balancing dataset to {n_samples * 2} URLs (half safe, half phishing)...")
    
    np.random.seed(42)
    phish_indices = np.random.choice(len(phish_urls), n_samples, replace=False)
    safe_indices = np.random.choice(len(safe_urls), n_samples, replace=False)

    selected_phish = [phish_urls[i] for i in phish_indices]
    selected_safe = [safe_urls[i] for i in safe_indices]

    urls = selected_phish + selected_safe
    labels = [1] * n_samples + [0] * n_samples

    return urls, labels

def main():
    urls, labels = load_local_datasets()

    print("\n[2/5] Extracting 30 features from URLs (this may take a minute)...")
    X_data = []
    y_data = []
    
    start_time = time.time()
    for idx, (url, label) in enumerate(zip(urls, labels)):
        feats = extract_features(url)
        # Convert feature dictionary to array ordered by MODEL_FEATURE_NAMES
        row = [float(feats.get(name, 0.0)) for name in MODEL_FEATURE_NAMES]
        X_data.append(row)
        y_data.append(label)
        if (idx + 1) % 10000 == 0:
            print(f"    Extracted features for {idx + 1} URLs...")
            
    X = np.array(X_data)
    y = np.array(y_data)
    print(f"  Extraction completed in {time.time() - start_time:.1f} seconds.")

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("\n[3/5] Training 100-Tree RandomForest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"  Model Accuracy: {accuracy * 100:.2f}%")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred))

    # Feature Importance analysis
    print("\n  Feature Importance Analysis:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for f in range(10):
        print(f"    {f+1}. Feature '{MODEL_FEATURE_NAMES[indices[f]]}' : {importances[indices[f]]:.4f}")

    # Save pickle
    pickle_path = "d:/hackathon-project/backend/ml/model.pkl"
    with open(pickle_path, "wb") as f:
        pickle.dump(model, f)
    print(f"\n[4/5] Saved legacy pickle model to: {pickle_path}")

    # Convert to ONNX
    print("\n[5/5] Exporting RandomForest to ONNX format...")
    initial_type = [('float_input', FloatTensorType([None, len(MODEL_FEATURE_NAMES)]))]
    # Disable ZipMap to get raw class probabilities tensor
    onnx_model = convert_sklearn(model, initial_types=initial_type, options={'zipmap': False})

    # Save local ONNX
    onnx_path = "d:/hackathon-project/backend/ml/model.onnx"
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"  Saved compiled model.onnx to: {onnx_path}")

    # Copy to extension asset bundle
    extension_onnx_path = "d:/hackathon-project/extension/ai/model.onnx"
    shutil.copyfile(onnx_path, extension_onnx_path)
    print("\nTraining completed successfully! [OK]")

if __name__ == "__main__":
    main()
