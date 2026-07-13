# 🔬 Technical Specifications & Mathematical Formulations

Detailed algorithmic and mathematical analysis of the PhishGuard Edge AI on-device inference pipeline.

---

## 1. Risk Score Fusion Engine

PhishGuard uses a **weighted ensemble** combining ML model predictions with heuristic rule evaluations:

$$R_{\text{final}} = \alpha \cdot P_{\text{ONNX}} + \beta \cdot \min\left(1.0, \sum_{i=1}^{n} w_i \cdot f_i\right)$$

| Parameter | Value | Description |
|-----------|-------|-------------|
| $\alpha$ | 0.75 | Weight of the ONNX Random Forest classifier |
| $\beta$ | 0.25 | Weight of the heuristic validation engine |
| $P_{\text{ONNX}}$ | [0, 1] | Probability output from the ONNX WASM model |
| $w_i$ | [0, 1] | Weight for heuristic rule $i$ |
| $f_i$ | {0, 1} | Binary outcome of rule evaluation $i$ |

### Decision Thresholds

| Zone | Score Range | Action |
|------|------------|--------|
| **Safe** | $R \le 0.30$ | Green badge, no intervention |
| **Warning** | $0.30 < R \le 0.50$ | Amber indicators, user alerted |
| **Danger** | $R > 0.50$ | Immediate redirect to `warning.html` |

### Ensemble Boosting Logic

When both engines agree, the score is boosted:
- If either engine scores ≥ 0.75 (heuristic) or ≥ 0.85 (ML): `combined = max(combined, max(hConf, mlConf))`
- If both score ≥ 0.50: `combined = max(combined, avg + 0.05)`

---

## 2. Feature Extraction Pipeline

### 30 URL Features

| Category | Features | Count |
|----------|----------|-------|
| **Length** | url_length, hostname_length, path_length, query_length, path_depth | 5 |
| **Count** | num_dots, num_hyphens, num_underscores, num_digits, num_subdomains, num_query_params, num_special_chars | 7 |
| **Ratio** | digit_ratio, letter_ratio, special_char_ratio, hostname_entropy | 4 |
| **Boolean** | uses_https, is_ip_address, is_known_tld_suspicious, has_suspicious_keyword, has_at_symbol, has_double_slash, has_redirect_param, has_encoded_chars, is_known_legitimate, brand_in_hostname, brand_hyphenated | 11 |
| **Advanced** | has_lookalike_chars, has_sensitive_path, is_shortened_url | 3 |

### Shannon Entropy

Used to detect randomly-generated hostnames (DGA domains):

$$H(S) = -\sum_{i=1}^{k} P(s_i) \log_2 P(s_i)$$

Where $P(s_i) = \frac{\text{Count}(s_i)}{\text{Length}(S)}$

**Threshold:** Hostnames with $H(S) \ge 3.5$ are flagged as high-entropy.

---

## 3. Homograph Attack Detection

### Punycode Detection
$$\text{is\_punycode} = \text{Regex}\left(\text{"^xn--"}\right)$$

### Mixed-Script Detection
$$\text{is\_mixed\_script} = \left(\exists c_a \in \mathcal{C}_{\text{Latin}} \land \exists c_b \in \mathcal{C}_{\text{Cyrillic}} \text{ within hostname}\right)$$

---

## 4. Heuristic Rule Weights

| Rule | Weight | Trigger |
|------|--------|---------|
| is_ip_address | 0.70 | Raw IP instead of domain |
| brand_hyphenated | 0.60 | Brand name with hyphens |
| brand_in_hostname | 0.55 | Brand on non-official domain |
| has_suspicious_keyword | 0.40 | Phishing keywords in URL |
| has_at_symbol | 0.40 | `@` symbol obscuring destination |
| is_known_tld_suspicious | 0.35 | High-risk TLD (.xyz, .tk, .ml) |
| has_lookalike_chars | 0.35 | 0→o, 1→l substitutions |
| is_shortened_url | 0.35 | URL shortener detected |
| has_encoded_chars | 0.22 | Percent-encoded obfuscation |
| has_redirect_param | 0.20 | Redirect parameter in URL |
| has_double_slash | 0.20 | Double-slash redirect technique |
| has_sensitive_path | 0.20 | login, account, verify in path |
| no_https_penalty | 0.18 | HTTP instead of HTTPS |
| high_entropy_penalty | 0.18 | Entropy > 3.5 |
| num_subdomains | 0.15/level | Per subdomain above 2 |
| url_length_penalty | 0.12 | URL longer than 100 chars |
| is_known_legitimate | -1.00 | Hard override for safe domains |

**Combo boost:** 3+ flags → +0.10; 5+ flags → +0.20

---

## 5. Model Training Pipeline

### RandomForest Classifier

| Parameter | Value |
|-----------|-------|
| Algorithm | RandomForestClassifier |
| n_estimators | 100 |
| max_depth | 15 |
| min_samples_split | 5 |
| min_samples_leaf | 2 |
| max_features | sqrt |
| class_weight | balanced |
| Training data | 60,000 URLs (balanced 50/50) |

### Gini Impurity

$$I_G(p) = 1 - \sum_{i=1}^{J} p_i^2$$

### ONNX Export

```
skl2onnx.convert_sklearn(model, target_opset=17, options={'zipmap': False})
```

The `zipmap=False` option outputs raw class probabilities as a tensor (`[P(safe), P(phishing)]`) instead of a dictionary, which is required for WASM execution.

### Model Statistics

| Metric | Value |
|--------|-------|
| ONNX file size | 4.4 MB |
| Email model size | 138 KB |
| Validation accuracy | ~95% |
| WASM inference time | < 5 ms |
