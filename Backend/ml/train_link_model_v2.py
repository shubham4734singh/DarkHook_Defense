import json
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


# Enhanced feature extraction with additional sophisticated features
def extract_features_v2(url: str) -> dict:
    """Extract 25+ advanced features from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()
    
    features = {}
    
    # Basic metrics
    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    
    # Character analysis
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["num_question_marks"] = url.count("?")
    features["num_equal_signs"] = url.count("=")
    features["num_ampersands"] = url.count("&")
    features["num_at_signs"] = url.count("@")
    features["num_digits"] = sum(c.isdigit() for c in url)
    
    # Protocol and security
    features["is_https"] = 1 if url.startswith("https://") else 0
    features["has_ip"] = 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0
    features["has_port"] = 1 if ":" in domain.split(".")[-1] else 0
    
    # Domain analysis
    domain_tokens = domain.replace("-", " ").replace("_", " ").split(".")
    features["num_subdomains"] = len(domain_tokens) - 2 if len(domain_tokens) > 1 else 0
    
    # TLD analysis with reputation scoring
    suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", 
                      ".loan", ".men", ".review", ".racing", ".win", ".bid", ".download", 
                      ".stream", ".icu", ".club", ".info"}
    
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    features["suspicious_tld"] = 1 if tld in suspicious_tlds else 0
    features["tld_is_country_code"] = 1 if (len(tld) == 3 and tld[1:].isalpha()) else 0
    
    # Keyword analysis - expanded suspicious terms
    phishing_keywords = [
        "login", "signin", "account", "verify", "update", "secure", "banking",
        "paypal", "ebay", "amazon", "apple", "microsoft", "google", "confirm",
        "suspended", "locked", "unusual", "click", "urgent", "immediately",
        "password", "credential", "wallet", "crypto", "invest", "prize", "winner",
        "free", "bonus", "gift", "limited", "expire", "claim"
    ]
    features["keyword_hits"] = sum(1 for kw in phishing_keywords if kw in full_url)
    
    # Entropy calculations (Shannon entropy for randomness detection)
    def shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in counter.values())
    
    features["domain_entropy"] = shannon_entropy(domain)
    features["path_entropy"] = shannon_entropy(path)
    features["url_entropy"] = shannon_entropy(url)
    
    # Character diversity (unique chars / total chars)
    features["char_diversity"] = len(set(url)) / len(url) if url else 0
    
    # Ratio features
    features["digit_ratio"] = features["num_digits"] / len(url) if url else 0
    features["special_char_ratio"] = (features["num_hyphens"] + features["num_underscores"]) / len(domain) if domain else 0
    
    # Advanced heuristics
    # Check for homograph attacks (mixed character sets, lookalike chars)
    lookalike_patterns = ["pa.ypal", "g00gle", "micros0ft", "yah00", "netfl1x", "amaz0n"]
    features["has_lookalike"] = 1 if any(pattern in full_url for pattern in lookalike_patterns) else 0
    
    # Free hosting detection
    free_hosting = ["repl.co", "herokuapp.com", "github.io", "blogspot.com", "wordpress.com",
                   "wix.com", "weebly.com", "000webhostapp.com", "pantheonsite.io", 
                   "onedumb.com", "ddns.net", "duckdns.org"]
    features["is_free_hosting"] = 1 if any(host in domain for host in free_hosting) else 0
    
    # Shortener detection
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]
    features["is_shortener"] = 1 if any(short in domain for short in shorteners) else 0
    
    # Path depth
    features["path_depth"] = path.count("/")
    
    # Suspicious patterns in path
    features["has_suspicious_path"] = 1 if any(x in path for x in ["../", "//", "%", "script"]) else 0
    
    return features


def train_v2() -> None:
    """Train enhanced models with better feature engineering and hyperparameters"""
    backend_root = Path(__file__).resolve().parent.parent
    data_path = backend_root / "ml" / "datasets" / "processed" / "url_dataset.csv"
    models_dir = backend_root / "ml" / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading data from: {data_path}")
    df = pd.read_csv(data_path)
    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])]
    
    print(f"Total samples: {len(df)}")
    print(f"Phishing (1): {(df['label'] == 1).sum()}")
    print(f"Benign (0): {(df['label'] == 0).sum()}")
    print("\nExtracting enhanced features...")
    
    features_list = []
    valid_indices = []
    
    for idx, url in enumerate(df["url"]):
        if idx % 50000 == 0:
            print(f"  Processed {idx}/{len(df)} URLs...")
        try:
            features = extract_features_v2(str(url))
            features_list.append(features)
            valid_indices.append(idx)
        except Exception as e:
            print(f"  Error processing URL {url}: {e}")
            continue
    
    X = pd.DataFrame(features_list)
    y = df["label"].iloc[valid_indices].values
    
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Features: {list(X.columns)}")
    
    # Split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Train Random Forest with optimized parameters
    print("\n=== Training Random Forest V2 ===")
    rf_model = RandomForestClassifier(
        n_estimators=200,  # Increased from 100
        max_depth=25,      # Slightly deeper
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"  # Handle class imbalance
    )
    rf_model.fit(X_train, y_train)
    rf_pred = rf_model.predict(X_test)
    
    rf_acc = accuracy_score(y_test, rf_pred)
    rf_precision = precision_score(y_test, rf_pred, zero_division=0)
    rf_recall = recall_score(y_test, rf_pred, zero_division=0)
    rf_f1 = f1_score(y_test, rf_pred, zero_division=0)
    
    print(f"RF Accuracy:  {rf_acc:.4f}")
    print(f"RF Precision: {rf_precision:.4f}")
    print(f"RF Recall:    {rf_recall:.4f}")
    print(f"RF F1:        {rf_f1:.4f}")
    
    # Train XGBoost with optimized parameters
    print("\n=== Training XGBoost V2 ===")
    
    # Calculate scale_pos_weight for imbalanced data
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
    
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,       # Increased from 6
        learning_rate=0.05,  # Slightly lower for better generalization
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1,
        eval_metric="logloss"
    )
    xgb_model.fit(X_train, y_train)
    xgb_pred = xgb_model.predict(X_test)
    
    xgb_acc = accuracy_score(y_test, xgb_pred)
    xgb_precision = precision_score(y_test, xgb_pred, zero_division=0)
    xgb_recall = recall_score(y_test, xgb_pred, zero_division=0)
    xgb_f1 = f1_score(y_test, xgb_pred, zero_division=0)
    
    print(f"XGB Accuracy:  {xgb_acc:.4f}")
    print(f"XGB Precision: {xgb_precision:.4f}")
    print(f"XGB Recall:    {xgb_recall:.4f}")
    print(f"XGB F1:        {xgb_f1:.4f}")
    
    # Feature importance for XGBoost
    feature_importance = pd.DataFrame({
        "feature": X.columns,
        "importance": xgb_model.feature_importances_
    }).sort_values("importance", ascending=False)
    
    print("\n=== Top 10 Most Important Features ===")
    print(feature_importance.head(10).to_string(index=False))
    
    # Save models
    import pickle
    
    rf_model_path = models_dir / "url_rf_model_v2.pkl"
    xgb_model_path = models_dir / "url_xgb_model_v2.pkl"
    
    with open(rf_model_path, "wb") as f:
        pickle.dump(rf_model, f)
    print(f"\nSaved RF model: {rf_model_path}")
    
    with open(xgb_model_path, "wb") as f:
        pickle.dump(xgb_model, f)
    print(f"Saved XGB model: {xgb_model_path}")
    
    # Save metrics
    metrics = {
        "random_forest_v2": {
            "accuracy": float(rf_acc),
            "precision": float(rf_precision),
            "recall": float(rf_recall),
            "f1": float(rf_f1),
        },
        "xgboost_v2": {
            "accuracy": float(xgb_acc),
            "precision": float(xgb_precision),
            "recall": float(xgb_recall),
            "f1": float(xgb_f1),
        },
        "feature_importance": feature_importance.head(15).to_dict(orient="records"),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "num_features": int(X.shape[1])
    }
    
    metrics_path = models_dir / "url_training_metrics_v2.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Saved metrics: {metrics_path}")
    
    # Classification reports
    print("\n=== XGBoost V2 Classification Report ===")
    print(classification_report(y_test, xgb_pred, zero_division=0))


if __name__ == "__main__":
    train_v2()
