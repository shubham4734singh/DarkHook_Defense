import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from modules.url_analysis.link import extract_features, load_url_model


def validate_model(data_path: Path, sample_size: int | None = None) -> dict:
    df = pd.read_csv(data_path)
    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])]

    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)

    print(f"Validating on {len(df)} URLs...")
    print(f"Phishing: {(df['label'] == 1).sum()}")
    print(f"Benign: {(df['label'] == 0).sum()}")
    print()

    model = load_url_model()

    features_list = []
    valid_indices = []
    for idx, url in enumerate(df["url"]):
        try:
            features_df, _ = extract_features(str(url))
            features_list.append(features_df.iloc[0])
            valid_indices.append(idx)
        except Exception:
            pass

    X = pd.DataFrame(features_list)
    y_true = df["label"].iloc[valid_indices].values
    df_valid = df.iloc[valid_indices].reset_index(drop=True)

    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
    else:
        y_pred = model.predict(X)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    print("=== VALIDATION RESULTS ===")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print()
    print("Confusion Matrix:")
    print(f"                Predicted")
    print(f"                0       1")
    print(f"Actual 0    {cm[0][0]:6d}  {cm[0][1]:6d}")
    print(f"Actual 1    {cm[1][0]:6d}  {cm[1][1]:6d}")
    print()

    report_dict = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    print(classification_report(y_true, y_pred, zero_division=0))

    misclassified = (y_pred != y_true)
    if misclassified.sum() > 0:
        print("=== SAMPLE MISCLASSIFICATIONS ===")
        errors_df = df_valid[misclassified].head(10).copy()
        errors_df["predicted"] = y_pred[misclassified][:10]
        for idx, row in errors_df.iterrows():
            print(f"URL: {row['url'][:80]}")
            print(f"  True: {row['label']} | Predicted: {row['predicted']}")
            print()

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": cm.tolist(),
        "classification_report": report_dict,
        "total_samples": int(len(y_true)),
        "misclassified": int(misclassified.sum()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate trained URL model against dataset")
    parser.add_argument("--data", default="ml/datasets/processed/url_dataset.csv")
    parser.add_argument("--sample-size", type=int, default=10000, help="Number of samples to test (default: 10k)")
    parser.add_argument("--output", default="ml/models/url_validation_report.json")
    args = parser.parse_args()

    backend_root = Path(__file__).resolve().parent.parent
    data_path = (backend_root / args.data).resolve()
    output_path = (backend_root / args.output).resolve()

    results = validate_model(data_path=data_path, sample_size=args.sample_size)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Validation report saved: {output_path}")


if __name__ == "__main__":
    main()
