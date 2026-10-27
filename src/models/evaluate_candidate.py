from pathlib import Path
import json

import lightgbm as lgb
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

DATA_DIR = Path("data/processed/ember/model_data")
REPORT_DIR = Path("reports/ember/model_comparison")

MODEL_PATH = Path(
    "src/models/candidates/lightgbm_baseline.txt"
)
SPLIT_PATH = REPORT_DIR / "split_indices.npz"
OUTPUT_PATH = REPORT_DIR / "baseline_test_results.json"

print("Loading reserved test split...")
X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy")

splits = np.load(SPLIT_PATH)
test_idx = splits["test_idx"]
X_test = np.asarray(X[test_idx], dtype=np.float32)
y_test = y[test_idx]

print("Loading baseline LightGBM...")
model = lgb.Booster(model_file=str(MODEL_PATH))

probabilities = model.predict(X_test)
threshold = 0.50
predictions = (probabilities >= threshold).astype(np.int8)

tn, fp, fn, tp = confusion_matrix(
    y_test, predictions, labels=[0, 1]
).ravel()

results = {
    "model": "lightgbm_baseline",
    "threshold": threshold,
    "test_records": int(len(y_test)),
    "accuracy": float(accuracy_score(y_test, predictions)),
    "precision": float(precision_score(
        y_test, predictions, zero_division=0
    )),
    "recall": float(recall_score(
        y_test, predictions, zero_division=0
    )),
    "f1_score": float(f1_score(
        y_test, predictions, zero_division=0
    )),
    "roc_auc": float(roc_auc_score(y_test, probabilities)),
    "pr_auc": float(average_precision_score(y_test, probabilities)),
    "true_negatives": int(tn),
    "false_positives": int(fp),
    "false_negatives": int(fn),
    "true_positives": int(tp),
}

print("\nTest classification report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Benign", "Malicious"],
    zero_division=0,
))
print("Confusion matrix (rows=true, columns=predicted):")
print(confusion_matrix(y_test, predictions))
print("\nMetrics:")
print(json.dumps(results, indent=2))

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print(f"\nSaved test results to: {OUTPUT_PATH}")