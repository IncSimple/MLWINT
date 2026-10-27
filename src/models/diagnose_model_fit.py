
from pathlib import Path
import json

import lightgbm as lgb
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)

# Project root: D:\2) Study Material\Projects\MLWINT
ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = ROOT / "src" / "models" / "candidates" / "lightgbm_baseline.txt"
SPLIT_PATH = ROOT / "reports" / "ember" / "model_comparison" / "split_indices.npz"
X_PATH = ROOT / "data" / "processed" / "ember" / "model_data" / "X_sample.npy"
Y_PATH = ROOT / "data" / "processed" / "ember" / "model_data" / "y_sample.npy"
THRESHOLD_PATH = ROOT / "reports" / "ember" / "model_comparison" / "selected_threshold.json"
OUTPUT_PATH = ROOT / "reports" / "ember" / "model_comparison" / "fit_diagnosis.json"

print("Loading existing dataset, model, and saved split...")

X = np.load(X_PATH, mmap_mode="r")
y = np.load(Y_PATH, mmap_mode="r")
splits = np.load(SPLIT_PATH)

train_idx = splits["train_idx"]
val_idx = splits["val_idx"]

model = lgb.Booster(model_file=str(MODEL_PATH))

with open(THRESHOLD_PATH, "r", encoding="utf-8") as file:
    threshold_data = json.load(file)

threshold = float(threshold_data["selected_threshold"])

print(f"Dataset shape: {X.shape}")
print(f"Training records: {len(train_idx):,}")
print(f"Validation records: {len(val_idx):,}")
print(f"Decision threshold: {threshold:.6f}")


def evaluate_split(name, indices):
    features = np.asarray(X[indices], dtype=np.float32)
    labels = np.asarray(y[indices], dtype=np.int32)

    probabilities = model.predict(features)
    predictions = (probabilities >= threshold).astype(np.int32)

    results = {
        "records": int(len(labels)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "pr_auc": float(average_precision_score(labels, probabilities)),
        "log_loss": float(log_loss(labels, probabilities, labels=[0, 1])),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
    }

    print(f"\n{name} results:")
    for metric, value in results.items():
        if isinstance(value, float):
            print(f"  {metric:12s}: {value:.6f}")
        else:
            print(f"  {metric:12s}: {value:,}")

    return results


train_results = evaluate_split("TRAINING", train_idx)
val_results = evaluate_split("VALIDATION", val_idx)

gaps = {
    "roc_auc_train_minus_validation":
        train_results["roc_auc"] - val_results["roc_auc"],
    "f1_train_minus_validation":
        train_results["f1"] - val_results["f1"],
    "log_loss_validation_minus_train":
        val_results["log_loss"] - train_results["log_loss"],
}

print("\nTraining-validation gaps:")
for name, value in gaps.items():
    print(f"  {name}: {value:+.6f}")

report = {
    "model": str(MODEL_PATH.relative_to(ROOT)),
    "threshold": threshold,
    "training": train_results,
    "validation": val_results,
    "gaps": gaps,
    "interpretation_note": (
        "Small train-validation gaps are encouraging, but fit diagnosis "
        "also requires learning curves and domain-aware generalization checks."
    ),
}

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as file:
    json.dump(report, file, indent=2)

print(f"\nSaved report to: {OUTPUT_PATH}")
print("\nInitial fit metrics completed.")
