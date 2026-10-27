
from pathlib import Path
import json
import time

import numpy as np
import lightgbm as lgb
import xgboost as xgb
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/processed/ember/model_data"
SPLITS = ROOT / "reports/ember/model_comparison/split_indices.npz"
REPORTS = ROOT / "reports/ember/model_comparison"
MODELS = ROOT / "src/models/candidates"

X = np.load(DATA / "X_sample.npy", mmap_mode="r")
y = np.load(DATA / "y_sample.npy", mmap_mode="r")
with np.load(SPLITS) as s:
    val_idx = s["val_idx"]

X_val = X[val_idx]
y_val = y[val_idx]

models = {
    "LightGBM": lgb.Booster(
        model_file=str(MODELS / "lightgbm_baseline.txt")
    ),
    "XGBoost": xgb.XGBClassifier(),
}
models["XGBoost"].load_model(str(MODELS / "xgboost_ember.json"))

def evaluate_at_threshold(y_true, prob, threshold):
    pred = (prob >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(
        y_true, pred, labels=[0, 1]
    ).ravel()
    return {
        "threshold": float(threshold),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": float(fp / (fp + tn)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
    }

results = {}

for name, model in models.items():
    start = time.perf_counter()
    if name == "LightGBM":
        prob = model.predict(X_val)
    else:
        prob = model.predict_proba(X_val)[:, 1]
    inference_seconds = time.perf_counter() - start

    # Find the threshold with the highest recall while keeping
    # empirical validation FPR <= 3%.
    negative_scores = prob[y_val == 0]
    candidate_thresholds = np.unique(
        np.concatenate(([0.0], negative_scores, [1.0]))
    )

    eligible = []
    for threshold in candidate_thresholds:
        metrics = evaluate_at_threshold(y_val, prob, threshold)
        if metrics["fpr"] <= 0.03:
            eligible.append(metrics)

    # For a given empirical FPR, lower thresholds usually improve recall.
    selected = max(eligible, key=lambda m: (m["recall"], m["threshold"]))

    results[name] = {
        "roc_auc": float(roc_auc_score(y_val, prob)),
        "pr_auc": float(average_precision_score(y_val, prob)),
        "inference_seconds_for_validation": round(inference_seconds, 4),
        "at_0_5": evaluate_at_threshold(y_val, prob, 0.5),
        "selected_at_fpr_le_3_percent": selected,
    }

output_path = REPORTS / "lightgbm_xgboost_threshold_comparison.json"
output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

for name, result in results.items():
    print(f"\n{name}")
    print("ROC-AUC:", result["roc_auc"])
    print("PR-AUC:", result["pr_auc"])
    print("Inference seconds:", result["inference_seconds_for_validation"])
    print("At threshold 0.5:", result["at_0_5"])
    print("At FPR <= 3%:", result["selected_at_fpr_le_3_percent"])

print("\nSaved:", output_path)
