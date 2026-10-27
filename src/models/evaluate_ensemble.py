
from pathlib import Path
import json

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
DATA_DIR = ROOT / "data/processed/ember/model_data"
SPLIT_FILE = ROOT / "reports/ember/model_comparison/split_indices.npz"
MODEL_DIR = ROOT / "src/models/candidates"
REPORT_DIR = ROOT / "reports/ember/model_comparison"

MAX_FPR = 0.03

X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy", mmap_mode="r")

with np.load(SPLIT_FILE) as split:
    val_idx = split["val_idx"]

X_val = np.asarray(X[val_idx], dtype=np.float32)
y_val = np.asarray(y[val_idx], dtype=np.int8)

lgb_model = lgb.Booster(
    model_file=str(MODEL_DIR / "lightgbm_baseline.txt")
)
xgb_model = xgb.XGBClassifier()
xgb_model.load_model(str(MODEL_DIR / "xgboost_ember.json"))

lgb_prob = lgb_model.predict(X_val)
xgb_prob = xgb_model.predict_proba(X_val)[:, 1]

# Equal-weight soft voting.
ensemble_prob = (lgb_prob + xgb_prob) / 2.0

models = {
    "LightGBM": lgb_prob,
    "XGBoost": xgb_prob,
    "Ensemble_50_50": ensemble_prob,
}


def metrics_at_threshold(y_true, prob, threshold):
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
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "precision": float(precision_score(
            y_true, pred, zero_division=0
        )),
        "recall": float(recall_score(
            y_true, pred, zero_division=0
        )),
        "f1": float(f1_score(
            y_true, pred, zero_division=0
        )),
        "accuracy": float(np.mean(pred == y_true)),
    }


def threshold_at_max_fpr(y_true, prob, max_fpr):
    # Candidate boundaries just above each negative score allow
    # the corresponding negative sample to be excluded.
    negative_scores = prob[y_true == 0]
    candidates = np.unique(np.concatenate([
        [0.0, 1.0],
        np.nextafter(negative_scores, np.inf),
    ]))

    eligible = []
    for threshold in candidates:
        result = metrics_at_threshold(y_true, prob, threshold)
        if result["fpr"] <= max_fpr:
            eligible.append(result)

    # Maximize recall; prefer higher precision of the threshold
    # only as a deterministic tie-breaker.
    return max(
        eligible,
        key=lambda row: (row["recall"], row["threshold"]),
    )


results = {}

for name, prob in models.items():
    results[name] = {
        "roc_auc": float(roc_auc_score(y_val, prob)),
        "pr_auc": float(average_precision_score(y_val, prob)),
        "at_threshold_0_5": metrics_at_threshold(
            y_val, prob, 0.5
        ),
        "at_validation_fpr_limit": threshold_at_max_fpr(
            y_val, prob, MAX_FPR
        ),
    }

    print(f"\n{name}")
    print("ROC-AUC:", results[name]["roc_auc"])
    print("PR-AUC:", results[name]["pr_auc"])
    print("At threshold 0.5:", results[name]["at_threshold_0_5"])
    print(
        f"At validation FPR <= {MAX_FPR:.1%}:",
        results[name]["at_validation_fpr_limit"],
    )

report = {
    "partition": "validation",
    "validation_samples": int(len(y_val)),
    "max_validation_fpr": MAX_FPR,
    "ensemble_method": "arithmetic mean of LightGBM and XGBoost probabilities",
    "results": results,
}

REPORT_DIR.mkdir(parents=True, exist_ok=True)
output_path = REPORT_DIR / "ensemble_validation_comparison.json"
output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

print("\nSaved:", output_path)
