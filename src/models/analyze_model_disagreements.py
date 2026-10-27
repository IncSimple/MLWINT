
from pathlib import Path
import json

import numpy as np
import lightgbm as lgb
import xgboost as xgb
from sklearn.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data/processed/ember/model_data"
SPLIT_FILE = ROOT / "reports/ember/model_comparison/split_indices.npz"
MODEL_DIR = ROOT / "src/models/candidates"
REPORT_DIR = ROOT / "reports/ember/model_comparison"

THRESHOLD = 0.5

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

lgb_pred = (lgb_prob >= THRESHOLD).astype(np.int8)
xgb_pred = (xgb_prob >= THRESHOLD).astype(np.int8)

# Confusion matrices use rows=true labels and columns=predicted labels.
lgb_cm = confusion_matrix(y_val, lgb_pred, labels=[0, 1])
xgb_cm = confusion_matrix(y_val, xgb_pred, labels=[0, 1])

lgb_correct = lgb_pred == y_val
xgb_correct = xgb_pred == y_val

# Local validation-array positions, not original dataset row IDs.
lgb_only_correct = np.flatnonzero(lgb_correct & ~xgb_correct)
xgb_only_correct = np.flatnonzero(xgb_correct & ~lgb_correct)
both_wrong = np.flatnonzero(~lgb_correct & ~xgb_correct)
disagree = np.flatnonzero(lgb_pred != xgb_pred)

def summarize(indices):
    if len(indices) == 0:
        return {
            "count": 0,
            "malware_true_label_1": 0,
            "benign_true_label_0": 0,
        }

    labels = y_val[indices]
    return {
        "count": int(len(indices)),
        "malware_true_label_1": int(np.sum(labels == 1)),
        "benign_true_label_0": int(np.sum(labels == 0)),
    }

def cm_summary(cm):
    tn, fp, fn, tp = cm.ravel()
    return {
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }

# Preserve indices relative to X_sample.npy for later investigation.
# The source sample matrix's original row IDs are val_idx[local_position].
report = {
    "partition": "validation",
    "threshold": THRESHOLD,
    "validation_samples": int(len(y_val)),
    "disagreement_count": int(len(disagree)),
    "disagreement_rate": float(np.mean(lgb_pred != xgb_pred)),
    "lightgbm_confusion_matrix": cm_summary(lgb_cm),
    "xgboost_confusion_matrix": cm_summary(xgb_cm),
    "lightgbm_only_correct": summarize(lgb_only_correct),
    "xgboost_only_correct": summarize(xgb_only_correct),
    "both_models_wrong": summarize(both_wrong),
    "disagreement_examples": [],
}

# Show up to 20 disagreements, prioritizing cases where one model is
# correct and the other is wrong. Include both model scores.
priority = np.concatenate([
    lgb_only_correct,
    xgb_only_correct,
    np.setdiff1d(disagree, np.concatenate([
        lgb_only_correct, xgb_only_correct
    ]), assume_unique=False),
])

seen = set()
for local_pos in priority:
    local_pos = int(local_pos)
    if local_pos in seen:
        continue
    seen.add(local_pos)

    report["disagreement_examples"].append({
        "validation_position": local_pos,
        "sample_row_index": int(val_idx[local_pos]),
        "true_label": int(y_val[local_pos]),
        "lightgbm_probability": float(lgb_prob[local_pos]),
        "lightgbm_prediction": int(lgb_pred[local_pos]),
        "xgboost_probability": float(xgb_prob[local_pos]),
        "xgboost_prediction": int(xgb_pred[local_pos]),
    })

    if len(report["disagreement_examples"]) >= 20:
        break

REPORT_DIR.mkdir(parents=True, exist_ok=True)
output_path = REPORT_DIR / "model_disagreement_analysis.json"
output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

print("Validation samples:", report["validation_samples"])
print("Disagreements:", report["disagreement_count"])
print("Disagreement rate:", f"{report['disagreement_rate']:.4%}")
print("\nLightGBM confusion matrix:", report["lightgbm_confusion_matrix"])
print("XGBoost confusion matrix:", report["xgboost_confusion_matrix"])
print("\nLightGBM only correct:", report["lightgbm_only_correct"])
print("XGBoost only correct:", report["xgboost_only_correct"])
print("Both models wrong:", report["both_models_wrong"])
print("\nExample disagreements:")
for item in report["disagreement_examples"]:
    print(item)

print("\nSaved:", output_path)
