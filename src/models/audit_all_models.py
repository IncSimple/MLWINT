
from pathlib import Path
import json

import lightgbm as lgb
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    log_loss,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/processed/ember/model_data"
MODELS = ROOT / "src/models/candidates"
REPORTS = ROOT / "reports/ember/model_comparison"

X = np.load(DATA / "X_sample.npy", mmap_mode="r")
y = np.load(DATA / "y_sample.npy", mmap_mode="r")

with np.load(REPORTS / "split_indices.npz") as splits:
    train_idx = splits["train_idx"]
    val_idx = splits["val_idx"]

X_train = np.asarray(X[train_idx], dtype=np.float32)
y_train = np.asarray(y[train_idx], dtype=np.int32)
X_val = np.asarray(X[val_idx], dtype=np.float32)
y_val = np.asarray(y[val_idx], dtype=np.int32)

print("Loading existing models...")
lightgbm_model = lgb.Booster(
    model_file=str(MODELS / "lightgbm_baseline.txt")
)
xgboost_model = xgb.XGBClassifier()
xgboost_model.load_model(str(MODELS / "xgboost_ember.json"))


def evaluate(name, y_true, probabilities):
    predictions = (probabilities >= 0.5).astype(np.int32)
    return {
        "model": name,
        "records": int(len(y_true)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
        "pr_auc": float(average_precision_score(y_true, probabilities)),
        "log_loss": float(
            log_loss(y_true, probabilities, labels=[0, 1])
        ),
        "f1_at_0_5": float(
            f1_score(y_true, predictions, zero_division=0)
        ),
    }


models = {
    "lightgbm": lambda X_: lightgbm_model.predict(X_),
    "xgboost": lambda X_: xgboost_model.predict_proba(X_)[:, 1],
}

results = {}

for name, predict in models.items():
    results[name] = {}
    for partition, features, labels in [
        ("train", X_train, y_train),
        ("validation", X_val, y_val),
    ]:
        probabilities = predict(features)
        results[name][partition] = evaluate(
            name, labels, probabilities
        )

# Ensemble: average the two models' probabilities.
for partition, features, labels in [
    ("train", X_train, y_train),
    ("validation", X_val, y_val),
]:
    p_lgb = lightgbm_model.predict(features)
    p_xgb = xgboost_model.predict_proba(features)[:, 1]
    p_ensemble = (p_lgb + p_xgb) / 2

    results.setdefault("ensemble", {})[partition] = evaluate(
        "ensemble", labels, p_ensemble
    )

for name, partitions in results.items():
    train = partitions["train"]
    val = partitions["validation"]

    print(f"\n===== {name.upper()} =====")
    for metric in ["roc_auc", "pr_auc", "log_loss", "f1_at_0_5"]:
        print(
            f"{metric:12s} "
            f"train={train[metric]:.6f} "
            f"validation={val[metric]:.6f}"
        )

    print(
        "ROC-AUC gap (train - validation): "
        f"{train['roc_auc'] - val['roc_auc']:+.6f}"
    )
    print(
        "Log-loss gap (validation - train): "
        f"{val['log_loss'] - train['log_loss']:+.6f}"
    )

output = REPORTS / "overfitting_audit.json"
output.write_text(json.dumps(results, indent=2), encoding="utf-8")
print(f"\nSaved audit report: {output}")
