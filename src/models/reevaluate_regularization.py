
from pathlib import Path
import json

import lightgbm as lgb
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/processed/ember/model_data"
REPORTS = ROOT / "reports/ember/model_comparison"
CANDIDATES = ROOT / "src/models/candidates"
EXPERIMENTS = CANDIDATES / "regularization_experiment"

X = np.load(DATA / "X_sample.npy", mmap_mode="r", allow_pickle=False)
y = np.load(DATA / "y_sample.npy", allow_pickle=False)

with np.load(REPORTS / "split_indices.npz", allow_pickle=False) as split:
    train_idx = split["train_idx"].copy()
    val_idx = split["val_idx"].copy()

splits = {
    "train": (np.asarray(X[train_idx], dtype=np.float32), y[train_idx]),
    "validation": (np.asarray(X[val_idx], dtype=np.float32), y[val_idx]),
}


def load_lgb(path):
    return lgb.Booster(model_file=str(path))


def load_xgb(path):
    model = xgb.XGBClassifier()
    model.load_model(str(path))
    return model


def lgb_prob(model, features):
    # Booster.predict returns probabilities; LGBMClassifier requires
    # predict_proba to obtain probabilities.
    if isinstance(model, lgb.Booster):
        return np.asarray(model.predict(features), dtype=np.float64)
    return model.predict_proba(features)[:, 1].astype(np.float64)


def xgb_prob(model, features):
    return model.predict_proba(features)[:, 1].astype(np.float64)


def metrics(name, split_name, labels, probabilities):
    probabilities = np.clip(
        np.asarray(probabilities, dtype=np.float64), 1e-7, 1 - 1e-7
    )
    pred = (probabilities >= 0.5).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(
        labels, pred, labels=[0, 1]
    ).ravel()

    return {
        "model": name,
        "split": split_name,
        "records": len(labels),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "pr_auc": float(average_precision_score(labels, probabilities)),
        "log_loss": float(log_loss(labels, probabilities)),
        "accuracy": float(accuracy_score(labels, pred)),
        "precision": float(precision_score(labels, pred, zero_division=0)),
        "recall": float(recall_score(labels, pred, zero_division=0)),
        "f1": float(f1_score(labels, pred, zero_division=0)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


baseline_lgb = load_lgb(CANDIDATES / "lightgbm_baseline.txt")
baseline_xgb = load_xgb(CANDIDATES / "xgboost_ember.json")
regularized_lgb = load_lgb(EXPERIMENTS / "lightgbm_regularized.txt")
regularized_xgb = load_xgb(EXPERIMENTS / "xgboost_regularized.json")

configs = {
    "A_baseline": (baseline_lgb, baseline_xgb),
    "B_regularized_lightgbm": (regularized_lgb, baseline_xgb),
    "C_regularized_xgboost": (baseline_lgb, regularized_xgb),
    "D_both_regularized": (regularized_lgb, regularized_xgb),
}

results = []

for config_name, (lgb_model, xgb_model) in configs.items():
    for split_name, (features, labels) in splits.items():
        p_lgb = lgb_prob(lgb_model, features)
        p_xgb = xgb_prob(xgb_model, features)
        p_ensemble = 0.5 * p_lgb + 0.5 * p_xgb

        results.extend([
            metrics(f"{config_name}_lightgbm", split_name, labels, p_lgb),
            metrics(f"{config_name}_xgboost", split_name, labels, p_xgb),
            metrics(f"{config_name}_ensemble", split_name, labels, p_ensemble),
        ])

output = REPORTS / "regularization_experiment_corrected.json"
output.write_text(json.dumps(results, indent=2), encoding="utf-8")

print(f"{'Model':38} {'Split':12} {'ROC-AUC':>9} "
      f"{'PR-AUC':>9} {'LogLoss':>9} {'F1':>8}")

for row in results:
    if row["split"] == "validation":
        print(
            f"{row['model']:38} {row['split']:12} "
            f"{row['roc_auc']:9.6f} {row['pr_auc']:9.6f} "
            f"{row['log_loss']:9.5f} {row['f1']:8.5f}"
        )

print("\nCorrected report saved to:", output)
