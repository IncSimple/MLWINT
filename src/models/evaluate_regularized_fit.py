
from pathlib import Path
import json

import lightgbm as lgb
import numpy as np
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    log_loss,
    accuracy_score,
    f1_score,
)

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/processed/ember/model_data"
REPORT = ROOT / "reports/ember/model_comparison"
MODEL = ROOT / "src/models/candidates/lightgbm_regularized.txt"

X = np.load(DATA / "X_sample.npy", mmap_mode="r")
y = np.load(DATA / "y_sample.npy")

with np.load(REPORT / "split_indices.npz") as splits:
    train_idx = splits["train_idx"]
    val_idx = splits["val_idx"]

model = lgb.Booster(model_file=str(MODEL))

def evaluate(indices):
    X_part = np.asarray(X[indices], dtype=np.float32)
    y_part = y[indices]
    prob = model.predict(X_part)
    pred = (prob >= 0.5).astype(np.int8)

    return {
        "records": int(len(indices)),
        "roc_auc": float(roc_auc_score(y_part, prob)),
        "pr_auc": float(average_precision_score(y_part, prob)),
        "log_loss": float(log_loss(y_part, prob)),
        "accuracy": float(accuracy_score(y_part, pred)),
        "f1": float(f1_score(y_part, pred)),
    }

results = {
    "model": str(MODEL.relative_to(ROOT)),
    "boosting_iterations": model.current_iteration(),
    "training": evaluate(train_idx),
    "validation": evaluate(val_idx),
}

results["gaps"] = {
    "roc_auc_train_minus_validation": (
        results["training"]["roc_auc"]
        - results["validation"]["roc_auc"]
    ),
    "log_loss_validation_minus_train": (
        results["validation"]["log_loss"]
        - results["training"]["log_loss"]
    ),
}

output = REPORT / "regularized_fit_audit.json"
output.write_text(json.dumps(results, indent=2), encoding="utf-8")

print(json.dumps(results, indent=2))
print(f"\nSaved to: {output}")
