
from pathlib import Path
import json
import time

import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    log_loss,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "data" / "processed" / "ember" / "model_data"
SPLIT_PATH = ROOT / "reports" / "ember" / "model_comparison" / "split_indices.npz"
MODEL_DIR = ROOT / "src" / "models" / "candidates"
REPORT_DIR = ROOT / "reports" / "ember" / "model_comparison"

X_PATH = DATA_DIR / "X_sample.npy"
Y_PATH = DATA_DIR / "y_sample.npy"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Load the same data and split used for the LightGBM experiments.
X = np.load(X_PATH)
y = np.load(Y_PATH)

with np.load(SPLIT_PATH) as split:
    train_idx = split["train_idx"]
    val_idx = split["val_idx"]

assert X.shape[0] == y.shape[0]
assert np.isfinite(X).all()
assert np.isin(y, [0, 1]).all()

X_train, y_train = X[train_idx], y[train_idx]
X_val, y_val = X[val_idx], y[val_idx]

print("XGBoost version:", xgb.__version__)
print("Training shape:", X_train.shape)
print("Validation shape:", X_val.shape)
print("Training labels:", np.bincount(y_train))
print("Validation labels:", np.bincount(y_val))

model = xgb.XGBClassifier(
    objective="binary:logistic",
    eval_metric="aucpr",
    n_estimators=1500,
    learning_rate=0.05,
    max_depth=8,
    min_child_weight=5,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_alpha=0.1,
    reg_lambda=5.0,
    tree_method="hist",
    device="cpu",
    early_stopping_rounds=50,
    n_jobs=6,
    random_state=42,
)

start = time.perf_counter()

model.fit(
    X_train,
    y_train,
    eval_set=[(X_val, y_val)],
    verbose=50,
)

training_seconds = time.perf_counter() - start

# Use validation probabilities to compare ranking performance.
val_prob = model.predict_proba(X_val)[:, 1]
val_pred = (val_prob >= 0.5).astype(np.int8)

tn, fp, fn, tp = confusion_matrix(
    y_val, val_pred, labels=[0, 1]
).ravel()

metrics = {
    "model": "XGBoost",
    "xgboost_version": xgb.__version__,
    "n_train": int(len(train_idx)),
    "n_validation": int(len(val_idx)),
    "n_estimators_requested": 1500,
    "best_iteration": int(model.best_iteration),
    "training_seconds": round(training_seconds, 2),
    "threshold": 0.5,
    "roc_auc": float(roc_auc_score(y_val, val_prob)),
    "pr_auc": float(average_precision_score(y_val, val_prob)),
    "accuracy": float(accuracy_score(y_val, val_pred)),
    "precision": float(precision_score(y_val, val_pred, zero_division=0)),
    "recall": float(recall_score(y_val, val_pred, zero_division=0)),
    "f1": float(f1_score(y_val, val_pred, zero_division=0)),
    "log_loss": float(log_loss(y_val, val_prob)),
    "tn": int(tn),
    "fp": int(fp),
    "fn": int(fn),
    "tp": int(tp),
}

model_path = MODEL_DIR / "xgboost_ember.json"
metrics_path = REPORT_DIR / "xgboost_validation.json"

model.save_model(model_path)
metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

print("\nValidation results")
for key, value in metrics.items():
    print(f"{key}: {value}")

print("\nModel saved to:", model_path)
print("Metrics saved to:", metrics_path)
