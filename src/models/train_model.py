
from pathlib import Path
import json
import time

import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

DATA_DIR = Path("data/processed/ember/model_data")
MODEL_DIR = Path("src/models")
REPORT_DIR = Path("reports/ember")

RANDOM_SEED = 42

REPORT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading prepared dataset...")
X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy")

if X.shape != (100_000, 2381):
    raise ValueError(f"Unexpected feature shape: {X.shape}")

if len(y) != len(X):
    raise ValueError("Feature and label counts do not match.")

print(f"Features: {X.shape}")
print(f"Labels: {y.shape}")
print(f"Class counts: {np.bincount(y)}")

X_train_idx, X_test_idx, y_train, y_test = train_test_split(
    np.arange(len(y)),
    y,
    test_size=0.20,
    random_state=RANDOM_SEED,
    stratify=y,
)

print(f"\nTraining records: {len(X_train_idx):,}")
print(f"Testing records: {len(X_test_idx):,}")

print("\nPreparing training arrays...")
X_train = np.asarray(X[X_train_idx], dtype=np.float32)
X_test = np.asarray(X[X_test_idx], dtype=np.float32)

model = lgb.LGBMClassifier(
    objective="binary",
    n_estimators=300,
    learning_rate=0.05,
    num_leaves=31,
    max_depth=-1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=RANDOM_SEED,
    n_jobs=-1,
    verbosity=-1,
)

print("\nTraining LightGBM...")
start = time.time()

model.fit(
    X_train,
    y_train,
    eval_set=[(X_test, y_test)],
    eval_metric="binary_logloss",
    callbacks=[lgb.log_evaluation(period=25)],
)

elapsed = time.time() - start

print("\nEvaluating model...")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

metrics = {
    "accuracy": float(accuracy_score(y_test, y_pred)),
    "precision": float(precision_score(y_test, y_pred, zero_division=0)),
    "recall": float(recall_score(y_test, y_pred, zero_division=0)),
    "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
    "roc_auc": float(roc_auc_score(y_test, y_prob)),
    "training_seconds": round(elapsed, 2),
    "training_records": int(len(X_train_idx)),
    "testing_records": int(len(X_test_idx)),
    "features": int(X.shape[1]),
}

print("\nClassification report:")
print(classification_report(
    y_test,
    y_pred,
    target_names=["Benign", "Malicious"],
    zero_division=0,
))

print("Confusion matrix (rows=true, columns=predicted):")
print(confusion_matrix(y_test, y_pred))

print("\nSummary metrics:")
for name, value in metrics.items():
    print(f"{name}: {value}")

model_path = MODEL_DIR / "lightgbm_ember.txt"
model.booster_.save_model(str(model_path))

with open(REPORT_DIR / "lightgbm_metrics.json", "w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2)

print(f"\nModel saved to: {model_path}")
print(f"Metrics saved to: {REPORT_DIR / 'lightgbm_metrics.json'}")
print("Training pipeline completed.")