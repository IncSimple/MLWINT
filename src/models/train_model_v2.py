
from pathlib import Path
import json
import time

import lightgbm as lgb
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

DATA_DIR = Path("data/processed/ember/model_data")
MODEL_DIR = Path("src/models")
REPORT_DIR = Path("reports/ember")

RANDOM_SEED = 42

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading prepared sample...")
X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy")

if X.shape != (100_000, 2381) or len(y) != len(X):
    raise ValueError(f"Unexpected dataset shapes: X={X.shape}, y={y.shape}")

# 70% train, 30% temporary.
all_idx = np.arange(len(y))
train_idx, temp_idx = train_test_split(
    all_idx,
    test_size=0.30,
    random_state=RANDOM_SEED,
    stratify=y,
)

# Split temporary data equally: 15% validation, 15% test.
val_idx, test_idx = train_test_split(
    temp_idx,
    test_size=0.50,
    random_state=RANDOM_SEED,
    stratify=y[temp_idx],
)

print(f"Training records:   {len(train_idx):,}")
print(f"Validation records: {len(val_idx):,}")
print(f"Test records:       {len(test_idx):,}")

print("\nLoading split arrays...")
X_train = np.asarray(X[train_idx], dtype=np.float32)
X_val = np.asarray(X[val_idx], dtype=np.float32)
X_test = np.asarray(X[test_idx], dtype=np.float32)

y_train = y[train_idx]
y_val = y[val_idx]
y_test = y[test_idx]

model = lgb.LGBMClassifier(
    objective="binary",
    n_estimators=1000,
    learning_rate=0.05,
    num_leaves=31,
    max_depth=-1,
    colsample_bytree=0.8,
    random_state=RANDOM_SEED,
    n_jobs=-1,
    verbosity=-1,
)

print("\nTraining with early stopping...")
start = time.time()

model.fit(
    X_train,
    y_train,
    eval_set=[(X_val, y_val)],
    eval_metric="binary_logloss",
    callbacks=[
        lgb.early_stopping(stopping_rounds=50, verbose=True),
        lgb.log_evaluation(period=25),
    ],
)

print(f"\nTraining time: {time.time() - start:.2f} seconds")
print(f"Best iteration: {model.best_iteration_}")

# Choose the threshold on validation data, not the test set.
val_prob = model.predict_proba(
    X_val, num_iteration=model.best_iteration_
)[:, 1]

threshold_results = []

for threshold in np.arange(0.10, 0.701, 0.01):
    val_pred = (val_prob >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(
        y_val, val_pred, labels=[0, 1]
    ).ravel()

    threshold_results.append({
        "threshold": round(float(threshold), 2),
        "false_negatives": int(fn),
        "false_positives": int(fp),
        "precision": float(precision_score(
            y_val, val_pred, zero_division=0
        )),
        "recall": float(recall_score(
            y_val, val_pred, zero_division=0
        )),
        "f1": float(f1_score(y_val, val_pred, zero_division=0)),
    })

# Select the threshold with the fewest total errors.
# If tied, prefer the one with fewer false negatives.
best = min(
    threshold_results,
    key=lambda r: (
        r["false_negatives"] + r["false_positives"],
        r["false_negatives"],
    ),
)

threshold = best["threshold"]

print("\nSelected using validation data:")
print(json.dumps(best, indent=2))

# Evaluate once on the untouched test set.
test_prob = model.predict_proba(
    X_test, num_iteration=model.best_iteration_
)[:, 1]
test_pred = (test_prob >= threshold).astype(np.int8)

tn, fp, fn, tp = confusion_matrix(
    y_test, test_pred, labels=[0, 1]
).ravel()

metrics = {
    "threshold": threshold,
    "best_iteration": int(model.best_iteration_),
    "accuracy": float(accuracy_score(y_test, test_pred)),
    "precision": float(precision_score(y_test, test_pred, zero_division=0)),
    "recall": float(recall_score(y_test, test_pred, zero_division=0)),
    "f1_score": float(f1_score(y_test, test_pred, zero_division=0)),
    "roc_auc": float(roc_auc_score(y_test, test_prob)),
    "true_negatives": int(tn),
    "false_positives": int(fp),
    "false_negatives": int(fn),
    "true_positives": int(tp),
    "training_records": int(len(train_idx)),
    "validation_records": int(len(val_idx)),
    "testing_records": int(len(test_idx)),
}

print("\nFinal test report:")
print(classification_report(
    y_test,
    test_pred,
    target_names=["Benign", "Malicious"],
    zero_division=0,
))
print("Confusion matrix (rows=true, columns=predicted):")
print(confusion_matrix(y_test, test_pred))
print("\nTest metrics:")
print(json.dumps(metrics, indent=2))

# Save as a new model; preserve the original model.
model.booster_.save_model(str(MODEL_DIR / "lightgbm_ember_v2.txt"))

with open(REPORT_DIR / "lightgbm_metrics_v2.json", "w", encoding="utf-8") as f:
    json.dump({
        "test_metrics": metrics,
        "selected_on_validation": best,
        "validation_threshold_results": threshold_results,
    }, f, indent=2)

print("\nSaved model: src/models/lightgbm_ember_v2.txt")
print("Saved report: reports/ember/lightgbm_metrics_v2.json")
print("Pipeline completed.")
