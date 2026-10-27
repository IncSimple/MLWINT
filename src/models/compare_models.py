
from pathlib import Path
import gc
import json
import time

import joblib
import lightgbm as lgb
import numpy as np

from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

DATA_DIR = Path("data/processed/ember/model_data")
MODEL_DIR = Path("src/models/candidates")
REPORT_DIR = Path("reports/ember/model_comparison")

SEED = 42
N_RECORDS = 100_000
N_FEATURES = 2381

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading prepared dataset...")
X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy")

if X.shape != (N_RECORDS, N_FEATURES) or len(y) != len(X):
    raise ValueError(f"Unexpected dataset shapes: X={X.shape}, y={y.shape}")

# Create the same fixed partitions for every candidate.
all_idx = np.arange(len(y))
train_idx, temp_idx = train_test_split(
    all_idx,
    test_size=0.30,
    random_state=SEED,
    stratify=y,
)

val_idx, test_idx = train_test_split(
    temp_idx,
    test_size=0.50,
    random_state=SEED,
    stratify=y[temp_idx],
)

# Save split indices so future experiments can reuse exactly the same split.
np.savez(
    REPORT_DIR / "split_indices.npz",
    train_idx=train_idx,
    val_idx=val_idx,
    test_idx=test_idx,
)

print(f"Training:   {len(train_idx):,}")
print(f"Validation: {len(val_idx):,}")
print(f"Test (reserved): {len(test_idx):,}")

# Materialize only the training and validation matrices.
# The final test partition remains untouched.
X_train = np.asarray(X[train_idx], dtype=np.float32)
y_train = y[train_idx]
X_val = np.asarray(X[val_idx], dtype=np.float32)
y_val = y[val_idx]

# Explore thresholds on validation data.
# We record the full trade-off rather than assuming one threshold is best.
thresholds = np.round(np.arange(0.10, 0.901, 0.02), 2)

candidates = [
    (
        "lightgbm_baseline",
        lgb.LGBMClassifier(
            objective="binary",
            n_estimators=1000,
            learning_rate=0.05,
            num_leaves=31,
            colsample_bytree=0.8,
            random_state=SEED,
            n_jobs=-1,
            verbosity=-1,
        ),
        "lightgbm",
    ),
    (
        "lightgbm_regularized",
        lgb.LGBMClassifier(
            objective="binary",
            n_estimators=1200,
            learning_rate=0.03,
            num_leaves=15,
            max_depth=7,
            min_child_samples=100,
            reg_alpha=1.0,
            reg_lambda=5.0,
            colsample_bytree=0.8,
            random_state=SEED,
            n_jobs=-1,
            verbosity=-1,
        ),
        "lightgbm",
    ),
    (
        "extra_trees",
        ExtraTreesClassifier(
            n_estimators=80,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight=None,
            random_state=SEED,
            n_jobs=-1,
        ),
        "sklearn",
    ),
    (
        "random_forest",
        RandomForestClassifier(
            n_estimators=80,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight=None,
            random_state=SEED,
            n_jobs=-1,
        ),
        "sklearn",
    ),
]

all_results = []

for name, model, model_type in candidates:
    print(f"\n{'=' * 65}")
    print(f"Training: {name}")
    start = time.time()

    if model_type == "lightgbm":
        model.fit(
            X_train,
            y_train,
            eval_set=[(X_val, y_val)],
            eval_metric="binary_logloss",
            callbacks=[
                lgb.early_stopping(stopping_rounds=50, verbose=True),
                lgb.log_evaluation(period=50),
            ],
        )
        best_iteration = int(model.best_iteration_ or model.n_estimators)
        val_prob = model.predict_proba(
            X_val, num_iteration=best_iteration
        )[:, 1]
        model.booster_.save_model(
            str(MODEL_DIR / f"{name}.txt")
        )
    else:
        model.fit(X_train, y_train)
        best_iteration = None
        val_prob = model.predict_proba(X_val)[:, 1]
        joblib.dump(model, MODEL_DIR / f"{name}.joblib")

    elapsed = round(time.time() - start, 2)

    # Threshold-independent ranking metrics.
    auc = float(roc_auc_score(y_val, val_prob))
    pr_auc = float(average_precision_score(y_val, val_prob))

    threshold_results = []
    for threshold in thresholds:
        pred = (val_prob >= threshold).astype(np.int8)
        tn, fp, fn, tp = confusion_matrix(
            y_val, pred, labels=[0, 1]
        ).ravel()

        threshold_results.append({
            "threshold": float(threshold),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "precision": float(precision_score(
                y_val, pred, zero_division=0
            )),
            "recall": float(recall_score(
                y_val, pred, zero_division=0
            )),
            "f1": float(f1_score(y_val, pred, zero_division=0)),
            "accuracy": float(accuracy_score(y_val, pred)),
        })

    # This is a diagnostic threshold only, not a final security policy.
    best_f1 = max(threshold_results, key=lambda r: r["f1"])
    at_half = min(
        threshold_results,
        key=lambda r: abs(r["threshold"] - 0.50),
    )

    result = {
        "model": name,
        "training_seconds": elapsed,
        "best_iteration": best_iteration,
        "validation_roc_auc": auc,
        "validation_pr_auc": pr_auc,
        "threshold_0_50": at_half,
        "best_validation_f1_threshold": best_f1,
        "threshold_results": threshold_results,
    }
    all_results.append(result)

    print(f"Training time: {elapsed} seconds")
    print(f"Validation ROC-AUC: {auc:.5f}")
    print(f"Validation PR-AUC:  {pr_auc:.5f}")
    print("At threshold 0.50:")
    print(
        f"  FN={at_half['fn']}, FP={at_half['fp']}, "
        f"precision={at_half['precision']:.4f}, "
        f"recall={at_half['recall']:.4f}"
    )
    print("Best validation F1 threshold (diagnostic):")
    print(
        f"  threshold={best_f1['threshold']:.2f}, "
        f"FN={best_f1['fn']}, FP={best_f1['fp']}, "
        f"F1={best_f1['f1']:.4f}"
    )

    # Release each model before training the next one.
    del model, val_prob
    gc.collect()

with open(REPORT_DIR / "comparison_results.json", "w", encoding="utf-8") as f:
    json.dump(all_results, f, indent=2)

print(f"\n{'=' * 65}")
print("VALIDATION SUMMARY")
print(
    f"{'Model':<25} {'ROC-AUC':>9} {'PR-AUC':>9} "
    f"{'F1':>8} {'FN':>7} {'FP':>7}"
)

for result in sorted(
    all_results,
    key=lambda r: r["validation_roc_auc"],
    reverse=True,
):
    row = result["best_validation_f1_threshold"]
    print(
        f"{result['model']:<25} "
        f"{result['validation_roc_auc']:>9.4f} "
        f"{result['validation_pr_auc']:>9.4f} "
        f"{row['f1']:>8.4f} "
        f"{row['fn']:>7} "
        f"{row['fp']:>7}"
    )

print(f"\nCandidate models saved in: {MODEL_DIR}")
print(f"Comparison report saved in: {REPORT_DIR}")
print("The test set was not evaluated.")
