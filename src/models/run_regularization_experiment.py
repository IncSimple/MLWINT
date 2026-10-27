
from pathlib import Path
import gc
import json
import time

import lightgbm as lgb
import numpy as np
import pandas as pd
import xgboost as xgb

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data/processed/ember/model_data"
REPORT_DIR = ROOT / "reports/ember/model_comparison"
CANDIDATE_DIR = ROOT / "src/models/candidates"
EXPERIMENT_DIR = CANDIDATE_DIR / "regularization_experiment"

X_PATH = DATA_DIR / "X_sample.npy"
Y_PATH = DATA_DIR / "y_sample.npy"
SPLIT_PATH = REPORT_DIR / "split_indices.npz"

LGB_BASELINE_PATH = CANDIDATE_DIR / "lightgbm_baseline.txt"
XGB_BASELINE_PATH = CANDIDATE_DIR / "xgboost_ember.json"

SEED = 42
THRESHOLD = 0.50
N_FEATURES = 2381

for path in (REPORT_DIR, EXPERIMENT_DIR):
    path.mkdir(parents=True, exist_ok=True)


def require_file(path):
    if not path.is_file():
        raise FileNotFoundError(f"Required file not found: {path}")


for path in (
    X_PATH,
    Y_PATH,
    SPLIT_PATH,
    LGB_BASELINE_PATH,
    XGB_BASELINE_PATH,
):
    require_file(path)


print("Loading dataset and preserving existing split...")
X = np.load(X_PATH, mmap_mode="r", allow_pickle=False)
y = np.load(Y_PATH, allow_pickle=False)

with np.load(SPLIT_PATH, allow_pickle=False) as split:
    train_idx = split["train_idx"].copy()
    val_idx = split["val_idx"].copy()

assert X.ndim == 2 and X.shape[1] == N_FEATURES
assert len(X) == len(y)
assert np.isfinite(y).all()
assert np.isin(y, [0, 1]).all()

# Validate the saved partition before using it.
assert len(np.intersect1d(train_idx, val_idx)) == 0
assert len(np.unique(np.concatenate([train_idx, val_idx]))) == (
    len(train_idx) + len(val_idx)
)
assert np.all((train_idx >= 0) & (train_idx < len(y)))
assert np.all((val_idx >= 0) & (val_idx < len(y)))

X_train = np.asarray(X[train_idx], dtype=np.float32)
y_train = y[train_idx]
X_val = np.asarray(X[val_idx], dtype=np.float32)
y_val = y[val_idx]

print("LightGBM version:", lgb.__version__)
print("XGBoost version:", xgb.__version__)
print("Train:", X_train.shape, "Validation:", X_val.shape)
print("Experiment artifacts:", EXPERIMENT_DIR)


def load_lightgbm(path):
    return lgb.Booster(model_file=str(path))


def load_xgboost(path):
    model = xgb.XGBClassifier()
    model.load_model(str(path))
    return model


def lgb_probability(model, features):
    return np.asarray(model.predict(features), dtype=np.float64)


def xgb_probability(model, features):
    return model.predict_proba(features)[:, 1].astype(np.float64)


def measure(model_name, split_name, y_true, probabilities):
    probabilities = np.asarray(probabilities, dtype=np.float64)
    probabilities = np.clip(probabilities, 1e-7, 1 - 1e-7)
    predictions = (probabilities >= THRESHOLD).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    return {
        "model": model_name,
        "split": split_name,
        "records": int(len(y_true)),
        "threshold": THRESHOLD,
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
        "pr_auc": float(average_precision_score(y_true, probabilities)),
        "log_loss": float(log_loss(y_true, probabilities)),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(
            precision_score(y_true, predictions, zero_division=0)
        ),
        "recall": float(
            recall_score(y_true, predictions, zero_division=0)
        ),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def evaluate_pair(name, lgb_model, xgb_model):
    """Evaluate one model pair and its equal-probability ensemble."""
    output = []

    for split_name, features, labels in (
        ("train", X_train, y_train),
        ("validation", X_val, y_val),
    ):
        p_lgb = lgb_probability(lgb_model, features)
        p_xgb = xgb_probability(xgb_model, features)
        p_ensemble = 0.5 * p_lgb + 0.5 * p_xgb

        output.extend([
            measure(f"{name}_lightgbm", split_name, labels, p_lgb),
            measure(f"{name}_xgboost", split_name, labels, p_xgb),
            measure(f"{name}_ensemble", split_name, labels, p_ensemble),
        ])

    return output


# A: Existing production candidates; nothing is overwritten.
print("\n[A] Loading existing baseline models...")
baseline_lgb = load_lightgbm(LGB_BASELINE_PATH)
baseline_xgb = load_xgboost(XGB_BASELINE_PATH)

results = []
results.extend(
    evaluate_pair("A_baseline", baseline_lgb, baseline_xgb)
)

del baseline_lgb, baseline_xgb
gc.collect()


# B: Regularize LightGBM; keep the existing XGBoost model.
print("\n[B] Training regularized LightGBM...")
start = time.perf_counter()

regularized_lgb = lgb.LGBMClassifier(
    objective="binary",
    n_estimators=2000,
    learning_rate=0.03,
    num_leaves=15,
    max_depth=7,
    min_child_samples=100,
    reg_alpha=1.0,
    reg_lambda=5.0,
    colsample_bytree=0.8,
    subsample=0.8,
    subsample_freq=1,
    random_state=SEED,
    n_jobs=-1,
    verbosity=-1,
)

regularized_lgb.fit(
    X_train,
    y_train,
    eval_set=[(X_val, y_val)],
    eval_metric="binary_logloss",
    callbacks=[
        lgb.early_stopping(stopping_rounds=75, verbose=True),
        lgb.log_evaluation(period=100),
    ],
)

lgb_train_seconds = time.perf_counter() - start
lgb_path = EXPERIMENT_DIR / "lightgbm_regularized.txt"
regularized_lgb.booster_.save_model(str(lgb_path))

existing_xgb = load_xgboost(XGB_BASELINE_PATH)
results.extend(
    evaluate_pair("B_regularized_lightgbm", regularized_lgb, existing_xgb)
)

del existing_xgb
gc.collect()


# C: Keep existing LightGBM; regularize XGBoost.
print("\n[C] Training regularized XGBoost...")
start = time.perf_counter()

regularized_xgb = xgb.XGBClassifier(
    objective="binary:logistic",
    eval_metric="aucpr",
    n_estimators=2000,
    learning_rate=0.03,
    max_depth=6,
    min_child_weight=10,
    gamma=0.2,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_alpha=1.0,
    reg_lambda=10.0,
    tree_method="hist",
    device="cpu",
    early_stopping_rounds=75,
    n_jobs=6,
    random_state=SEED,
)

regularized_xgb.fit(
    X_train,
    y_train,
    eval_set=[(X_val, y_val)],
    verbose=100,
)

xgb_train_seconds = time.perf_counter() - start
xgb_path = EXPERIMENT_DIR / "xgboost_regularized.json"
regularized_xgb.save_model(str(xgb_path))

existing_lgb = load_lightgbm(LGB_BASELINE_PATH)
results.extend(
    evaluate_pair("C_regularized_xgboost", existing_lgb, regularized_xgb)
)

del existing_lgb
gc.collect()


# D: Both models regularized.
print("\n[D] Evaluating both regularized models...")
results.extend(
    evaluate_pair("D_both_regularized", regularized_lgb, regularized_xgb)
)


# Record training-versus-validation generalization gaps.
by_model = {}

for row in results:
    by_model.setdefault(row["model"], {})[row["split"]] = row

for model_name, pair in by_model.items():
    if "train" not in pair or "validation" not in pair:
        continue

    train = pair["train"]
    val = pair["validation"]

    pair["gaps"] = {
        "roc_auc_train_minus_validation":
            train["roc_auc"] - val["roc_auc"],
        "pr_auc_train_minus_validation":
            train["pr_auc"] - val["pr_auc"],
        "log_loss_validation_minus_train":
            val["log_loss"] - train["log_loss"],
        "f1_train_minus_validation":
            train["f1"] - val["f1"],
    }


# Measure prediction latency on the same validation batch.
# These timings are approximate and include repeated prediction calls.
latency_results = []

for model_name, predict_fn, model in (
    ("lightgbm_regularized", lgb_probability, regularized_lgb.booster_),
    ("xgboost_regularized", xgb_probability, regularized_xgb),
):
    durations = []
    for _ in range(3):
        start = time.perf_counter()
        predict_fn(model, X_val)
        durations.append(time.perf_counter() - start)

    latency_results.append({
        "model": model_name,
        "validation_records": len(X_val),
        "mean_seconds_3_runs": float(np.mean(durations)),
        "records_per_second": float(len(X_val) / np.mean(durations)),
    })


# Save a single consolidated report and a flat CSV for analysis.
report = {
    "experiment": "MLWINT coordinated regularization comparison",
    "seed": SEED,
    "features": N_FEATURES,
    "n_train": int(len(train_idx)),
    "n_validation": int(len(val_idx)),
    "threshold": THRESHOLD,
    "note": (
        "Validation was used for early stopping and comparison. "
        "Metrics are exploratory; do not treat this as a pristine "
        "final test evaluation."
    ),
    "training_seconds": {
        "regularized_lightgbm": round(lgb_train_seconds, 2),
        "regularized_xgboost": round(xgb_train_seconds, 2),
    },
    "models": by_model,
    "latency": latency_results,
    "artifacts": {
        "regularized_lightgbm": str(lgb_path.relative_to(ROOT)),
        "regularized_xgboost": str(xgb_path.relative_to(ROOT)),
    },
}

json_path = REPORT_DIR / "regularization_experiment.json"
csv_path = REPORT_DIR / "regularization_experiment.csv"

json_path.write_text(
    json.dumps(report, indent=2), encoding="utf-8"
)
pd.DataFrame(results).to_csv(csv_path, index=False)

print("\n=== VALIDATION COMPARISON ===")
print(
    f"{'Model':38} {'ROC-AUC':>9} {'PR-AUC':>9} "
    f"{'LogLoss':>9} {'F1':>8} {'FN':>6} {'FP':>6}"
)

for name, pair in sorted(by_model.items()):
    if "validation" not in pair:
        continue

    row = pair["validation"]
    print(
        f"{name:38} "
        f"{row['roc_auc']:9.6f} "
        f"{row['pr_auc']:9.6f} "
        f"{row['log_loss']:9.5f} "
        f"{row['f1']:8.5f} "
        f"{row['fn']:6d} "
        f"{row['fp']:6d}"
    )

print("\nTraining time:")
print(f"  Regularized LightGBM: {lgb_train_seconds:.2f}s")
print(f"  Regularized XGBoost:  {xgb_train_seconds:.2f}s")

print("\nSaved report:", json_path)
print("Saved CSV:", csv_path)
print("Saved experimental models in:", EXPERIMENT_DIR)
print("\nExisting production candidates were not overwritten.")
