
from pathlib import Path
import json

import lightgbm as lgb
import numpy as np
from sklearn.metrics import confusion_matrix

DATA_DIR = Path("data/processed/ember/model_data")
REPORT_DIR = Path("reports/ember/model_comparison")

MODEL_PATH = Path("src/models/candidates/lightgbm_baseline.txt")
SPLIT_PATH = REPORT_DIR / "split_indices.npz"
OUTPUT_PATH = REPORT_DIR / "selected_threshold.json"

MAX_FPR = 0.03

print("Loading validation partition only...")

X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy")

splits = np.load(SPLIT_PATH)
val_idx = splits["val_idx"]

X_val = np.asarray(X[val_idx], dtype=np.float32)
y_val = y[val_idx]

# Confirm that validation labels are the expected binary classes.
if not np.isin(y_val, [0, 1]).all():
    raise ValueError("Unexpected validation labels.")

print(f"Validation records: {len(y_val):,}")
print(f"Benign: {np.count_nonzero(y_val == 0):,}")
print(f"Malicious: {np.count_nonzero(y_val == 1):,}")

print("\nLoading saved LightGBM baseline...")
model = lgb.Booster(model_file=str(MODEL_PATH))
probabilities = model.predict(X_val)

# Evaluate all distinct score boundaries. A threshold just above a
# score excludes records tied at that score; 0.0 includes all records.
unique_scores = np.unique(probabilities)
thresholds = np.concatenate((
    [0.0],
    np.nextafter(unique_scores, np.inf),
))

candidates = []

for threshold in thresholds:
    predictions = (probabilities >= threshold).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_val, predictions, labels=[0, 1]
    ).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0

    if fpr <= MAX_FPR:
        candidates.append({
            "threshold": float(threshold),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "false_positive_rate": float(fpr),
            "recall": float(recall),
            "precision": float(precision),
        })

if not candidates:
    raise RuntimeError(
        "No threshold satisfies the false-positive constraint."
    )

# Maximize recall first. For ties, prefer fewer false positives,
# then higher precision, then the higher threshold.
best = max(
    candidates,
    key=lambda r: (
        r["recall"],
        -r["false_positives"],
        r["precision"],
        r["threshold"],
    ),
)

result = {
    "model": "lightgbm_baseline",
    "selection_partition": "validation",
    "max_validation_false_positive_rate": MAX_FPR,
    "selected_threshold": best["threshold"],
    "validation_metrics": best,
    "warning": (
        "The 3% constraint applies to this validation sample. "
        "It is not a guarantee of future false-positive rates."
    ),
}

print("\nSelected threshold:")
print(json.dumps(result, indent=2))

REPORT_DIR.mkdir(parents=True, exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print(f"\nSaved threshold configuration: {OUTPUT_PATH}")
print("Reserved test set was not loaded or evaluated.")
