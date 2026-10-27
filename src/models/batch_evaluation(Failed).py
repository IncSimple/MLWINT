
from pathlib import Path
import csv
import json

import lightgbm as lgb
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

DATA_DIR = Path("data/processed/ember/model_data")
REPORT_DIR = Path("reports/ember/batch_evaluation")

MODEL_PATH = Path("src/models/candidates/lightgbm_baseline.txt")
SPLIT_PATH = Path("reports/ember/model_comparison/split_indices.npz")
THRESHOLD_PATH = Path(
    "reports/ember/model_comparison/selected_threshold.json"
)

N_BATCHES = 10
SEED = 42

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def calculate_metrics(y_true, probabilities, threshold):
    predictions = (probabilities >= threshold).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    return {
        "records": int(len(y_true)),
        "benign": int(np.count_nonzero(y_true == 0)),
        "malicious": int(np.count_nonzero(y_true == 1)),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(
            y_true, predictions, zero_division=0
        )),
        "recall": float(recall_score(
            y_true, predictions, zero_division=0
        )),
        "f1_score": float(f1_score(
            y_true, predictions, zero_division=0
        )),
        "false_positive_rate": float(
            fp / (fp + tn) if (fp + tn) else 0.0
        ),
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
    }


print("Loading selected threshold...")
if not THRESHOLD_PATH.exists():
    raise FileNotFoundError(
        f"{THRESHOLD_PATH} not found. Run select_threshold.py first."
    )

with open(THRESHOLD_PATH, "r", encoding="utf-8") as f:
    threshold_config = json.load(f)

threshold = float(threshold_config["selected_threshold"])
print(f"Using validation-selected threshold: {threshold:.6f}")

print("\nLoading reserved test indices...")
splits = np.load(SPLIT_PATH)
test_indices = splits["test_idx"].copy()

# Shuffle deterministically so batches are not based on original ordering.
rng = np.random.default_rng(SEED)
rng.shuffle(test_indices)

X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy")

if len(test_indices) < N_BATCHES:
    raise ValueError("Not enough records for the requested batch count.")

batches = np.array_split(test_indices, N_BATCHES)

print(f"Test records: {len(test_indices):,}")
print(f"Number of batches: {len(batches)}")
print(f"Approximate records per batch: {len(test_indices) // N_BATCHES:,}")

print("\nLoading the single trained model...")
model = lgb.Booster(model_file=str(MODEL_PATH))

batch_results = []
all_true = []
all_probabilities = []

for batch_number, indices in enumerate(batches, start=1):
    print(f"\nProcessing batch {batch_number}/{N_BATCHES}...")

    X_batch = np.asarray(X[indices], dtype=np.float32)
    y_batch = y[indices]

    # The same trained model processes every batch.
    probabilities = model.predict(X_batch)

    metrics = calculate_metrics(y_batch, probabilities, threshold)
    metrics["batch"] = batch_number
    metrics["threshold"] = threshold

    batch_results.append(metrics)
    all_true.append(y_batch.copy())
    all_probabilities.append(probabilities.copy())

    print(
        f"Records={metrics['records']:,} | "
        f"FN={metrics['false_negatives']} | "
        f"FP={metrics['false_positives']} | "
        f"Recall={metrics['recall']:.4f} | "
        f"FPR={metrics['false_positive_rate']:.4f}"
    )

# Global metrics are calculated from every test prediction together.
# They are NOT calculated by averaging the batch metrics.
y_global = np.concatenate(all_true)
prob_global = np.concatenate(all_probabilities)

global_metrics = calculate_metrics(
    y_global, prob_global, threshold
)
global_metrics["number_of_batches"] = N_BATCHES
global_metrics["model"] = "lightgbm_baseline"
global_metrics["threshold"] = threshold
global_metrics["evaluation_partition"] = "reserved_test"

print("\n" + "=" * 65)
print("GLOBAL TEST METRICS")
print("=" * 65)

for key, value in global_metrics.items():
    if isinstance(value, float):
        print(f"{key}: {value:.6f}")
    else:
        print(f"{key}: {value}")

# Save per-batch results.
csv_path = REPORT_DIR / "per_batch_metrics.csv"
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=batch_results[0].keys())
    writer.writeheader()
    writer.writerows(batch_results)

# Save global metrics and per-batch results together.
json_path = REPORT_DIR / "global_metrics.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump({
        "global_metrics": global_metrics,
        "batch_metrics": batch_results,
    }, f, indent=2)

print(f"\nPer-batch report: {csv_path}")
print(f"Global report: {json_path}")
print("\nBatch evaluation completed successfully.")
