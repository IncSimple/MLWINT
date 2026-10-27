
from pathlib import Path
import json

import numpy as np
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]

X_PATH = ROOT / "data/processed/ember/model_data/X_sample.npy"
Y_PATH = ROOT / "data/processed/ember/model_data/y_sample.npy"
OUT_DIR = ROOT / "reports/ember/eda"

CHUNK_SIZE = 5000
SAMPLE_SIZE = 10000
RANDOM_SEED = 42

print("Loading EMBER dataset using memory mapping...")
X = np.load(X_PATH, mmap_mode="r")
y = np.load(Y_PATH, mmap_mode="r")

assert X.ndim == 2, f"Expected 2D features, got {X.shape}"
assert y.ndim == 1, f"Expected 1D labels, got {y.shape}"
assert len(X) == len(y), "Feature and label counts differ"

OUT_DIR.mkdir(parents=True, exist_ok=True)

# 1. Dataset structure and labels
labels, counts = np.unique(y, return_counts=True)
label_counts = {
    str(label): int(count)
    for label, count in zip(labels, counts)
}

print("\n--- DATASET STRUCTURE ---")
print("Feature shape:", X.shape)
print("Feature dtype:", X.dtype)
print("Label shape:", y.shape)
print("Label counts:", label_counts)

# 2. Scan every record for non-finite values.
# Memory use is limited by processing the data in chunks.
nonfinite_total = 0
rows_with_nonfinite = 0
min_values = np.full(X.shape[1], np.inf, dtype=np.float64)
max_values = np.full(X.shape[1], -np.inf, dtype=np.float64)
finite_counts = np.zeros(X.shape[1], dtype=np.int64)

for start in range(0, len(X), CHUNK_SIZE):
    end = min(start + CHUNK_SIZE, len(X))
    chunk = np.asarray(X[start:end], dtype=np.float64)

    finite_mask = np.isfinite(chunk)
    nonfinite_total += int((~finite_mask).sum())
    rows_with_nonfinite += int((~finite_mask).any(axis=1).sum())

    for j in range(X.shape[1]):
        values = chunk[finite_mask[:, j], j]
        if values.size:
            min_values[j] = min(min_values[j], values.min())
            max_values[j] = max(max_values[j], values.max())
            finite_counts[j] += values.size

print("\n--- DATA QUALITY ---")
print("Non-finite feature values:", nonfinite_total)
print("Rows containing non-finite values:", rows_with_nonfinite)
print("Features with no finite values:", int((finite_counts == 0).sum()))

# 3. Sample-based feature distribution analysis
rng = np.random.default_rng(RANDOM_SEED)
sample_indices = rng.choice(
    len(X), size=min(SAMPLE_SIZE, len(X)), replace=False
)
sample = np.asarray(X[sample_indices], dtype=np.float32)

sample_mean = np.nanmean(
    np.where(np.isfinite(sample), sample, np.nan), axis=0
)
sample_std = np.nanstd(
    np.where(np.isfinite(sample), sample, np.nan), axis=0
)

valid_features = np.isfinite(sample).all(axis=0)
sample_min = np.min(sample[:, valid_features], axis=0) if valid_features.any() else []
sample_max = np.max(sample[:, valid_features], axis=0) if valid_features.any() else []

# 4. Exact duplicate feature rows in the sampled records.
# This is a sample-based check, not a full-dataset duplicate audit.
unique_rows = np.unique(sample, axis=0).shape[0]
sample_duplicates = len(sample) - unique_rows

# 5. Plot representative feature distributions.
# Feature indices are used because the saved matrix has no column names.
plot_indices = [
    i for i in range(X.shape[1])
    if np.isfinite(sample[:, i]).all()
][:6]

for feature_index in plot_indices:
    plt.figure(figsize=(7, 4))
    plt.hist(sample[:, feature_index], bins=50)
    plt.title(f"EMBER feature index {feature_index}")
    plt.xlabel("Feature value")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(
        OUT_DIR / f"feature_{feature_index}_distribution.png",
        dpi=120
    )
    plt.close()

report = {
    "dataset_rows": int(X.shape[0]),
    "feature_count": int(X.shape[1]),
    "feature_dtype": str(X.dtype),
    "label_counts": label_counts,
    "nonfinite_values": int(nonfinite_total),
    "rows_with_nonfinite_values": int(rows_with_nonfinite),
    "features_with_no_finite_values": int((finite_counts == 0).sum()),
    "sample_size": int(len(sample)),
    "exact_duplicate_rows_in_sample": int(sample_duplicates),
    "sample_feature_mean_finite_count": int(np.isfinite(sample_mean).sum()),
    "sample_feature_std_finite_count": int(np.isfinite(sample_std).sum()),
    "sample_feature_min": float(np.min(sample_min)) if len(sample_min) else None,
    "sample_feature_max": float(np.max(sample_max)) if len(sample_max) else None,
    "limitations": [
        "Duplicate-row analysis uses a sample, not the entire dataset.",
        "Distribution plots cover representative feature indices only.",
        "Potential label leakage and malware-family leakage require separate analysis."
    ]
}

report_path = OUT_DIR / "eda_report.json"
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

print("\n--- SAMPLE ANALYSIS ---")
print("Sample size:", len(sample))
print("Exact duplicate rows in sample:", sample_duplicates)
print("Feature distribution plots:", len(plot_indices))
print("\nSaved report:", report_path)
print("EDA audit completed.")
