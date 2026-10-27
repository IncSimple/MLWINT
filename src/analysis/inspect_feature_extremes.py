from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
X_PATH = ROOT / "data/processed/ember/model_data/X_sample.npy"

X = np.load(X_PATH, mmap_mode="r")

global_min = float("inf")
global_max = float("-inf")
min_location = None
max_location = None

for start in range(0, X.shape[0], 5000):
    end = min(start + 5000, X.shape[0])
    chunk = np.asarray(X[start:end])

    local_min_idx = np.unravel_index(np.argmin(chunk), chunk.shape)
    local_max_idx = np.unravel_index(np.argmax(chunk), chunk.shape)

    local_min = float(chunk[local_min_idx])
    local_max = float(chunk[local_max_idx])

    if local_min < global_min:
        global_min = local_min
        min_location = (start + local_min_idx[0], local_min_idx[1])

    if local_max > global_max:
        global_max = local_max
        max_location = (start + local_max_idx[0], local_max_idx[1])

print("Full dataset shape:", X.shape)
print("Global minimum:", global_min, "at row/feature:", min_location)
print("Global maximum:", global_max, "at row/feature:", max_location)

feature_indices = sorted({min_location[1], max_location[1]})

for j in feature_indices:
    values = np.asarray(X[:, j], dtype=np.float64)
    q = np.quantile(values, [0, 0.01, 0.25, 0.50, 0.75, 0.99, 1])

    print(f"\nFeature index {j}")
    print("Min, 1%, 25%, median, 75%, 99%, max:")
    print(q)
    print("Unique values:", len(np.unique(values)))
    print("Zero fraction:", float(np.mean(values == 0)))

print("\nInspection complete. No data was modified.")
