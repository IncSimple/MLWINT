
from pathlib import Path
import json
import time
import statistics

import numpy as np
import lightgbm as lgb
import xgboost as xgb

ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "data/processed/ember/model_data"
SPLIT_FILE = ROOT / "reports/ember/model_comparison/split_indices.npz"
MODEL_DIR = ROOT / "src/models/candidates"
REPORT_DIR = ROOT / "reports/ember/model_comparison"

REPEATS = 10
WARMUP_RUNS = 2

# Load the same validation examples for both models.
X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
with np.load(SPLIT_FILE) as split:
    val_idx = split["val_idx"]

X_val = np.asarray(X[val_idx], dtype=np.float32)

models = {
    "LightGBM": lgb.Booster(
        model_file=str(MODEL_DIR / "lightgbm_baseline.txt")
    ),
    "XGBoost": xgb.XGBClassifier(),
}
models["XGBoost"].load_model(
    str(MODEL_DIR / "xgboost_ember.json")
)


def predict(model_name, model):
    if model_name == "LightGBM":
        return model.predict(X_val)
    return model.predict_proba(X_val)[:, 1]


results = {}

for name, model in models.items():
    # Warm-up: exclude initial startup effects from timing.
    for _ in range(WARMUP_RUNS):
        predict(name, model)

    durations = []

    for _ in range(REPEATS):
        start = time.perf_counter()
        predictions = predict(name, model)
        durations.append(time.perf_counter() - start)

    results[name] = {
        "validation_samples": int(len(X_val)),
        "warmup_runs": WARMUP_RUNS,
        "timed_runs": REPEATS,
        "median_seconds": statistics.median(durations),
        "mean_seconds": statistics.mean(durations),
        "min_seconds": min(durations),
        "max_seconds": max(durations),
        "median_ms_per_1000_samples": (
            statistics.median(durations) / len(X_val) * 1000 * 1000
        ),
        "last_prediction_count": int(len(predictions)),
    }

    print(f"\n{name}")
    print(f"Median time: {results[name]['median_seconds']:.6f} seconds")
    print(f"Mean time:   {results[name]['mean_seconds']:.6f} seconds")
    print(f"Fastest:     {results[name]['min_seconds']:.6f} seconds")
    print(f"Slowest:     {results[name]['max_seconds']:.6f} seconds")
    print(
        "Median ms per 1,000 samples: "
        f"{results[name]['median_ms_per_1000_samples']:.4f}"
    )

REPORT_DIR.mkdir(parents=True, exist_ok=True)
output_path = REPORT_DIR / "inference_benchmark.json"
output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

print(f"\nSaved benchmark: {output_path}")
