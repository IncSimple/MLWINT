
from pathlib import Path
import json
import statistics
import time

import numpy as np
import lightgbm as lgb
import xgboost as xgb

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data/processed/ember/model_data"
SPLIT_FILE = ROOT / "reports/ember/model_comparison/split_indices.npz"
MODEL_DIR = ROOT / "src/models/candidates"
REPORT_DIR = ROOT / "reports/ember/model_comparison"

WARMUP_RUNS = 2
REPEATS = 10

X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
with np.load(SPLIT_FILE) as split:
    val_idx = split["val_idx"]

X_val = np.asarray(X[val_idx], dtype=np.float32)

lgb_model = lgb.Booster(
    model_file=str(MODEL_DIR / "lightgbm_baseline.txt")
)
xgb_model = xgb.XGBClassifier()
xgb_model.load_model(str(MODEL_DIR / "xgboost_ember.json"))


def predict_ensemble():
    lgb_prob = lgb_model.predict(X_val)
    xgb_prob = xgb_model.predict_proba(X_val)[:, 1]
    return (lgb_prob + xgb_prob) / 2.0


for _ in range(WARMUP_RUNS):
    predict_ensemble()

durations = []

for _ in range(REPEATS):
    start = time.perf_counter()
    probabilities = predict_ensemble()
    durations.append(time.perf_counter() - start)

result = {
    "validation_samples": int(len(X_val)),
    "warmup_runs": WARMUP_RUNS,
    "timed_runs": REPEATS,
    "median_seconds": statistics.median(durations),
    "mean_seconds": statistics.mean(durations),
    "min_seconds": min(durations),
    "max_seconds": max(durations),
    "median_ms_per_1000_samples": (
        statistics.median(durations) / len(X_val) * 1_000_000
    ),
    "probability_count": int(len(probabilities)),
}

REPORT_DIR.mkdir(parents=True, exist_ok=True)
output_path = REPORT_DIR / "ensemble_inference_benchmark.json"
output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

print("Ensemble inference benchmark")
print("Median seconds:", f"{result['median_seconds']:.6f}")
print("Mean seconds:", f"{result['mean_seconds']:.6f}")
print("Fastest seconds:", f"{result['min_seconds']:.6f}")
print("Slowest seconds:", f"{result['max_seconds']:.6f}")
print("Median ms per 1,000 samples:",
      f"{result['median_ms_per_1000_samples']:.4f}")
print("Saved:", output_path)
