
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

DATA_DIR = Path("data/processed/ember/model_data")
MODEL_PATH = Path("src/models/lightgbm_ember.txt")

print("Loading dataset and saved model...")
X = np.load(DATA_DIR / "X_sample.npy", mmap_mode="r")
y = np.load(DATA_DIR / "y_sample.npy")

# Recreate the exact split used by the initial training script.
_, test_idx, _, y_test = train_test_split(
    np.arange(len(y)),
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

X_test = np.asarray(X[test_idx], dtype=np.float32)

model = lgb.Booster(model_file=str(MODEL_PATH))

print(f"Test records: {len(y_test):,}")
print("\nThreshold comparison")
print("-" * 78)

for threshold in [0.20, 0.30, 0.40, 0.50, 0.60, 0.70]:
    probabilities = model.predict(X_test)
    predictions = (probabilities >= threshold).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    precision = precision_score(
        y_test, predictions, zero_division=0
    )
    recall = recall_score(
        y_test, predictions, zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, zero_division=0
    )

    print(
        f"Threshold={threshold:.2f} | "
        f"FN={fn:5d} | FP={fp:5d} | "
        f"Precision={precision:.4f} | "
        f"Recall={recall:.4f} | F1={f1:.4f}"
    )

print("\nDiagnostic complete. No model files were changed.")
