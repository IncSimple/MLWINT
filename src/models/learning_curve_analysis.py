
from pathlib import Path
import json

import lightgbm as lgb
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import log_loss, roc_auc_score

ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = ROOT / "src/models/candidates/lightgbm_baseline.txt"
SPLIT_PATH = ROOT / "reports/ember/model_comparison/split_indices.npz"
X_PATH = ROOT / "data/processed/ember/model_data/X_sample.npy"
Y_PATH = ROOT / "data/processed/ember/model_data/y_sample.npy"
OUTPUT_DIR = ROOT / "reports/ember/model_comparison"

SIZES = [5000, 10000, 20000, 35000, 50000, 70000]

print("Loading dataset and saved partitions...")
X = np.load(X_PATH, mmap_mode="r")
y = np.load(Y_PATH, mmap_mode="r")
splits = np.load(SPLIT_PATH)

train_idx = splits["train_idx"]
val_idx = splits["val_idx"]

model = lgb.Booster(model_file=str(MODEL_PATH))

# Use the existing model. We evaluate progressively larger subsets
# of its original training partition and the same validation partition.
X_val = np.asarray(X[val_idx], dtype=np.float32)
y_val = np.asarray(y[val_idx], dtype=np.int32)

rng = np.random.default_rng(42)
ordered_train_idx = rng.permutation(train_idx)

results = []

for size in SIZES:
    size = min(size, len(ordered_train_idx))
    indices = ordered_train_idx[:size]

    X_train = np.asarray(X[indices], dtype=np.float32)
    y_train = np.asarray(y[indices], dtype=np.int32)

    train_probs = model.predict(X_train)
    val_probs = model.predict(X_val)

    row = {
        "training_records": int(size),
        "train_roc_auc": float(roc_auc_score(y_train, train_probs)),
        "validation_roc_auc": float(roc_auc_score(y_val, val_probs)),
        "train_log_loss": float(log_loss(y_train, train_probs, labels=[0, 1])),
        "validation_log_loss": float(log_loss(y_val, val_probs, labels=[0, 1])),
    }
    row["roc_auc_gap"] = (
        row["train_roc_auc"] - row["validation_roc_auc"]
    )
    row["log_loss_gap"] = (
        row["validation_log_loss"] - row["train_log_loss"]
    )

    results.append(row)

    print(
        f'{size:>6,} rows | '
        f'Train AUC: {row["train_roc_auc"]:.6f} | '
        f'Val AUC: {row["validation_roc_auc"]:.6f} | '
        f'Train log loss: {row["train_log_loss"]:.5f} | '
        f'Val log loss: {row["validation_log_loss"]:.5f}'
    )

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

json_path = OUTPUT_DIR / "learning_curve_results.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

sizes = [r["training_records"] for r in results]

plt.figure(figsize=(9, 5))
plt.plot(sizes, [r["train_roc_auc"] for r in results], marker="o",
         label="Training ROC-AUC")
plt.plot(sizes, [r["validation_roc_auc"] for r in results], marker="o",
         label="Validation ROC-AUC")
plt.xlabel("Training subset size")
plt.ylabel("ROC-AUC")
plt.title("MLWINT: Training vs Validation ROC-AUC")
plt.grid(True, alpha=0.3)
plt.legend()
plt.tight_layout()
auc_path = OUTPUT_DIR / "learning_curve_roc_auc.png"
plt.savefig(auc_path, dpi=150)
plt.close()

plt.figure(figsize=(9, 5))
plt.plot(sizes, [r["train_log_loss"] for r in results], marker="o",
         label="Training log loss")
plt.plot(sizes, [r["validation_log_loss"] for r in results], marker="o",
         label="Validation log loss")
plt.xlabel("Training subset size")
plt.ylabel("Log loss (lower is better)")
plt.title("MLWINT: Training vs Validation Log Loss")
plt.grid(True, alpha=0.3)
plt.legend()
plt.tight_layout()
loss_path = OUTPUT_DIR / "learning_curve_log_loss.png"
plt.savefig(loss_path, dpi=150)
plt.close()

print("\nSaved:")
print(json_path)
print(auc_path)
print(loss_path)
print(
    "\nNote: this evaluates one already-trained model on different subsets. "
    "It is a subset-size diagnostic, not a conventional learning curve "
    "from separately retrained models."
)
