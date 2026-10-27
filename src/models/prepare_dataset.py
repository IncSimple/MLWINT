
from pathlib import Path
import numpy as np

CHUNK_DIR = Path("data/processed/ember/train_full_chunks")
OUTPUT_DIR = Path("data/processed/ember/model_data")

# Start with 100,000 records: 50,000 benign and 50,000 malicious.
SAMPLES_PER_CLASS = 50_000
RANDOM_SEED = 42

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

rng = np.random.default_rng(RANDOM_SEED)

x_files = sorted(CHUNK_DIR.glob("X_*.npy"))

if not x_files:
    raise FileNotFoundError(f"No feature chunks found in {CHUNK_DIR}")

print(f"Found {len(x_files)} feature chunks.")

# Select random record indices without loading the entire dataset.
labels_by_chunk = []
total_records = 0

for x_path in x_files:
    chunk_id = x_path.stem.replace("X_", "")
    y_path = CHUNK_DIR / f"y_{chunk_id}.npy"

    y = np.load(y_path, mmap_mode="r")
    labels_by_chunk.append(np.asarray(y).copy())
    total_records += len(y)

all_labels = np.concatenate(labels_by_chunk)

if len(all_labels) != total_records:
    raise ValueError("Unexpected record count.")

benign_indices = np.flatnonzero(all_labels == 0)
malicious_indices = np.flatnonzero(all_labels == 1)

if len(benign_indices) < SAMPLES_PER_CLASS:
    raise ValueError("Not enough benign records.")
if len(malicious_indices) < SAMPLES_PER_CLASS:
    raise ValueError("Not enough malicious records.")

selected_indices = np.concatenate([
    rng.choice(benign_indices, SAMPLES_PER_CLASS, replace=False),
    rng.choice(malicious_indices, SAMPLES_PER_CLASS, replace=False),
])

rng.shuffle(selected_indices)

# Build one 100,000-record feature matrix from the selected chunks.
X = np.empty((len(selected_indices), 2381), dtype=np.float32)
y = all_labels[selected_indices].astype(np.int8)

# Map global record indices to their chunk and local row.
chunk_starts = np.cumsum([0] + [len(labels) for labels in labels_by_chunk])
chunk_ids = np.searchsorted(chunk_starts[1:], selected_indices, side="right")

for chunk_index in np.unique(chunk_ids):
    selected_positions = np.flatnonzero(chunk_ids == chunk_index)
    local_indices = selected_indices[selected_positions] - chunk_starts[chunk_index]

    chunk_id = x_files[chunk_index].stem.replace("X_", "")
    X_chunk = np.load(CHUNK_DIR / f"X_{chunk_id}.npy", mmap_mode="r")

    X[selected_positions] = X_chunk[local_indices]

    print(
        f"Loaded selected rows from chunk {chunk_index + 1}/"
        f"{len(x_files)}"
    )

np.save(OUTPUT_DIR / "X_sample.npy", X)
np.save(OUTPUT_DIR / "y_sample.npy", y)

print("\nDataset preparation complete.")
print(f"X shape: {X.shape}")
print(f"y shape: {y.shape}")
print(f"Benign: {np.count_nonzero(y == 0):,}")
print(f"Malicious: {np.count_nonzero(y == 1):,}")
print(f"Saved to: {OUTPUT_DIR}")
