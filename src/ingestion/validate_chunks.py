
from pathlib import Path
import numpy as np

CHUNK_DIR = Path("data/processed/ember/train_full_chunks")
EXPECTED_FEATURES = 2381

x_files = sorted(CHUNK_DIR.glob("X_*.npy"))

if not x_files:
    raise FileNotFoundError(f"No X chunks found in {CHUNK_DIR}")

total_records = 0
total_benign = 0
total_malicious = 0
total_bytes = 0

print(f"Found {len(x_files)} feature chunks.")
print("Validating...")

for i, x_path in enumerate(x_files, start=1):
    chunk_id = x_path.stem.replace("X_", "")
    y_path = CHUNK_DIR / f"y_{chunk_id}.npy"

    if not y_path.exists():
        raise FileNotFoundError(f"Missing label file: {y_path}")

    X = np.load(x_path, mmap_mode="r")
    y = np.load(y_path, mmap_mode="r")

    if X.ndim != 2 or X.shape[1] != EXPECTED_FEATURES:
        raise ValueError(f"Unexpected feature shape in {x_path}: {X.shape}")

    if len(X) != len(y):
        raise ValueError(f"X/y size mismatch in chunk {chunk_id}")

    if not np.isin(y, [0, 1]).all():
        raise ValueError(f"Unexpected labels in chunk {chunk_id}")

    if not np.isfinite(X).all():
        raise ValueError(f"Non-finite features in chunk {chunk_id}")

    total_records += len(y)
    total_benign += int(np.count_nonzero(y == 0))
    total_malicious += int(np.count_nonzero(y == 1))
    total_bytes += x_path.stat().st_size + y_path.stat().st_size

    if i % 100 == 0 or i == len(x_files):
        print(f"Validated {i}/{len(x_files)} chunks")

y_files = list(CHUNK_DIR.glob("y_*.npy"))

if len(y_files) != len(x_files):
    raise ValueError(
        f"Found {len(x_files)} X files but {len(y_files)} y files"
    )

print("\nValidation complete!")
print(f"Chunks: {len(x_files)}")
print(f"Records: {total_records:,}")
print(f"Benign (0): {total_benign:,}")
print(f"Malicious (1): {total_malicious:,}")
print(f"Feature dimensions: {EXPECTED_FEATURES}")
print(f"Approx. stored size: {total_bytes / (1024**3):.2f} GiB")

assert total_records == 600_000
assert total_benign == 300_000
assert total_malicious == 300_000

print("All checks passed.")
