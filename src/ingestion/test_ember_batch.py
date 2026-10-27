
import json
from pathlib import Path

import numpy as np
from ember import PEFeatureExtractor

ROOT = Path(__file__).resolve().parents[2]
DATA_FILE = ROOT / "data" / "raw" / "ember2018" / "train_features_1.jsonl"
BATCH_SIZE = 100


def main():
    extractor = PEFeatureExtractor(feature_version=2)
    vectors = []
    labels = []
    skipped_unlabeled = 0

    with DATA_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if len(labels) + skipped_unlabeled >= BATCH_SIZE:
                break

            if not line.strip():
                continue

            record = json.loads(line)
            label = record.get("label")

            if label == -1:
                skipped_unlabeled += 1
                continue

            if label not in (0, 1):
                raise ValueError(f"Unexpected label: {label}")

            vector = extractor.process_raw_features(record)

            if vector.shape != (2381,):
                raise ValueError(f"Unexpected vector shape: {vector.shape}")

            if not np.isfinite(vector).all():
                raise ValueError("Non-finite feature value found")

            vectors.append(vector)
            labels.append(label)

    X = np.asarray(vectors, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int8)

    print("Feature matrix shape:", X.shape)
    print("Feature dtype:", X.dtype)
    print("Label array shape:", y.shape)
    print("Label counts:", {int(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))})
    print("Unlabeled records skipped:", skipped_unlabeled)
    print("All features finite:", bool(np.isfinite(X).all()))
    print("\nBatch conversion passed.")


if __name__ == "__main__":
    main()
