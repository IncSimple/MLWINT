
import json
from pathlib import Path

import numpy as np
from ember.features import PEFeatureExtractor

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "ember2018"
CHUNK_DIR = PROJECT_ROOT / "data" / "processed" / "ember" / "train_full_chunks"

TARGET_CHUNK = 0
TARGET_ROW = 486
TARGET_FEATURES = [793, 795, 807, 821, 825, 828, 834, 836]

INPUT_FILES = [f"train_features_{i}.jsonl" for i in range(6)]

saved_X = np.load(CHUNK_DIR / f"X_{TARGET_CHUNK:05d}.npy")
saved_y = np.load(CHUNK_DIR / f"y_{TARGET_CHUNK:05d}.npy")

target_vector = saved_X[TARGET_ROW]
target_label = int(saved_y[TARGET_ROW])

print("Target chunk:", TARGET_CHUNK)
print("Target row:", TARGET_ROW)
print("Target label:", target_label)
print("Saved feature 825:", target_vector[825])

extractor = PEFeatureExtractor(feature_version=2)

global_labeled_index = TARGET_CHUNK * 500 + TARGET_ROW
labeled_index = 0
found = False

for filename in INPUT_FILES:
    path = RAW_DIR / filename
    print(f"Searching {filename}...")

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            record = json.loads(line)
            label = int(record.get("label", -1))

            if label not in (0, 1):
                continue

            if labeled_index == global_labeled_index:
                print("\nMATCH FOUND")
                print("Source file:", filename)
                print("Raw line number:", line_number)
                print("Raw label:", label)

                reproduced = np.asarray(
                    extractor.process_raw_features(record),
                    dtype=np.float32,
                )

                print("\nFeature comparison")
                print("Saved shape:", target_vector.shape)
                print("Reproduced shape:", reproduced.shape)
                print("Exact match:", np.array_equal(target_vector, reproduced))
                print(
                    "Maximum absolute difference:",
                    np.max(np.abs(target_vector - reproduced)),
                )

                print("\nSelected features")
                for i in TARGET_FEATURES:
                    print(
                        f"Feature {i}: "
                        f"saved={target_vector[i]:,.3f}, "
                        f"reproduced={reproduced[i]:,.3f}"
                    )

                found = True
                break

            labeled_index += 1

    if found:
        break

if not found:
    print("Target record was not found in the raw files.")

