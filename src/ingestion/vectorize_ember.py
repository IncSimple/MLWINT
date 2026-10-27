
import argparse
import json
from pathlib import Path

import numpy as np
from ember import PEFeatureExtractor

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "data" / "raw" / "ember2018"
OUTPUT_DIR = ROOT / "data" / "processed" / "ember"


def convert_files(files, output_prefix, max_records=None):
    extractor = PEFeatureExtractor(feature_version=2)
    features = []
    labels = []
    processed = 0
    skipped_unlabeled = 0

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for path in files:
        print(f"Reading {path.name}...")

        with path.open("r", encoding="utf-8") as file:
            for line in file:
                if max_records is not None and processed >= max_records:
                    break

                if not line.strip():
                    continue

                record = json.loads(line)
                label = record.get("label")

                if label == -1:
                    skipped_unlabeled += 1
                    processed += 1
                    continue

                if label not in (0, 1):
                    raise ValueError(
                        f"Unexpected label {label} in {path.name}"
                    )

                vector = extractor.process_raw_features(record)

                if vector.shape != (2381,):
                    raise ValueError(
                        f"Unexpected feature shape {vector.shape}"
                    )

                if not np.isfinite(vector).all():
                    raise ValueError("Non-finite feature value found")

                features.append(vector)
                labels.append(label)
                processed += 1

        if max_records is not None and processed >= max_records:
            break

    X = np.asarray(features, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int8)

    x_path = OUTPUT_DIR / f"{output_prefix}_X.npy"
    y_path = OUTPUT_DIR / f"{output_prefix}_y.npy"

    np.save(x_path, X)
    np.save(y_path, y)

    print("\nConversion complete")
    print(f"Records processed: {processed:,}")
    print(f"Unlabeled skipped: {skipped_unlabeled:,}")
    print(f"Labeled records: {len(y):,}")
    print(f"Feature matrix: {X.shape}")
    print(f"Label counts: {dict(zip(*np.unique(y, return_counts=True)))}")
    print(f"Saved features: {x_path}")
    print(f"Saved labels: {y_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-records",
        type=int,
        default=1000,
        help="Maximum raw records to process; use 0 for all records.",
    )
    args = parser.parse_args()

    files = sorted(RAW_DIR.glob("train_features_*.jsonl"))
    if not files:
        raise FileNotFoundError(f"No training files found in {RAW_DIR}")

    limit = None if args.max_records == 0 else args.max_records
    convert_files(files, "pilot", limit)


if __name__ == "__main__":
    main()
