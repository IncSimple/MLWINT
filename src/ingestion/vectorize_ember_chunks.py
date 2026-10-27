
import argparse
import json
import os
from pathlib import Path

import numpy as np
from ember.features import PEFeatureExtractor


# Resolve paths relative to the MLWINT project root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "ember2018"

# Keep the original pilot chunks untouched.
OUT_DIR = PROJECT_ROOT / "data" / "processed" / "ember" / "train_full_chunks"
MANIFEST_PATH = OUT_DIR / "manifest.json"

INPUT_FILES = [
    f"train_features_{i}.jsonl" for i in range(6)
]

FEATURE_VERSION = 2
FEATURE_DIM = 2381


def atomic_save_npy(path: Path, array: np.ndarray) -> None:
    """Write an NPY file atomically."""
    temp_path = path.with_name(path.name + ".tmp")

    with open(temp_path, "wb") as file:
        np.save(file, array)

    os.replace(temp_path, path)


def save_manifest(manifest: dict) -> None:
    """Write the checkpoint atomically."""
    temp_path = MANIFEST_PATH.with_name("manifest.json.tmp")

    with open(temp_path, "w", encoding="utf-8") as file:
        json.dump(manifest, file, indent=2)
        file.flush()
        os.fsync(file.fileno())

    os.replace(temp_path, MANIFEST_PATH)


def load_manifest() -> dict:
    if MANIFEST_PATH.exists():
        with open(MANIFEST_PATH, "r", encoding="utf-8") as file:
            manifest = json.load(file)

        print("Resuming from the existing checkpoint.")
        return manifest

    return {
        "file_index": 0,
        # Number of physical JSONL lines already committed in this file.
        "next_line_number": 0,
        "next_chunk_index": 0,
        "records_saved": 0,
        "unlabeled_skipped": 0,
        "completed_chunks": 0,
        "completed_files": [],
    }


def save_chunk(
    features: list,
    labels: list,
    file_index: int,
    line_number: int,
    pending_unlabeled: int,
    manifest: dict,
) -> None:
    """Save one chunk, then commit its checkpoint."""
    chunk_index = manifest["next_chunk_index"]

    X = np.asarray(features, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int8)

    if X.ndim != 2 or X.shape[1] != FEATURE_DIM:
        raise ValueError(f"Unexpected feature matrix shape: {X.shape}")

    if not np.isfinite(X).all():
        raise ValueError("Feature matrix contains NaN or infinite values.")

    if not np.isin(y, [0, 1]).all():
        raise ValueError(f"Unexpected labels found: {np.unique(y)}")

    x_path = OUT_DIR / f"X_{chunk_index:05d}.npy"
    y_path = OUT_DIR / f"y_{chunk_index:05d}.npy"

    # If interrupted before the manifest is updated, the same chunk
    # index will be regenerated and safely overwritten on resume.
    atomic_save_npy(x_path, X)
    atomic_save_npy(y_path, y)

    # Commit progress only after both files have been written.
    manifest["records_saved"] += len(y)
    manifest["unlabeled_skipped"] += pending_unlabeled
    manifest["completed_chunks"] += 1
    manifest["next_chunk_index"] += 1
    manifest["file_index"] = file_index
    manifest["next_line_number"] = line_number

    save_manifest(manifest)

    print(
        f"Saved chunk {chunk_index:05d}: "
        f"X={X.shape}, labels={dict(zip(*np.unique(y, return_counts=True)))}; "
        f"total labeled={manifest['records_saved']:,}, "
        f"unlabeled skipped={manifest['unlabeled_skipped']:,}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resumable EMBER 2018 feature vectorization"
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=500,
        help="Number of labeled records per chunk (default: 500)",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Optional limit on raw records read during this run, for testing",
    )
    args = parser.parse_args()

    if args.chunk_size < 1:
        raise ValueError("--chunk-size must be at least 1.")
    if args.max_records is not None and args.max_records < 1:
        raise ValueError("--max-records must be at least 1.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for filename in INPUT_FILES:
        if not (RAW_DIR / filename).is_file():
            raise FileNotFoundError(f"Missing input file: {RAW_DIR / filename}")

    extractor = PEFeatureExtractor(feature_version=FEATURE_VERSION)
    manifest = load_manifest()

    if not 0 <= manifest["file_index"] <= len(INPUT_FILES):
        raise ValueError("Invalid file index in manifest.")
    if manifest["next_line_number"] < 0:
        raise ValueError("Invalid line checkpoint in manifest.")

    run_records = 0
    stopped_early = False

    while manifest["file_index"] < len(INPUT_FILES):
        file_index = manifest["file_index"]
        filename = INPUT_FILES[file_index]
        input_path = RAW_DIR / filename
        committed_line = manifest["next_line_number"]

        print(f"\nProcessing {filename}")
        print(f"Resuming after raw line {committed_line:,}")

        features = []
        labels = []
        pending_unlabeled = 0
        line_number = 0

        with open(input_path, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                # Skip lines already included in the last checkpoint.
                if line_number <= committed_line:
                    continue

                if args.max_records is not None and run_records >= args.max_records:
                    stopped_early = True
                    break

                record = json.loads(line)
                label = int(record.get("label", -1))
                run_records += 1

                if label == -1:
                    pending_unlabeled += 1
                elif label in (0, 1):
                    vector = extractor.process_raw_features(record)
                    vector = np.asarray(vector, dtype=np.float32)

                    if vector.shape != (FEATURE_DIM,):
                        raise ValueError(
                            f"Unexpected vector shape in {filename}, "
                            f"line {line_number}: {vector.shape}"
                        )

                    if not np.isfinite(vector).all():
                        raise ValueError(
                            f"Non-finite feature values in {filename}, "
                            f"line {line_number}"
                        )

                    features.append(vector)
                    labels.append(label)
                else:
                    raise ValueError(
                        f"Unexpected label {label} in {filename}, "
                        f"line {line_number}"
                    )

                if len(labels) >= args.chunk_size:
                    save_chunk(
                        features,
                        labels,
                        file_index,
                        line_number,
                        pending_unlabeled,
                        manifest,
                    )
                    features = []
                    labels = []
                    pending_unlabeled = 0
                    committed_line = line_number

        if stopped_early:
            # Do not checkpoint uncommitted records. They will be
            # reread after the last saved chunk when the script resumes.
            print(
                f"\nTest/run limit reached after reading "
                f"{run_records:,} raw records this run."
            )
            print("Any unsaved partial chunk will be recomputed on resume.")
            break

        # The file ended. Save any remaining labeled records.
        if labels:
            save_chunk(
                features,
                labels,
                file_index,
                line_number,
                pending_unlabeled,
                manifest,
            )
            pending_unlabeled = 0

        # Commit any trailing unlabeled records and move to the next file.
        manifest["unlabeled_skipped"] += pending_unlabeled
        if filename not in manifest["completed_files"]:
            manifest["completed_files"].append(filename)

        manifest["file_index"] = file_index + 1
        manifest["next_line_number"] = 0
        save_manifest(manifest)

        print(f"Finished {filename}")

    print("\nVectorization status")
    print(f"Labeled records saved: {manifest['records_saved']:,}")
    print(f"Unlabeled records skipped: {manifest['unlabeled_skipped']:,}")
    print(f"Chunks saved: {manifest['completed_chunks']}")
    print(f"Output directory: {OUT_DIR}")

    if manifest["file_index"] == len(INPUT_FILES):
        print("All six training files have been processed.")
    elif stopped_early:
        print("Run stopped at the requested limit; you can resume later.")


if __name__ == "__main__":
    main()

