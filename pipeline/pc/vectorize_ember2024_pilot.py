import gc
import hashlib
import inspect
import json
import shutil
from datetime import datetime, timezone
from importlib.metadata import version
from itertools import zip_longest
from pathlib import Path

import numpy as np
from thrember.features import PEFeatureExtractor


ROOT = Path(__file__).resolve().parents[1]

SAMPLING_REPORT = (
    ROOT / "reports/ember2024/pilot-v1/sampling.json"
)

RUN_ID = "vectorized-v1"

OUTPUT = (
    ROOT / "data/processed/ember2024/pilot-v1"
    / RUN_ID
)
REPORT = (
    ROOT / "reports/ember2024/pilot-v1"
    / f"{RUN_ID}.json"
)

FEATURE_COUNT = 2568

FEATURE_GROUPS = (
    "general",
    "histogram",
    "byteentropy",
    "strings",
    "header",
    "section",
    "imports",
    "exports",
    "datadirectories",
    "richheader",
    "authenticode",
    "pefilewarnings",
)


def sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def save_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def save_npz(path, **arrays):
    temporary = path.with_suffix(path.suffix + ".tmp")

    with temporary.open("wb") as stream:
        np.savez_compressed(stream, **arrays)

    temporary.replace(path)


def save_npy(path, array):
    temporary = path.with_suffix(path.suffix + ".tmp")

    with temporary.open("wb") as stream:
        np.save(stream, array, allow_pickle=False)

    temporary.replace(path)


def feature_hash(vector):
    canonical = np.array(vector, dtype="<f4", copy=True)

    # Normalize signed zero for comparison.
    # Other negative feature values are preserved.
    canonical[canonical == 0] = 0.0

    return np.void(
        hashlib.sha256(canonical.tobytes()).digest()
    )


def counts(labels):
    return {
        "benign": int(np.sum(labels == 0)),
        "malicious": int(np.sum(labels == 1)),
    }


def utc_text(timestamp):
    return datetime.fromtimestamp(
        int(timestamp),
        timezone.utc,
    ).isoformat()


def build_phase(phase, weeks, extractor, protocol_hash):
    """
    Cache the vectorized phase.

    A completed phase is reusable after interruption, provided its
    protocol and output checksums still match.
    """
    matrix_path = OUTPUT / f"X_{phase}_all.npy"
    metadata_path = OUTPUT / f"{phase}_all_metadata.npz"
    marker_path = OUTPUT / f"{phase}_cache_complete.json"

    if marker_path.exists():
        marker = json.loads(
            marker_path.read_text(encoding="utf-8")
        )

        if marker["protocol_sha256"] != protocol_hash:
            raise ValueError("Cached phase uses a different protocol.")

        if (
            sha256(matrix_path) != marker["matrix_sha256"]
            or sha256(metadata_path) != marker["metadata_sha256"]
        ):
            raise ValueError(f"Cached {phase} outputs changed.")

        print(f"Reusing verified {phase} vector cache.", flush=True)

        with np.load(metadata_path, allow_pickle=False) as saved:
            metadata = {
                key: saved[key].copy()
                for key in saved.files
            }

        return matrix_path, metadata

    total = sum(week["selected_rows"] for week in weeks)

    matrix = np.lib.format.open_memmap(
        matrix_path,
        mode="w+",
        dtype=np.float32,
        shape=(total, FEATURE_COUNT),
    )

    metadata = {
        "sha256": np.empty(total, dtype="S64"),
        "timestamp": np.empty(total, dtype=np.int64),
        "label": np.empty(total, dtype=np.int8),
        "week": np.empty(total, dtype=np.int16),
        "sample_row": np.empty(total, dtype=np.int32),
        "source_line": np.empty(total, dtype=np.int64),
        "feature_hash": np.empty(total, dtype="V32"),
    }

    position = 0

    for week in weeks:
        raw_path = ROOT / week["raw_file"]
        trace_path = ROOT / week["trace_file"]

        print(
            f"\nVectorizing {phase}, week {week['week_id']:02d}...",
            flush=True,
        )

        if (
            sha256(raw_path) != week["raw_sha256"]
            or sha256(trace_path) != week["trace_sha256"]
        ):
            raise ValueError("A sampled source file changed.")

        week_rows = 0

        with (
            raw_path.open("rb") as raw_stream,
            trace_path.open(encoding="utf-8") as trace_stream,
        ):
            for sample_row, pair in enumerate(
                zip_longest(raw_stream, trace_stream)
            ):
                raw_line, trace_line = pair

                if raw_line is None or trace_line is None:
                    raise ValueError("Raw and provenance row counts differ.")

                record = json.loads(raw_line)
                trace = json.loads(trace_line)

                if (
                    trace["sample_row"] != sample_row
                    or trace["phase"] != phase
                    or trace["week_id"] != week["week_id"]
                    or record.get("file_type") != "Win32"
                    or record.get("sha256", "").lower() != trace["sha256"]
                    or record.get("label") != trace["label"]
                    or record.get("first_submission_date")
                    != trace["first_submission_date"]
                    or record.get("week_id") != trace["week_id"]
                ):
                    raise ValueError(
                        f"Provenance mismatch: {phase}, "
                        f"week {week['week_id']}, row {sample_row}"
                    )

                if type(trace["label"]) is not int or trace["label"] not in (0, 1):
                    raise ValueError("Unexpected binary label.")

                # Pass feature fields ONLY.
                # Labels and intelligence annotations cannot enter X.
                feature_record = {
                    name: record[name]
                    for name in FEATURE_GROUPS
                }

                try:
                    vector = extractor.process_raw_features(
                        feature_record
                    )
                except Exception as error:
                    raise RuntimeError(
                        f"Vectorization failed: {phase}, "
                        f"week {week['week_id']}, "
                        f"row {sample_row}, SHA={trace['sha256']}"
                    ) from error

                if (
                    vector.shape != (FEATURE_COUNT,)
                    or vector.dtype != np.float32
                    or not np.isfinite(vector).all()
                ):
                    raise ValueError(
                        f"Invalid feature vector: {trace['sha256']}"
                    )

                if position >= total:
                    raise ValueError("More source rows than expected.")

                matrix[position] = vector

                metadata["sha256"][position] = trace["sha256"].encode("ascii")
                metadata["timestamp"][position] = trace["first_submission_date"]
                metadata["label"][position] = trace["label"]
                metadata["week"][position] = trace["week_id"]
                metadata["sample_row"][position] = sample_row
                metadata["source_line"][position] = trace["source_line"]
                metadata["feature_hash"][position] = feature_hash(vector)

                position += 1
                week_rows += 1

        if week_rows != week["selected_rows"]:
            raise ValueError("Week row count differs from sampling report.")

        matrix.flush()

        print(
            f"Completed {position:,}/{total:,} {phase} rows.",
            flush=True,
        )

    if position != total:
        raise ValueError("Phase row count mismatch.")

    matrix.flush()
    del matrix
    gc.collect()

    save_npz(metadata_path, **metadata)

    save_json(marker_path, {
        "protocol_sha256": protocol_hash,
        "rows": total,
        "matrix_sha256": sha256(matrix_path),
        "metadata_sha256": sha256(metadata_path),
    })

    return matrix_path, metadata


def select_rows(data):
    """
    Keep consistent unique files.
    Preserve validation files while removing training feature overlap.
    """
    global_seen = {}
    keep = {}
    audit = {}

    for phase in ("train", "validation"):
        phase_seen = set()
        selected = []

        for row in range(len(data[phase]["label"])):
            digest = bytes(data[phase]["sha256"][row])

            signature = (
                int(data[phase]["label"][row]),
                data[phase]["feature_hash"][row].tobytes(),
            )

            previous = global_seen.get(digest)

            if previous is not None and previous != signature:
                raise ValueError(
                    "The same file hash has inconsistent labels or features: "
                    + digest.decode("ascii")
                )

            global_seen[digest] = signature

            if digest not in phase_seen:
                selected.append(row)
                phase_seen.add(digest)

        keep[phase] = np.asarray(selected, dtype=np.int64)

        audit[f"{phase}_repeated_sha256_rows_removed"] = (
            len(data[phase]["label"]) - len(selected)
        )

    validation_sha = {
        bytes(value)
        for value in data["validation"]["sha256"][keep["validation"]]
    }
    validation_features = {
        value.tobytes()
        for value in data["validation"]["feature_hash"][keep["validation"]]
    }

    before = len(keep["train"])

    keep["train"] = np.asarray([
        row for row in keep["train"]
        if bytes(data["train"]["sha256"][row]) not in validation_sha
    ], dtype=np.int64)

    audit["training_sha_overlap_rows_removed"] = (
        before - len(keep["train"])
    )

    before = len(keep["train"])

    keep["train"] = np.asarray([
        row for row in keep["train"]
        if data["train"]["feature_hash"][row].tobytes()
        not in validation_features
    ], dtype=np.int64)

    audit["training_heldout_feature_overlap_rows_removed"] = (
        before - len(keep["train"])
    )

    candidates = keep["train"]

    if not len(candidates):
        raise ValueError("No training rows remain.")

    _, first_positions, group_ids = np.unique(
        data["train"]["feature_hash"][candidates],
        return_index=True,
        return_inverse=True,
    )

    masks = np.zeros(len(first_positions), dtype=np.uint8)

    np.bitwise_or.at(
        masks,
        group_ids,
        np.left_shift(
            np.uint8(1),
            data["train"]["label"][candidates].astype(np.uint8),
        ),
    )

    # Conflicting feature groups are excluded from experimental training.
    # Validation remains unchanged apart from repeated-file removal.
    conflicting_groups = masks == 3

    conflicting_rows = int(np.sum(conflicting_groups[group_ids]))

    keep["train"] = candidates[
        np.sort(first_positions[~conflicting_groups])
    ]

    audit["training_conflicting_feature_groups"] = int(
        conflicting_groups.sum()
    )
    audit["training_conflicting_feature_rows_removed"] = conflicting_rows

    audit["training_repeated_feature_rows_removed"] = (
        len(candidates) - conflicting_rows - len(keep["train"])
    )

    for phase in ("train", "validation"):
        retained = data[phase]["label"][keep[phase]]

        if not np.array_equal(np.unique(retained), [0, 1]):
            raise ValueError(f"{phase} no longer contains both classes.")

    final_train_sha = {
        bytes(value)
        for value in data["train"]["sha256"][keep["train"]]
    }
    final_train_features = {
        value.tobytes()
        for value in data["train"]["feature_hash"][keep["train"]]
    }

    audit["final_cross_partition_sha256_overlap"] = len(
        final_train_sha & validation_sha
    )
    audit["final_cross_partition_feature_overlap"] = len(
        final_train_features & validation_features
    )

    if (
        audit["final_cross_partition_sha256_overlap"]
        or audit["final_cross_partition_feature_overlap"]
    ):
        raise ValueError("Final overlap checks failed.")

    if (
        data["train"]["timestamp"][keep["train"]].max()
        >= data["validation"]["timestamp"][keep["validation"]].min()
    ):
        raise ValueError("Final chronological separation failed.")

    return keep, audit


def write_partition(phase, source_path, metadata, retained):
    destination = OUTPUT / f"X_{phase}.npy"
    temporary = destination.with_suffix(".npy.tmp")

    source = np.load(
        source_path,
        mmap_mode="r",
        allow_pickle=False,
    )

    result = np.lib.format.open_memmap(
        temporary,
        mode="w+",
        dtype=np.float32,
        shape=(len(retained), FEATURE_COUNT),
    )

    for start in range(0, len(retained), 2048):
        stop = min(start + 2048, len(retained))
        result[start:stop] = source[retained[start:stop]]

    result.flush()
    del result, source
    gc.collect()

    temporary.replace(destination)

    label_path = OUTPUT / f"y_{phase}.npy"
    provenance_path = OUTPUT / f"{phase}_provenance.npz"

    selected_metadata = {
        key: values[retained]
        for key, values in metadata.items()
    }

    save_npy(label_path, selected_metadata["label"])

    save_npz(
        provenance_path,
        sampled_phase_row=retained,
        **selected_metadata,
    )

    timestamps = selected_metadata["timestamp"]

    return {
        "rows": len(retained),
        "labels": counts(selected_metadata["label"]),
        "features": FEATURE_COUNT,
        "first_submission_min": utc_text(timestamps.min()),
        "first_submission_max": utc_text(timestamps.max()),
        "files": {
            path.name: sha256(path)
            for path in (
                destination,
                label_path,
                provenance_path,
            )
        },
    }


def main():
    sampling = json.loads(
        SAMPLING_REPORT.read_text(encoding="utf-8")
    )

    if sampling["status"] != "sampled":
        raise ValueError("Sampling has not completed.")

    extractor = PEFeatureExtractor()

    if (
        extractor.dim != FEATURE_COUNT
        or tuple(feature.name for feature in extractor.features)
        != FEATURE_GROUPS
    ):
        raise ValueError("Unexpected feature-extractor schema.")

    protocol = {
        "sampling_report_sha256": sha256(SAMPLING_REPORT),
        "feature_count": FEATURE_COUNT,
        "feature_groups": list(FEATURE_GROUPS),
        "extractor_code_sha256": sha256(
            Path(inspect.getfile(PEFeatureExtractor))
        ),
        "packages": {
            name: version(name)
            for name in ("thrember", "numpy", "scikit-learn", "signify")
        },
        "cleanup_policy": (
            "consistent unique SHA; validation precedence; "
            "remove training feature conflicts and repetitions"
        ),
    }

    protocol_hash = hashlib.sha256(
        json.dumps(protocol, sort_keys=True).encode("utf-8")
    ).hexdigest()

    if REPORT.exists():
        state = json.loads(REPORT.read_text(encoding="utf-8"))

        if state["protocol"] != protocol:
            raise ValueError(
                "Existing outputs use another protocol. Use a new RUN_ID."
            )

        if state["status"] == "complete":
            print("Vectorization already completed.")
            print(json.dumps(state["summary"], indent=2))
            return
    else:
        OUTPUT.mkdir(parents=True, exist_ok=True)
        REPORT.parent.mkdir(parents=True, exist_ok=True)

        state = {
            "status": "running",
            "protocol": protocol,
        }

    save_json(REPORT, state)

    total_rows = sum(
        week["selected_rows"]
        for week in sampling["weeks"].values()
    )

    required_space = (
        2 * total_rows * FEATURE_COUNT * 4
        + 2 * 1024 ** 3
    )

    if shutil.disk_usage(ROOT).free < required_space:
        raise RuntimeError("Insufficient working disk space.")

    data = {}
    matrices = {}

    try:
        for phase in ("train", "validation"):
            weeks = sorted(
                [
                    week for week in sampling["weeks"].values()
                    if week["phase"] == phase
                ],
                key=lambda week: week["week_id"],
            )

            matrices[phase], data[phase] = build_phase(
                phase,
                weeks,
                extractor,
                protocol_hash,
            )

        print("\nChecking repeated files and feature overlap...", flush=True)

        retained, audit = select_rows(data)

        partitions = {}

        for phase in ("train", "validation"):
            partitions[phase] = write_partition(
                phase,
                matrices[phase],
                data[phase],
                retained[phase],
            )

        state["status"] = "complete"
        state["summary"] = {
            "partitions": partitions,
            "audit": audit,
            "chronological_separation": True,
            "note": (
                "Temporal Win32 development pilot. "
                "Near-duplicate and family-level separation are not "
                "established by these exact-identity checks. "
                "Official test and challenge data were not used."
            ),
        }

        save_json(REPORT, state)

        print("\nVECTORIZATION AND CLEANUP SUMMARY")

        for phase, result in partitions.items():
            print(
                f"{phase}: rows={result['rows']:,}, "
                f"labels={result['labels']}, "
                f"features={result['features']}"
            )
            print(
                "  Period:",
                result["first_submission_min"],
                "to",
                result["first_submission_max"],
            )

        print("\nAudit:")
        print(json.dumps(audit, indent=2))

        print("\nData:", OUTPUT)
        print("Report:", REPORT)
        print("No models trained. Sampled raw records preserved.")

    except BaseException as error:
        state["status"] = (
            "interrupted"
            if isinstance(error, KeyboardInterrupt)
            else "failed"
        )
        state["error_type"] = type(error).__name__
        save_json(REPORT, state)
        raise


if __name__ == "__main__":
    main()