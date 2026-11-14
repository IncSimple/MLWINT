"""First MLWINT tools: prepared-record analysis and dataset summaries."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import numpy as np

if __package__:
    from .ember2024_models import Ember2024Models, FEATURE_COUNT, sha256
else:
    from ember2024_models import Ember2024Models, FEATURE_COUNT, sha256


SOURCE_REPORT = "reports/ember2024/pilot-v1/vectorized-v1.json"
SOURCE_HASH = (
    "5314a9c610241105b0320c73ad8210b555"
    "e9c8e630cbb67ae69359e53c3be2de"
)
DATA_DIR = "data/processed/ember2024/pilot-v1/vectorized-v1"

LIMITATIONS = [
    "A predicted benign result does not establish that a file is safe.",
    "Scores are model outputs, not guaranteed real-world probabilities.",
    "Executable capabilities and system impact have not been assessed.",
]


def check_threshold(threshold):
    if not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError(
            "Threshold must be finite and between zero and one."
        )


def label_counts(labels, rows):
    if labels is None:
        return {
            "benign": 0,
            "malicious": 0,
            "unlabeled": rows,
        }

    y = np.asarray(labels)

    if y.shape != (rows,) or not np.isin(y, [-1, 0, 1]).all():
        raise ValueError(
            "Labels must align with rows and contain only -1, 0, or 1."
        )

    return {
        "benign": int(np.sum(y == 0)),
        "malicious": int(np.sum(y == 1)),
        "unlabeled": int(np.sum(y == -1)),
    }


def role_scores(models, features, compare=False):
    scores = {
        "primary": models.predict_proba(features),
    }

    if compare:
        scores["challenger"] = models.predict_proba(
            features, "challenger"
        )
        scores["research"] = (
            scores["primary"] + scores["challenger"]
        ) / 2

    return scores


def analyze_record(
    models,
    features,
    *,
    record_id=None,
    provided_label=None,
    threshold=0.5,
    compare=False,
):
    check_threshold(threshold)

    vector = np.asarray(features)

    if vector.shape not in (
        (FEATURE_COUNT,),
        (1, FEATURE_COUNT),
    ):
        raise ValueError(
            "analyze_record requires exactly one EMBER2024 record."
        )

    counts = label_counts(
        None if provided_label is None else [provided_label],
        1,
    )
    label = next(
        name for name, count in counts.items() if count
    )
    scores = role_scores(models, vector, compare)

    return {
        "record_id": record_id,
        "provided_label": label,
        "primary_role": "primary",
        "threshold": float(threshold),
        "model_results": {
            role: {
                "malicious_score": float(values[0]),
                "prediction": (
                    "predicted_malicious"
                    if values[0] >= threshold
                    else "predicted_benign"
                ),
            }
            for role, values in scores.items()
        },
        "capability_assessment": "not_assessed",
        "limitations": LIMITATIONS,
    }


def summarize_dataset(
    models,
    features,
    labels=None,
    *,
    threshold=0.5,
    compare=False,
    batch_size=2048,
):
    check_threshold(threshold)
    X = np.asarray(features)

    if (
        X.ndim != 2
        or X.shape[1] != FEATURE_COUNT
        or len(X) == 0
    ):
        raise ValueError(
            f"Expected a nonempty matrix with {FEATURE_COUNT} columns."
        )

    if not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer.")

    provided = label_counts(labels, len(X))

    roles = (
        ("primary", "challenger", "research")
        if compare
        else ("primary",)
    )
    totals = {role: 0 for role in roles}
    disagreements = 0

    for start in range(0, len(X), batch_size):
        batch = X[start:start + batch_size]
        scores = role_scores(models, batch, compare)

        decisions = {
            role: values >= threshold
            for role, values in scores.items()
        }

        for role in roles:
            totals[role] += int(np.sum(decisions[role]))

        if compare:
            disagreements += int(
                np.sum(
                    decisions["primary"]
                    != decisions["challenger"]
                )
            )

    return {
        "rows": len(X),
        "provided_label_counts": provided,
        "threshold": float(threshold),
        "prediction_counts": {
            role: {
                "predicted_malicious": count,
                "predicted_benign": len(X) - count,
            }
            for role, count in totals.items()
        },
        "primary_challenger_disagreements": (
            disagreements if compare else None
        ),
        "counting_note": (
            "Prediction counts are not dataset-provided label counts."
        ),
    }


def load_prepared_validation(root):
    report_path = root / SOURCE_REPORT

    if sha256(report_path) != SOURCE_HASH:
        raise ValueError(
            "Prepared-data report differs from the verified version."
        )

    report = json.loads(
        report_path.read_text(encoding="utf-8-sig")
    )
    partition = report["summary"]["partitions"]["validation"]

    for name, expected in partition["files"].items():
        if sha256(root / DATA_DIR / name) != expected:
            raise ValueError(
                f"Prepared-data checksum mismatch: {name}"
            )

    X = np.load(
        root / DATA_DIR / "X_validation.npy",
        mmap_mode="r",
        allow_pickle=False,
    )
    y = np.load(
        root / DATA_DIR / "y_validation.npy",
        allow_pickle=False,
    )

    with np.load(
        root / DATA_DIR / "validation_provenance.npz",
        allow_pickle=False,
    ) as z:
        identities = z["sha256"].copy()
        provenance_labels = z["label"].copy()

    if X.shape != (partition["rows"], FEATURE_COUNT):
        raise ValueError(
            "Prepared-data dimensions differ from the report."
        )

    if (
        len(identities) != len(X)
        or not np.array_equal(y, provenance_labels)
    ):
        raise ValueError(
            "Prepared-data provenance is misaligned."
        )

    label_counts(y, len(X))
    return X, y, identities, partition


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--record", type=int, default=0)
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    models = Ember2024Models(args.project_root)
    check_threshold(args.threshold)

    print("Verifying prepared validation inputs...", flush=True)

    X, y, identities, partition = load_prepared_validation(
        models.root
    )

    if not 0 <= args.record < len(X):
        parser.error(
            f"--record must be between 0 and {len(X) - 1}."
        )

    report = {
        "tool_version": "mlwint-tools-v0.1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": (
            "Previously used development validation; "
            "inference demonstration only."
        ),
        "input_type": (
            "Prepared EMBER2024 feature records, "
            "not executable files"
        ),
        "source_report": SOURCE_REPORT,
        "source_report_sha256": SOURCE_HASH,
        "period": {
            key: partition[key]
            for key in (
                "first_submission_min",
                "first_submission_max",
            )
        },
        "models": models.describe(),
        "record_analysis": analyze_record(
            models,
            X[args.record],
            record_id={
                "row_index": args.record,
                "sha256": identities[args.record].decode("ascii"),
            },
            provided_label=int(y[args.record]),
            threshold=args.threshold,
            compare=args.compare,
        ),
        "limitations": LIMITATIONS,
    }

    if args.summary:
        print(
            "Summarizing dataset predictions in batches...",
            flush=True,
        )
        report["dataset_summary"] = summarize_dataset(
            models,
            X,
            y,
            threshold=args.threshold,
            compare=args.compare,
        )

    folder = models.root / "reports/ember2024/agent-v0.1"
    folder.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S"
    )
    output = folder / (
        f"tools-{stamp}-{uuid4().hex[:8]}.json"
    )

    with output.open("x", encoding="utf-8") as stream:
        json.dump(
            report,
            stream,
            indent=2,
            allow_nan=False,
        )
        stream.write("\n")

    print(json.dumps(report, indent=2, allow_nan=False))
    print(f"\nReport: {output}")


if __name__ == "__main__":
    main()