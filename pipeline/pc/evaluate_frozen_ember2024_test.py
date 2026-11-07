"""Stream, audit and evaluate the official test using frozen models."""

from datetime import datetime, timezone
from importlib.metadata import version
import inspect
import json
from pathlib import Path
import zipfile

import numpy as np
from thrember.features import PEFeatureExtractor

import prepare_ember2024_test_week as prep

from vectorize_ember2024_pilot import (
    save_json,
    save_npz,
    sha256,
)


ROOT = Path(__file__).resolve().parents[1]

REPORT = (
    ROOT
    / "reports/ember2024/independent-win32-v1"
)

DATA = (
    ROOT
    / "data/processed/ember2024/independent-win32-v1"
    / "test-vectorized-v1"
)


def read(path):
    return json.loads(
        path.read_text(encoding="utf-8-sig")
    )


def checked(path, digest):
    if sha256(path) != digest:
        raise ValueError(
            f"Checksum mismatch: {path}"
        )


def verify(frozen, archive_info):
    checked(
        REPORT / "frozen_protocol.json",
        archive_info["frozen_protocol_sha256"],
    )

    protocol = frozen["protocol"]

    if (
        archive_info["archive_sha256"]
        != protocol["dataset"]["sha256"]
        or archive_info["archive_size_bytes"]
        != protocol["dataset"]["size_bytes"]
    ):
        raise ValueError(
            "Verified archive differs from the frozen dataset."
        )

    for name, digest in protocol["protected_inputs"].items():
        checked(
            ROOT / name,
            digest,
        )

    for item in frozen["model_snapshots"].values():
        checked(
            ROOT / item["file"],
            item["sha256"],
        )

    current_packages = {
        name: version(name)
        for name in protocol["runtime_packages"]
    }

    if current_packages != protocol["runtime_packages"]:
        raise ValueError(
            "Package versions differ from the freeze."
        )

    extractor_code = sha256(
        Path(inspect.getfile(PEFeatureExtractor))
    )

    if (
        list(prep.FEATURE_GROUPS)
        != protocol["feature_groups"]
        or prep.FEATURE_COUNT
        != protocol["feature_count"]
        or PEFeatureExtractor().dim
        != protocol["feature_count"]
        or extractor_code
        != protocol["extractor_code_sha256"]
    ):
        raise ValueError(
            "Feature extractor differs from the freeze."
        )


def audit(meta, training, development):
    order = np.argsort(
        meta["sha256"],
        kind="stable",
    )

    left = order[:-1]
    right = order[1:]

    same = (
        meta["sha256"][left]
        == meta["sha256"][right]
    )

    bad = same & (
        (
            meta["label"][left]
            != meta["label"][right]
        )
        | (
            meta["feature_hash"][left]
            != meta["feature_hash"][right]
        )
    )

    if bad.any():
        raise ValueError(
            "A repeated test SHA256 has inconsistent "
            "labels or vectors."
        )

    _, official = np.unique(
        meta["sha256"],
        return_index=True,
    )
    official.sort()

    flags = {}
    details = {}

    for name, reference in (
        ("training", training),
        ("development", development),
    ):
        flags[name + "_sha"] = np.isin(
            meta["sha256"],
            reference["sha256"],
        )

        flags[name + "_vector"] = np.isin(
            meta["feature_hash"],
            reference["feature_hash"],
        )

        sorted_ref = np.argsort(
            reference["sha256"]
        )

        matching = official[
            flags[name + "_sha"][official]
        ]

        positions = np.searchsorted(
            reference["sha256"][sorted_ref],
            meta["sha256"][matching],
        )

        ref_rows = sorted_ref[positions]

        details[
            name + "_same_sha_label_disagreements"
        ] = int(
            np.sum(
                meta["label"][matching]
                != reference["label"][ref_rows]
            )
        )

        details[
            name + "_same_sha_vector_disagreements"
        ] = int(
            np.sum(
                meta["feature_hash"][matching]
                != reference["feature_hash"][ref_rows]
            )
        )

    overlap = np.logical_or.reduce(
        list(flags.values())
    )

    primary = official[
        ~overlap[official]
    ]

    cutoff = max(
        int(training["timestamp"].max()),
        int(development["timestamp"].max()),
    )

    if (
        len(primary)
        and int(meta["timestamp"][primary].min())
        <= cutoff
    ):
        raise ValueError(
            "Primary test population overlaps earlier "
            "training/development time."
        )

    _, inverse, sizes = np.unique(
        meta["feature_hash"][official],
        return_inverse=True,
        return_counts=True,
    )

    masks = np.zeros(
        len(sizes),
        dtype=np.uint8,
    )

    np.bitwise_or.at(
        masks,
        inverse,
        np.left_shift(
            np.uint8(1),
            meta["label"][official],
        ),
    )

    details.update(
        physical_test_rows=len(meta["label"]),
        unique_official_files=len(official),

        cross_week_repeated_sha_rows_removed=(
            len(meta["label"]) - len(official)
        ),

        repeated_sha_timestamp_disagreements=int(
            np.sum(
                same
                & (
                    meta["timestamp"][left]
                    != meta["timestamp"][right]
                )
            )
        ),

        primary_novel_files=len(primary),

        excluded_overlap_files=(
            len(official) - len(primary)
        ),

        official_label_counts={
            "benign": int(
                np.sum(
                    meta["label"][official] == 0
                )
            ),
            "malicious": int(
                np.sum(
                    meta["label"][official] == 1
                )
            ),
        },

        primary_label_counts={
            "benign": int(
                np.sum(
                    meta["label"][primary] == 0
                )
            ),
            "malicious": int(
                np.sum(
                    meta["label"][primary] == 1
                )
            ),
        },

        repeated_test_feature_groups=int(
            np.sum(sizes > 1)
        ),

        conflicting_test_feature_groups=int(
            np.sum(masks == 3)
        ),

        chronology_cutoff=cutoff,
    )

    details.update(
        {
            name + "_overlap_files": int(
                np.sum(flag[official])
            )
            for name, flag in flags.items()
        }
    )

    return (
        official.astype(np.int64),
        primary.astype(np.int64),
        details,
    )


def prepare(archive_info, identity):
    state_path = REPORT / "test_preparation.json"

    state = {
        "status": "preparing",
        "identity": identity,
        "weeks": [],
    }

    if state_path.exists():
        state = read(state_path)

        if state["identity"] != identity:
            raise ValueError(
                "Existing test preparation uses "
                "different code or inputs."
            )
    else:
        save_json(
            state_path,
            state,
        )

    offset = 0

    for position, week in enumerate(state["weeks"]):
        expected_member = (
            archive_info["members"][position]["member"]
        )

        if (
            week["week"] != 52 + position
            or week["source_member"] != expected_member
        ):
            raise ValueError(
                "Checkpoint source order changed."
            )

        for chunk in week["chunks"]:
            if chunk["offset"] != offset:
                raise ValueError(
                    "Checkpoint row offsets changed."
                )

            checked(
                ROOT / chunk["x_file"],
                chunk["x_sha256"],
            )

            checked(
                ROOT / chunk["metadata_file"],
                chunk["metadata_sha256"],
            )

            offset += chunk["rows"]

    if state["status"] == "complete":
        checked(
            DATA / "test_rows.npz",
            state["test_rows_sha256"],
        )
        return state

    archive_path = ROOT / archive_info["archive_file"]

    with zipfile.ZipFile(archive_path) as archive:
        expected_members = [
            member["member"]
            for member in archive_info["members"]
        ]

        if sorted(archive.namelist()) != expected_members:
            raise ValueError(
                "Archive member inventory changed."
            )

        extractor = PEFeatureExtractor()

        for position in range(
            len(state["weeks"]),
            12,
        ):
            member = (
                archive_info["members"][position]["member"]
            )

            week_number = 52 + position

            print(
                f"\nVectorizing official test week "
                f"{week_number}: {member}",
                flush=True,
            )

            # Empty overlap references here retain all files.
            # Global overlap auditing is performed afterward.
            result = prep.prepare_week(
                ROOT,
                DATA,
                archive,
                member,
                week_number,
                extractor,
                {},
                set(),
                offset,
            )

            state = dict(
                state,
                weeks=state["weeks"] + [result],
            )

            save_json(
                state_path,
                state,
            )

            offset += result["stats"]["stored_rows"]

            print(
                f"Week checkpoint saved; "
                f"stored rows={offset:,}",
                flush=True,
            )

    if not offset:
        raise ValueError(
            "No test vectors were prepared."
        )

    meta = prep.metadata_schema(offset)

    for week in state["weeks"]:
        for chunk in week["chunks"]:
            begin = chunk["offset"]
            end = begin + chunk["rows"]

            with np.load(
                ROOT / chunk["metadata_file"],
                allow_pickle=False,
            ) as saved:
                for name in meta:
                    meta[name][begin:end] = saved[name]

    print(
        "Auditing exact overlap with training "
        "and development...",
        flush=True,
    )

    training_index = (
        ROOT
        / "data/processed/ember2024/full-win32-v1"
        / "row_index.npz"
    )

    with np.load(
        training_index,
        allow_pickle=False,
    ) as saved:
        selected = saved["valid_indices"]

        training = {
            name: saved[name][selected]
            for name in (
                "sha256",
                "feature_hash",
                "label",
                "timestamp",
            )
        }

    development_index = (
        ROOT
        / "data/processed/ember2024/pilot-v1"
        / "vectorized-v1/validation_provenance.npz"
    )

    with np.load(
        development_index,
        allow_pickle=False,
    ) as saved:
        development = {
            name: saved[name].copy()
            for name in (
                "feature_hash",
                "label",
                "timestamp",
            )
        }

        development["sha256"] = np.array(
            [
                np.void(
                    bytes.fromhex(
                        value.decode("ascii")
                    )
                )
                for value in saved["sha256"]
            ],
            dtype="V32",
        )

    official, primary, details = audit(
        meta,
        training,
        development,
    )

    details["source_week_timestamp_mismatch_rows"] = sum(
        w["stats"].get("source_week_timestamp_mismatch_rows", 0)
        for w in state["weeks"]
    )
    details["source_rows"] = sum(
        week["stats"]["source_rows"]
        for week in state["weeks"]
    )

    details[
        "within_week_repeated_sha_rows_removed"
    ] = sum(
        week["stats"]["repeated_sha_rows"]
        for week in state["weeks"]
    )

    save_npz(
        DATA / "test_rows.npz",
        **meta,
        official_indices=official,
        primary_indices=primary,
    )

    state.update(
        status="complete",
        audit=details,
        test_rows_sha256=sha256(
            DATA / "test_rows.npz"
        ),
    )

    save_json(
        state_path,
        state,
    )

    return state


def metrics(y, probability, thresholds):
    from sklearn.metrics import (
        average_precision_score,
        roc_auc_score,
        log_loss,
        brier_score_loss,
    )

    count = len(y)

    if not count:
        return {
            "status": "empty",
            "rows": 0,
        }

    if (
        probability.shape != y.shape
        or not np.isfinite(probability).all()
        or np.any(
            (probability < 0)
            | (probability > 1)
        )
    ):
        raise ValueError(
            "Invalid test probabilities."
        )

    both_classes = (
        len(np.unique(y)) == 2
    )

    result = {
        "rows": count,
        "benign": int(np.sum(y == 0)),
        "malicious": int(np.sum(y == 1)),

        "log_loss": float(
            log_loss(
                y,
                probability,
                labels=[0, 1],
            )
        ),

        "pr_auc": (
            float(
                average_precision_score(
                    y,
                    probability,
                )
            )
            if both_classes
            else None
        ),

        "roc_auc": (
            float(
                roc_auc_score(
                    y,
                    probability,
                )
            )
            if both_classes
            else None
        ),

        "brier_score": float(
            brier_score_loss(
                y,
                probability,
            )
        ),

        "decisions": {},
    }

    for name, entry in thresholds.items():
        threshold = entry["threshold"]

        prediction = (
            probability >= threshold
        )

        tp = int(
            np.sum(
                prediction & (y == 1)
            )
        )

        fp = int(
            np.sum(
                prediction & (y == 0)
            )
        )

        fn = int(
            np.sum(
                ~prediction & (y == 1)
            )
        )

        tn = int(
            np.sum(
                ~prediction & (y == 0)
            )
        )

        result["decisions"][name] = {
            "threshold": threshold,
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,

            "accuracy": (
                (tp + tn) / count
            ),

            "precision": (
                tp / (tp + fp)
                if tp + fp
                else 0.0
            ),

            "recall": (
                tp / (tp + fn)
                if tp + fn
                else None
            ),

            "f1": (
                2 * tp / (2 * tp + fp + fn)
                if 2 * tp + fp + fn
                else 0.0
            ),

            "fpr": (
                fp / (fp + tn)
                if fp + tn
                else None
            ),

            "fnr": (
                fn / (tp + fn)
                if tp + fn
                else None
            ),
        }

    return result


def evaluate(frozen, state, identity):
    import lightgbm as lgb
    import xgboost as xgb

    prediction_dir = DATA / "predictions"
    prediction_dir.mkdir(exist_ok=True)

    marker_path = (
        REPORT / "prediction_progress.json"
    )

    marker = {
        "identity": identity,
        "test_rows_sha256": state["test_rows_sha256"],
        "chunks": [],
    }

    if marker_path.exists():
        marker = read(marker_path)

        if (
            marker["identity"] != identity
            or marker["test_rows_sha256"]
            != state["test_rows_sha256"]
        ):
            raise ValueError(
                "Prediction checkpoint identity changed."
            )

    chunks = [
        chunk
        for week in state["weeks"]
        for chunk in week["chunks"]
    ]

    if len(marker["chunks"]) > len(chunks):
        raise ValueError(
            "Invalid prediction checkpoint count."
        )

    for entry in marker["chunks"]:
        checked(
            ROOT / entry["file"],
            entry["sha256"],
        )

    primary_model = lgb.Booster(
        model_file=str(
            ROOT
            / frozen["model_snapshots"]["lightgbm"]["file"]
        )
    )

    challenger = xgb.Booster()

    challenger.load_model(
        ROOT
        / frozen["model_snapshots"]["xgboost"]["file"]
    )

    challenger.set_param(
        {
            "nthread": 4,
            "device": "cpu",
        }
    )

    if (
        primary_model.num_feature() != 2568
        or challenger.num_features() != 2568
    ):
        raise ValueError(
            "Frozen model dimensions differ "
            "from test features."
        )

    for number in range(
        len(marker["chunks"]),
        len(chunks),
    ):
        chunk = chunks[number]

        matrix = np.load(
            ROOT / chunk["x_file"],
            mmap_mode="r",
            allow_pickle=False,
        )

        try:
            light = primary_model.predict(
                matrix,
                num_threads=4,
            )

            boost = challenger.inplace_predict(
                np.asarray(matrix)
            ).astype(np.float64)

        finally:
            matrix._mmap.close()

        if (
            light.shape != (chunk["rows"],)
            or boost.shape != light.shape
        ):
            raise ValueError(
                "Prediction shape changed."
            )

        prediction_path = (
            prediction_dir
            / f"chunk_{number:04d}.npz"
        )

        save_npz(
            prediction_path,
            lightgbm=light,
            xgboost=boost,
        )

        marker["chunks"].append(
            {
                "file": (
                    prediction_path
                    .relative_to(ROOT)
                    .as_posix()
                ),
                "sha256": sha256(
                    prediction_path
                ),
            }
        )

        save_json(
            marker_path,
            marker,
        )

        print(
            f"Predicted chunk "
            f"{number + 1}/{len(chunks)}",
            flush=True,
        )

    with np.load(
        DATA / "test_rows.npz",
        allow_pickle=False,
    ) as saved:
        y = saved["label"]
        weeks = saved["week"]

        selections = {
            "primary_novel": saved["primary_indices"],
            "secondary_official_unique": (
                saved["official_indices"]
            ),
        }

    probabilities = {
        name: np.empty(
            len(y),
            dtype=np.float64,
        )
        for name in (
            "lightgbm",
            "xgboost",
        )
    }

    for chunk, entry in zip(
        chunks,
        marker["chunks"],
    ):
        begin = chunk["offset"]
        end = begin + chunk["rows"]

        with np.load(
            ROOT / entry["file"],
            allow_pickle=False,
        ) as saved:
            for name in probabilities:
                probabilities[name][begin:end] = (
                    saved[name]
                )

    weights = frozen["protocol"]["ensemble"]

    probabilities["ensemble_50_50"] = (
        weights["lightgbm_weight"]
        * probabilities["lightgbm"]
        + weights["xgboost_weight"]
        * probabilities["xgboost"]
    )

    populations = {}

    for population, selected in selections.items():
        populations[population] = {
            "rows": len(selected),
            "models": {},
            "weekly": {},
        }

        for name, probability in probabilities.items():
            thresholds = (
                frozen["protocol"]["thresholds"][name]
            )

            populations[population]["models"][name] = (
                metrics(
                    y[selected],
                    probability[selected],
                    thresholds,
                )
            )

            for week in range(52, 64):
                subset = selected[
                    weeks[selected] == week
                ]

                weekly = (
                    populations[population]["weekly"]
                    .setdefault(str(week), {})
                )

                weekly[name] = metrics(
                    y[subset],
                    probability[subset],
                    thresholds,
                )

    return populations


def print_summary(result):
    def percent(value):
        if value is None:
            return "N/A"
        return f"{value:.3%}"

    print(
        "\nINDEPENDENT WIN32 TEST SUMMARY"
    )

    print(
        json.dumps(
            result["audit"],
            indent=2,
        )
    )

    for population, values in result["populations"].items():
        print(
            f"\n{population}: "
            f"{values['rows']:,} files"
        )

        for name, value in values["models"].items():
            if value.get("status") == "empty":
                print(
                    name + ": no eligible files"
                )
                continue

            print(
                f"{name}: "
                f"LogLoss={value['log_loss']:.6f}; "
                f"PR-AUC={value['pr_auc']}; "
                f"ROC-AUC={value['roc_auc']}"
            )

            for policy, decision in value["decisions"].items():
                print(
                    f"  {policy}: "
                    f"FP={decision['FP']}, "
                    f"FN={decision['FN']}, "
                    f"recall={percent(decision['recall'])}, "
                    f"actual test FPR="
                    f"{percent(decision['fpr'])}"
                )

    print(
        "\nFull report including weekly results: "
        f"{REPORT / 'test_report.json'}"
    )


def main():
    REPORT.mkdir(
        parents=True,
        exist_ok=True,
    )

    DATA.mkdir(
        parents=True,
        exist_ok=True,
    )

    frozen = read(
        REPORT / "frozen_protocol.json"
    )

    archive_info = read(
        REPORT / "test_archive_verified.json"
    )

    if (
        frozen["status"] != "frozen"
        or archive_info["status"] != "verified"
    ):
        raise ValueError(
            "Freeze and archive verification "
            "must be complete."
        )

    verify(
        frozen,
        archive_info,
    )

    identity = {
        "frozen_protocol_sha256": sha256(
            REPORT / "frozen_protocol.json"
        ),

        "archive_sha256": (
            archive_info["archive_sha256"]
        ),

        "archive_members": (
            archive_info["members"]
        ),

        "script_sha256": sha256(
            Path(__file__)
        ),

        "preparation_helper_sha256": sha256(
            Path(inspect.getfile(prep))
        ),

        "vector_helper_sha256": sha256(
            ROOT
            / "scripts/vectorize_ember2024_pilot.py"
        ),
    }

    result_path = (
        REPORT / "test_report.json"
    )

    if result_path.exists():
        result = read(result_path)

        if result["identity"] != identity:
            raise ValueError(
                "An evaluation already exists under "
                "a different code/input identity."
            )

        print(
            "Reusing saved results; "
            "no test predictions are recomputed."
        )

        print_summary(result)
        return

    archive = (
        ROOT / archive_info["archive_file"]
    )

    if (
        archive.stat().st_size
        != archive_info["archive_size_bytes"]
    ):
        raise ValueError(
            "Test archive size changed."
        )

    print(
        "Verifying archive checksum...",
        flush=True,
    )

    checked(
        archive,
        archive_info["archive_sha256"],
    )

    state = prepare(
        archive_info,
        identity,
    )

    print("\nTEST OVERLAP AUDIT")

    print(
        json.dumps(
            state["audit"],
            indent=2,
        )
    )

    print(
        "Running frozen model predictions; "
        "no fitting or threshold selection...",
        flush=True,
    )

    populations = evaluate(
        frozen,
        state,
        identity,
    )

    verify(
        frozen,
        archive_info,
    )

    result = {
        "status": "complete",

        "evaluated_utc": (
            datetime.now(timezone.utc).isoformat()
        ),

        "identity": identity,
        "audit": state["audit"],
        "populations": populations,

        "models_and_thresholds_unchanged": True,

        "note": (
            "All thresholds fixed before test access. "
            "Validation FPR target names do not imply "
            "achieved test FPR. Primary excludes exact "
            "training/development SHA and vector matches; "
            "family/near-duplicate separation is not "
            "established. This evaluates late-2024 data, "
            "not current-2026 malware."
        ),
    }

    save_json(
        result_path,
        result,
    )

    print_summary(result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            "\nStopped. Rerun unchanged code to reuse "
            "completed weeks and prediction chunks."
        )
        raise SystemExit(130)