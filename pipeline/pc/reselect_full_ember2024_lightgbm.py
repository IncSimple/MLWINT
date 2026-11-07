"""
Give full-cohort LightGBM the same chronological round-selection
budget as XGBoost.

Existing models and the frozen official-test benchmark are preserved.
This follow-up uses training/internal stopping/development validation.
"""

import argparse
import gc
from pathlib import Path
import shutil
import subprocess
import sys
import time

import train_full_ember2024_lightgbm as base

from probe_full_ember2024_lightgbm_v2 import (
    GIB,
    read_json,
    save_json,
    sha256,
    windows_apis,
    system_memory,
    start_watchdog,
)


RUN = "lightgbm-full-temporal-v2"
MAX_ROUNDS = 2000
PATIENCE = 75


def locations(root):
    return (
        root / "reports/ember2024/full-win32-v1" / RUN,
        root / "src/models/candidates/ember2024" / RUN,
        root / "data/processed/ember2024/full-win32-v1" / RUN,
    )


def split_text(root, protocol, indices, labels, data_dir):
    import numpy as np

    manifest = read_json(
        root / protocol["stream_manifest"]
    )

    original = root / manifest["text_file"]
    marker = data_dir / "split_complete.json"

    fit_idx = indices["inner_fit_indices"]
    stop_idx = indices["inner_stop_indices"]

    if not np.array_equal(
        np.concatenate([fit_idx, stop_idx]),
        indices["valid_indices"],
    ):
        raise ValueError(
            "Chronological partitions are not "
            "a contiguous prefix/suffix."
        )

    identity = {
        "source_sha256": manifest["text_sha256"],
        "fit_rows": len(fit_idx),
        "stop_rows": len(stop_idx),
    }

    if marker.exists():
        saved = read_json(marker)

        if saved["identity"] != identity:
            raise ValueError(
                "Existing text split has different inputs."
            )

        for entry in saved["parts"].values():
            if sha256(root / entry["file"]) != entry["sha256"]:
                raise ValueError(
                    "Chronological text split checksum changed."
                )

        return saved

    destinations = {
        "fit": data_dir / "inner_fit.libsvm",
        "stop": data_dir / "inner_stop.libsvm",
    }

    temporary = {
        name: path.with_suffix(".partial")
        for name, path in destinations.items()
    }

    print(
        "Splitting existing training text into "
        "earlier-fit and stopping files...",
        flush=True,
    )

    count = 0

    with (
        original.open("rb") as source,
        temporary["fit"].open("wb") as fit,
        temporary["stop"].open("wb") as stop,
    ):
        for line in source:
            if count >= len(indices["valid_indices"]):
                raise ValueError(
                    "Training text has too many rows."
                )

            if len(line) > 2 * 1024**2:
                raise ValueError(
                    "Unexpectedly large vector record."
                )

            physical_row = indices["valid_indices"][count]
            expected_label = int(labels[physical_row])

            if (
                line.split(maxsplit=1)[0]
                != str(expected_label).encode("ascii")
            ):
                raise ValueError(
                    "Training text label order changed."
                )

            destination = (
                fit
                if count < len(fit_idx)
                else stop
            )

            destination.write(line)
            count += 1

            if count % 200000 == 0:
                print(
                    f"  Split {count:,} training rows",
                    flush=True,
                )

    if count != len(indices["valid_indices"]):
        raise ValueError(
            "Training text has missing rows."
        )

    for name in destinations:
        temporary[name].replace(
            destinations[name]
        )

    result = {
        "identity": identity,
        "parts": {
            name: {
                "file": path.relative_to(root).as_posix(),
                "sha256": sha256(path),
            }
            for name, path in destinations.items()
        },
    }

    save_json(marker, result)
    return result


def select_rounds(
    root,
    protocol,
    report_dir,
    model_dir,
    data_dir,
):
    import lightgbm as lgb
    import numpy as np

    state_path = report_dir / "round_selection.json"

    if state_path.exists():
        state = read_json(state_path)

        if (
            sha256(root / state["model_file"])
            != state["model_sha256"]
        ):
            raise ValueError(
                "Saved round selector changed."
            )

        print(
            "Reusing full-cohort selection: "
            f"{state['selected_rounds']} rounds.",
            flush=True,
        )

        return state

    prepared = read_json(
        root
        / "reports/ember2024/full-win32-v1"
        / "preparation.json"
    )

    with np.load(
        root / prepared["row_index_file"],
        allow_pickle=False,
    ) as saved:
        indices = {
            name: saved[name]
            for name in (
                "valid_indices",
                "inner_fit_indices",
                "inner_stop_indices",
            )
        }

        labels = saved["label"]
        weeks = saved["week"]
        timestamps = saved["timestamp"]

    fit_idx = indices["inner_fit_indices"]
    stop_idx = indices["inner_stop_indices"]

    if (
        np.any(weeks[fit_idx] >= 36)
        or np.any(weeks[stop_idx] < 36)
        or timestamps[fit_idx].max()
        >= timestamps[stop_idx].min()
    ):
        raise ValueError(
            "Invalid internal chronological split."
        )

    split = split_text(
        root,
        protocol,
        indices,
        labels,
        data_dir,
    )

    params = dict(
        protocol["parameters"],
        two_round=True,
        precise_float_parser=True,
    )

    print(
        "STAGE 1: selecting rounds; "
        f"fit={len(fit_idx):,}, "
        f"stop={len(stop_idx):,}",
        flush=True,
    )

    fit = lgb.Dataset(
        str(root / split["parts"]["fit"]["file"]),
        params=params,
        free_raw_data=True,
    )

    fit.construct()

    stop = lgb.Dataset(
        str(root / split["parts"]["stop"]["file"]),
        reference=fit,
        params=params,
        free_raw_data=True,
    )

    stop.construct()

    if (
        fit.num_data() != len(fit_idx)
        or stop.num_data() != len(stop_idx)
        or not np.array_equal(
            fit.get_label(),
            labels[fit_idx],
        )
        or not np.array_equal(
            stop.get_label(),
            labels[stop_idx],
        )
    ):
        raise ValueError(
            "Internal split dimensions or labels changed."
        )

    history = {}

    selected_model = lgb.train(
        params,
        fit,
        num_boost_round=MAX_ROUNDS,
        valid_sets=[stop],
        valid_names=["inner_stop"],
        keep_training_booster=True,
        callbacks=[
            lgb.early_stopping(
                PATIENCE,
                first_metric_only=True,
            ),
            lgb.log_evaluation(50),
            lgb.record_evaluation(history),
        ],
    )

    selected_rounds = int(
        selected_model.best_iteration
        or selected_model.current_iteration()
    )

    evaluated_rounds = len(
        history["inner_stop"]["binary_logloss"]
    )

    destination = (
        model_dir / "lightgbm_round_selector.txt"
    )

    temporary = destination.with_suffix(".tmp")

    selected_model.save_model(
        str(temporary),
        num_iteration=selected_rounds,
    )

    temporary.replace(destination)

    result = {
        "selected_rounds": selected_rounds,
        "evaluated_rounds": evaluated_rounds,
        "maximum_budget_reached": (
            evaluated_rounds == MAX_ROUNDS
        ),
        "best_internal_log_loss": float(
            selected_model.best_score[
                "inner_stop"
            ]["binary_logloss"]
        ),
        "fit_rows": len(fit_idx),
        "stopping_rows": len(stop_idx),
        "history": history,
        "model_file": (
            destination.relative_to(root).as_posix()
        ),
        "model_sha256": sha256(destination),
    }

    save_json(state_path, result)

    del selected_model, stop, fit
    gc.collect()

    return result


def worker(root):
    import numpy as np
    from train_ember2024_lightgbm import measure

    report_dir, model_dir, data_dir = locations(root)

    protocol = read_json(
        report_dir / "protocol.json"
    )

    for name, digest in protocol["protected_inputs"].items():
        if sha256(root / name) != digest:
            raise ValueError(
                f"Protected input changed: {name}"
            )

    kernel, psapi = windows_apis()

    finished, watchdog = start_watchdog(
        report_dir,
        kernel,
        psapi,
    )

    try:
        selection = select_rounds(
            root,
            protocol,
            report_dir,
            model_dir,
            data_dir,
        )
    finally:
        finished.set()
        watchdog.join(timeout=2)

    if not (
        1
        <= selection["selected_rounds"]
        <= MAX_ROUNDS
    ):
        raise ValueError(
            "Invalid selected round budget."
        )

    print(
        "\nSTAGE 2: full refit for "
        f"{selection['selected_rounds']} selected rounds",
        flush=True,
    )

    # Reuse the previously tested full-refit worker,
    # directing its outputs into this new candidate run.
    base.RUN = RUN
    base.ROUNDS = selection["selected_rounds"]

    refit_report = report_dir / "report.json"

    if refit_report.exists():
        existing = read_json(refit_report)

        if (
            existing["protocol"] != protocol
            or sha256(root / existing["model_file"])
            != existing["model_sha256"]
        ):
            raise ValueError(
                "Existing refit report/model differs "
                "from this run."
            )
    else:
        base.worker(
            root,
            root / protocol["probe_report"],
        )

    result = read_json(refit_report)

    result.update(
        role="lightgbm_followup_candidate",
        round_selection=selection,
        note=(
            "Full-cohort inner chronological selection "
            "with 2,000-round cap and 75-round patience. "
            "Other LightGBM settings unchanged. "
            "Later validation is reused development data. "
            "The earlier official test benchmark has "
            "already been seen; this follow-up is not "
            "an independently confirmed improvement. "
            "No official test predictions computed here."
        ),
    )

    save_json(refit_report, result)

    old = read_json(
        root
        / "reports/ember2024/full-win32-v1"
        / "primary-full-fixed1109-v1/report.json"
    )

    xgb_report_dir = (
        root
        / "reports/ember2024/full-win32-v1"
        / "challenger-full-temporal-v1"
    )

    xgb = read_json(
        xgb_report_dir / "report.json"
    )

    with np.load(
        report_dir / "validation_predictions.npz",
        allow_pickle=False,
    ) as saved:
        y = saved["y_true"]
        light = saved["probability"]

    with np.load(
        xgb_report_dir / "validation_predictions.npz",
        allow_pickle=False,
    ) as saved:
        if not np.array_equal(
            y,
            saved["y_true"],
        ):
            raise ValueError(
                "Validation row order differs "
                "between candidates."
            )

        boost = saved["xgboost"]

    ensemble = measure(
        y,
        (light + boost) / 2.0,
    )

    comparisons = {
        "lightgbm_1109": old["validation"],
        "lightgbm_reselected": result["validation"],
        "xgboost_2000": xgb["validation"]["xgboost"],
        "new_ensemble_50_50": ensemble,
    }

    for name, digest in protocol["protected_inputs"].items():
        if sha256(root / name) != digest:
            raise ValueError(
                f"Protected input changed: {name}"
            )

    summary = {
        "status": "complete",
        "protocol": protocol,
        "round_selection": selection,
        "training": result["training"],
        "validation": comparisons,
        "lightgbm_loss_gap": (
            result["gaps"][
                "log_loss_validation_minus_train"
            ]
        ),
        "note": result["note"],
    }

    save_json(
        report_dir / "comparison.json",
        summary,
    )

    print(
        "\nLIGHTGBM FULL-COHORT RESELECTION SUMMARY"
    )

    print(
        f"Selected rounds={selection['selected_rounds']}; "
        "budget reached="
        f"{selection['maximum_budget_reached']}"
    )

    print(
        "New LightGBM training loss="
        f"{result['training']['log_loss']:.6f}; "
        f"gap={summary['lightgbm_loss_gap']:.6f}"
    )

    for name, value in comparisons.items():
        print(
            f"{name}: "
            f"loss={value['log_loss']:.6f}, "
            f"PR-AUC={value['pr_auc']:.6f}, "
            f"recall={value['recall']:.3%}, "
            f"FPR={value['false_positive_rate']:.3%}, "
            f"FP={value['confusion']['fp']}, "
            f"FN={value['confusion']['fn']}"
        )

    print(
        f"Report: {report_dir / 'comparison.json'}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )

    parser.add_argument(
        "--worker",
        action="store_true",
    )

    args = parser.parse_args()
    root = args.project_root.resolve()

    report_dir, model_dir, data_dir = locations(root)

    if args.worker:
        worker(root)
        return

    old_path = (
        root
        / "reports/ember2024/full-win32-v1"
        / "primary-full-fixed1109-v1/report.json"
    )

    xgb_path = (
        root
        / "reports/ember2024/full-win32-v1"
        / "challenger-full-temporal-v1/report.json"
    )

    old = read_json(old_path)
    xgb = read_json(xgb_path)

    probes = [
        name
        for name in old["protocol"]["protected_inputs"]
        if (
            "/two-round-probes/" in name
            and name.endswith("/report.json")
        )
    ]

    if len(probes) != 1:
        raise ValueError(
            "Could not identify the original "
            "LightGBM cache report."
        )

    probe_path = root / probes[0]
    probe = read_json(probe_path)

    manifest_path = (
        probe_path.parents[2] / "manifest.json"
    )

    manifest = read_json(manifest_path)

    if (
        probe["manifest_sha256"]
        != sha256(manifest_path)
        or manifest["status"] != "complete"
        or xgb["round_selection"]["fit_rows"]
        != 1079988
        or xgb["round_selection"]["stopping_rows"]
        != 119986
    ):
        raise ValueError(
            "Training text or XGBoost "
            "chronological cohort mismatch."
        )

    params = dict(
        probe["worker"]["parameters"]
    )

    params.pop("two_round", None)
    params.pop("precise_float_parser", None)

    protected = dict(
        old["protocol"]["protected_inputs"]
    )

    additional_paths = (
        old_path,
        xgb_path,
        manifest_path,
        Path(base.__file__),
        root / xgb["model_file"],
        root / old["model_file"],
        xgb_path.parent / "validation_predictions.npz",
    )

    for path in additional_paths:
        protected[
            path.relative_to(root).as_posix()
        ] = sha256(path)

    protected[manifest["text_file"]] = (
        manifest["text_sha256"]
    )

    protocol = {
        "run": RUN,
        "script_sha256": sha256(
            Path(__file__)
        ),
        "maximum_rounds": MAX_ROUNDS,
        "patience": PATIENCE,
        "parameters": params,
        "probe_report": probes[0],
        "stream_manifest": (
            manifest_path.relative_to(root).as_posix()
        ),
        "protected_inputs": protected,
    }

    for folder in (
        report_dir,
        model_dir,
        data_dir,
    ):
        folder.mkdir(
            parents=True,
            exist_ok=True,
        )

    protocol_path = (
        report_dir / "protocol.json"
    )

    if protocol_path.exists():
        if read_json(protocol_path) != protocol:
            raise ValueError(
                "Existing reselection run uses "
                "a different protocol."
            )
    else:
        if any(model_dir.iterdir()):
            raise FileExistsError(
                "Untracked candidate models already exist."
            )

        save_json(
            protocol_path,
            protocol,
        )

    if (report_dir / "comparison.json").exists():
        print(
            "Already complete: "
            f"{report_dir / 'comparison.json'}"
        )
        return

    kernel, psapi = windows_apis()
    memory = system_memory(kernel)

    print(
        "Available RAM="
        f"{memory['available_physical'] / GIB:.2f} GiB; "
        "available commit="
        f"{memory['available_commit'] / GIB:.2f} GiB"
    )

    if (
        memory["available_physical"] < 6 * GIB
        or memory["available_commit"] < 8 * GIB
    ):
        print(
            "Close unused applications and rerun; "
            "starting buffer is 6 GiB RAM "
            "and 8 GiB commit."
        )
        return

    if (
        not (data_dir / "split_complete.json").exists()
        and shutil.disk_usage(root).free < 20 * GIB
    ):
        raise RuntimeError(
            "At least 20 GiB free disk space is needed "
            "for chronological text files and headroom."
        )

    for name in (
        "stop.request",
        "guard.json",
        "heartbeat.json",
    ):
        (report_dir / name).unlink(
            missing_ok=True
        )

    process = subprocess.Popen(
        [
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "--project-root",
            str(root),
            "--worker",
        ]
    )

    logged = time.monotonic()

    try:
        while process.poll() is None:
            if time.monotonic() - logged >= 20:
                try:
                    beat = read_json(
                        report_dir / "heartbeat.json"
                    )
                except (
                    FileNotFoundError,
                    PermissionError,
                ):
                    beat = None

                if beat:
                    print(
                        "Worker RAM="
                        f"{beat['memory']['working_set'] / GIB:.2f} GiB; "
                        "system available="
                        f"{beat['system']['available_physical'] / GIB:.2f} GiB",
                        flush=True,
                    )

                logged = time.monotonic()

            time.sleep(0.25)

    except KeyboardInterrupt:
        print(
            "Stopping. Completed selection is reusable; "
            "unfinished fitting restarts."
        )

    finally:
        if process.poll() is None:
            (report_dir / "stop.request").write_text(
                "stop\n",
                encoding="ascii",
            )

            while process.poll() is None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    continue

    if process.returncode:
        guard_path = (
            report_dir / "guard.json"
        )

        if guard_path.exists():
            print(
                read_json(guard_path)
            )

        raise SystemExit(
            process.returncode
        )


if __name__ == "__main__":
    main()