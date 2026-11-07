"""Fit a full-cohort LightGBM candidate for the pilot's fixed 1,109 rounds.

Reuses a successful streaming probe's binary cache. Snapshots support inspection;
later validation is evaluated only after training, never for stopping/tuning.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from probe_full_ember2024_lightgbm_v2 import (
    GIB, read_json, save_json, sha256, windows_apis, system_memory,
    process_memory, start_watchdog,
)

RUN = "primary-full-fixed1109-v1"
ROUNDS = 1109


def paths(root):
    return (root / "reports/ember2024/full-win32-v1" / RUN,
            root / "src/models/candidates/ember2024" / RUN)


def atomic_model(model, path):
    temporary = path.with_suffix(".tmp")
    model.save_model(str(temporary))
    temporary.replace(path)


def worker(root, probe_path):
    report_dir, model_dir = paths(root)
    kernel, psapi = windows_apis()
    finished, watchdog = start_watchdog(report_dir, kernel, psapi)
    try:
        import lightgbm as lgb
        import numpy as np
        from train_ember2024_lightgbm import measure, gaps

        protocol = read_json(report_dir / "protocol.json")
        probe = read_json(probe_path)
        if lgb.__version__ != probe["worker"]["lightgbm_version"]:
            raise ValueError("LightGBM version differs from the cache-building environment.")
        params = dict(probe["worker"]["parameters"])
        params.pop("two_round", None)
        params.pop("precise_float_parser", None)
        prepared_path = root / "reports/ember2024/full-win32-v1/preparation.json"
        preparation = read_json(prepared_path)
        baseline_path = root / "reports/ember2024/pilot-v1/primary-temporal-v1/report.json"
        baseline = read_json(baseline_path)
        pilot_data = root / "data/processed/ember2024/pilot-v1/vectorized-v1"

        def verify_protected():
            for filename, expected in protocol["protected_inputs"].items():
                if sha256(root / filename) != expected:
                    raise ValueError(f"Protected input changed: {filename}")

        verify_protected()
        with np.load(root / preparation["row_index_file"], allow_pickle=False) as saved:
            selected = saved["valid_indices"]
            physical_labels = saved["label"]
        y_train = physical_labels[selected]
        chunks = [c for w in preparation["weeks"] for c in w["chunks"]]
        if len(selected) != probe["summary"]["training_rows"]:
            raise ValueError("Training row count differs from the cache.")
        dataset = lgb.Dataset(str(root / probe["worker"]["binary_cache"]),
                              params=params, free_raw_data=True)
        print("Loading verified full-training binary cache...", flush=True)
        dataset.construct()
        if (dataset.num_data() != len(selected) or dataset.num_feature() != 2568
                or not np.array_equal(dataset.get_label(), y_train)):
            raise ValueError("Cached training dimensions or labels changed.")
        checkpoint_state = report_dir / "checkpoint.json"
        def checkpoint_model(model):
            count = model.current_iteration()
            # Separate files keep the previous committed checkpoint valid if interrupted.
            destination = model_dir / f"checkpoint_{count:04d}.txt"
            atomic_model(model, destination)
            save_json(checkpoint_state, {
                "rounds": count, "model_file": destination.relative_to(root).as_posix(),
                "model_sha256": sha256(destination),
                "purpose": "Diagnostic snapshot; interrupted fits restart from round zero.",
            })

        def progress(env):
            count = env.model.current_iteration()
            if count % 50 == 0 or count == ROUNDS:
                print(f"Training: {count}/{ROUNDS} rounds", flush=True)
            if count % 200 == 0 or count == ROUNDS:
                checkpoint_model(env.model)

        progress.order = 50
        began = time.monotonic()
        model = lgb.train(params, dataset, num_boost_round=ROUNDS,
                          keep_training_booster=True, callbacks=[progress])
        training_seconds = time.monotonic() - began
        if model.current_iteration() != ROUNDS:
            raise ValueError("Unexpected final boosting round count.")
        final_path = model_dir / "lightgbm_primary_full.txt"
        atomic_model(model, final_path)
        # Free the binned dataset/histogram learner before chunked prediction.
        predictor = lgb.Booster(model_file=str(final_path))
        del model, dataset
        import gc
        gc.collect()

        print("Measuring training predictions in chunks...", flush=True)
        probabilities = np.empty(len(selected), dtype=np.float64)
        for number, chunk in enumerate(chunks):
            low = chunk["offset"]
            high = low + chunk["rows"]
            a, b = np.searchsorted(selected, [low, high])
            source = root / chunk["x_file"]
            if sha256(source) != chunk["x_sha256"]:
                raise ValueError(f"Vector chunk changed: {source}")
            matrix = np.load(source, mmap_mode="r", allow_pickle=False)
            try:
                if b > a:
                    probabilities[a:b] = predictor.predict(
                        matrix[selected[a:b] - low], num_threads=params["num_threads"])
            finally:
                matrix._mmap.close()
            if (number + 1) % 24 == 0 or number + 1 == len(chunks):
                print(f"  Assessed {int(b):,}/{len(selected):,} training rows", flush=True)
        training = measure(y_train, probabilities)
        x_validation = np.load(pilot_data / "X_validation.npy", mmap_mode="r", allow_pickle=False)
        y_validation = np.load(pilot_data / "y_validation.npy", allow_pickle=False)
        val_probabilities = np.empty(len(y_validation), dtype=np.float64)
        try:
            for begin in range(0, len(y_validation), 2048):
                end = min(begin + 2048, len(y_validation))
                val_probabilities[begin:end] = predictor.predict(
                    x_validation[begin:end], num_threads=params["num_threads"])
        finally:
            x_validation._mmap.close()
        validation = measure(y_validation, val_probabilities)
        with (report_dir / "validation_predictions.npz").open("wb") as stream:
            np.savez_compressed(stream, y_true=y_validation, probability=val_probabilities)
        verify_protected()
        result = {
            "status": "complete", "run_id": RUN, "role": "experimental_primary_lightgbm",
            "protocol": protocol, "rounds": ROUNDS,
            "training_seconds_this_invocation": training_seconds,
            "parameters": params, "training": training, "validation": validation,
            "gaps": gaps(training, validation),
            "pilot_baseline": {"training": baseline["training"],
                               "validation": baseline["validation"]},
            "model_file": final_path.relative_to(root).as_posix(),
            "model_sha256": sha256(final_path),
            "validation_predictions_sha256": sha256(report_dir / "validation_predictions.npz"),
            "memory": process_memory(psapi, kernel.GetCurrentProcess()),
            "protected_inputs_unchanged": True,
            "note": "Fixed budget inherited from pilot; no later-validation stopping. "
                    "Historical pilot comparison uses the same later validation, which "
                    "has been reused for development. Bin boundaries/loading differ with "
                    "the new cohort; this does not isolate dataset size alone. "
                    "Official test/challenge data were not used. No automatic promotion.",
        }
        save_json(report_dir / "report.json", result)
        print("\nFULL LIGHTGBM TRAINING SUMMARY")
        print("Model          Rows   TrainLoss     ValLoss        Gap      ValPR      ValF1")
        for name, train, val in (("pilot", baseline["training"], baseline["validation"]),
                                 ("full", training, validation)):
            print(f"{name:<10} {train['records']:>8} {train['log_loss']:>11.6f} "
                  f"{val['log_loss']:>11.6f} {val['log_loss']-train['log_loss']:>10.6f} "
                  f"{val['pr_auc']:>10.6f} {val['f1']:>10.6f}")
            print(f"  Validation recall={val['recall']:.3%}, FPR={val['false_positive_rate']:.3%}, "
                  f"FP={val['confusion']['fp']}, FN={val['confusion']['fn']}, "
                  f"ROC-AUC={val['roc_auc']:.6f}, Brier={val['brier_score']:.6f}")
        print(f"Model: {final_path}\nReport: {report_dir / 'report.json'}")
    finally:
        finished.set()
        watchdog.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--probe-report", type=Path)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.project_root.resolve()
    report_dir, model_dir = paths(root)
    if args.worker:
        worker(root, args.probe_report)
        return
    if args.probe_report:
        probe_path = args.probe_report.resolve()
    else:
        candidates = sorted((root / "data/processed/ember2024/full-win32-v1/streaming-input-v1/two-round-probes").glob("*/report.json"), reverse=True)
        probe_path = next((p for p in candidates if read_json(p)["summary"]["status"] == "complete"), None)
        if probe_path is None:
            raise FileNotFoundError("No successful streaming probe report was found.")
    probe = read_json(probe_path)
    if probe["summary"]["status"] != "complete" or probe["summary"].get("guard") is not None:
        raise ValueError("Use a completed streaming probe with a binary cache.")
    preparation_path = root / "reports/ember2024/full-win32-v1/preparation.json"
    baseline_path = root / "reports/ember2024/pilot-v1/primary-temporal-v1/report.json"
    pilot_report_path = root / "reports/ember2024/pilot-v1/vectorized-v1.json"
    pilot_report = read_json(pilot_report_path)
    baseline = read_json(baseline_path)
    if baseline["round_selection"]["selected_rounds"] != ROUNDS:
        raise ValueError("This run's fixed round budget differs from the pilot.")
    manifest_path = probe_path.parents[2] / "manifest.json"
    manifest = read_json(manifest_path)
    if (probe["manifest_sha256"] != sha256(manifest_path)
            or manifest["protocol"]["preparation_sha256"] != sha256(preparation_path)):
        raise ValueError("Probe/streaming/preparation provenance mismatch.")
    protected = {}
    for path in (probe_path, manifest_path, preparation_path, baseline_path, pilot_report_path):
        protected[path.relative_to(root).as_posix()] = sha256(path)
    prep = read_json(preparation_path)
    protected[prep["row_index_file"]] = prep["row_index_sha256"]
    cache = root / probe["worker"]["binary_cache"]
    protected[cache.relative_to(root).as_posix()] = probe["worker"]["binary_cache_sha256"]
    pilot_data = root / "data/processed/ember2024/pilot-v1/vectorized-v1"
    for filename, expected in pilot_report["summary"]["partitions"]["validation"]["files"].items():
        protected[(pilot_data / filename).relative_to(root).as_posix()] = expected
    if baseline["data_report_sha256"] != sha256(pilot_report_path):
        raise ValueError("Pilot baseline and validation provenance mismatch.")
    protocol = {"run_id": RUN, "fixed_rounds": ROUNDS,
                "script_sha256": sha256(Path(__file__)), "protected_inputs": protected}
    report_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)
    protocol_path = report_dir / "protocol.json"
    if protocol_path.exists():
        if read_json(protocol_path) != protocol:
            raise ValueError("Existing candidate run has a different protocol.")
    else:
        if any(model_dir.iterdir()):
            raise FileExistsError("Untracked model files already exist in the candidate directory.")
        save_json(protocol_path, protocol)
    if (report_dir / "report.json").exists():
        result = read_json(report_dir / "report.json")
        if result["status"] == "complete":
            print(f"Already complete: {report_dir / 'report.json'}")
            return
    kernel, psapi = windows_apis()
    memory = system_memory(kernel)
    print(f"Available RAM: {memory['available_physical']/GIB:.2f} GiB; "
          f"available commit: {memory['available_commit']/GIB:.2f} GiB")
    if memory["available_physical"] < 6 * GIB or memory["available_commit"] < 8 * GIB:
        print("Save your work, close unused applications and rerun. Starting buffer: 6 GiB RAM/8 GiB commit.")
        return
    # Each invocation gets fresh telemetry; snapshots are for diagnosis, not continuation.
    for name in ("stop.request", "guard.json", "heartbeat.json"):
        (report_dir / name).unlink(missing_ok=True)
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--project-root", str(root),
               "--probe-report", str(probe_path), "--worker"]
    process = subprocess.Popen(command)
    logged = time.monotonic()
    try:
        while process.poll() is None:
            if time.monotonic() - logged >= 20:
                try:
                    beat = read_json(report_dir / "heartbeat.json")
                except (FileNotFoundError, PermissionError):
                    beat = None
                if beat:
                    print(f"Worker RAM={beat['memory']['working_set']/GIB:.2f} GiB; "
                          f"system available={beat['system']['available_physical']/GIB:.2f} GiB", flush=True)
                logged = time.monotonic()
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("Stopping worker; diagnostic snapshots are retained. A retry restarts fitting.", flush=True)
    finally:
        if process.poll() is None:
            (report_dir / "stop.request").write_text("stop\n", encoding="ascii")
            while process.poll() is None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    continue
    if process.returncode != 0:
        if (report_dir / "guard.json").exists():
            print(json.dumps(read_json(report_dir / "guard.json"), indent=2))
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
