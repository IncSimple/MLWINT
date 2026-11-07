"""Chronological XGBoost challenger, full refit, and fixed 50/50 research ensemble.

Requires XGBoost 3.4.1 in the EMBER2024 environment. Uses dense float32 batches:
zero is a real feature value, not a missing value. Disk-backed CPU histogram
training keeps raw feature batches bounded. Later validation never selects rounds.
"""

import argparse
from datetime import datetime, timezone
import gc
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from probe_full_ember2024_lightgbm_v2 import (
    GIB, read_json, save_json, sha256, windows_apis,
    system_memory, process_memory, start_watchdog,
)

RUN = "challenger-full-temporal-v1"
MAX_ROUNDS = 2000
PATIENCE = 75
PARAMETERS = {
    "objective": "binary:logistic", "eval_metric": "logloss",
    "tree_method": "hist", "device": "cpu", "grow_policy": "depthwise",
    "eta": 0.05, "max_depth": 6, "min_child_weight": 1,
    "lambda": 1.0, "alpha": 0.0, "gamma": 0.0,
    "colsample_bytree": 0.8, "subsample": 1.0,
    "max_bin": 256, "max_cached_hist_node": 64,
    "nthread": min(6, os.cpu_count() or 1), "seed": 42,
    "validate_parameters": True, "verbosity": 1,
}


def locations(root):
    return (root / "reports/ember2024/full-win32-v1" / RUN,
            root / "src/models/candidates/ember2024" / RUN,
            root / "data/processed/ember2024/full-win32-v1/xgboost-cache" / RUN)


def atomic_model(model, path):
    temporary = path.with_name(path.stem + ".temporary.ubj")
    model.save_model(temporary)
    temporary.replace(path)


def make_iterator(root, chunks, selection, labels, prefix, np, xgb):
    class Iterator(xgb.DataIter):
        def __init__(self):
            self.position = 0
            self.batch = None
            self.batch_labels = None
            super().__init__(cache_prefix=str(prefix), release_data=True)

        def reset(self):
            self.position = 0
            self.batch = self.batch_labels = None

        def next(self, input_data):
            while self.position < len(chunks):
                chunk = chunks[self.position]
                self.position += 1
                low, high = chunk["offset"], chunk["offset"] + chunk["rows"]
                a, b = np.searchsorted(selection, [low, high])
                if a == b:
                    continue
                physical = selection[a:b]
                mapped = np.load(root / chunk["x_file"], mmap_mode="r", allow_pickle=False)
                try:
                    if mapped.dtype != np.float32 or mapped.shape != (chunk["rows"], 2568):
                        raise ValueError("Unexpected feature chunk shape or dtype.")
                    self.batch = np.array(mapped[physical - low], dtype=np.float32,
                                          order="C", copy=True)
                finally:
                    mapped._mmap.close()
                self.batch_labels = labels[physical].astype(np.float32)
                input_data(data=self.batch, label=self.batch_labels)
                return True
            return False

    return Iterator()


def fit_challenger(root, preparation, indices, labels, model_dir, report_dir, cache_dir, np, xgb):
    chunks = [c for w in preparation["weeks"] for c in w["chunks"]]
    selection_path = report_dir / "round_selection.json"
    if selection_path.exists():
        selection = read_json(selection_path)
        selector_path = model_dir / "xgboost_round_selector.ubj"
        if sha256(selector_path) != selection["model_sha256"]:
            raise ValueError("Saved round selector changed.")
        rounds = selection["selected_rounds"]
        print(f"Reusing verified selection: {rounds} boosting rounds.", flush=True)
    else:
        print("STAGE 1: internal chronological round selection", flush=True)
        fit_idx, stop_idx = indices["inner_fit_indices"], indices["inner_stop_indices"]
        print(f"Earlier fit rows: {len(fit_idx):,}; stopping rows: {len(stop_idx):,}", flush=True)
        fit_it = make_iterator(root, chunks, fit_idx, labels, cache_dir / "fit", np, xgb)
        fit = xgb.ExtMemQuantileDMatrix(fit_it, max_bin=PARAMETERS["max_bin"],
                                      nthread=PARAMETERS["nthread"])
        stop_it = make_iterator(root, chunks, stop_idx, labels, cache_dir / "stop", np, xgb)
        stop = xgb.ExtMemQuantileDMatrix(stop_it, ref=fit, max_bin=PARAMETERS["max_bin"],
                                       nthread=PARAMETERS["nthread"])
        if fit.num_row() != len(fit_idx) or stop.num_row() != len(stop_idx):
            raise ValueError("Internal training row counts changed.")
        history = {}
        began = time.monotonic()
        selector = xgb.train(PARAMETERS, fit, num_boost_round=MAX_ROUNDS,
                             evals=[(stop, "internal_stop")],
                             early_stopping_rounds=PATIENCE, evals_result=history,
                             verbose_eval=50)
        rounds = selector.best_iteration + 1
        best = selector[:rounds]
        selector_path = model_dir / "xgboost_round_selector.ubj"
        atomic_model(best, selector_path)
        selection = {
            "selected_rounds": rounds, "evaluated_rounds": selector.num_boosted_rounds(),
            "maximum_budget_reached": selector.num_boosted_rounds() == MAX_ROUNDS,
            "best_internal_log_loss": float(selector.best_score),
            "fit_rows": len(fit_idx), "stopping_rows": len(stop_idx),
            "training_seconds": time.monotonic() - began,
            "model_sha256": sha256(selector_path), "history": history,
        }
        save_json(selection_path, selection)
        del selector, best, stop, fit, stop_it, fit_it
        gc.collect()
    if not 1 <= rounds <= MAX_ROUNDS:
        raise ValueError("Invalid selected boosting round count.")
    print(f"\nSTAGE 2: refit all {len(indices['valid_indices']):,} rows for {rounds} rounds", flush=True)
    full_it = make_iterator(root, chunks, indices["valid_indices"], labels,
                            cache_dir / "full", np, xgb)
    full = xgb.ExtMemQuantileDMatrix(full_it, max_bin=PARAMETERS["max_bin"],
                                   nthread=PARAMETERS["nthread"])
    if full.num_row() != len(indices["valid_indices"]):
        raise ValueError("Full training row count changed.")

    class Progress(xgb.callback.TrainingCallback):
        def after_iteration(self, model, epoch, evals_log):
            if (epoch + 1) % 50 == 0 or epoch + 1 == rounds:
                print(f"Full refit: {epoch + 1}/{rounds} rounds", flush=True)
            if (epoch + 1) % 200 == 0:
                atomic_model(model, model_dir / f"snapshot_{epoch + 1:04d}.ubj")
            return False

    began = time.monotonic()
    model = xgb.train(PARAMETERS, full, num_boost_round=rounds, callbacks=[Progress()])
    elapsed = time.monotonic() - began
    final_path = model_dir / "xgboost_challenger_full.ubj"
    atomic_model(model, final_path)
    del model, full, full_it
    gc.collect()
    predictor = xgb.Booster()
    predictor.load_model(final_path)
    predictor.set_param({"nthread": PARAMETERS["nthread"], "device": "cpu"})
    return predictor, selection, elapsed, final_path


def worker(root, cache_dir):
    report_dir, model_dir, _ = locations(root)
    kernel, psapi = windows_apis()
    finished, watchdog = start_watchdog(report_dir, kernel, psapi)
    try:
        import numpy as np
        import xgboost as xgb
        from train_ember2024_lightgbm import measure, gaps

        if xgb.__version__ != "3.4.1":
            raise ValueError("Use the pinned xgboost==3.4.1 environment for this run.")
        protocol = read_json(report_dir / "protocol.json")

        def verify():
            for name, expected in protocol["protected_inputs"].items():
                if sha256(root / name) != expected:
                    raise ValueError(f"Protected input changed: {name}")

        verify()
        prepared = read_json(root / "reports/ember2024/full-win32-v1/preparation.json")
        with np.load(root / prepared["row_index_file"], allow_pickle=False) as saved:
            indices = {k: saved[k] for k in ("valid_indices", "inner_fit_indices", "inner_stop_indices")}
            labels, weeks, timestamps = saved["label"], saved["week"], saved["timestamp"]
        valid, fit, stop = (indices[k] for k in ("valid_indices", "inner_fit_indices", "inner_stop_indices"))
        if (not np.array_equal(np.sort(np.concatenate([fit, stop])), valid)
                or np.intersect1d(fit, stop).size
                or np.any(weeks[fit] >= 36) or np.any(weeks[stop] < 36)
                or timestamps[fit].max() >= timestamps[stop].min()):
            raise ValueError("Internal chronological partition mismatch.")
        for selected in indices.values():
            if np.any(np.diff(selected) <= 0) or not np.array_equal(np.unique(labels[selected]), [0, 1]):
                raise ValueError("Invalid row order or label coverage.")
        model, selection, elapsed, model_path = fit_challenger(
            root, prepared, indices, labels, model_dir, report_dir, cache_dir, np, xgb)
        print("\nSTAGE 3: training metrics and later-period validation", flush=True)
        train_probability = np.empty(len(valid), dtype=np.float64)
        chunks = [c for w in prepared["weeks"] for c in w["chunks"]]
        for number, chunk in enumerate(chunks):
            low, high = chunk["offset"], chunk["offset"] + chunk["rows"]
            a, b = np.searchsorted(valid, [low, high])
            mapped = np.load(root / chunk["x_file"], mmap_mode="r", allow_pickle=False)
            try:
                if b > a:
                    train_probability[a:b] = model.inplace_predict(mapped[valid[a:b] - low])
            finally:
                mapped._mmap.close()
            if (number + 1) % 24 == 0 or number + 1 == len(chunks):
                print(f"  Assessed {int(b):,}/{len(valid):,} training rows", flush=True)
        training = measure(labels[valid], train_probability)
        pilot = root / "data/processed/ember2024/pilot-v1/vectorized-v1"
        y = np.load(pilot / "y_validation.npy", allow_pickle=False)
        x = np.load(pilot / "X_validation.npy", mmap_mode="r", allow_pickle=False)
        probability = np.empty(len(y), dtype=np.float64)
        try:
            for begin in range(0, len(y), 2048):
                end = min(begin + 2048, len(y))
                probability[begin:end] = model.inplace_predict(np.asarray(x[begin:end]))
        finally:
            x._mmap.close()
        lgb_report_dir = root / "reports/ember2024/full-win32-v1/primary-full-fixed1109-v1"
        with np.load(lgb_report_dir / "validation_predictions.npz", allow_pickle=False) as saved:
            if not np.array_equal(saved["y_true"], y):
                raise ValueError("LightGBM and XGBoost validation row order differs.")
            lgb_probability = saved["probability"]
        ensemble_probability = (lgb_probability + probability) / 2.0
        validation = {"lightgbm": measure(y, lgb_probability),
                      "xgboost": measure(y, probability),
                      "ensemble_50_50": measure(y, ensemble_probability)}
        lgb_report = read_json(lgb_report_dir / "report.json")
        if abs(validation["lightgbm"]["log_loss"] - lgb_report["validation"]["log_loss"]) > 1e-10:
            raise ValueError("Saved LightGBM predictions do not reproduce its report.")
        predictions_path = report_dir / "validation_predictions.npz"
        with predictions_path.open("wb") as stream:
            np.savez_compressed(stream, y_true=y, lightgbm=lgb_probability,
                                xgboost=probability, ensemble_50_50=ensemble_probability)
        verify()
        result = {
            "status": "complete", "run_id": RUN, "role": "xgboost_challenger",
            "protocol": protocol, "parameters": PARAMETERS, "xgboost_version": xgb.__version__,
            "round_selection": selection, "refit_seconds": elapsed, "training": training,
            "validation": validation, "xgboost_gaps": gaps(training, validation["xgboost"]),
            "model_file": model_path.relative_to(root).as_posix(), "model_sha256": sha256(model_path),
            "validation_predictions_sha256": sha256(predictions_path),
            "memory": process_memory(psapi, kernel.GetCurrentProcess()),
            "protected_inputs_unchanged": True,
            "note": "Rounds selected only on inner chronological stopping rows, then full refit. "
                    "Later validation is reused development data. Ensemble weights fixed at 50/50. "
                    "No official test/challenge use, no independent generalization claim, no promotion. "
                    "Early stopping is based on log loss, not error rate at threshold 0.5.",
        }
        save_json(report_dir / "report.json", result)
        print("\nXGBOOST AND ENSEMBLE SUMMARY")
        print(f"Selected rounds: {selection['selected_rounds']}; budget reached: {selection['maximum_budget_reached']}")
        print(f"XGBoost training loss={training['log_loss']:.6f}; "
              f"validation loss={validation['xgboost']['log_loss']:.6f}; "
              f"gap={result['xgboost_gaps']['log_loss_validation_minus_train']:.6f}")
        print("Model                 LogLoss     PR-AUC    ROC-AUC         F1     FP     FN")
        for name, metric in validation.items():
            print(f"{name:<20} {metric['log_loss']:>9.6f} {metric['pr_auc']:>10.6f} "
                  f"{metric['roc_auc']:>10.6f} {metric['f1']:>10.6f} "
                  f"{metric['confusion']['fp']:>6} {metric['confusion']['fn']:>6}")
            print(f"  Recall={metric['recall']:.3%}; FPR={metric['false_positive_rate']:.3%}")
        print(f"Model: {model_path}\nReport: {report_dir / 'report.json'}")
    finally:
        finished.set()
        watchdog.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--worker-cache", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.project_root.resolve()
    if args.worker_cache:
        worker(root, args.worker_cache)
        return
    import xgboost as xgb
    if xgb.__version__ != "3.4.1":
        raise RuntimeError("Install xgboost==3.4.1 in the EMBER2024 environment first.")
    report_dir, model_dir, cache_root = locations(root)
    prep_path = root / "reports/ember2024/full-win32-v1/preparation.json"
    lgb_dir = root / "reports/ember2024/full-win32-v1/primary-full-fixed1109-v1"
    lgb = read_json(lgb_dir / "report.json")
    prep = read_json(prep_path)
    if prep["status"] != "complete" or lgb["status"] != "complete":
        raise ValueError("Full preparation and LightGBM training must both be complete.")
    if lgb["protocol"]["protected_inputs"][prep_path.relative_to(root).as_posix()] != sha256(prep_path):
        raise ValueError("XGBoost would use a different cohort from LightGBM.")
    protected = {prep_path.relative_to(root).as_posix(): sha256(prep_path),
                 prep["row_index_file"]: prep["row_index_sha256"],
                 (lgb_dir / "report.json").relative_to(root).as_posix(): sha256(lgb_dir / "report.json"),
                 (lgb_dir / "validation_predictions.npz").relative_to(root).as_posix(): lgb["validation_predictions_sha256"]}
    for name, expected in lgb["protocol"]["protected_inputs"].items():
        if "/pilot-v1/vectorized-v1/" in name:
            protected[name] = expected
    print("Verifying cohort chunks and protected validation inputs...", flush=True)
    for week in prep["weeks"]:
        for chunk in week["chunks"]:
            if sha256(root / chunk["x_file"]) != chunk["x_sha256"]:
                raise ValueError(f"Feature chunk changed: {chunk['x_file']}")
        print(f"  Verified week {week['week']:02d}", flush=True)
    for name, expected in protected.items():
        if sha256(root / name) != expected:
            raise ValueError(f"Protected input changed: {name}")
    protocol = {"run_id": RUN, "script_sha256": sha256(Path(__file__)),
                "parameters": PARAMETERS, "maximum_rounds": MAX_ROUNDS,
                "patience": PATIENCE, "protected_inputs": protected,
                "xgboost_version": xgb.__version__, "ensemble_weights": [0.5, 0.5]}
    report_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)
    protocol_path = report_dir / "protocol.json"
    if protocol_path.exists():
        if read_json(protocol_path) != protocol:
            raise ValueError("Existing challenger run uses a different protocol.")
    else:
        if any(model_dir.iterdir()):
            raise FileExistsError("Untracked candidate models already exist.")
        save_json(protocol_path, protocol)
    if (report_dir / "report.json").exists():
        print(f"Already complete: {report_dir / 'report.json'}")
        return
    kernel, psapi = windows_apis()
    memory = system_memory(kernel)
    print(f"Available RAM={memory['available_physical']/GIB:.2f} GiB; "
          f"commit headroom={memory['available_commit']/GIB:.2f} GiB")
    if memory["available_physical"] < 6 * GIB or memory["available_commit"] < 8 * GIB:
        print("Close unused applications and rerun: starting buffer is 6 GiB RAM/8 GiB commit.")
        return
    if shutil.disk_usage(root).free < 20 * GIB:
        raise RuntimeError("Free at least 20 GiB for external-memory caches and headroom.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    cache_dir = cache_root / stamp
    cache_dir.mkdir(parents=True, exist_ok=False)
    for name in ("stop.request", "guard.json", "heartbeat.json"):
        (report_dir / name).unlink(missing_ok=True)
    process = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()),
                               "--project-root", str(root), "--worker-cache", str(cache_dir)])
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
        print("Stopping. A completed round selection is reusable; an incomplete fit restarts.")
    finally:
        if process.poll() is None:
            (report_dir / "stop.request").write_text("stop\n", encoding="ascii")
            while process.poll() is None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    continue
    if process.returncode:
        if (report_dir / "guard.json").exists():
            print(json.dumps(read_json(report_dir / "guard.json"), indent=2))
        print(f"Attempt cache directory: {cache_dir}")
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
