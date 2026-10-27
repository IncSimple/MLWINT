"""Controlled development sweep. Defaults to inspection; --run enables training.

Use python -m src.models.run_mild_regularization --help from the repository root.
No training, data reads or directory creation occurs merely by importing this module.
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import lightgbm as lgb
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, average_precision_score, brier_score_loss, confusion_matrix,
    f1_score, log_loss, precision_score, recall_score, roc_auc_score,
)

from src.models.probabilities import lightgbm_probability

ROOT = Path(__file__).resolve().parents[2]
FEATURES = 2381
BASELINES = {
    "lightgbm_baseline": "src/models/candidates/lightgbm_baseline.txt",
    "xgboost_baseline": "src/models/candidates/xgboost_ember.json",
}
INPUTS = {
    "features": "data/processed/ember/model_data/X_sample.npy",
    "labels": "data/processed/ember/model_data/y_sample.npy",
    "split": "reports/ember/model_comparison/split_indices.npz",
    **BASELINES,
}
CAUTION = (
    "Exploratory EMBER 2018/v2 comparison on reused training/validation partitions. "
    "No test predictions are computed. These are not independent final benchmark results."
)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    """Replace only this run's checkpoint, without leaving a partial JSON file."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_name(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise ValueError("Names must contain 1-80 letters, digits, underscores or hyphens")
    if value.upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)],
                         *[f"LPT{i}" for i in range(10)]}:
        raise ValueError("Windows device names are not valid run/candidate names")
    return value


def resolve_candidates(config, jobs):
    names = set(BASELINES)
    candidates = []
    for item in config["candidates"]:
        name = safe_name(item["name"])
        algorithm = item["algorithm"]
        if name in names or algorithm not in {"lightgbm", "xgboost"}:
            raise ValueError("Candidate names must be unique and use a supported algorithm")
        names.add(name)
        changes = item["changes"]
        baseline = config[algorithm]
        if len(changes) != 1 or any(k not in baseline for k in changes):
            raise ValueError("Each candidate must override exactly one explicit baseline parameter")
        key = next(iter(changes))
        if changes[key] == baseline[key]:
            raise ValueError("Candidate override must differ from its baseline")
        params = {**baseline, **changes, "random_state": config["seed"], "n_jobs": jobs}
        if algorithm == "xgboost":
            params["early_stopping_rounds"] = config["early_stopping_rounds"]
        candidates.append({"name": name, "algorithm": algorithm,
                           "changes": changes, "parameters": params})
    if not candidates:
        raise ValueError("At least one candidate is required")
    return candidates


def read_inputs(research_root):
    paths = {name: research_root / relative for name, relative in INPUTS.items()}
    for path in paths.values():
        if not path.is_file():
            raise FileNotFoundError(f"Required input is missing: {path}")
    features = np.load(paths["features"], mmap_mode="r", allow_pickle=False)
    labels = np.load(paths["labels"], allow_pickle=False)
    if features.ndim != 2 or features.shape[1] != FEATURES or features.dtype != np.float32:
        raise ValueError("Features must be an (n, 2381) float32 array")
    if labels.shape != (len(features),) or not np.isin(labels, [0, 1]).all():
        raise ValueError("Labels must be a matching one-dimensional binary array")
    with np.load(paths["split"], allow_pickle=False) as saved:
        splits = {name: saved[name].copy() for name in ("train_idx", "val_idx", "test_idx")}
    for indices in splits.values():
        if indices.ndim != 1 or indices.dtype.kind not in "iu" or len(indices) == 0:
            raise ValueError("Each split must be a nonempty one-dimensional integer array")
        if np.any(indices >= len(labels)) or np.any(indices < 0):
            raise ValueError("Split index is outside the dataset")
    joined = np.concatenate(list(splits.values()))
    if not np.array_equal(np.sort(joined), np.arange(len(labels))):
        raise ValueError("Saved splits must be disjoint and cover every sample exactly once")
    for key in ("train_idx", "val_idx"):
        if len(np.unique(labels[splits[key]])) != 2:
            raise ValueError("Training and validation each require both classes")
    return paths, features, labels, splits


def probability(algorithm, model, features, jobs):
    if algorithm == "lightgbm":
        if isinstance(model, lgb.Booster):
            # Bound threads for loaded baselines as well as newly fitted classifiers.
            return np.asarray(model.predict(features, num_threads=jobs), dtype=np.float64)
        return lightgbm_probability(model, features)
    return np.asarray(model.predict_proba(features)[:, 1], dtype=np.float64)


def metrics(labels, scores, threshold):
    scores = np.asarray(scores, dtype=np.float64)
    if scores.shape != labels.shape or not np.isfinite(scores).all():
        raise ValueError("Probabilities must be finite and match the labels")
    if np.any((scores < 0) | (scores > 1)):
        raise ValueError("Probabilities must be in [0, 1]")
    predicted = (scores >= threshold).astype(np.int8)
    tn, fp, fn, tp = map(int, confusion_matrix(labels, predicted, labels=[0, 1]).ravel())
    bins = np.minimum((scores * 10).astype(int), 9)
    reliability = []
    for index in range(10):
        mask = bins == index
        count = int(mask.sum())
        reliability.append({
            "lower": index / 10, "upper": (index + 1) / 10, "count": count,
            "mean_probability": float(scores[mask].mean()) if count else None,
            "malicious_fraction": float(labels[mask].mean()) if count else None,
        })
    return {
        "records": len(labels), "threshold": threshold,
        "roc_auc": float(roc_auc_score(labels, scores)),
        "pr_auc": float(average_precision_score(labels, scores)),
        "log_loss": float(log_loss(labels, scores, labels=[0, 1])),
        "brier_score": float(brier_score_loss(labels, scores)),
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
        "false_positive_rate": fp / (tn + fp),
        "false_negative_rate": fn / (fn + tp),
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "reliability_10_bins": reliability,
    }


def peak_process_bytes():
    """Cumulative process high-water mark, not isolated model memory."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                )
            ]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters),
                                              wintypes.DWORD]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters),
                                          counters.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(counters.PeakWorkingSetSize)
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def benchmark(predict, batch, repeats):
    predict(batch)
    durations = []
    for _ in range(repeats):
        start = time.perf_counter()
        predict(batch)
        durations.append(time.perf_counter() - start)
    return {"records": len(batch), "repetitions": repeats, "warmup_calls": 1,
            "seconds": durations, "mean_seconds": float(np.mean(durations)),
            "records_per_second": float(len(batch) / np.mean(durations)),
            "process_peak_bytes": peak_process_bytes(),
            "memory_scope": "Cumulative process peak including data and all models loaded so far"}


def validation_rankings(results):
    rows = [{"model": name, **{k: row["validation"][k] for k in
             ("pr_auc", "log_loss", "roc_auc", "brier_score", "f1")}}
            for name, row in results.items()]
    return {
        "by_pr_auc": sorted(rows, key=lambda r: (-r["pr_auc"], r["log_loss"], r["model"])),
        "by_log_loss": sorted(rows, key=lambda r: (r["log_loss"], -r["pr_auc"], r["model"])),
    }


def execute(plan, paths, features, labels, splits):
    report_dir = Path(plan["report_directory"])
    model_dir = Path(plan["model_directory"])
    # Fail before hashing or training if either unique run directory exists.
    if report_dir.exists() or model_dir.exists():
        raise FileExistsError("Run output already exists; use a new --run-id")
    report_dir.mkdir(parents=True, exist_ok=False)
    model_dir.mkdir(parents=True, exist_ok=False)
    report = {
        "status": "running", "caution": CAUTION,
        "configuration": {key: value for key, value in plan.items()
                          if key not in {"report_directory", "model_directory", "mode"}},
        "inputs": {}, "results": {}, "artifacts": {}, "baseline_models": {},
    }
    report_path = report_dir / "report.json"
    write_json(report_path, report)
    try:
        print("Hashing input data and baseline artifacts...", flush=True)
        report["inputs"] = {key: {"path": INPUTS[key], "sha256": sha256(path),
                                   "bytes": path.stat().st_size}
                            for key, path in paths.items()}
        write_json(report_path, report)
        data = {name: (np.asarray(features[splits[key]], dtype=np.float32), labels[splits[key]])
                for name, key in (("train", "train_idx"), ("validation", "val_idx"))}
        for values, _ in data.values():
            if not np.isfinite(values).all():
                raise ValueError("Training/validation features contain nonfinite values")
        batch = data["validation"][0][:plan["latency_batch_size"]]
        models = {}
        predictions = {}

        def assess(name, predict):
            predictions[name] = {key: predict(values) for key, (values, _) in data.items()}
            result = {key: metrics(y, predictions[name][key], plan["threshold"])
                      for key, (_, y) in data.items()}
            result["gaps"] = {f"{key}_train_minus_validation":
                              result["train"][key] - result["validation"][key]
                              for key in ("roc_auc", "pr_auc", "f1")}
            result["gaps"]["log_loss_validation_minus_train"] = (
                result["validation"]["log_loss"] - result["train"]["log_loss"])
            result["latency"] = benchmark(predict, batch, plan["latency_repeats"])
            report["results"][name] = result
            report["rankings"] = validation_rankings(report["results"])
            write_json(report_path, report)

        jobs = plan["jobs"]
        for name in BASELINES:
            algorithm = "lightgbm" if name.startswith("lightgbm") else "xgboost"
            if algorithm == "lightgbm":
                model = lgb.Booster(model_file=str(paths[name]))
            else:
                model = xgb.XGBClassifier()
                model.load_model(str(paths[name]))
                model.set_params(n_jobs=jobs)
            models[name] = (algorithm, model)
            report["baseline_models"][name] = (
                {"effective_parameters": model.params, "tree_count": model.num_trees()}
                if algorithm == "lightgbm" else
                {"effective_parameters": json.loads(model.get_booster().save_config()),
                 "best_iteration_count": int(model.best_iteration) + 1
                 if hasattr(model, "best_iteration") else model.get_booster().num_boosted_rounds()}
            )
            print(f"Evaluating {name}", flush=True)
            assess(name, lambda values, a=algorithm, m=model: probability(a, m, values, jobs))

        for candidate in plan["candidates"]:
            name, algorithm = candidate["name"], candidate["algorithm"]
            print(f"Training {name}: {candidate['changes']}", flush=True)
            start = time.perf_counter()
            train_x, train_y = data["train"]
            val_x, val_y = data["validation"]
            if algorithm == "lightgbm":
                model = lgb.LGBMClassifier(**candidate["parameters"])
                model.fit(train_x, train_y, eval_set=[(val_x, val_y)],
                          eval_metric="binary_logloss", callbacks=[
                              lgb.early_stopping(plan["early_stopping_rounds"], verbose=False),
                              lgb.log_evaluation(100)])
                best = int(model.best_iteration_ or model.n_estimators)
            else:
                model = xgb.XGBClassifier(**candidate["parameters"])
                model.fit(train_x, train_y, eval_set=[(val_x, val_y)], verbose=100)
                best = int(model.best_iteration) + 1
            training_seconds = time.perf_counter() - start
            path = model_dir / (name + (".txt" if algorithm == "lightgbm" else ".json"))
            if algorithm == "lightgbm":
                model.booster_.save_model(str(path))
                effective = model.booster_.params
            else:
                model.save_model(str(path))
                effective = json.loads(model.get_booster().save_config())
            models[name] = (algorithm, model)
            report["artifacts"][name] = {
                "filename": path.name, "sha256": sha256(path), "bytes": path.stat().st_size,
                "best_iteration_count": best, "training_seconds": training_seconds,
                "effective_parameters": effective,
            }
            assess(name, lambda values, a=algorithm, m=model: probability(a, m, values, jobs))

        lgb_names = [name for name, (algorithm, _) in models.items() if algorithm == "lightgbm"]
        xgb_names = [name for name, (algorithm, _) in models.items() if algorithm == "xgboost"]
        for left in lgb_names:
            for right in xgb_names:
                name = f"ensemble__{left}__{right}"
                print(f"Evaluating {name}", flush=True)
                # Metrics reuse cached per-model scores; latency executes both models.
                result = {key: metrics(y, 0.5 * predictions[left][key]
                                       + 0.5 * predictions[right][key], plan["threshold"])
                          for key, (_, y) in data.items()}
                result["members"] = [left, right]
                result["weights"] = [0.5, 0.5]
                result["gaps"] = {f"{key}_train_minus_validation":
                                  result["train"][key] - result["validation"][key]
                                  for key in ("roc_auc", "pr_auc", "f1")}
                result["gaps"]["log_loss_validation_minus_train"] = (
                    result["validation"]["log_loss"] - result["train"]["log_loss"])
                result["latency"] = benchmark(
                    lambda values, l=models[left], r=models[right]:
                    0.5 * probability(*l, values, jobs) + 0.5 * probability(*r, values, jobs),
                    batch, plan["latency_repeats"])
                report["results"][name] = result
                report["rankings"] = validation_rankings(report["results"])
                write_json(report_path, report)

        for key in ("split", *BASELINES):
            if sha256(paths[key]) != report["inputs"][key]["sha256"]:
                raise RuntimeError("A protected input changed during the experiment: " + key)
        report["protected_inputs_unchanged"] = True
        report["status"] = "complete"
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(report_path, report)
        for ranking, rows in report["rankings"].items():
            with (report_dir / f"{ranking}.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
        return report
    except BaseException as error:
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        # Local paths in exception messages stay in terminal output, not public reports.
        write_json(report_path, report)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--research-root", type=Path, default=ROOT)
    parser.add_argument("--output-root", type=Path, default=ROOT)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/mild_regularization.json")
    parser.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--latency-batch-size", type=int, default=1024)
    parser.add_argument("--latency-repeats", type=int, default=3)
    parser.add_argument("--run", action="store_true", help="Train; default only validates and prints a plan")
    args = parser.parse_args(argv)
    if min(args.jobs, args.latency_batch_size, args.latency_repeats) < 1:
        parser.error("Thread count, latency batch size and repetitions must be positive")
    config = json.loads(args.config.read_text(encoding="utf-8"))
    if not 0 <= config["threshold"] <= 1 or config["early_stopping_rounds"] < 1:
        raise ValueError("Invalid threshold or early-stopping patience")
    run_id = safe_name(args.run_id)
    candidates = resolve_candidates(config, args.jobs)
    paths, features, labels, splits = read_inputs(args.research_root.resolve())
    plan = {
        "run_id": run_id, "mode": "train" if args.run else "dry_run", "caution": CAUTION,
        "seed": config["seed"], "threshold": config["threshold"],
        "early_stopping_rounds": config["early_stopping_rounds"],
        "baseline_configurations": {key: config[key] for key in ("lightgbm", "xgboost")},
        "candidates": candidates, "jobs": args.jobs,
        "ensemble_policy": {
            "weights": [0.5, 0.5], "pairing": "All LightGBM/XGBoost pairs including saved baselines",
            "pair_count": (1 + sum(c["algorithm"] == "lightgbm" for c in candidates)) *
                          (1 + sum(c["algorithm"] == "xgboost" for c in candidates)),
        },
        "feature_schema": "EMBER 2018 feature version 2; 2381 float32 columns; signed hashes preserved",
        "sample_shape": list(features.shape),
        "split_counts": {key: len(value) for key, value in splits.items()},
        "latency_batch_size": min(args.latency_batch_size, len(splits["val_idx"])),
        "latency_repeats": args.latency_repeats,
        "latency_rows": "First rows in saved validation-index order; no score-based selection",
        "environment": {
            "python": platform.python_version(), "platform": platform.platform(),
            "cpu": platform.processor(), "logical_cpus": os.cpu_count(),
            "packages": {name: version(name) for name in
                         ("numpy", "lightgbm", "xgboost", "scikit-learn", "scipy")},
        },
        "config_sha256": sha256(args.config),
        "source_sha256": {"runner": sha256(Path(__file__)),
                          "probabilities": sha256(Path(__file__).with_name("probabilities.py"))},
        "report_directory": str(args.output_root.resolve() /
                                "reports/ember/model_comparison/mild_regularization" / run_id),
        "model_directory": str(args.output_root.resolve() /
                               "src/models/candidates/mild_regularization" / run_id),
    }
    if Path(plan["report_directory"]).exists() or Path(plan["model_directory"]).exists():
        raise FileExistsError("Run output already exists; use a new --run-id")
    print(json.dumps(plan, indent=2, allow_nan=False), flush=True)
    if not args.run:
        print("Dry run complete. No files written or models trained. Add --run to train.")
        return plan
    report = execute(plan, paths, features, labels, splits)
    print("Completed:", plan["report_directory"], flush=True)
    for row in report["rankings"]["by_pr_auc"]:
        print(f"{row['model']} PR-AUC={row['pr_auc']:.6f} "
              f"LogLoss={row['log_loss']:.6f} ROC-AUC={row['roc_auc']:.6f}")
    return report


if __name__ == "__main__":
    main()
