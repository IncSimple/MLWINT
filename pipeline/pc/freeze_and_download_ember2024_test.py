"""Freeze MLWINT's evaluation protocol, then download/inspect official Win32 test.

No model fitting or test predictions. Run using the EMBER2024 environment.
The protocol is written before the test archive is downloaded or opened.
"""

import argparse
from datetime import datetime, timezone
import inspect
from importlib.metadata import version
import json
from pathlib import Path
import shutil
import zipfile

import numpy as np
from thrember.features import PEFeatureExtractor

from vectorize_ember2024_pilot import FEATURE_COUNT, FEATURE_GROUPS, save_json, sha256


RUN = "independent-win32-v1"
REPOSITORY = "joyce8/EMBER2024"
REVISION = "3d23efef7c0f0b702c5024400cfff4c3744a3832"
TEST_NAME = "Win32_test.zip"
TEST_BYTES = 2593425203
TEST_SHA = "c05f6562dee3ace4195087be918eb00181e33bc31464c671fb5ba00c9dd5dfdb"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def checked(path, digest):
    if sha256(path) != digest:
        raise ValueError(f"Checksum mismatch: {path}")


def make_protocol(root):
    lgb_path = root / "reports/ember2024/full-win32-v1/primary-full-fixed1109-v1/report.json"
    xgb_path = root / "reports/ember2024/full-win32-v1/challenger-full-temporal-v1/report.json"
    prep_path = root / "reports/ember2024/full-win32-v1/preparation.json"
    pilot_path = root / "reports/ember2024/pilot-v1/vectorized-v1.json"
    inventory_path = root / "reports/ember2024/download_inventory_v1.json"
    lgb, xgb = read_json(lgb_path), read_json(xgb_path)
    prep, pilot, inventory = read_json(prep_path), read_json(pilot_path), read_json(inventory_path)
    if any(r["status"] != "complete" for r in (lgb, xgb, prep, pilot)):
        raise ValueError("Required model/data reports are incomplete.")
    file_info = next(f for f in inventory["files"] if f["filename"] == TEST_NAME)
    if (inventory["repository"] != REPOSITORY or inventory["revision"] != REVISION
            or file_info["sha256"] != TEST_SHA or file_info["size_bytes"] != TEST_BYTES):
        raise ValueError("Pinned archive inventory differs from this evaluation protocol.")
    preparation_digest = sha256(prep_path)
    prep_key = prep_path.relative_to(root).as_posix()
    if (lgb["protocol"]["protected_inputs"][prep_key] != preparation_digest
            or xgb["protocol"]["protected_inputs"][prep_key] != preparation_digest):
        raise ValueError("Models were trained with different data preparations.")
    index_path = root / prep["row_index_file"]
    checked(index_path, prep["row_index_sha256"])
    validation_dir = root / "data/processed/ember2024/pilot-v1/vectorized-v1"
    for name, digest in pilot["summary"]["partitions"]["validation"]["files"].items():
        checked(validation_dir / name, digest)
    extractor_code = sha256(Path(inspect.getfile(PEFeatureExtractor)))
    packages = {name: version(name) for name in pilot["protocol"]["packages"]}
    if (PEFeatureExtractor().dim != FEATURE_COUNT
            or extractor_code != pilot["protocol"]["extractor_code_sha256"]
            or packages != pilot["protocol"]["packages"]
            or list(FEATURE_GROUPS) != pilot["protocol"]["feature_groups"]):
        raise ValueError("Extractor/schema/environment differs from the development data.")
    runtime = dict(packages, lightgbm=version("lightgbm"), xgboost=version("xgboost"))
    if (runtime["lightgbm"] != "4.7.0" or runtime["xgboost"] != xgb["xgboost_version"]):
        raise ValueError("Use the model-training package versions for evaluation.")
    prediction_path = xgb_path.parent / "validation_predictions.npz"
    checked(prediction_path, xgb["validation_predictions_sha256"])
    y_validation = np.load(validation_dir / "y_validation.npy", allow_pickle=False)
    with np.load(prediction_path, allow_pickle=False) as saved:
        if not np.array_equal(saved["y_true"], y_validation):
            raise ValueError("Development prediction row order changed.")
        probabilities = {name: saved[name].copy() for name in (
            "lightgbm", "xgboost", "ensemble_50_50")}
    if not np.array_equal(np.unique(y_validation), [0, 1]):
        raise ValueError("Validation requires both binary classes.")
    if not np.allclose(probabilities["ensemble_50_50"],
                       (probabilities["lightgbm"] + probabilities["xgboost"]) / 2,
                       rtol=0, atol=1e-15):
        raise ValueError("Saved ensemble probabilities are not a 50/50 average.")
    benign_count = int(np.sum(y_validation == 0))
    thresholds = {}
    for name, probability in probabilities.items():
        if (probability.shape != y_validation.shape or not np.isfinite(probability).all()
                or np.any((probability < 0) | (probability > 1))):
            raise ValueError(f"Invalid saved probabilities: {name}")
        benign = np.sort(probability[y_validation == 0])[::-1]
        entries = {"fixed_0.5": {"threshold": 0.5}}
        for limit in (0.005, 0.01, 0.02):
            budget = int(np.floor(limit * benign_count))
            # With >= decisions, exclude the (budget+1)-th benign score, including ties.
            threshold = float(np.nextafter(float(benign[budget]), np.inf))
            actual_fp = int(np.sum(benign >= threshold))
            if actual_fp > budget:
                raise ValueError("Threshold exceeds its development false-alarm budget.")
            entries[f"development_fpr_limit_{limit:g}"] = {
                "threshold": threshold, "development_fpr_limit": limit,
                "development_max_fp": budget, "development_actual_fp": actual_fp,
                "development_actual_fpr": actual_fp / benign_count,
            }
        thresholds[name] = entries
    models = {}
    for name, report in (("lightgbm", lgb), ("xgboost", xgb)):
        path = root / report["model_file"]
        checked(path, report["model_sha256"])
        models[name] = {"source_file": path.relative_to(root).as_posix(),
                        "sha256": report["model_sha256"],
                        "rounds": lgb["rounds"] if name == "lightgbm"
                                  else xgb["round_selection"]["selected_rounds"]}
    protected = {p.relative_to(root).as_posix(): sha256(p)
                 for p in (lgb_path, xgb_path, prep_path, pilot_path, inventory_path,
                           prediction_path, index_path)}
    for name, digest in pilot["summary"]["partitions"]["validation"]["files"].items():
        protected[(validation_dir / name).relative_to(root).as_posix()] = digest
    return {
        "run_id": RUN, "models": models, "thresholds": thresholds,
        "decision_rule": "malicious if probability >= frozen threshold",
        "ensemble": {"lightgbm_weight": 0.5, "xgboost_weight": 0.5},
        "dataset": {"repository": REPOSITORY, "revision": REVISION,
                    "filename": TEST_NAME, "size_bytes": TEST_BYTES, "sha256": TEST_SHA,
                    "scope": "All official Win32 test weeks; no subsampling"},
        "feature_count": FEATURE_COUNT, "feature_groups": list(FEATURE_GROUPS),
        "extractor_code_sha256": extractor_code, "runtime_packages": runtime,
        "protected_inputs": protected,
        "evaluation_policy": {
            "primary_population": "Unique test SHA256 files with no exact SHA256 or "
                                  "canonical feature-vector match in actual training OR development validation",
            "secondary_population": "All unique official test SHA256 files, including overlaps; "
                                    "report overlaps separately and do not describe these as independent",
            "training_reference": "full row_index.npz restricted to valid_indices",
            "development_reference": "pilot-v1/vectorized-v1/validation_provenance.npz",
            "test_repeat_policy": "Keep first occurrence of each SHA256 in chronological source order; "
                                  "verify repeated labels and canonical vectors; abort on inconsistency",
            "same_vector_different_test_sha": "Keep distinct files; report repeated/conflicting vector groups",
            "chronology": "Require primary test timestamps later than all training and development timestamps",
            "metrics": ["log_loss", "average_precision_PR_AUC", "ROC_AUC", "Brier", "accuracy",
                        "precision", "recall", "F1", "FPR", "FNR", "TP", "TN", "FP", "FN"],
            "time_breakdown": "Report metrics and class counts per source week for each population",
            "threshold_policy": "Use all frozen thresholds; do not select or adjust thresholds on test",
            "tuning_policy": "No fitting, calibration, weight tuning or feature selection on test",
            "data_quality_policy": "Report exclusions and inconsistencies; never drop hard examples based on predictions",
            "limitations": "Exact overlap audit does not establish family or near-duplicate independence. "
                           "This is later-2024 evaluation, not evidence of performance on 2026 malware.",
        },
        "freeze_script_sha256": sha256(Path(__file__)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--freeze-only", action="store_true")
    args = parser.parse_args()
    root = args.project_root.resolve()
    report_dir = root / "reports/ember2024" / RUN
    snapshot_dir = root / "data/processed/ember2024" / RUN / "frozen_models"
    protocol = make_protocol(root)
    report_dir.mkdir(parents=True, exist_ok=True)
    freeze_path = report_dir / "frozen_protocol.json"
    if freeze_path.exists():
        frozen = read_json(freeze_path)
        if frozen["protocol"] != protocol:
            raise ValueError("Frozen protocol differs from current inputs. Preserve it; investigate before proceeding.")
        for info in frozen["model_snapshots"].values():
            checked(root / info["file"], info["sha256"])
        print("Reusing verified frozen protocol.", flush=True)
    else:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshots = {}
        for name, info in protocol["models"].items():
            source = root / info["source_file"]
            destination = snapshot_dir / ("lightgbm.txt" if name == "lightgbm" else "xgboost.ubj")
            if destination.exists():
                checked(destination, info["sha256"])
            else:
                shutil.copyfile(source, destination)
                checked(destination, info["sha256"])
            snapshots[name] = {"file": destination.relative_to(root).as_posix(), "sha256": info["sha256"]}
        frozen = {"status": "frozen", "frozen_utc": datetime.now(timezone.utc).isoformat(),
                  "protocol": protocol, "model_snapshots": snapshots}
        save_json(freeze_path, frozen)
    print(f"Frozen protocol: {freeze_path}", flush=True)
    print("Frozen models: LightGBM 1,109 rounds; XGBoost 2,000 rounds; ensemble weights 50/50.")
    for name, entries in protocol["thresholds"].items():
        print(name + ": " + ", ".join(f"{key}={value['threshold']:.9f}" for key, value in entries.items()))
    if args.freeze_only:
        return
    archives = root / "data/raw/ember2024/archives"
    archives.mkdir(parents=True, exist_ok=True)
    archive_path = archives / TEST_NAME
    if not archive_path.exists():
        if shutil.disk_usage(root).free < 12 * 1024**3:
            raise RuntimeError("Free at least 12 GiB for test download, vectors and disk headroom.")
        from huggingface_hub import hf_hub_download
        print("Downloading pinned official Win32 test archive (about 2.42 GiB)...", flush=True)
        downloaded = hf_hub_download(repo_id=REPOSITORY, repo_type="dataset", filename=TEST_NAME,
                                     revision=REVISION, local_dir=str(archives))
        if Path(downloaded).resolve() != archive_path.resolve():
            raise ValueError("Download returned an unexpected path.")
    print("Verifying official test archive checksum...", flush=True)
    if archive_path.stat().st_size != TEST_BYTES:
        raise ValueError("Test archive size differs from the pinned inventory.")
    checked(archive_path, TEST_SHA)
    with zipfile.ZipFile(archive_path) as archive:
        members = sorted(archive.infolist(), key=lambda m: m.filename)
        jsonl = [m for m in members if m.filename.endswith("_Win32_test.jsonl")]
        if len(jsonl) != 12 or len(members) != 12:
            raise ValueError("Unexpected test archive layout. Preserve archive and inspect before vectorization.")
        inventory = [{"member": m.filename, "compressed_bytes": m.compress_size,
                      "uncompressed_bytes": m.file_size} for m in jsonl]
    # Recheck inputs/snapshots in case they were edited while the download ran.
    if make_protocol(root) != frozen["protocol"]:
        raise ValueError("Frozen inputs changed during download.")
    for info in frozen["model_snapshots"].values():
        checked(root / info["file"], info["sha256"])
    result = {
        "status": "verified", "frozen_protocol_sha256": sha256(freeze_path),
        "archive_file": archive_path.relative_to(root).as_posix(),
        "archive_sha256": TEST_SHA, "archive_size_bytes": TEST_BYTES,
        "members": inventory, "total_uncompressed_bytes": sum(m["uncompressed_bytes"] for m in inventory),
        "free_disk_gib": round(shutil.disk_usage(root).free / 1024**3, 3),
        "models_and_thresholds_unchanged": True, "test_predictions_computed": False,
    }
    save_json(report_dir / "test_archive_verified.json", result)
    print("\nFROZEN TEST PREPARATION SUMMARY")
    print(json.dumps(result, indent=2))
    print("No archive extraction or model fitting. Next: vectorize, audit overlap, and evaluate frozen predictions.")


if __name__ == "__main__":
    main()
"""Freeze MLWINT's evaluation protocol, then download/inspect official Win32 test.

No model fitting or test predictions. Run using the EMBER2024 environment.
The protocol is written before the test archive is downloaded or opened.
"""

import argparse
from datetime import datetime, timezone
import inspect
from importlib.metadata import version
import json
from pathlib import Path
import shutil
import zipfile

import numpy as np
from thrember.features import PEFeatureExtractor

from vectorize_ember2024_pilot import FEATURE_COUNT, FEATURE_GROUPS, save_json, sha256


RUN = "independent-win32-v1"
REPOSITORY = "joyce8/EMBER2024"
REVISION = "3d23efef7c0f0b702c5024400cfff4c3744a3832"
TEST_NAME = "Win32_test.zip"
TEST_BYTES = 2593425203
TEST_SHA = "c05f6562dee3ace4195087be918eb00181e33bc31464c671fb5ba00c9dd5dfdb"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def checked(path, digest):
    if sha256(path) != digest:
        raise ValueError(f"Checksum mismatch: {path}")


def make_protocol(root):
    lgb_path = root / "reports/ember2024/full-win32-v1/primary-full-fixed1109-v1/report.json"
    xgb_path = root / "reports/ember2024/full-win32-v1/challenger-full-temporal-v1/report.json"
    prep_path = root / "reports/ember2024/full-win32-v1/preparation.json"
    pilot_path = root / "reports/ember2024/pilot-v1/vectorized-v1.json"
    inventory_path = root / "reports/ember2024/download_inventory_v1.json"
    lgb, xgb = read_json(lgb_path), read_json(xgb_path)
    prep, pilot, inventory = read_json(prep_path), read_json(pilot_path), read_json(inventory_path)
    if any(r["status"] != "complete" for r in (lgb, xgb, prep, pilot)):
        raise ValueError("Required model/data reports are incomplete.")
    file_info = next(f for f in inventory["files"] if f["filename"] == TEST_NAME)
    if (inventory["repository"] != REPOSITORY or inventory["revision"] != REVISION
            or file_info["sha256"] != TEST_SHA or file_info["size_bytes"] != TEST_BYTES):
        raise ValueError("Pinned archive inventory differs from this evaluation protocol.")
    preparation_digest = sha256(prep_path)
    prep_key = prep_path.relative_to(root).as_posix()
    if (lgb["protocol"]["protected_inputs"][prep_key] != preparation_digest
            or xgb["protocol"]["protected_inputs"][prep_key] != preparation_digest):
        raise ValueError("Models were trained with different data preparations.")
    index_path = root / prep["row_index_file"]
    checked(index_path, prep["row_index_sha256"])
    validation_dir = root / "data/processed/ember2024/pilot-v1/vectorized-v1"
    for name, digest in pilot["summary"]["partitions"]["validation"]["files"].items():
        checked(validation_dir / name, digest)
    extractor_code = sha256(Path(inspect.getfile(PEFeatureExtractor)))
    packages = {name: version(name) for name in pilot["protocol"]["packages"]}
    if (PEFeatureExtractor().dim != FEATURE_COUNT
            or extractor_code != pilot["protocol"]["extractor_code_sha256"]
            or packages != pilot["protocol"]["packages"]
            or list(FEATURE_GROUPS) != pilot["protocol"]["feature_groups"]):
        raise ValueError("Extractor/schema/environment differs from the development data.")
    runtime = dict(packages, lightgbm=version("lightgbm"), xgboost=version("xgboost"))
    if (runtime["lightgbm"] != "4.7.0" or runtime["xgboost"] != xgb["xgboost_version"]):
        raise ValueError("Use the model-training package versions for evaluation.")
    prediction_path = xgb_path.parent / "validation_predictions.npz"
    checked(prediction_path, xgb["validation_predictions_sha256"])
    y_validation = np.load(validation_dir / "y_validation.npy", allow_pickle=False)
    with np.load(prediction_path, allow_pickle=False) as saved:
        if not np.array_equal(saved["y_true"], y_validation):
            raise ValueError("Development prediction row order changed.")
        probabilities = {name: saved[name].copy() for name in (
            "lightgbm", "xgboost", "ensemble_50_50")}
    if not np.array_equal(np.unique(y_validation), [0, 1]):
        raise ValueError("Validation requires both binary classes.")
    if not np.allclose(probabilities["ensemble_50_50"],
                       (probabilities["lightgbm"] + probabilities["xgboost"]) / 2,
                       rtol=0, atol=1e-15):
        raise ValueError("Saved ensemble probabilities are not a 50/50 average.")
    benign_count = int(np.sum(y_validation == 0))
    thresholds = {}
    for name, probability in probabilities.items():
        if (probability.shape != y_validation.shape or not np.isfinite(probability).all()
                or np.any((probability < 0) | (probability > 1))):
            raise ValueError(f"Invalid saved probabilities: {name}")
        benign = np.sort(probability[y_validation == 0])[::-1]
        entries = {"fixed_0.5": {"threshold": 0.5}}
        for limit in (0.005, 0.01, 0.02):
            budget = int(np.floor(limit * benign_count))
            # With >= decisions, exclude the (budget+1)-th benign score, including ties.
            threshold = float(np.nextafter(float(benign[budget]), np.inf))
            actual_fp = int(np.sum(benign >= threshold))
            if actual_fp > budget:
                raise ValueError("Threshold exceeds its development false-alarm budget.")
            entries[f"development_fpr_limit_{limit:g}"] = {
                "threshold": threshold, "development_fpr_limit": limit,
                "development_max_fp": budget, "development_actual_fp": actual_fp,
                "development_actual_fpr": actual_fp / benign_count,
            }
        thresholds[name] = entries
    models = {}
    for name, report in (("lightgbm", lgb), ("xgboost", xgb)):
        path = root / report["model_file"]
        checked(path, report["model_sha256"])
        models[name] = {"source_file": path.relative_to(root).as_posix(),
                        "sha256": report["model_sha256"],
                        "rounds": lgb["rounds"] if name == "lightgbm"
                                  else xgb["round_selection"]["selected_rounds"]}
    protected = {p.relative_to(root).as_posix(): sha256(p)
                 for p in (lgb_path, xgb_path, prep_path, pilot_path, inventory_path,
                           prediction_path, index_path)}
    for name, digest in pilot["summary"]["partitions"]["validation"]["files"].items():
        protected[(validation_dir / name).relative_to(root).as_posix()] = digest
    return {
        "run_id": RUN, "models": models, "thresholds": thresholds,
        "decision_rule": "malicious if probability >= frozen threshold",
        "ensemble": {"lightgbm_weight": 0.5, "xgboost_weight": 0.5},
        "dataset": {"repository": REPOSITORY, "revision": REVISION,
                    "filename": TEST_NAME, "size_bytes": TEST_BYTES, "sha256": TEST_SHA,
                    "scope": "All official Win32 test weeks; no subsampling"},
        "feature_count": FEATURE_COUNT, "feature_groups": list(FEATURE_GROUPS),
        "extractor_code_sha256": extractor_code, "runtime_packages": runtime,
        "protected_inputs": protected,
        "evaluation_policy": {
            "primary_population": "Unique test SHA256 files with no exact SHA256 or "
                                  "canonical feature-vector match in actual training OR development validation",
            "secondary_population": "All unique official test SHA256 files, including overlaps; "
                                    "report overlaps separately and do not describe these as independent",
            "training_reference": "full row_index.npz restricted to valid_indices",
            "development_reference": "pilot-v1/vectorized-v1/validation_provenance.npz",
            "test_repeat_policy": "Keep first occurrence of each SHA256 in chronological source order; "
                                  "verify repeated labels and canonical vectors; abort on inconsistency",
            "same_vector_different_test_sha": "Keep distinct files; report repeated/conflicting vector groups",
            "chronology": "Require primary test timestamps later than all training and development timestamps",
            "metrics": ["log_loss", "average_precision_PR_AUC", "ROC_AUC", "Brier", "accuracy",
                        "precision", "recall", "F1", "FPR", "FNR", "TP", "TN", "FP", "FN"],
            "time_breakdown": "Report metrics and class counts per source week for each population",
            "threshold_policy": "Use all frozen thresholds; do not select or adjust thresholds on test",
            "tuning_policy": "No fitting, calibration, weight tuning or feature selection on test",
            "data_quality_policy": "Report exclusions and inconsistencies; never drop hard examples based on predictions",
            "limitations": "Exact overlap audit does not establish family or near-duplicate independence. "
                           "This is later-2024 evaluation, not evidence of performance on 2026 malware.",
        },
        "freeze_script_sha256": sha256(Path(__file__)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--freeze-only", action="store_true")
    args = parser.parse_args()
    root = args.project_root.resolve()
    report_dir = root / "reports/ember2024" / RUN
    snapshot_dir = root / "data/processed/ember2024" / RUN / "frozen_models"
    protocol = make_protocol(root)
    report_dir.mkdir(parents=True, exist_ok=True)
    freeze_path = report_dir / "frozen_protocol.json"
    if freeze_path.exists():
        frozen = read_json(freeze_path)
        if frozen["protocol"] != protocol:
            raise ValueError("Frozen protocol differs from current inputs. Preserve it; investigate before proceeding.")
        for info in frozen["model_snapshots"].values():
            checked(root / info["file"], info["sha256"])
        print("Reusing verified frozen protocol.", flush=True)
    else:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshots = {}
        for name, info in protocol["models"].items():
            source = root / info["source_file"]
            destination = snapshot_dir / ("lightgbm.txt" if name == "lightgbm" else "xgboost.ubj")
            if destination.exists():
                checked(destination, info["sha256"])
            else:
                shutil.copyfile(source, destination)
                checked(destination, info["sha256"])
            snapshots[name] = {"file": destination.relative_to(root).as_posix(), "sha256": info["sha256"]}
        frozen = {"status": "frozen", "frozen_utc": datetime.now(timezone.utc).isoformat(),
                  "protocol": protocol, "model_snapshots": snapshots}
        save_json(freeze_path, frozen)
    print(f"Frozen protocol: {freeze_path}", flush=True)
    print("Frozen models: LightGBM 1,109 rounds; XGBoost 2,000 rounds; ensemble weights 50/50.")
    for name, entries in protocol["thresholds"].items():
        print(name + ": " + ", ".join(f"{key}={value['threshold']:.9f}" for key, value in entries.items()))
    if args.freeze_only:
        return
    archives = root / "data/raw/ember2024/archives"
    archives.mkdir(parents=True, exist_ok=True)
    archive_path = archives / TEST_NAME
    if not archive_path.exists():
        if shutil.disk_usage(root).free < 12 * 1024**3:
            raise RuntimeError("Free at least 12 GiB for test download, vectors and disk headroom.")
        from huggingface_hub import hf_hub_download
        print("Downloading pinned official Win32 test archive (about 2.42 GiB)...", flush=True)
        downloaded = hf_hub_download(repo_id=REPOSITORY, repo_type="dataset", filename=TEST_NAME,
                                     revision=REVISION, local_dir=str(archives))
        if Path(downloaded).resolve() != archive_path.resolve():
            raise ValueError("Download returned an unexpected path.")
    print("Verifying official test archive checksum...", flush=True)
    if archive_path.stat().st_size != TEST_BYTES:
        raise ValueError("Test archive size differs from the pinned inventory.")
    checked(archive_path, TEST_SHA)
    with zipfile.ZipFile(archive_path) as archive:
        members = sorted(archive.infolist(), key=lambda m: m.filename)
        jsonl = [m for m in members if m.filename.endswith("_Win32_test.jsonl")]
        if len(jsonl) != 12 or len(members) != 12:
            raise ValueError("Unexpected test archive layout. Preserve archive and inspect before vectorization.")
        inventory = [{"member": m.filename, "compressed_bytes": m.compress_size,
                      "uncompressed_bytes": m.file_size} for m in jsonl]
    # Recheck inputs/snapshots in case they were edited while the download ran.
    if make_protocol(root) != frozen["protocol"]:
        raise ValueError("Frozen inputs changed during download.")
    for info in frozen["model_snapshots"].values():
        checked(root / info["file"], info["sha256"])
    result = {
        "status": "verified", "frozen_protocol_sha256": sha256(freeze_path),
        "archive_file": archive_path.relative_to(root).as_posix(),
        "archive_sha256": TEST_SHA, "archive_size_bytes": TEST_BYTES,
        "members": inventory, "total_uncompressed_bytes": sum(m["uncompressed_bytes"] for m in inventory),
        "free_disk_gib": round(shutil.disk_usage(root).free / 1024**3, 3),
        "models_and_thresholds_unchanged": True, "test_predictions_computed": False,
    }
    save_json(report_dir / "test_archive_verified.json", result)
    print("\nFROZEN TEST PREPARATION SUMMARY")
    print(json.dumps(result, indent=2))
    print("No archive extraction or model fitting. Next: vectorize, audit overlap, and evaluate frozen predictions.")


if __name__ == "__main__":
    main()
