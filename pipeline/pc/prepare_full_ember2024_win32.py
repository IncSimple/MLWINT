"""Prepare the earlier 40 weeks of EMBER2024 Win32; no model training.

Place this file in MLWINT/scripts and use the EMBER2024 environment.
Completed weeks are reusable. Only this run's outputs are written.
"""

import argparse
import gc
import hashlib
import inspect
import json
import shutil
import zipfile
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

import numpy as np
from thrember.features import PEFeatureExtractor

from vectorize_ember2024_pilot import (
    FEATURE_COUNT, FEATURE_GROUPS, feature_hash,
    save_json, save_npy, save_npz, sha256,
)


RUN = "full-win32-v1"
CHUNK_ROWS = 5000
TRAIN_WEEKS = 40
INNER_FIT_WEEKS = 36
MAX_LINE_BYTES = 32 * 1024 * 1024
MIN_FREE_BYTES = 5 * 1024**3


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def checked_hash(path, expected):
    if sha256(path) != expected:
        raise ValueError(f"Checksum mismatch: {path}")


def relative(root, path):
    return path.relative_to(root).as_posix()


def label_counts(labels):
    return {
        "benign": int(np.count_nonzero(labels == 0)),
        "malicious": int(np.count_nonzero(labels == 1)),
    }


def metadata_schema(rows):
    return {
        "sha256": np.empty(rows, dtype="V32"),
        "feature_hash": np.empty(rows, dtype="V32"),
        "label": np.empty(rows, dtype=np.int8),
        "timestamp": np.empty(rows, dtype=np.int64),
        "week": np.empty(rows, dtype=np.int16),
        "source_line": np.empty(rows, dtype=np.int64),
    }


def select_rows(meta):
    """Check repeated identities, then select one row per consistent vector."""
    order = np.argsort(meta["sha256"], kind="stable")
    left, right = order[:-1], order[1:]
    repeated = meta["sha256"][left] == meta["sha256"][right]
    inconsistent = repeated & (
        (meta["label"][left] != meta["label"][right])
        | (meta["feature_hash"][left] != meta["feature_hash"][right])
        | (meta["timestamp"][left] != meta["timestamp"][right])
    )
    if np.any(inconsistent):
        row = int(right[np.flatnonzero(inconsistent)[0]])
        raise ValueError(
            "Repeated SHA has inconsistent label, vector or timestamp: "
            + meta["sha256"][row].tobytes().hex()
        )
    _, first_sha = np.unique(meta["sha256"], return_index=True)
    first_sha.sort()
    _, first_feature, inverse = np.unique(
        meta["feature_hash"][first_sha],
        return_index=True, return_inverse=True,
    )
    masks = np.zeros(len(first_feature), dtype=np.uint8)
    bits = np.left_shift(np.uint8(1), meta["label"][first_sha])
    np.bitwise_or.at(masks, inverse, bits)
    conflict = masks == 3
    valid = np.sort(first_sha[first_feature[~conflict]])
    conflicting_rows = int(np.count_nonzero(conflict[inverse]))
    consistent_rows = len(first_sha) - conflicting_rows
    return valid.astype(np.int64), {
        "cross_week_repeated_sha_rows_removed": int(len(order) - len(first_sha)),
        "conflicting_feature_groups": int(np.count_nonzero(conflict)),
        "conflicting_feature_rows_removed": conflicting_rows,
        "consistent_repeated_feature_rows_removed": int(consistent_rows - len(valid)),
    }


def prepare_week(root, output, archive, member, week, extractor,
                 heldout_sha, heldout_features, offset):
    folder = output / f"week_{week:02d}"
    folder.mkdir(parents=True, exist_ok=True)
    start = datetime.strptime(Path(member).name[:10], "%Y-%m-%d").replace(
        tzinfo=timezone.utc
    )
    low, high = int(start.timestamp()), int((start + timedelta(days=7)).timestamp())
    vectors = []
    records = []
    chunks = []
    seen = {}
    stats = {
        "source_rows": 0, "unique_sha_rows": 0, "repeated_sha_rows": 0,
        "heldout_sha_rows_excluded": 0, "heldout_vector_rows_excluded": 0,
        "raw_feature_variants_checked": 0, "stored_rows": 0,
    }

    def flush():
        if not vectors:
            return
        if shutil.disk_usage(output).free < MIN_FREE_BYTES:
            raise RuntimeError("Less than 5 GiB free. Free space, then rerun.")
        number = len(chunks)
        x_path = folder / f"chunk_{number:03d}.npy"
        m_path = folder / f"chunk_{number:03d}.metadata.npz"
        matrix = np.stack(vectors).astype(np.float32, copy=False)
        meta = metadata_schema(len(records))
        for i, record in enumerate(records):
            for name, value in zip(meta, record):
                meta[name][i] = value
        save_npy(x_path, matrix)
        save_npz(m_path, **meta)
        chunks.append({
            "x_file": relative(root, x_path), "x_sha256": sha256(x_path),
            "metadata_file": relative(root, m_path),
            "metadata_sha256": sha256(m_path),
            "rows": len(records), "offset": offset + stats["stored_rows"],
        })
        stats["stored_rows"] += len(records)
        vectors.clear()
        records.clear()

    with archive.open(member) as stream:
        line_number = 0
        while True:
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            line_number += 1
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f"Oversized JSON record: {member}:{line_number}")
            raw = json.loads(line)
            label = raw["label"]
            timestamp = raw["first_submission_date"]
            if type(label) is not int or label not in (0, 1):
                raise ValueError(f"Unexpected label: {member}:{line_number}")
            if (raw["file_type"] != "Win32" or raw["week_id"] != week
                    or type(timestamp) is not int or not low <= timestamp < high):
                raise ValueError(f"Unexpected file type/week/date: {member}:{line_number}")
            identity = bytes.fromhex(raw["sha256"])
            if len(identity) != 32:
                raise ValueError("Invalid SHA256 length.")
            stats["source_rows"] += 1
            features = {name: raw[name] for name in FEATURE_GROUPS}
            raw_hash = hashlib.sha256(json.dumps(
                features, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")).digest()
            previous = seen.get(identity)
            vector = None
            if previous is not None:
                if previous[:2] != (label, timestamp):
                    raise ValueError(f"Conflicting repeated file: {raw['sha256']}")
                stats["repeated_sha_rows"] += 1
                if previous[2] != raw_hash:
                    vector = np.asarray(extractor.process_raw_features(features), dtype=np.float32)
                    if (vector.shape != (FEATURE_COUNT,) or not np.isfinite(vector).all()
                            or feature_hash(vector).tobytes() != previous[3]):
                        raise ValueError(f"Inconsistent repeated vector: {raw['sha256']}")
                    stats["raw_feature_variants_checked"] += 1
            else:
                vector = np.asarray(extractor.process_raw_features(features), dtype=np.float32)
                if vector.shape != (FEATURE_COUNT,) or not np.isfinite(vector).all():
                    raise ValueError(f"Invalid feature vector: {member}:{line_number}")
                digest = feature_hash(vector).tobytes()
                seen[identity] = (label, timestamp, raw_hash, digest)
                stats["unique_sha_rows"] += 1
                if identity in heldout_sha:
                    if heldout_sha[identity] != (label, digest):
                        raise ValueError("Training/validation identity is inconsistent.")
                    stats["heldout_sha_rows_excluded"] += 1
                elif digest in heldout_features:
                    stats["heldout_vector_rows_excluded"] += 1
                else:
                    vectors.append(vector)
                    records.append((np.void(identity), np.void(digest), label,
                                    timestamp, week, line_number))
                    if len(vectors) >= CHUNK_ROWS:
                        flush()
            if stats["source_rows"] % 5000 == 0:
                print(f"  Read {stats['source_rows']:,} records; "
                      f"unique SHA={stats['unique_sha_rows']:,}", flush=True)
    flush()
    if stats["source_rows"] == 0:
        raise ValueError(f"Empty source week: {member}")
    return {"week": week, "source_member": member, "stats": stats, "chunks": chunks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    root = parser.parse_args().project_root.resolve()
    archive_path = root / "data/raw/ember2024/archives/Win32_train.zip"
    verified_path = root / "reports/ember2024/train_archive_verified_v1.json"
    pilot_report_path = root / "reports/ember2024/pilot-v1/vectorized-v1.json"
    pilot = root / "data/processed/ember2024/pilot-v1/vectorized-v1"
    output = root / "data/processed/ember2024" / RUN
    report_path = root / "reports/ember2024" / RUN / "preparation.json"
    output.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    verified, old_report = read_json(verified_path), read_json(pilot_report_path)
    if verified["status"] != "verified" or old_report["status"] != "complete":
        raise ValueError("Source archive/pilot verification is incomplete.")
    print("Verifying archive checksum; this can take several minutes...", flush=True)
    if archive_path.stat().st_size != verified["size_bytes"]:
        raise ValueError("Archive size changed.")
    checked_hash(archive_path, verified["sha256"])
    extractor = PEFeatureExtractor()
    extractor_hash = sha256(Path(inspect.getfile(PEFeatureExtractor)))
    packages = {name: version(name) for name in old_report["protocol"]["packages"]}
    if (extractor.dim != FEATURE_COUNT
            or list(FEATURE_GROUPS) != old_report["protocol"]["feature_groups"]
            or extractor_hash != old_report["protocol"]["extractor_code_sha256"]
            or packages != old_report["protocol"]["packages"]):
        raise ValueError("Use the same extractor and package versions as the pilot.")

    validation = old_report["summary"]["partitions"]["validation"]
    train_info = old_report["summary"]["partitions"]["train"]

    def verify_pilot():
        checked_hash(pilot_report_path, protocol["pilot_report_sha256"])
        for name, digest in validation["files"].items():
            checked_hash(pilot / name, digest)
        checked_hash(pilot / "train_provenance.npz",
                     train_info["files"]["train_provenance.npz"])

    protocol = {
        "run": RUN, "archive_sha256": verified["sha256"],
        "dataset_revision": verified["revision"],
        "pilot_report_sha256": sha256(pilot_report_path),
        "script_sha256": sha256(Path(__file__)),
        "feature_count": FEATURE_COUNT, "feature_groups": list(FEATURE_GROUPS),
        "extractor_code_sha256": extractor_hash, "packages": packages,
        "training_weeks": TRAIN_WEEKS, "inner_fit_weeks": INNER_FIT_WEEKS,
        "chunk_rows": CHUNK_ROWS, "validation_files": validation["files"],
        "cleanup": "validation precedence; unique consistent SHA; "
                   "exclude conflicting feature groups; one row per consistent vector",
    }
    verify_pilot()
    with np.load(pilot / "validation_provenance.npz", allow_pickle=False) as data:
        heldout_sha = {
            bytes.fromhex(s.decode("ascii")): (int(y), h.tobytes())
            for s, y, h in zip(data["sha256"], data["label"], data["feature_hash"])
        }
        heldout_features = {h.tobytes() for h in data["feature_hash"]}
        validation_min = int(data["timestamp"].min())

    state = {"status": "preparing", "protocol": protocol, "weeks": []}
    if report_path.exists():
        state = read_json(report_path)
        if state["protocol"] != protocol:
            raise ValueError("Existing run uses a different protocol. Do not overwrite it.")
    else:
        save_json(report_path, state)

    chunks = [c for w in state["weeks"] for c in w["chunks"]]
    offset = 0
    print("Verifying completed chunks...", flush=True)
    for week_number, week in enumerate(state["weeks"]):
        if week["week"] != week_number:
            raise ValueError("Checkpoint week order is inconsistent.")
        for chunk in week["chunks"]:
            if chunk["offset"] != offset:
                raise ValueError("Checkpoint row offsets are inconsistent.")
            checked_hash(root / chunk["x_file"], chunk["x_sha256"])
            checked_hash(root / chunk["metadata_file"], chunk["metadata_sha256"])
            offset += chunk["rows"]
    if state["status"] == "complete":
        checked_hash(root / state["row_index_file"], state["row_index_sha256"])
        print(json.dumps(state["summary"], indent=2))
        print(f"Already complete: {report_path}")
        return

    with zipfile.ZipFile(archive_path) as archive:
        members = sorted(n for n in archive.namelist() if n.endswith("_Win32_train.jsonl"))
        expected = sorted(m["filename"] for m in verified["contents"]["members"]
                          if m["filename"].endswith("_Win32_train.jsonl"))
        if members != expected or len(members) != 52:
            raise ValueError("Unexpected archive members.")
        for week in range(len(state["weeks"]), TRAIN_WEEKS):
            print(f"\nPreparing week {week:02d}: {members[week]}", flush=True)
            result = prepare_week(root, output, archive, members[week], week,
                                  extractor, heldout_sha, heldout_features, offset)
            next_state = dict(state, weeks=state["weeks"] + [result])
            save_json(report_path, next_state)
            state = next_state
            chunks.extend(result["chunks"])
            offset += result["stats"]["stored_rows"]
            print(f"Week checkpoint saved. Stored rows so far: {offset:,}", flush=True)
            gc.collect()

    print("\nAuditing identities and vectors across all weeks...", flush=True)
    if offset == 0:
        raise ValueError("No training rows prepared.")
    meta = metadata_schema(offset)
    for chunk in chunks:
        begin = chunk["offset"]
        end = begin + chunk["rows"]
        with np.load(root / chunk["metadata_file"], allow_pickle=False) as saved:
            for name in meta:
                meta[name][begin:end] = saved[name]
    if (np.isin(meta["sha256"], np.array([np.void(h) for h in heldout_sha], dtype="V32")).any()
            or np.isin(meta["feature_hash"],
                       np.array([np.void(h) for h in heldout_features], dtype="V32")).any()):
        raise ValueError("Held-out overlap remains.")
    valid, audit = select_rows(meta)
    if not len(valid) or int(meta["timestamp"][valid].max()) >= validation_min:
        raise ValueError("Empty training selection or temporal overlap.")
    with np.load(pilot / "train_provenance.npz", allow_pickle=False) as old:
        old_ids = np.array([np.void(bytes.fromhex(s.decode("ascii")))
                            for s in old["sha256"]], dtype="V32")
        old_matches = np.isin(old_ids, meta["sha256"])
        if not old_matches.all():
            raise ValueError("Some pilot training identities were not recovered.")
        sorted_rows = np.argsort(meta["sha256"], kind="stable")
        lookup = np.searchsorted(meta["sha256"][sorted_rows], old_ids)
        recovered = sorted_rows[lookup]
        if (np.any(meta["label"][recovered] != old["label"])
                or np.any(meta["feature_hash"][recovered] != old["feature_hash"])):
            raise ValueError("Recovered pilot labels/features changed.")
        old_final_representatives = int(np.count_nonzero(
            np.isin(old_ids, meta["sha256"][valid])))

    inner_fit = valid[meta["week"][valid] < INNER_FIT_WEEKS]
    inner_stop = valid[meta["week"][valid] >= INNER_FIT_WEEKS]
    if not len(inner_fit) or not len(inner_stop):
        raise ValueError("Empty inner temporal partition.")
    if int(meta["timestamp"][inner_fit].max()) >= int(meta["timestamp"][inner_stop].min()):
        raise ValueError("Inner temporal overlap.")
    for selection in (valid, inner_fit, inner_stop):
        if len(np.unique(meta["label"][selection])) != 2:
            raise ValueError("Both classes are required in each training partition.")
    # These are PHYSICAL offsets into the chunk manifest, not compact matrix indices.
    index_path = output / "row_index.npz"
    save_npz(index_path, **meta, valid_indices=valid,
             inner_fit_indices=inner_fit, inner_stop_indices=inner_stop)
    verify_pilot()
    source_totals = {
        key: int(sum(w["stats"][key] for w in state["weeks"]))
        for key in state["weeks"][0]["stats"]
    }
    summary = {
        "source": source_totals, "audit": audit,
        "physical_stored_rows": offset, "usable_training_rows": len(valid),
        "training_labels": label_counts(meta["label"][valid]),
        "inner_fit_rows": len(inner_fit), "inner_stop_rows": len(inner_stop),
        "validation_rows": validation["rows"], "validation_unchanged": True,
        "cross_partition_sha256_overlap": 0, "cross_partition_feature_overlap": 0,
        "chronological_separation": True, "feature_count": FEATURE_COUNT,
        "pilot_training_identities_recovered": int(len(old_ids)),
        "pilot_files_retained_as_final_representatives": old_final_representatives,
        "stored_vector_gib": round(sum((root / c["x_file"]).stat().st_size
                                       for c in chunks) / 1024**3, 3),
        "note": "Use valid_indices when loading chunks. Exact duplicates/conflicts "
                "were audited; near-duplicate and family separation are not established. "
                "Inner stopping weeks can share related files with earlier fit weeks. "
                "Official test/challenge data were not read. Training RAM is not measured.",
    }
    complete = dict(state, status="complete", summary=summary,
                    row_index_file=relative(root, index_path),
                    row_index_sha256=sha256(index_path))
    save_json(report_path, complete)
    print("\nFULL EARLIER-PERIOD PREPARATION SUMMARY")
    print(json.dumps(summary, indent=2))
    print(f"\nReport: {report_path}")
    print("No models trained. Next: measure training memory, then fit LightGBM.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped. Rerun the same command to reuse completed weeks.")
        raise SystemExit(130)
