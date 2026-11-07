"""
Test-only loader: retain source-week timestamp anomalies
and count them for the evaluation audit.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import shutil

import numpy as np

import prepare_full_ember2024_win32 as base

from prepare_full_ember2024_win32 import (
    CHUNK_ROWS,
    FEATURE_COUNT,
    FEATURE_GROUPS,
    MAX_LINE_BYTES,
    MIN_FREE_BYTES,
    feature_hash,
    metadata_schema,
    relative,
    save_npy,
    save_npz,
    sha256,
)

if sha256(Path(base.__file__)) != 'd4be627ca0d6cb1a70bc93ab5adad2f9e2563c9e7ef5dd3ef67398f56aa93124':
    raise ValueError(
        "Original training helper changed after the date repair."
    )

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

    stats["source_week_timestamp_mismatch_rows"] = 0

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
                    or type(timestamp) is not int):
                raise ValueError(f"Unexpected file type/week/date: {member}:{line_number}")
            identity = bytes.fromhex(raw["sha256"])
            if len(identity) != 32:
                raise ValueError("Invalid SHA256 length.")
            if not low <= timestamp < high:
                stats["source_week_timestamp_mismatch_rows"] += 1
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
