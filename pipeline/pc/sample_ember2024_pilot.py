import hashlib
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]

ARCHIVE = ROOT / "data/raw/ember2024/archives/Win32_train.zip"
VERIFICATION = ROOT / "reports/ember2024/train_archive_verified_v1.json"

PILOT_ID = "pilot-v1"
OUTPUT = ROOT / "data/interim/ember2024" / PILOT_ID
REPORT = ROOT / "reports/ember2024" / PILOT_ID / "sampling.json"

SEED = 42
TRAIN_WEEKS = 40
TRAIN_PER_CLASS_PER_WEEK = 1500
VALIDATION_PER_CLASS_PER_WEEK = 1000

MAX_RECORD_BYTES = 32 * 1024 * 1024
GIB = 1024 ** 3


def sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def save_state(state):
    temporary = REPORT.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(state, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(REPORT)


def utc_text(timestamp):
    return datetime.fromtimestamp(
        timestamp,
        timezone.utc,
    ).isoformat()


def sample_week(archive, member, week_id, phase, quota):
    """Uniform reservoir sampling separately within each class."""
    start_date = datetime.strptime(
        member.filename[:10],
        "%Y-%m-%d",
    ).replace(tzinfo=timezone.utc)

    start_timestamp = int(start_date.timestamp())
    stop_timestamp = start_timestamp + 7 * 24 * 60 * 60

    generators = {
        label: np.random.default_rng(
            np.random.SeedSequence([SEED, week_id, label])
        )
        for label in (0, 1)
    }

    seen = [0, 0]
    reservoirs = {0: [], 1: []}
    scanned = 0

    with archive.open(member) as stream:
        source_line = 0

        while True:
            line = stream.readline(MAX_RECORD_BYTES + 1)

            if not line:
                break

            source_line += 1

            if len(line) > MAX_RECORD_BYTES:
                raise ValueError(
                    f"Record exceeds size limit: "
                    f"{member.filename}, line {source_line}"
                )

            if not line.strip():
                continue

            record = json.loads(line)

            label = record.get("label")
            timestamp = record.get("first_submission_date")
            digest = record.get("sha256")

            if type(label) is not int or label not in (0, 1):
                raise ValueError("Unexpected binary label.")

            if record.get("file_type") != "Win32":
                raise ValueError("Unexpected file type.")

            if record.get("week_id") != week_id:
                raise ValueError("Record week does not match its member.")

            if (
                type(timestamp) is not int
                or not start_timestamp <= timestamp < stop_timestamp
            ):
                raise ValueError(
                    f"Timestamp outside expected week: "
                    f"{member.filename}, line {source_line}"
                )

            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in digest.lower()
                )
            ):
                raise ValueError("Invalid source SHA-256.")

            scanned += 1
            seen[label] += 1

            item = (
                source_line,
                line,
                digest.lower(),
                label,
                timestamp,
            )

            if len(reservoirs[label]) < quota:
                reservoirs[label].append(item)
            else:
                position = int(
                    generators[label].integers(seen[label])
                )

                if position < quota:
                    reservoirs[label][position] = item

            if scanned % 10000 == 0:
                print(
                    f"  Scanned {scanned:,} records",
                    flush=True,
                )

    if any(seen[label] < quota for label in (0, 1)):
        raise ValueError(
            f"Insufficient class examples in {member.filename}"
        )

    selected = sorted(
        reservoirs[0] + reservoirs[1],
        key=lambda item: item[0],
    )

    directory = OUTPUT / phase
    directory.mkdir(parents=True, exist_ok=True)

    raw_path = directory / f"week_{week_id:02d}.jsonl"
    trace_path = directory / f"week_{week_id:02d}.source.jsonl"

    raw_temporary = raw_path.with_suffix(".jsonl.tmp")
    trace_temporary = trace_path.with_suffix(".jsonl.tmp")

    with (
        raw_temporary.open("wb") as raw_output,
        trace_temporary.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as trace_output,
    ):
        for sample_row, item in enumerate(selected):
            source_line, line, digest, label, timestamp = item

            raw_output.write(
                line if line.endswith(b"\n") else line + b"\n"
            )

            trace_output.write(json.dumps({
                "sample_row": sample_row,
                "source_member": member.filename,
                "source_line": source_line,
                "sha256": digest,
                "label": label,
                "first_submission_date": timestamp,
                "week_id": week_id,
                "phase": phase,
            }) + "\n")

    # Replace only this run's uncommitted output files.
    raw_temporary.replace(raw_path)
    trace_temporary.replace(trace_path)

    timestamps = [item[4] for item in selected]

    return {
        "week_id": week_id,
        "phase": phase,
        "source_member": member.filename,
        "scanned_rows": scanned,
        "source_class_counts": {
            "benign": seen[0],
            "malicious": seen[1],
        },
        "selected_rows": len(selected),
        "selected_class_counts": {
            "benign": quota,
            "malicious": quota,
        },
        "minimum_timestamp": min(timestamps),
        "maximum_timestamp": max(timestamps),
        "raw_file": str(raw_path.relative_to(ROOT)),
        "raw_sha256": sha256(raw_path),
        "trace_file": str(trace_path.relative_to(ROOT)),
        "trace_sha256": sha256(trace_path),
    }


def summarize(state):
    summary = {}
    phase_hashes = {}

    for phase in ("train", "validation"):
        weeks = [
            week for week in state["weeks"].values()
            if week["phase"] == phase
        ]

        hashes = set()
        duplicate_rows = 0

        for week in weeks:
            with (ROOT / week["trace_file"]).open(
                encoding="utf-8"
            ) as stream:
                for line in stream:
                    digest = json.loads(line)["sha256"]

                    if digest in hashes:
                        duplicate_rows += 1

                    hashes.add(digest)

        phase_hashes[phase] = hashes

        summary[phase] = {
            "rows": sum(week["selected_rows"] for week in weeks),
            "benign": sum(
                week["selected_class_counts"]["benign"]
                for week in weeks
            ),
            "malicious": sum(
                week["selected_class_counts"]["malicious"]
                for week in weeks
            ),
            "first_submission_min": utc_text(min(
                week["minimum_timestamp"] for week in weeks
            )),
            "first_submission_max": utc_text(max(
                week["maximum_timestamp"] for week in weeks
            )),
            "duplicate_sha256_rows": duplicate_rows,
        }

    latest_training = max(
        week["maximum_timestamp"]
        for week in state["weeks"].values()
        if week["phase"] == "train"
    )
    earliest_validation = min(
        week["minimum_timestamp"]
        for week in state["weeks"].values()
        if week["phase"] == "validation"
    )

    if latest_training >= earliest_validation:
        raise ValueError("Chronological separation failed.")

    summary["cross_partition_sha256_overlap"] = len(
        phase_hashes["train"] & phase_hashes["validation"]
    )
    summary["chronological_separation"] = True

    return summary


def main():
    verification = json.loads(
        VERIFICATION.read_text(encoding="utf-8")
    )

    if verification["status"] != "verified":
        raise ValueError("Archive verification is incomplete.")

    if ARCHIVE.stat().st_size != verification["size_bytes"]:
        raise ValueError("Archive size changed.")

    protocol = {
        "pilot_id": PILOT_ID,
        "archive_sha256": verification["sha256"],
        "dataset_revision": verification["revision"],
        "sampling": "class_stratified_reservoir_v1",
        "seed": SEED,
        "numpy_version": np.__version__,
        "training_weeks": TRAIN_WEEKS,
        "training_per_class_per_week": TRAIN_PER_CLASS_PER_WEEK,
        "validation_per_class_per_week": VALIDATION_PER_CLASS_PER_WEEK,
    }

    if REPORT.exists():
        state = json.loads(REPORT.read_text(encoding="utf-8"))

        if state["protocol"] != protocol:
            raise ValueError(
                "Existing pilot uses a different protocol. "
                "Use a new PILOT_ID."
            )

        if state["status"] == "sampled":
            print("Sampling already completed.")
            print(json.dumps(state["summary"], indent=2))
            return
    else:
        OUTPUT.mkdir(parents=True, exist_ok=True)
        REPORT.parent.mkdir(parents=True, exist_ok=True)

        state = {
            "status": "sampling",
            "protocol": protocol,
            "weeks": {},
            "note": (
                "Sampled from official training data only. "
                "Vectorization and overlap cleanup must precede training."
            ),
        }
        save_state(state)

    print("Rechecking archive checksum...", flush=True)

    if sha256(ARCHIVE) != verification["sha256"]:
        raise ValueError("Archive checksum changed.")

    try:
        with zipfile.ZipFile(ARCHIVE) as archive:
            members = sorted(
                [
                    item for item in archive.infolist()
                    if item.filename.endswith("_Win32_train.jsonl")
                ],
                key=lambda item: item.filename,
            )

            if len(members) != 52:
                raise ValueError("Expected 52 weekly training members.")

            for week_id, member in enumerate(members):
                key = str(week_id)

                if key in state["weeks"]:
                    completed = state["weeks"][key]

                    for path_key, checksum_key in (
                        ("raw_file", "raw_sha256"),
                        ("trace_file", "trace_sha256"),
                    ):
                        path = ROOT / completed[path_key]

                        if (
                            not path.is_file()
                            or sha256(path) != completed[checksum_key]
                        ):
                            raise ValueError(
                                f"Completed week output changed: {week_id}"
                            )

                    print(
                        f"Week {week_id:02d}: verified checkpoint; skipping.",
                        flush=True,
                    )
                    continue

                if shutil.disk_usage(ROOT).free < 2 * GIB:
                    raise RuntimeError(
                        "Less than 2 GiB free. Sampling stopped "
                        "before starting another week."
                    )

                phase = (
                    "train" if week_id < TRAIN_WEEKS
                    else "validation"
                )
                quota = (
                    TRAIN_PER_CLASS_PER_WEEK
                    if phase == "train"
                    else VALIDATION_PER_CLASS_PER_WEEK
                )

                print(
                    f"\nWeek {week_id:02d} | {phase} | "
                    f"{member.filename}",
                    flush=True,
                )

                state["weeks"][key] = sample_week(
                    archive,
                    member,
                    week_id,
                    phase,
                    quota,
                )

                state["status"] = "sampling"
                save_state(state)

                print(
                    f"  Saved {2 * quota:,} selected records.",
                    flush=True,
                )

        state["summary"] = summarize(state)
        state["status"] = "sampled"
        save_state(state)

        print("\nPILOT SAMPLING SUMMARY")
        print(json.dumps(state["summary"], indent=2))
        print("\nReport:", REPORT)
        print("No features vectorized or models trained.")

    except BaseException as error:
        state["status"] = (
            "interrupted"
            if isinstance(error, KeyboardInterrupt)
            else "failed"
        )
        state["error_type"] = type(error).__name__
        save_state(state)
        raise


if __name__ == "__main__":
    main()