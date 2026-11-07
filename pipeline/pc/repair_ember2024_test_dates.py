"""
Repair source-week date validation while preserving:
- frozen models and thresholds
- the original training helper
- completed test-vectorization checkpoints
- the final test chronology and overlap checks
"""

import argparse
import ast
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def read(path):
    return json.loads(
        path.read_text(encoding="utf-8-sig")
    )


def write_bytes(path, contents):
    temporary = path.with_suffix(
        path.suffix + ".repair.tmp"
    )
    temporary.write_bytes(contents)
    temporary.replace(path)


def write_json(path, contents):
    text = (
        json.dumps(
            contents,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )

    write_bytes(
        path,
        text.encode("utf-8"),
    )


def build(root):
    scripts = root / "scripts"

    report = (
        root
        / "reports/ember2024/independent-win32-v1"
    )

    backup = (
        report / "source_week_date_repair_v1"
    )

    evaluator = (
        scripts / "evaluate_frozen_ember2024_test.py"
    )

    helper = (
        scripts / "prepare_ember2024_test_week.py"
    )

    checkpoint = (
        report / "test_preparation.json"
    )

    if (
        (report / "test_report.json").exists()
        or (report / "prediction_progress.json").exists()
    ):
        raise RuntimeError(
            "Predictions/results already exist. "
            "Do not migrate a scored evaluation."
        )

    backup_checkpoint = (
        backup / "checkpoint_before.json"
    )

    state = read(
        backup_checkpoint
        if backup_checkpoint.exists()
        else checkpoint
    )

    backup_source = (
        backup / "evaluator_before.py"
    )

    source_path = (
        backup_source
        if backup_source.exists()
        else evaluator
    )

    old = state["identity"]

    if state["status"] != "preparing":
        raise ValueError(
            "This repair requires an unfinished "
            "vectorization checkpoint."
        )

    if digest(source_path) != old["script_sha256"]:
        raise ValueError(
            "Evaluator differs from its original checkpoint."
        )

    original_helper = (
        scripts / "prepare_full_ember2024_win32.py"
    )

    if (
        digest(original_helper)
        != old["preparation_helper_sha256"]
    ):
        raise ValueError(
            "Original training helper changed."
        )

    vector_helper = (
        scripts / "vectorize_ember2024_pilot.py"
    )

    if (
        digest(vector_helper)
        != old["vector_helper_sha256"]
    ):
        raise ValueError(
            "Vector helper changed."
        )

    if (
        digest(report / "frozen_protocol.json")
        != old["frozen_protocol_sha256"]
    ):
        raise ValueError(
            "Frozen evaluation protocol changed."
        )

    offset = 0

    for position, week in enumerate(state["weeks"]):
        if week["week"] != 52 + position:
            raise ValueError(
                "Checkpoint week order changed."
            )

        for chunk in week["chunks"]:
            if chunk["offset"] != offset:
                raise ValueError(
                    "Checkpoint offsets changed."
                )

            for field, checksum in (
                ("x_file", "x_sha256"),
                ("metadata_file", "metadata_sha256"),
            ):
                if (
                    digest(root / chunk[field])
                    != chunk[checksum]
                ):
                    raise ValueError(
                        "A completed checkpoint chunk changed."
                    )

            offset += chunk["rows"]

    spec = importlib.util.spec_from_file_location(
        "mlwint_original_prep",
        original_helper,
    )

    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)

    function = inspect.getsource(
        base.prepare_week
    )

    old_condition = (
        "or type(timestamp) is not int "
        "or not low <= timestamp < high):"
    )

    if function.count(old_condition) != 1:
        raise ValueError(
            "Unexpected original date-validation code."
        )

    # Keep file type, week ID and timestamp-type validation.
    # Source-week date discrepancies are audited separately.
    function = function.replace(
        old_condition,
        "or type(timestamp) is not int):",
        1,
    )

    flush_marker = "    def flush():"
    row_marker = '            stats["source_rows"] += 1'

    if (
        function.count(flush_marker) != 1
        or function.count(row_marker) != 1
    ):
        raise ValueError(
            "Unexpected preparation helper structure."
        )

    function = function.replace(
        flush_marker,
        (
            '    stats["source_week_timestamp_mismatch_rows"] = 0\n'
            "\n"
            "    def flush():"
        ),
        1,
    )

    function = function.replace(
        row_marker,
        (
            "            if not low <= timestamp < high:\n"
            '                stats["source_week_timestamp_mismatch_rows"] += 1\n'
            '            stats["source_rows"] += 1'
        ),
        1,
    )

    header = '''"""
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
'''

    expected_base_hash = (
        old["preparation_helper_sha256"]
    )

    header += (
        "\n"
        f"if sha256(Path(base.__file__)) != {expected_base_hash!r}:\n"
        "    raise ValueError(\n"
        '        "Original training helper changed after the date repair."\n'
        "    )\n"
        "\n"
    )

    helper_bytes = (
        header + function
    ).encode("utf-8")

    source = source_path.read_text(
        encoding="utf-8-sig"
    )

    old_import = (
        "import prepare_full_ember2024_win32 as prep"
    )

    audit_line = (
        '    details["source_rows"] = sum('
    )

    if (
        source.count(old_import) != 1
        or source.count(audit_line) != 1
    ):
        raise ValueError(
            "Unexpected evaluator import/audit structure."
        )

    source = source.replace(
        old_import,
        "import prepare_ember2024_test_week as prep",
        1,
    )

    source = source.replace(
        audit_line,
        (
            '    details["source_week_timestamp_mismatch_rows"] = sum(\n'
            '        w["stats"].get("source_week_timestamp_mismatch_rows", 0)\n'
            '        for w in state["weeks"]\n'
            "    )\n"
            + audit_line
        ),
        1,
    )

    evaluator_bytes = source.encode("utf-8")

    ast.parse(
        helper_bytes.decode("utf-8")
    )

    ast.parse(
        evaluator_bytes.decode("utf-8")
    )

    new_identity = dict(
        old,
        script_sha256=hashlib.sha256(
            evaluator_bytes
        ).hexdigest(),
        preparation_helper_sha256=hashlib.sha256(
            helper_bytes
        ).hexdigest(),
    )

    return {
        "root": root,
        "report": report,
        "backup": backup,
        "evaluator": evaluator,
        "helper": helper,
        "checkpoint": checkpoint,
        "old_state": state,
        "offset": offset,
        "helper_bytes": helper_bytes,
        "evaluator_bytes": evaluator_bytes,
        "new_identity": new_identity,
        "original_source": source_path.read_bytes(),
    }


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
        "--dry-run",
        action="store_true",
    )

    args = parser.parse_args()
    root = args.project_root.resolve()

    record = (
        root
        / "reports/ember2024/independent-win32-v1"
        / "source_week_date_repair_v1/repair.json"
    )

    if record.exists():
        done = read(record)
        scripts = root / "scripts"

        evaluator_hash = digest(
            scripts / "evaluate_frozen_ember2024_test.py"
        )

        helper_hash = digest(
            scripts / "prepare_ember2024_test_week.py"
        )

        current_checkpoint = read(
            record.parent.parent
            / "test_preparation.json"
        )

        if (
            evaluator_hash
            != done["new_identity"]["script_sha256"]
            or helper_hash
            != done["new_identity"]["preparation_helper_sha256"]
            or current_checkpoint["identity"]
            != done["new_identity"]
        ):
            raise ValueError(
                "Previously repaired inputs changed."
            )

        print(
            "Repair already applied; "
            "current checkpoint verified."
        )
        return

    plan = build(root)

    print(
        f"Verified {len(plan['old_state']['weeks'])} "
        f"completed weeks and "
        f"{plan['offset']:,} stored rows."
    )

    current = read(
        plan["checkpoint"]
    )

    if current["identity"] not in (
        plan["old_state"]["identity"],
        plan["new_identity"],
    ):
        raise ValueError(
            "Current checkpoint has an unexpected identity."
        )

    for path, content, old_hash in (
        (
            plan["evaluator"],
            plan["evaluator_bytes"],
            plan["old_state"]["identity"]["script_sha256"],
        ),
        (
            plan["helper"],
            plan["helper_bytes"],
            None,
        ),
    ):
        new_hash = hashlib.sha256(
            content
        ).hexdigest()

        if (
            path.exists()
            and digest(path) not in (old_hash, new_hash)
        ):
            raise ValueError(
                f"Unexpected existing file: {path}"
            )

    if args.dry_run:
        print(
            "Dry run passed; no files changed."
        )
        return

    plan["backup"].mkdir(
        parents=True,
        exist_ok=True,
    )

    backup_source = (
        plan["backup"] / "evaluator_before.py"
    )

    if not backup_source.exists():
        write_bytes(
            backup_source,
            plan["original_source"],
        )

    backup_checkpoint = (
        plan["backup"] / "checkpoint_before.json"
    )

    if not backup_checkpoint.exists():
        write_json(
            backup_checkpoint,
            plan["old_state"],
        )

    write_bytes(
        plan["helper"],
        plan["helper_bytes"],
    )

    write_bytes(
        plan["evaluator"],
        plan["evaluator_bytes"],
    )

    current["identity"] = plan["new_identity"]

    current["source_week_date_repair"] = {
        "policy": (
            "Retain records outside named source-week "
            "dates and count discrepancies. The existing "
            "final training/development chronology check "
            "remains mandatory."
        ),
        "checkpoint_rows_preserved": plan["offset"],
    }

    write_json(
        plan["checkpoint"],
        current,
    )

    write_json(
        record,
        {
            "old_identity": (
                plan["old_state"]["identity"]
            ),
            "new_identity": (
                plan["new_identity"]
            ),
            "rows_preserved": plan["offset"],
            "reason": (
                "Valid Win32 week-55 record has a "
                "2024-10-12 timestamp in the "
                "2024-10-13 source member. "
                "No scores or thresholds were used "
                "to change ingestion."
            ),
        },
    )

    print(
        "Repair complete. Frozen protocol, models, "
        "archive and original training helper unchanged."
    )

    print(
        "Rerun evaluate_frozen_ember2024_test.py "
        "to continue from the next unfinished week."
    )


if __name__ == "__main__":
    main()