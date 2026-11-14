"""MLWINT static PE-file analysis using the verified EMBER2024 models."""

import argparse
import contextlib
import hashlib
import inspect
import io
import json
import struct
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from uuid import uuid4

import numpy as np

if __package__:
    from .ember2024_models import (
        Ember2024Models,
        FEATURE_COUNT,
        sha256,
    )
    from .ember2024_tools import (
        SOURCE_REPORT,
        SOURCE_HASH,
        LIMITATIONS,
        analyze_record,
    )
else:
    from ember2024_models import (
        Ember2024Models,
        FEATURE_COUNT,
        sha256,
    )
    from ember2024_tools import (
        SOURCE_REPORT,
        SOURCE_HASH,
        LIMITATIONS,
        analyze_record,
    )


MAX_FILE_BYTES = 64 * 1024 * 1024


def verified_extractor(root):
    from thrember.features import PEFeatureExtractor

    report_path = root / SOURCE_REPORT

    if sha256(report_path) != SOURCE_HASH:
        raise ValueError(
            "The verified training feature report has changed."
        )

    protocol = json.loads(
        report_path.read_text(encoding="utf-8-sig")
    )["protocol"]

    packages = {
        name: version(name)
        for name in protocol["packages"]
    }

    if packages != protocol["packages"]:
        raise ValueError(
            "Extractor dependencies differ; use the pinned "
            "EMBER2024 environment."
        )

    source_hash = sha256(
        Path(inspect.getfile(PEFeatureExtractor))
    )

    if source_hash != protocol["extractor_code_sha256"]:
        raise ValueError(
            "The extractor differs from the version used for training."
        )

    extractor = PEFeatureExtractor()

    if extractor.dim != FEATURE_COUNT:
        raise ValueError("Unexpected extractor feature count.")

    groups = [
        feature.name
        for feature in extractor.features
    ]

    if groups != protocol["feature_groups"]:
        raise ValueError(
            "Extractor feature groups or order differ from training."
        )

    return extractor, {
        "feature_count": FEATURE_COUNT,
        "feature_groups": groups,
        "extractor_file_sha256": source_hash,
        "packages": {
            **packages,
            "pefile": version("pefile"),
        },
    }


def read_pe(path):
    if not path.is_file():
        raise ValueError("Input must be an existing file.")

    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)

    if len(data) > MAX_FILE_BYTES:
        raise ValueError(
            "This prototype supports files up to 64 MiB."
        )

    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError(
            "Input is not a supported Windows PE file."
        )

    offset = struct.unpack_from("<I", data, 0x3C)[0]

    if offset < 64 or offset + 26 > len(data):
        raise ValueError("Invalid PE header offset.")

    if data[offset:offset + 4] != b"PE\x00\x00":
        raise ValueError("PE signature was not found.")

    magic = struct.unpack_from("<H", data, offset + 24)[0]

    if magic not in (0x10B, 0x20B):
        raise ValueError(
            "Only PE32 and PE32+ images are supported."
        )

    return data


def static_evidence(raw):
    header = raw["header"]
    coff = header["coff"]
    optional = header["optional"]
    imports = raw["imports"]
    library_names = sorted(imports)
    signature = raw["authenticode"]

    return {
        "machine": coff["machine"],
        "subsystem": optional["subsystem"],
        "pe_format": (
            "PE32+"
            if optional["magic"] == 0x20B
            else "PE32"
        ),
        "coff_timestamp_unverified": int(coff["timestamp"]),
        "entry_point_rva": int(
            optional["address_of_entrypoint"]
        ),
        "file_entropy": float(raw["general"]["entropy"]),
        "section_count": len(raw["section"]["sections"]),
        "sections": raw["section"]["sections"],
        "overlay": raw["section"]["overlay"],
        "imported_library_count": len(imports),
        "imported_symbol_count": sum(
            len(symbols)
            for symbols in imports.values()
        ),
        "import_examples": {
            name: imports[name][:20]
            for name in library_names[:30]
        },
        "import_examples_truncated": (
            len(imports) > 30
            or any(
                len(symbols) > 20
                for symbols in imports.values()
            )
        ),
        "authenticode": {
            "parsed_signature_count": int(
                signature["num_certs"]
            ),
            "parse_error": bool(signature["parse_error"]),
            "trust_verification": "not_performed",
        },
        "normalized_parser_warnings": raw["pefilewarnings"],
        "interpretation": (
            "These are static observations. Imports do not prove "
            "execution; entropy and signature presence do not "
            "establish maliciousness or safety."
        ),
    }


def analyze_file(
    models,
    file_path,
    *,
    threshold=0.5,
    compare=False,
):
    path = Path(file_path).resolve()

    if not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError(
            "Threshold must be finite and between zero and one."
        )

    extractor, extractor_info = verified_extractor(models.root)
    data = read_pe(path)

    identity = {
        "path": str(path),
        "filename": path.name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    messages = io.StringIO()

    with (
        contextlib.redirect_stdout(messages),
        contextlib.redirect_stderr(messages),
    ):
        raw = extractor.raw_features(data)

        if (
            raw["general"]["is_pe"] != 1
            or not raw["header"]
        ):
            raise ValueError(
                "The extractor could not parse this PE file."
            )

        vector = extractor.process_raw_features(raw)

    if raw["sha256"] != identity["sha256"]:
        raise ValueError(
            "Extractor and input file hashes disagree."
        )

    if (
        vector.shape != (FEATURE_COUNT,)
        or not np.isfinite(vector).all()
    ):
        raise ValueError(
            "Extraction did not produce a valid "
            "2,568-feature vector."
        )

    analysis = analyze_record(
        models,
        vector,
        record_id={"sha256": identity["sha256"]},
        threshold=threshold,
        compare=compare,
    )

    captured = messages.getvalue()

    return {
        "status": "complete",
        "tool_version": "mlwint-file-analysis-v0.1",
        "analysis_method": (
            "Static file reading and parsing; "
            "target file not executed"
        ),
        "file": identity,
        "extractor": extractor_info,
        "models": models.describe(),
        "classification": analysis,
        "static_evidence": static_evidence(raw),
        "extractor_messages": captured[-4000:],
        "extractor_messages_truncated": len(captured) > 4000,
        "capability_assessment": "not_assessed",
        "system_impact": "not_established",
        "limitations": LIMITATIONS + [
            (
                "The model was evaluated on EMBER2024 data; "
                "accuracy on this file is unknown."
            ),
            (
                "Static parsing is not an isolated malware "
                "sandbox or a behavioral analysis."
            ),
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        type=Path,
        required=True,
    )
    parser.add_argument("--project-root", type=Path)
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
    )
    parser.add_argument(
        "--compare",
        action="store_true",
    )
    args = parser.parse_args()

    models = Ember2024Models(args.project_root)

    try:
        print(
            "Reading and analyzing the PE file...",
            flush=True,
        )

        report = analyze_file(
            models,
            args.file,
            threshold=args.threshold,
            compare=args.compare,
        )

    except Exception as error:
        report = {
            "status": "cannot_analyze",
            "file": str(args.file.resolve()),
            "error_type": type(error).__name__,
            "error": str(error),
            "prediction": None,
        }

    report["created_utc"] = (
        datetime.now(timezone.utc).isoformat()
    )

    folder = (
        models.root
        / "reports/ember2024/agent-v0.1/files"
    )
    folder.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S"
    )
    output = folder / (
        f"file-{stamp}-{uuid4().hex[:8]}.json"
    )

    with output.open("x", encoding="utf-8") as stream:
        json.dump(
            report,
            stream,
            indent=2,
            allow_nan=False,
        )
        stream.write("\n")

    print(json.dumps(report, indent=2, allow_nan=False))
    print(f"\nReport: {output}")

    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    sys.exit(main())