from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import inspect
import json
import math
from pathlib import Path
import re
import uuid
import zipfile


PROFILE_ID = "mlwint-security-static-v1"
HIGH_ENTROPY = 7.2
SPARSE_IMPORT_LIMIT = 8

FEATURE_NAMES = (
    "pe_metadata_available",
    "section_metadata_available",
    "import_metadata_available",
    "reported_entry_section_unique",
    "writable_executable_section_fraction",
    "high_entropy_executable_fraction",
    "reported_entry_writable_executable",
    "reported_entry_high_entropy_executable",
    "executable_raw_size_share",
    "executable_virtual_expansion_log",
    "overlay_entropy_size_interaction",
    "high_entropy_sparse_imports",
    "writable_executable_sparse_imports",
    "high_entropy_dynamic_resolution",
    "process_memory_api_cooccurrence",
    "process_memory_thread_api_cooccurrence",
    "token_query_adjust_api_cooccurrence",
    "registry_create_set_api_cooccurrence",
    "service_create_start_api_cooccurrence",
    "network_process_api_cooccurrence",
    "loader_memory_protect_api_cooccurrence",
    "debugger_timing_api_cooccurrence",
)


def number(value, name, minimum=0):
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be numeric.")

    value = float(value)
    if not math.isfinite(value) or value < minimum:
        raise ValueError(f"Invalid {name}: {value}")

    return value


def entropy(value, name):
    value = number(value, name)
    if value > 8.000001:
        raise ValueError(f"Entropy outside expected range: {name}")
    return value


def extract_security_features(record):
    """Return ordered static indicators, without executing a file."""
    values = {name: 0.0 for name in FEATURE_NAMES}

    general = record.get("general")
    if not isinstance(general, dict):
        raise ValueError("Missing general file metadata.")

    is_pe = general.get("is_pe")
    if type(is_pe) is not int or is_pe not in (0, 1):
        raise ValueError("Unexpected general.is_pe value.")

    # These particular additions describe PE metadata.
    # Zero means inapplicable for non-PE inputs, not benign.
    if is_pe == 0:
        return values

    values["pe_metadata_available"] = 1.0
    file_size = number(general.get("size"), "file size", minimum=1)

    section_info = record.get("section")
    section_available = (
        isinstance(section_info, dict)
        and isinstance(section_info.get("sections"), list)
    )
    import_available = isinstance(record.get("imports"), dict)

    values["section_metadata_available"] = float(section_available)
    values["import_metadata_available"] = float(import_available)

    sections = []
    entry_matches = []
    executable = []
    writable_executable = []
    high_entropy_executable = []

    if section_available:
        entry_name = section_info.get("entry")
        if not isinstance(entry_name, str):
            raise ValueError("Invalid reported entry-section name.")

        for original in section_info["sections"]:
            if not isinstance(original, dict):
                raise ValueError("Invalid section record.")

            name = original.get("name")
            props = original.get("props")

            if (
                not isinstance(name, str)
                or not isinstance(props, list)
                or not all(isinstance(prop, str) for prop in props)
            ):
                raise ValueError("Invalid section name/properties.")

            section = {
                "name": name.casefold(),
                "props": set(props),
                "size": number(original.get("size"), "section size"),
                "vsize": number(original.get("vsize"), "virtual size"),
                "entropy": entropy(
                    original.get("entropy"), "section entropy"
                ),
            }
            sections.append(section)

        executable = [
            section for section in sections
            if "MEM_EXECUTE" in section["props"]
        ]
        writable_executable = [
            section for section in executable
            if "MEM_WRITE" in section["props"]
        ]
        high_entropy_executable = [
            section for section in executable
            if section["entropy"] >= HIGH_ENTROPY
        ]

        entry_matches = [
            section for section in sections
            if entry_name
            and section["name"] == entry_name.casefold()
        ]

        values["reported_entry_section_unique"] = float(
            len(entry_matches) == 1
        )
        values["writable_executable_section_fraction"] = (
            len(writable_executable) / max(len(sections), 1)
        )
        values["high_entropy_executable_fraction"] = (
            len(high_entropy_executable) / max(len(executable), 1)
        )
        values["executable_raw_size_share"] = (
            sum(section["size"] for section in executable) / file_size
        )
        values["executable_virtual_expansion_log"] = max(
            (
                math.log1p(
                    section["vsize"] / max(section["size"], 1)
                )
                for section in executable
            ),
            default=0.0,
        )

        if len(entry_matches) == 1:
            entry = entry_matches[0]
            entry_executable = "MEM_EXECUTE" in entry["props"]
            values["reported_entry_writable_executable"] = float(
                entry_executable and "MEM_WRITE" in entry["props"]
            )
            values["reported_entry_high_entropy_executable"] = float(
                entry_executable
                and entry["entropy"] >= HIGH_ENTROPY
            )

        overlay = section_info.get("overlay")
        if not isinstance(overlay, dict):
            raise ValueError("Missing overlay metadata.")

        overlay_entropy = entropy(
            overlay.get("entropy"), "overlay entropy"
        )
        overlay_share = number(
            overlay.get("size_ratio"), "overlay size share"
        )
        values["overlay_entropy_size_interaction"] = (
            overlay_entropy / 8.0 * overlay_share
        )

    api_names = set()
    import_count = 0

    if import_available:
        for library, functions in record["imports"].items():
            if (
                not isinstance(library, str)
                or not isinstance(functions, list)
                or not all(isinstance(name, str) for name in functions)
            ):
                raise ValueError("Unexpected import metadata.")

            import_count += len(functions)
            for name in functions:
                # Handle common decorations without substring matching.
                name = name.rsplit(":", 1)[-1].lstrip("_")
                name = re.sub(r"@\d+$", "", name)
                api_names.add(name.casefold())

    def has(*names):
        return any(
            variant in api_names
            for name in names
            for variant in (
                name.casefold(),
                name.casefold() + "a",
                name.casefold() + "w",
            )
        )

    if import_available:
        process_access = has("OpenProcess", "NtOpenProcess")
        process_memory = has(
            "WriteProcessMemory", "NtWriteVirtualMemory"
        )
        remote_thread = has(
            "CreateRemoteThread", "CreateRemoteThreadEx",
            "NtCreateThreadEx",
        )
        dynamic_resolution = (
            has("LoadLibrary", "LoadLibraryEx")
            and has("GetProcAddress")
        )
        network = has(
            "InternetOpen", "InternetConnect", "HttpSendRequest",
            "WinHttpOpen", "WinHttpSendRequest",
            "URLDownloadToFile", "connect",
        )
        process_launch = has(
            "CreateProcess", "ShellExecute", "ShellExecuteEx", "WinExec"
        )

        indicators = {
            "process_memory_api_cooccurrence": (
                process_access and process_memory
            ),
            "process_memory_thread_api_cooccurrence": (
                process_access and process_memory and remote_thread
            ),
            "token_query_adjust_api_cooccurrence": (
                has("GetTokenInformation")
                and has("AdjustTokenPrivileges")
            ),
            "registry_create_set_api_cooccurrence": (
                has("RegCreateKey", "RegCreateKeyEx")
                and has("RegSetValue", "RegSetValueEx")
            ),
            "service_create_start_api_cooccurrence": (
                has("CreateService") and has("StartService")
            ),
            "network_process_api_cooccurrence": (
                network and process_launch
            ),
            "loader_memory_protect_api_cooccurrence": (
                dynamic_resolution
                and has("VirtualProtect", "VirtualProtectEx")
            ),
            "debugger_timing_api_cooccurrence": (
                has("IsDebuggerPresent", "CheckRemoteDebuggerPresent")
                and has(
                    "GetTickCount", "GetTickCount64",
                    "QueryPerformanceCounter",
                )
            ),
        }

        for name, present in indicators.items():
            values[name] = float(present)

        if section_available:
            sparse = import_count <= SPARSE_IMPORT_LIMIT
            values["high_entropy_sparse_imports"] = float(
                bool(high_entropy_executable) and sparse
            )
            values["writable_executable_sparse_imports"] = float(
                bool(writable_executable) and sparse
            )
            values["high_entropy_dynamic_resolution"] = float(
                bool(high_entropy_executable) and dynamic_resolution
            )

    if not all(math.isfinite(value) for value in values.values()):
        raise ValueError("Non-finite derived security features.")

    return values


def probe_archives():
    import numpy as np
    from thrember.features import PEFeatureExtractor

    root = Path(__file__).resolve().parents[2]
    archive_dir = root / "data/raw/ember2024/archives"

    expected_extractor_hash = (
        "aa9b29e2267a037ebec0b234234edfc2f8d"
        "2316e579ab1a0fba6878e70288eca"
    )

    source = Path(inspect.getsourcefile(PEFeatureExtractor))
    actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    if actual_hash != expected_extractor_hash:
        raise RuntimeError("Installed extractor differs from the pinned version.")

    extractor = PEFeatureExtractor()
    if extractor.dim != 2568 or len(FEATURE_NAMES) != 22:
        raise RuntimeError("Unexpected feature dimensions.")

    categories = {
        "Win32": "Win32",
        "Win64": "Win64",
        ".NET": "Dot_Net",
        "APK": "APK",
        "PDF": "PDF",
        "ELF": "ELF",
    }

    report = {
        "profile_id": PROFILE_ID,
        "active_feature_count": 2568,
        "candidate_extra_feature_count": len(FEATURE_NAMES),
        "candidate_combined_feature_count": 2568 + len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "high_entropy_threshold": HIGH_ENTROPY,
        "sparse_import_limit": SPARSE_IMPORT_LIMIT,
        "extractor_sha256": actual_hash,
        "module_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "models_trained": False,
        "ready_for_training": False,
        "scope": "Sampled feature compatibility check only.",
        "limitations": [
            "Indicators do not prove maliciousness or runtime behaviour.",
            "Reported entry section may be the extractor's fallback section.",
            "PE-specific additions are inapplicable to APK, PDF and ELF.",
            "Full dataset preparation and compatible model training remain.",
            "Source archive checksums are not reverified in this probe.",
        ],
        "categories": {},
    }

    for category, token in categories.items():
        print(f"\nChecking {category}...", flush=True)
        sampled = 0
        pe_rows = 0
        nonzero = Counter()
        errors = []

        try:
            with zipfile.ZipFile(
                archive_dir / f"{token}_train.zip"
            ) as container:
                members = sorted(
                    (
                        entry for entry in container.infolist()
                        if not entry.is_dir()
                        and entry.filename.endswith("_train.jsonl")
                    ),
                    key=lambda entry: entry.filename,
                )
                if len(members) != 52:
                    raise ValueError("Expected 52 weekly JSONL members.")

                for member in members:
                    with container.open(member) as stream:
                        for line_number in (1, 2):
                            location = (
                                f"{member.filename}:{line_number}"
                            )
                            line = stream.readline(16 * 1024 * 1024 + 1)
                            if not line or len(line) > 16 * 1024 * 1024:
                                raise ValueError(
                                    f"Missing/oversized record: {location}"
                                )

                            raw = json.loads(line)
                            if raw.get("file_type") != token:
                                raise ValueError(
                                    f"Unexpected file type: {location}"
                                )

                            derived = extract_security_features(raw)
                            extra = np.asarray(
                                [derived[name] for name in FEATURE_NAMES],
                                dtype=np.float32,
                            )
                            original = extractor.process_raw_features(raw)
                            combined = np.concatenate([original, extra])

                            if (
                                original.shape != (2568,)
                                or combined.shape != (2590,)
                                or not np.isfinite(combined).all()
                                or not np.array_equal(
                                    combined[:2568], original
                                )
                            ):
                                raise ValueError(
                                    f"Feature compatibility failure: {location}"
                                )

                            sampled += 1
                            pe_rows += int(
                                derived["pe_metadata_available"]
                            )
                            nonzero.update(
                                name for name, value in derived.items()
                                if value != 0
                            )

        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")

        passed = sampled == 104 and not errors
        report["categories"][category] = {
            "status": "sampled_pass" if passed else "failed",
            "sampled_rows": sampled,
            "sampled_pe_rows": pe_rows,
            "nonzero_feature_counts": dict(nonzero),
            "errors": errors,
        }
        print(
            f"  {'PASS' if passed else 'FAILED'}: "
            f"{sampled} sampled records",
            flush=True,
        )
        for error in errors:
            print(f"  {error}", flush=True)

    passed = all(
        entry["status"] == "sampled_pass"
        for entry in report["categories"].values()
    )
    report["status"] = "sampled_pass" if passed else "failed"

    output_dir = root / "reports/ember2024/security-static-v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = output_dir / f"probe-{stamp}-{uuid.uuid4().hex[:8]}.json"

    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")

    print(f"\nStatus: {report['status']}")
    print(f"Candidate combined features: {report['candidate_combined_feature_count']}")
    print(f"Report: {output}")
    print("No models or existing feature arrays were modified.")

    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(probe_archives())