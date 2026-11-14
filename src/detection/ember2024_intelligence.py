"""Combine MLWINT classification with evidence from static capa rules."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

if __package__:
    from .ember2024_models import Ember2024Models, sha256
    from .ember2024_file_analysis import analyze_file
else:
    from ember2024_models import Ember2024Models, sha256
    from ember2024_file_analysis import analyze_file


CAPA_VERSION = "9.4.0"


def resource_hash(folder, suffixes):
    digest = hashlib.sha256()
    count = 0

    for path in sorted(folder.rglob("*")):
        if path.is_file() and any(
            path.name.endswith(suffix)
            for suffix in suffixes
        ):
            relative = path.relative_to(folder).as_posix()
            digest.update(relative.encode("utf-8") + b"\0")
            digest.update(bytes.fromhex(sha256(path)))
            count += 1

    if not count:
        raise ValueError(
            f"No capa resources found in {folder}"
        )

    return {
        "files": count,
        "sha256": digest.hexdigest(),
    }


def address_text(address):
    value = address.get("value")
    value = (
        hex(value)
        if isinstance(value, int)
        else str(value)
    )

    return f"{address.get('type', 'unknown')}:{value}"


def evidence_examples(tree, maximum=8):
    examples = []
    stack = [tree]

    while stack and len(examples) < maximum:
        current = stack.pop()

        if current.get("success") is not True:
            continue

        node = current.get("node", {})

        if (
            node.get("type") == "feature"
            and current.get("locations")
        ):
            examples.append({
                "feature": node["feature"],
                "locations": current["locations"][:5],
            })

        stack.extend(
            reversed(current.get("children", []))
        )

    return examples


def summarize_capa(document, expected_hash):
    meta = document["meta"]

    if (
        meta["version"] != CAPA_VERSION
        or meta["flavor"] != "static"
    ):
        raise ValueError(
            "Expected static capa 9.4.0 output."
        )

    if meta["sample"]["sha256"].lower() != expected_hash:
        raise ValueError(
            "capa analyzed different file contents; "
            "results were not combined."
        )

    capabilities = []
    limitations = []

    for name, rule in sorted(document["rules"].items()):
        info = rule["meta"]

        if (
            info.get("lib")
            or info.get("capa/subscope")
            or info.get("is_subscope_rule")
        ):
            continue

        matches = rule["matches"]

        if not matches:
            continue

        examples = []

        for _, tree in matches[:3]:
            examples.extend(evidence_examples(tree))

        finding = {
            "rule_name": name,
            "namespace": info.get("namespace"),
            "description": info.get("description", ""),
            "match_count": len(matches),
            "match_locations": [
                address
                for address, _ in matches[:10]
            ],
            "evidence_examples": examples[:8],
            "evidence_is_excerpt": True,
            "attack": info.get(
                "att&ck",
                info.get("attack", []),
            ),
            "mbc": info.get("mbc", []),
        }

        namespace = info.get("namespace") or ""

        if namespace.startswith("internal/limitation"):
            limitations.append(finding)
        else:
            capabilities.append(finding)

    return {
        "status": "completed",
        "engine": f"capa {CAPA_VERSION}",
        "analysis": meta["analysis"],
        "capability_count": len(capabilities),
        "capabilities": capabilities,
        "detected_analysis_limitations": limitations,
        "interpretation": (
            "Static rule matches indicate possible capabilities, "
            "including legitimate functionality. They do not "
            "prove execution, malicious intent, or system damage. "
            "An empty result does not establish that "
            "capabilities are absent."
        ),
    }


def run_capa(
    file,
    expected_hash,
    python,
    source,
    folder,
    timeout=300,
):
    if not python.is_file():
        raise FileNotFoundError(
            "Create the separate capa environment first."
        )

    rules = source / "rules"
    signatures = source / "sigs"

    resources = {
        "rules": resource_hash(
            rules,
            (".yml", ".yaml"),
        ),
        "signatures": resource_hash(
            signatures,
            (".sig", ".pat", ".pat.gz"),
        ),
    }

    command = [
        str(python),
        "-m", "capa.main",
        "-j",
        "-q",
        "-f", "pe",
        "-b", "vivisect",
        "-r", str(rules),
        "-s", str(signatures),
        str(file),
    ]

    env = dict(
        os.environ,
        CAPA_SAVE_WORKSPACE="0",
    )

    stdout_path = folder / "capa.json"
    stderr_path = folder / "capa.stderr.txt"

    flags = (
        subprocess.CREATE_NO_WINDOW
        if os.name == "nt"
        else 0
    )

    with (
        stdout_path.open("wb") as stdout,
        stderr_path.open("wb") as stderr,
    ):
        process = subprocess.Popen(
            command,
            stdout=stdout,
            stderr=stderr,
            env=env,
            cwd=str(python.parent),
            creationflags=flags,
        )

        try:
            code = process.wait(timeout=timeout)

        except (
            subprocess.TimeoutExpired,
            KeyboardInterrupt,
        ):
            if os.name == "nt":
                subprocess.run(
                    [
                        "taskkill",
                        "/PID", str(process.pid),
                        "/T",
                        "/F",
                    ],
                    capture_output=True,
                    creationflags=flags,
                )
            else:
                process.kill()

            process.wait(timeout=15)
            raise

    if code != 0:
        raise RuntimeError(
            f"capa exited with code {code}; "
            f"see {stderr_path}"
        )

    if stdout_path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError(
            "capa output exceeds this prototype's "
            "128 MiB limit."
        )

    document = json.loads(
        stdout_path.read_text(encoding="utf-8-sig")
    )

    result = summarize_capa(document, expected_hash)

    result["resources"] = resources
    result["raw_output"] = str(stdout_path)
    result["raw_output_sha256"] = sha256(stdout_path)
    result["diagnostics_file"] = str(stderr_path)
    result["diagnostics_excerpt"] = (
        stderr_path.read_text(
            encoding="utf-8",
            errors="replace",
        )[-4000:]
    )

    return result


def readable_report(report):
    primary = (
        report["classification"]
        ["model_results"]["primary"]
    )
    evidence = report["static_evidence"]
    capa = report["capability_analysis"]

    lines = [
        "MLWINT Intelligence Report",
        f"File: {json.dumps(report['file']['filename'])}",
        f"SHA256: {report['file']['sha256']}",
        "Primary model: EMBER2024 XGBoost",
        f"Prediction: {primary['prediction']}",
        (
            "Malicious-class score: "
            f"{primary['malicious_score']:.6f}"
        ),
        (
            "Threshold: "
            f"{report['classification']['threshold']}"
        ),
        "The score is not a verified probability of harm.",
        "",
        (
            f"Static observations: {evidence['pe_format']}, "
            f"{evidence['section_count']} sections, "
            f"{evidence['imported_library_count']} "
            "imported libraries."
        ),
        "",
        f"Capability analysis: {capa['status']}",
    ]

    if capa["status"] == "completed":
        lines.append(
            f"Matched capabilities: {capa['capability_count']}"
        )

        for finding in capa["capabilities"]:
            lines.append(
                f"- {json.dumps(finding['rule_name'])}"
            )

            locations = ", ".join(
                address_text(address)
                for address
                in finding["match_locations"][:3]
            )

            lines.append(
                f"  Match locations: {locations}"
            )

            for item in finding["evidence_examples"][:3]:
                lines.append(
                    "  Evidence: "
                    + json.dumps(item, ensure_ascii=True)
                )

        lines.append(
            "Detected analysis limitations: "
            + json.dumps([
                item["rule_name"]
                for item
                in capa["detected_analysis_limitations"]
            ])
        )

        lines.extend([
            "",
            capa["interpretation"],
            f"Full rule evidence: {capa['raw_output']}",
        ])

    else:
        lines.append(
            "Reason: " + json.dumps(capa["error"])
        )

    lines.extend([
        "",
        (
            "System impact: not established; execution "
            "and system context were not observed."
        ),
        (
            "The classifier decision is retained "
            "independently of capability matches."
        ),
        "A predicted benign result is not proof of safety.",
    ])

    return "\n".join(lines) + "\n"


def analyze_intelligence(
    models,
    file,
    python,
    source,
    folder,
    *,
    threshold=0.5,
    compare=False,
    timeout=300,
):
    report = analyze_file(
        models,
        file,
        threshold=threshold,
        compare=compare,
    )

    try:
        report["capability_analysis"] = run_capa(
            Path(report["file"]["path"]),
            report["file"]["sha256"],
            python,
            source,
            folder,
            timeout,
        )

    except Exception as error:
        report["status"] = "partial"
        report["capability_analysis"] = {
            "status": "unavailable",
            "error_type": type(error).__name__,
            "error": str(error),
        }

    if report["capability_analysis"]["status"] == "completed":
        report["capability_assessment"] = (
            "static_rule_matches_available"
        )

        report["classification"].pop(
            "capability_assessment",
            None,
        )

        outdated_limitation = (
            "Executable capabilities and system impact "
            "have not been assessed."
        )

        for owner in (report, report["classification"]):
            owner["limitations"] = [
                text
                for text in owner["limitations"]
                if text != outdated_limitation
            ]

        report["limitations"].append(
            report["capability_analysis"]["interpretation"]
        )

    report["tool_version"] = "mlwint-intelligence-v0.1"
    report["created_utc"] = (
        datetime.now(timezone.utc).isoformat()
    )

    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--capa-python", type=Path)
    parser.add_argument("--capa-source", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout must be positive.")

    models = Ember2024Models(args.project_root)

    python = (
        args.capa_python
        or models.root
        / "experiments/capa/.venv/Scripts/python.exe"
    ).resolve()

    source = (
        args.capa_source
        or models.root / "tools/capa-source-v9.4.0"
    ).resolve()

    parent = (
        args.output_dir
        or models.root
        / "reports/ember2024/agent-v0.1/intelligence"
    ).resolve()

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S"
    )
    folder = parent / (
        f"run-{stamp}-{uuid4().hex[:8]}"
    )
    folder.mkdir(parents=True, exist_ok=False)

    print(
        "Running classification, static inspection "
        "and capa analysis...",
        flush=True,
    )

    report = analyze_intelligence(
        models,
        args.file,
        python,
        source,
        folder,
        threshold=args.threshold,
        compare=args.compare,
        timeout=args.timeout,
    )

    (folder / "report.json").write_text(
        json.dumps(
            report,
            indent=2,
            allow_nan=False,
        ) + "\n",
        encoding="utf-8",
    )

    text = readable_report(report)

    (folder / "report.txt").write_text(
        text,
        encoding="utf-8",
    )

    print(text)
    print(f"Reports: {folder}")

    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    sys.exit(main())