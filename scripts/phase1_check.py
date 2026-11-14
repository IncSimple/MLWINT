"""Step 2.0 check of the Phase 1 detectors on the PC. Save as MLWINT/scripts/phase1_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase1_check.py

  1. bundle  : every file's SHA-256 matches the bundle manifest
  2. parity  : for each format, 300 saved test vectors are scored on the PC and compared with the probability
               Colab computed (must agree to ~1e-6), and their verdicts must match
  3. real files: scans Windows system files that are certainly clean (signed Microsoft programs and .NET
               libraries) plus any PDFs in a folder you pass with --pdf-folder; reports verdicts per format
Read-only: files are only read. Writes reports/phase2/scanner-check-v1.json.
"""
import argparse, json, sys, time
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase1_detectors import Phase1Detectors  # noqa: E402

SYSTEM_SETS = [  # (folder, patterns, how many)
    (Path(r'C:\Windows\System32'), ('*.exe',), 150),
    (Path(r'C:\Windows\System32'), ('*.dll',), 150),
    (Path(r'C:\Windows\SysWOW64'), ('*.exe', '*.dll'), 150),
    (Path(r'C:\Windows\Microsoft.NET\Framework64'), ('**/*.dll',), 150),
]


def pick(folder, patterns, n):
    files = []
    for p in patterns:
        try:
            files += [f for f in folder.glob(p) if f.is_file()]
        except OSError:
            pass
    files = sorted(set(files))
    step = max(1, len(files) // n)
    return files[::step][:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', default=None, help='default: MLWINT/models/phase1')
    ap.add_argument('--pdf-folder', default=None, help='optional folder with PDFs you know are clean')
    a = ap.parse_args()

    print('1. Verifying the bundle ...', flush=True)
    det = Phase1Detectors(a.bundle)
    print(f'   OK: {len(det.manifest["files"])} files, formats {", ".join(det.manifest["formats"])}', flush=True)

    print('2. Parity with Colab (saved test vectors) ...', flush=True)
    parity = {}
    for key in det.cards:
        with np.load(det.dir / f'parity/{key}.npz') as z:
            X, expected = z['X'], z['ensemble_probability']
        got = det.probability(key, X)
        diff = float(np.max(np.abs(got - expected)))
        same = int(sum(det.verdict(key, g) == det.verdict(key, e) for g, e in zip(got, expected)))
        parity[key] = dict(vectors=len(X), max_abs_difference=diff, same_verdict=same,
                           ok=bool(diff < 1e-5 and same == len(X)))
        print(f'   {det.cards[key]["format"]:6s} max difference {diff:.2e}; same verdict {same}/{len(X)} '
              f'{"OK" if parity[key]["ok"] else "MISMATCH"}', flush=True)

    print('3. Scanning clean Windows system files (read-only) ...', flush=True)
    targets = [f for folder, pats, n in SYSTEM_SETS for f in pick(folder, pats, n)]
    if a.pdf_folder:
        targets += pick(Path(a.pdf_folder), ('**/*.pdf',), 200)
    results, t0 = [], time.time()
    for i, f in enumerate(targets, 1):
        results.append(det.scan_file(f))
        if i % 100 == 0:
            print(f'   {i}/{len(targets)} files; {time.time() - t0:.0f} s', flush=True)
    by = Counter((r.get('format', '-'), r.get('verdict', r['status'])) for r in results)
    print('\n   format  verdict      files')
    for (fmt, v), n in sorted(by.items()):
        print(f'   {fmt:6s}  {v:11s} {n}')
    flagged = sorted((r for r in results if r.get('verdict') in ('MALICIOUS', 'SUSPICIOUS')),
                     key=lambda r: -r['probability'])
    if flagged:
        print('\n   Flagged system files (expected to be rare; these are likely false alarms):')
        for r in flagged[:15]:
            print(f'   {r["verdict"]:10s} {r["probability"]:.3f}  {r["format"]:6s} {r["path"]}')
    scanned = [r for r in results if r['status'] == 'scanned']
    report = dict(status='PHASE2_STEP0_CHECKED' if all(p['ok'] for p in parity.values()) else 'PARITY_MISMATCH',
                  parity=parity, files_tried=len(results), files_scanned=len(scanned),
                  verdicts={f'{k[0]} {k[1]}': n for k, n in sorted(by.items())},
                  flagged=[{k: r[k] for k in ('path', 'format', 'probability', 'verdict')} for r in flagged],
                  seconds_per_file=round((time.time() - t0) / max(1, len(results)), 3),
                  note='System files are assumed clean; any MALICIOUS/SUSPICIOUS among them is a false alarm.')
    out = ROOT / 'reports/phase2/scanner-check-v1.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f'\n{report["status"]}: {len(scanned)} files scanned, {report["seconds_per_file"]} s per file. Report: {out}')


if __name__ == '__main__':
    main()