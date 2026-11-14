"""Step 2.1 check: verdict + evidence for a few files. Save as MLWINT/scripts/phase2_evidence_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase2_evidence_check.py
    (add  --file "path"  to look at your own files, and  --pdf "path"  for PDFs; files are only read)

  1. PDF self-test: a tiny made-up PDF text (never written to disk) with JavaScript, an auto-open action and a
     #xx-disguised /Launch must produce exactly those findings
  2. Each file: Phase 1 verdict + capability / ATT&CK evidence (capa takes ~20-60 s per program)
Writes reports/phase2/evidence-check-v1.json.
"""
import argparse, json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase1_detectors import Phase1Detectors  # noqa: E402
from src.detection.phase2_evidence import evidence_for_file, pdf_indicators  # noqa: E402

DEFAULT_FILES = [Path(r'C:\Windows\System32\notepad.exe'),
                 Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Web.Mobile.dll')]
SELF_TEST_PDF = (b'%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n'
                 b'2 0 obj << /S /JavaScript /JS (app.alert\\(1\\)) >> endobj\n'
                 b'3 0 obj << /S /#4c#61unch /F (calc.exe) >> endobj\n%%EOF\n')


def show(result, verdict):
    print(f'\n=== {result["path"]}')
    print(f'    Phase 1: {verdict.get("verdict", verdict["status"])} '
          f'(score {verdict.get("probability", float("nan")):.3f}, {verdict.get("format", "-")})')
    ev = result.get('evidence', {})
    if ev.get('status') != 'completed':
        print(f'    evidence: {ev.get("status", result["status"])} {ev.get("reason", result.get("reason", ""))[:200]}')
        return
    items = ev.get('capabilities') or ev.get('findings') or []
    print(f'    {len(items)} capabilities / indicators; ATT&CK tactics: '
          + (', '.join(f'{t} ({n})' for t, n in result['attack_tactics'].items()) or 'none'))
    for t in result['attack_techniques'][:12]:
        print(f'      {t["id"]:10s} {t["tactic"]:18s} {t["technique"][:45]:45s} <- {", ".join(t["evidence"][:2])}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', action='append', default=[])
    ap.add_argument('--pdf', action='append', default=[])
    a = ap.parse_args()

    print('1. PDF indicator self-test ...', flush=True)
    found = {f['indicator'] for f in pdf_indicators(SELF_TEST_PDF)['findings']}
    expected = {'/JavaScript', '/JS', '/OpenAction', '/Launch', '#xx-escaped names'}
    ok = expected <= found
    print(f'   found {sorted(found)} -> {"OK" if ok else "MISSING " + str(sorted(expected - found))}', flush=True)

    det = Phase1Detectors()
    files = [Path(f) for f in (a.file + a.pdf)] or [f for f in DEFAULT_FILES if f.is_file()]
    print(f'2. Verdict + evidence for {len(files)} file(s) ...', flush=True)
    out = []
    for f in files:
        t0 = time.time()
        verdict = det.scan_file(f)
        result = evidence_for_file(f)
        result['seconds'] = round(time.time() - t0, 1)
        show(result, verdict)
        out.append(dict(verdict={k: verdict.get(k) for k in ('status', 'format', 'probability', 'verdict')},
                        **{k: result.get(k) for k in ('path', 'sha256', 'format', 'attack_tactics', 'attack_techniques',
                                                     'seconds')},
                        evidence_status=result.get('evidence', {}).get('status', result['status']),
                        items=len(result.get('evidence', {}).get('capabilities')
                                  or result.get('evidence', {}).get('findings') or [])))
    report = dict(status='PHASE2_STEP1_CHECKED' if ok else 'PDF_SELF_TEST_FAILED', pdf_self_test=sorted(found),
                  files=out, note='Capabilities and indicators show what a file can do, not that it is malicious.')
    target = ROOT / 'reports/phase2/evidence-check-v1.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2))
    print(f'\n{report["status"]}. Report: {target}')


if __name__ == '__main__':
    main()