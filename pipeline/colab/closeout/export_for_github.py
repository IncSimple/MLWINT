"""Collects the Phase 1 results and models from Google Drive into one zip for GitHub.
Usage (any Colab runtime):  !python export_for_github.py

Writes MyDrive/MLWINT-colab/github-export-phase1.zip containing
  results/<type>/...   small reports, tables and graphs (no datasets, no per-file scores or hashes)
  results/phase1/...   the close-out report, tables, graph and the four detector cards
  release/...          the eight shipped model files + SHA256SUMS.txt (for the GitHub Release)
Every model is checked against the checksum in its detector card. Missing optional files are listed,
not fatal.
"""
import hashlib, json, zipfile
from pathlib import Path

ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
OUT = ROOT / 'github-export-phase1.zip'
TYPES = {
    'win32': ('experiments/win32-fourway-v1', dict(xgb='xgboost-extended-v1', lgbm='lightgbm-extended-v1',
                                                   svm='svm-raw-v2'), 'four-way-full-dev-v1'),
    'win64': ('experiments/win64-fourway-v1', dict(xgb='xgboost-v1', lgbm='lightgbm-v1', svm='svm-raw-v1'), 'four-way-v1'),
    'dotnet': ('experiments/dotnet-fourway-v1', dict(xgb='xgboost-v1', lgbm='lightgbm-v1', svm='svm-raw-v1'), 'four-way-v1'),
    'pdf': ('experiments/pdf-fourway-v1', dict(xgb='xgboost-v1', lgbm='lightgbm-v1', svm='svm-raw-v1'), 'four-way-v1'),
}
FOURWAY_FILES = ('report.json', 'roles.json', 'protocol.json', 'test_comparison.csv', 'development_ranking.csv',
                 'test_weekly.csv', 'overfitting_gap.csv', '{t}_four_way.png', '{t}_overfitting_gap.png')
CLOSEOUT = ROOT / 'experiments/phase1-closeout-v1'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def main():
    plan, missing = [], []

    def add(src, dest):
        (plan if src.exists() else missing).append((src, dest))

    for t, (exp, jobs, fourway) in TYPES.items():
        base = ROOT / exp
        add(base / 'leakage-audit-v1/report.json', f'results/{t}/leakage_audit.json')
        for m, job in jobs.items():
            add(base / job / 'report.json', f'results/{t}/{m}_report.json')
            add(base / job / ('tuning_curve.png' if m == 'svm' else 'learning_curve.png'), f'results/{t}/{m}_curve.png')
        for name in FOURWAY_FILES:
            name = name.format(t=t)
            add(base / fourway / name, f'results/{t}/four_way/{name}')
    retrain = ROOT / 'experiments/pdf-fourway-v1/retrain-0-51-v1'
    for name in ('report.json', 'roles.json', 'selection.json', 'protocol.json', 'test_comparison.csv',
                 'pdf_retrain_0_51.png'):
        add(retrain / name, f'results/pdf/retrain_0_51/{name}')
    for p in sorted(CLOSEOUT.glob('*')):
        if p.suffix in ('.json', '.csv', '.png'):
            add(p, f'results/phase1/{p.name}')

    # models: exactly the files named in the detector cards, checksum-verified
    sums = []
    for t in TYPES:
        card = json.loads((CLOSEOUT / f'verdict_policy_{t}.json').read_text())
        for m, v in card['models'].items():
            src = ROOT / v['file']
            if sha(src) != v['sha256']:
                raise SystemExit(f'Checksum mismatch for {src}: not exported')
            plan.append((src, f'release/{src.name}'))
            sums.append(f'{v["sha256"]}  {src.name}')

    with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
        for src, dest in plan:
            z.write(src, dest)
        z.writestr('release/SHA256SUMS.txt', '\n'.join(sums) + '\n')
    print(f'Wrote {OUT} ({OUT.stat().st_size / 1024**2:.1f} MB): {len(plan)} files, {len(sums)} models')
    if missing:
        print('Not found (skipped):')
        for src, _ in missing:
            print('  ', src.relative_to(ROOT))


if __name__ == '__main__':
    main()
