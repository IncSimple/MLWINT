"""Step 2.3 check of the threat meter on the PC. Save as MLWINT/scripts/phase2_meter_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase2_meter_check.py [more files ...]

  1. bundle : every file of models/phase2 matches its SHA-256
  2. parity : 100 dev malware vectors per format; family and every enabled behaviour model must give the same
              probabilities as Colab (difference < 1e-5)
  3. tiers  : the reliability tier of every tag and family, from the sealed test
  4. meter  : notepad.exe, a .NET library and any files you pass, with capa / PDF evidence (~20 s per program)
Read-only. Writes reports/phase2/meter-check-v1.json.
"""
import argparse, json, sys, time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase2_evidence import evidence_for_file          # noqa: E402
from src.detection.phase2_meter import ThreatMeter, explain, tier, FAMILY_MIN_TEST_PRECISION  # noqa: E402

DEFAULT_FILES = [Path(r'C:\Windows\System32\notepad.exe'),
                 Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Web.Mobile.dll')]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='*', type=Path)
    ap.add_argument('--no-evidence', action='store_true', help='skip capa (faster)')
    a = ap.parse_args()

    print('1. Verifying both bundles ...', flush=True)
    meter = ThreatMeter()
    cl = meter.classifiers
    print(f'   OK: phase2 {len(cl.manifest["files"])} files, formats {", ".join(cl.cards)}', flush=True)

    print('2. Parity with Colab ...', flush=True)
    parity, worst = {}, 0.0
    for key, card in cl.cards.items():
        with np.load(cl.dir / f'parity/{key}.npz') as z:
            X, saved = z['X'], {k: z[k] for k in z.files if k != 'X'}
        diffs = {}
        for name, expected in saved.items():
            got = cl.family_probabilities(key, X) if name == 'family' else cl.tag_probability(key, name[4:], X)
            diffs[name] = float(np.max(np.abs(got - expected)))
        parity[key] = dict(vectors=len(X), models=len(diffs), max_abs_difference=max(diffs.values()))
        worst = max(worst, parity[key]['max_abs_difference'])
        print(f'   {key:<7} {len(diffs):>2} models x {len(X)} vectors: max difference '
              f'{parity[key]["max_abs_difference"]:.1e}', flush=True)
    if worst > 1e-5:
        sys.exit('   PARITY FAILED - stop and paste this output')

    print('3. Reliability tiers from the sealed test ...', flush=True)
    tiers = {}
    for key, card in cl.cards.items():
        rep = cl.reports[key]
        fp = rep.get('family', {}).get('precision_when_named')
        groups = {}
        for tag, v in card['behaviour'].items():
            if v.get('model'):
                groups.setdefault(tier(rep['behaviour'][tag]['precision'])[0], []).append(tag)
        tiers[key] = dict(family='shown' if fp is not None and fp >= FAMILY_MIN_TEST_PRECISION else 'hidden',
                          family_test_precision=fp, **groups)
        print(f'   {key:<7} family {tiers[key]["family"]} ({fp:.1%}) | ' + ' | '.join(
            f'{g}: {", ".join(groups[g])}' for g in ('strong', 'normal', 'hint', 'hidden') if g in groups), flush=True)

    print('4. Meter on real files ...', flush=True)
    results = []
    for f in DEFAULT_FILES + a.files:
        t0 = time.time()
        ev = None if a.no_evidence else evidence_for_file(f)
        r = meter.assess(f, evidence=ev)
        r['seconds'] = round(time.time() - t0, 1)
        results.append(r)
        print(explain(r), f'\n  ({r["seconds"]} s)\n', flush=True)

    report = dict(status='PHASE2_STEP3_CHECKED', parity=parity, tiers=tiers,
                  files=[{k: v for k, v in r.items() if k != 'signature'} | dict(signature=r.get('signature'))
                         for r in results])
    out = ROOT / 'reports/phase2/meter-check-v1.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1, default=str))
    print(f'PHASE2_STEP3_CHECKED: {out}')


if __name__ == '__main__':
    main()