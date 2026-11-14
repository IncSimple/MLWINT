"""Step 3.2 check of the offline ATT&CK knowledge. Save as MLWINT/scripts/phase3_attack_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase3_attack_check.py [T1055 T1027 ...]

  1. loads data/attack/enterprise-attack.json, prints its ATT&CK version and SHA-256, builds the index
  2. known answers: five techniques must have their official names
  3. every technique id MLWINT's own rules can report (emulation + PDF check) must be explained
  4. every technique id in your saved analysis reports (capa / emulation) is looked up: found / replaced / missing
Read-only (writes only the index next to the data and reports/phase3/attack-check-v1.json).
"""
import json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase3_attack import AttackKnowledge  # noqa: E402
from src.detection.phase2_evidence import PDF_INDICATORS  # noqa: E402

KNOWN = {'T1055': 'Process Injection', 'T1547.001': 'Registry Run Keys / Startup Folder', 'T1059.001': 'PowerShell',
         'T1486': 'Data Encrypted for Impact', 'T1105': 'Ingress Tool Transfer'}
EMULATION_IDS = ['T1105', 'T1071', 'T1055', 'T1547.001', 'T1543.003', 'T1106', 'T1059.001', 'T1059.003', 'T1053.005',
                 'T1490', 'T1486', 'T1555', 'T1056.001', 'T1113', 'T1027', 'T1622', 'T1134']


def main():
    t0 = time.time()
    kb = AttackKnowledge()
    idx = kb.index
    print(f'1. ATT&CK Enterprise v{kb.version}  (sha256 {kb.sha256[:16]}..., loaded in {time.time() - t0:.1f} s)')
    tech = idx['techniques']
    subs = sum('.' in t for t in tech)
    mitig = len({m['id'] for t in tech.values() for m in t['mitigations']})
    print(f'   {len(tech) - subs} techniques, {subs} sub-techniques, {mitig} mitigations, {len(idx["tactics"])} tactics, '
          f'{len(idx["revoked_by"])} revoked ids')
    t1 = time.time()
    AttackKnowledge()
    print(f'   second load from the index: {time.time() - t1:.2f} s')

    ok = True
    print('2. Known answers:')
    for tid, name in KNOWN.items():
        e = kb.explain(tid)
        good = e['found'] and e['name'] == name
        ok &= good
        print(f'   {"PASS" if good else "FAIL"}  {tid} -> {e.get("name")}  ({len(e.get("mitigations", []))} mitigations)')

    print('3. Techniques MLWINT itself can report:')
    own = sorted(set(EMULATION_IDS) | {v[2] for v in PDF_INDICATORS.values()})
    missing = [t for t in own if not kb.explain(t)['found']]
    ok &= not missing
    print(f'   {len(own) - len(missing)} of {len(own)} explained' + (f'; MISSING: {missing}' if missing else ''))

    print('4. Techniques in your saved analysis reports:')
    seen = {}
    for rep in sorted((ROOT / 'reports/analyse').glob('analysis-*.json')):
        for r in json.loads(rep.read_text(encoding='utf-8')).get('results', []):
            for t in r.get('attack', []):
                seen[t['id']] = seen.get(t['id'], 0) + 1
    found = {t: kb.explain(t) for t in sorted(seen)}
    replaced = [t for t, e in found.items() if e['found'] and e.get('note')]
    absent = [t for t, e in found.items() if not e['found']]
    print(f'   {len(seen)} different ids: {len(seen) - len(absent)} explained '
          f'({len(replaced)} via a replacement / parent), {len(absent)} not in ATT&CK')
    for t in replaced + absent:
        print(f'     {t}: {found[t].get("note")}')

    print('5. Examples:')
    for tid in sys.argv[1:] or ['T1055', 'T1547.001', 'T1027']:
        print('   ' + kb.short(tid))

    status = 'PHASE3_STEP2_CHECKED' if ok else 'PHASE3_STEP2_FAILED'
    out = ROOT / 'reports/phase3/attack-check-v1.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(status=status, attack_version=kb.version, sha256=kb.sha256, own_ids=own,
                                   own_missing=missing, report_ids=seen, report_missing=absent,
                                   report_replaced=replaced), indent=1), encoding='utf-8')
    print(f'\n{status}: {out}')


if __name__ == '__main__':
    main()