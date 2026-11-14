"""Step 3.4 check of the advice engine. Save as MLWINT/scripts/phase3_advice_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase3_advice_check.py [analysis-....json]

  1. scenario self-test: ten made-up situations (clean file, phishing-style PDF, PDF with JavaScript, signed
     installer with a PUA tag, malware never run, malware running + autostart + stealer, ransomware that ran, ...)
     must get the expected actions - and must NOT get the wrong ones (no password advice for a file never run,
     no "delete" for a clean file, "disconnect" always first when something is running)
  2. your newest analysis report (or the one you name): advice for every file, with counts per headline
Read-only. Writes reports/phase3/advice-check-v1.json.
"""
import json, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase3_advice import advise, advice_text  # noqa: E402


def result(level, verdict='MALICIOUS', fmt='Win32', tags=(), attack=(), ctx=None, pdf_active=None, signer=None,
           evidence_points=0.0, deep=None):
    return dict(status='assessed', path=f'C:\\test\\{level.lower()}.{"pdf" if fmt == "PDF" else "exe"}',
                level=level, verdict=verdict, format=fmt, score=0,
                behaviours=[dict(tag=t, tier='strong') for t in tags], attack=[dict(id=a) for a in attack],
                parts=[dict(part='evidence', points=evidence_points)], pdf_active_content=pdf_active,
                signature=dict(status='Valid', signer=f'CN={signer}') if signer else dict(status='NotSigned'),
                deep_check=deep or {}, local_context=ctx)


def context(running=False, autostart=False, ran=False, site='example-downloads.test'):
    return dict(origin=dict(zone=3, zone_name='the Internet', site=site) if site else None,
                running=[dict(pid=4242, name='bad.exe')] if running else [],
                autostart=[dict(where='HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name='Updater',
                                command='C:\\test\\bad.exe')] if autostart else [],
                ran_before=dict(compatibility_assistant=ran, userassist=None), defender=[])


SCENARIOS = [  # (name, result, must have action ids, must NOT have, first action id or None)
    ('clean signed program', result('LOW', 'CLEAN', signer='Valve Corp.', ctx=context()), set(),
     {'delete_file', 'do_not_run', 'offline_scan', 'change_passwords'}, None),
    ('phishing-style PDF, nothing active', result('GUARDED', 'MALICIOUS', 'PDF', pdf_active=[], ctx=context()),
     {'pdf_links'}, {'delete_file', 'do_not_run', 'offline_scan', 'pdf_js'}, 'pdf_links'),
    ('PDF with JavaScript, HIGH', result('HIGH', 'MALICIOUS', 'PDF', pdf_active=['/JS'], ctx=context()),
     {'pdf_js', 'delete_file'}, {'pdf_links', 'change_passwords'}, 'pdf_js'),
    ('signed installer tagged PUA (GUARDED)', result('GUARDED', 'SUSPICIOUS', tags=['pua'], signer='BitTorrent Inc',
                                                     ctx=context(ran=True)),
     {'trust_source', 'custom_install'}, {'offline_scan', 'change_passwords', 'disconnect'}, None),
    ('HIGH program, never run', result('HIGH', tags=['stealer'], evidence_points=6, ctx=context()),
     {'do_not_run', 'delete_file'}, {'change_passwords', 'disconnect', 'offline_scan'}, 'do_not_run'),
    ('SEVERE stealer running + autostart', result('SEVERE', tags=['stealer', 'backdoor'], attack=['T1055'],
                                                  ctx=context(running=True, autostart=True, ran=True)),
     {'disconnect', 'end_process', 'remove_startup', 'offline_scan', 'change_passwords', 'consider_reset'},
     {'do_not_run'}, 'disconnect'),
    ('ransomware that ran', result('HIGH', tags=['ransom'], attack=['T1486'], ctx=context(ran=True)),
     {'protect_backups', 'offline_scan'}, {'do_not_run', 'change_passwords'}, 'protect_backups'),
    ('worm that ran', result('ELEVATED', tags=['worm'], ctx=context(ran=True)),
     {'offline_scan', 'scan_other_devices'}, {'change_passwords', 'do_not_run'}, None),
    ('HIGH program, context not checked', result('HIGH', tags=['spyware'], ctx=None),
     {'do_not_run', 'offline_scan', 'delete_file', 'change_passwords'}, {'disconnect'}, 'do_not_run'),
    ('adware that ran', result('ELEVATED', 'SUSPICIOUS', tags=['adware'], ctx=context(ran=True)),
     {'uninstall', 'offline_scan'}, {'change_passwords'}, None),
]


def main():
    print('1. Scenario self-test:')
    ok, out = True, []
    for name, r, must, must_not, first in SCENARIOS:
        adv = advise(r)
        ids = [a['id'] for a in adv['actions']]
        missing, wrong = must - set(ids), must_not & set(ids)
        first_ok = first is None or (ids and ids[0] == first)
        passed = not missing and not wrong and first_ok
        ok &= passed
        print(f'   {"PASS" if passed else "FAIL"}  {name:<40} -> {adv["headline"]}')
        if not passed:
            print(f'         actions {ids}; missing {sorted(missing)}; should not have {sorted(wrong)}; '
                  f'first ok {first_ok}')
        out.append(dict(scenario=name, passed=passed, advice=adv))
    print('\n   example (running stealer):')
    print(advice_text(advise(SCENARIOS[5][1])))

    reports = sorted((ROOT / 'reports/analyse').glob('analysis-*.json'))
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else (reports[-1] if reports else None)
    real = []
    if path:
        print(f'\n2. Advice for your report {path.name}:')
        heads = Counter()
        for r in json.loads(path.read_text(encoding='utf-8')).get('results', []):
            adv = advise(r)
            heads[(r.get('level', '-'), adv['headline'])] += 1
            real.append(dict(file=r.get('path'), level=r.get('level'), advice=adv))
        for (lvl, h), n in sorted(heads.items(), key=lambda kv: -kv[1]):
            print(f'   {n:>4}  {lvl:<8} {h}')
        urgent_low = [x['file'] for x in real if x['level'] == 'LOW' and any(a['priority'] == 1 for a in
                                                                             x['advice']['actions'])]
        print(f'   LOW files with an urgent action: {len(urgent_low)} (must be 0)')
        ok &= not urgent_low
    status = 'PHASE3_STEP4_CHECKED' if ok else 'PHASE3_STEP4_FAILED'
    dest = ROOT / 'reports/phase3/advice-check-v1.json'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(dict(status=status, scenarios=out, report=str(path), files=real), indent=1,
                               default=str), encoding='utf-8')
    print(f'\n{status}: {dest}')


if __name__ == '__main__':
    main()