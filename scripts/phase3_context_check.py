"""Step 3.1 check of the local context checks. Save as MLWINT/scripts/phase3_context_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase3_context_check.py [files ...]

  1. what Windows lets MLWINT read without admin rights (counts per source)
  2. known-answer tests built from this PC itself: a file that IS set to start automatically, a program that IS
     running, a downloaded file that HAS a download mark, a program Windows HAS recorded as started
  3. the full context for any files you pass
Read-only. Writes reports/phase3/context-check-v1.json.
"""
import json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase3_context import ContextChecker, mark_of_the_web, norm  # noqa: E402


def first(items, test):
    return next((x for x in items if test(x)), None)


def main():
    cc = ContextChecker()
    t0 = time.time()
    auto, procs, dfn, pca, ua = cc.autostart(), cc.processes(), cc.defender(), cc.pca(), cc.userassist()
    print(f'1. Sources readable without admin rights ({time.time() - t0:.1f} s to index):')
    kinds = {}
    for a in auto:
        k = a['where'].split(' (')[0].split('\\Software')[0] if not a['where'].startswith(('HKCU', 'HKLM\\')) \
            else 'Run / RunOnce keys'
        kinds[k] = kinds.get(k, 0) + 1
    for k, n in sorted(kinds.items()):
        print(f'   autostart - {k:<40} {n}')
    print(f'   running processes with a visible path       {sum(1 for p in procs if p.get("ExecutablePath"))} of {len(procs)}')
    print(f'   Program Compatibility Assistant records      {len(pca)}')
    print(f'   UserAssist records                           {len(ua)}')
    print(f'   Microsoft Defender detections                {len(dfn)}')
    for k, v in cc.notes.items():
        print(f'   note ({k}): {v}')

    print('2. Known-answer tests from this PC:')
    tests, ok = [], True
    run_key = first(auto, lambda a: a['where'].startswith(('HKCU', 'HKLM\\')) and
                    first([w for w in a['command'].replace('"', ' "').split('"') if w.strip().lower().endswith('.exe')],
                          lambda w: Path(w.strip()).is_file()))
    if run_key:
        exe = first([w for w in run_key['command'].replace('"', ' "').split('"') if w.strip().lower().endswith('.exe')],
                    lambda w: Path(w.strip()).is_file()).strip()
        tests.append(('set to start automatically', exe, lambda c: bool(c['autostart'])))
    proc = first(procs, lambda p: p.get('ExecutablePath') and p['Name'].lower() == 'explorer.exe') or \
        first(procs, lambda p: p.get('ExecutablePath'))
    if proc:
        tests.append(('running now', proc['ExecutablePath'], lambda c: bool(c['running'])))
    marked = first(sorted(Path.home().joinpath('Downloads').glob('*')), lambda f: f.is_file() and mark_of_the_web(f))
    if marked:
        tests.append(('has a download mark', str(marked), lambda c: bool(c['origin'])))
    started = first(sorted(pca), lambda p: Path(p).is_file())
    if started:
        tests.append(('recorded as started', started, lambda c: c['ran_before']['compatibility_assistant']))
    results = []
    for what, f, check in tests:
        c = cc.check(f)
        passed = check(c)
        ok &= passed
        print(f'   {"PASS" if passed else "FAIL"}  {what:<28} {f}')
        for line in c['facts']:
            print(f'         - {line}')
        results.append(dict(test=what, file=f, passed=passed, context=c))
    if len(tests) < 3:
        print('   (some tests had no example on this PC)')

    print('3. Your files:')
    mine = []
    for f in sys.argv[1:]:
        c = cc.check(f)
        print(f'   {f}')
        for line in c['facts']:
            print(f'         - {line}')
        mine.append(c)

    out = ROOT / 'reports/phase3/context-check-v1.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    status = 'PHASE3_STEP1_CHECKED' if ok else 'PHASE3_STEP1_FAILED'
    out.write_text(json.dumps(dict(status=status, sources=dict(autostart=kinds, processes=len(procs), pca=len(pca),
                                                               userassist=len(ua), defender=len(dfn)),
                                   notes=cc.notes, tests=results, files=mine), indent=1, default=str), encoding='utf-8')
    print(f'\n{status}: {out}')


if __name__ == '__main__':
    main()