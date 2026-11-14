"""Check of the scan memory, the large-file check and the whole-PC search. Save as MLWINT/scripts/memory_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/memory_check.py
Uses copies of Windows' own notepad.exe in a temp folder and a TEMPORARY memory file (your real memory in
reports/memory/ is not touched). Checks:
  memory   1 first scan analyses   2 second scan reuses (same score, much faster)   3 a copy elsewhere is checked
           again   4 a new modified date is checked again   5 a re-download (same name, new contents) is checked
           again   6 --fresh analyses again   7 a deeper scan than before analyses again   8 an MLWINT update
           (models / rules) analyses again
  large    9 a 'large' file is skipped without the option   10 checked with the option (signature, report-only
           Defender scan, half-weight detector)   11 Defender's answers are read correctly (clean / detected / missing)
  whole PC 12 fixed drives found   13 the folder walk skips excluded folders, the Recycle Bin and junction loops
Writes reports/memory/memory-check-v1.json.
"""
import json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT))
import mlwint_analyse as cli  # noqa: E402
import src.detection.large_files as lf  # noqa: E402
import src.detection.phase2_meter as pm  # noqa: E402
from src.detection.scan_memory import ScanMemory, file_stamp  # noqa: E402

QUICK = dict(evidence='none', deep='none', context='none', reputation='off', large=False, fresh=False)


def main():
    checks = []
    notepad = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'notepad.exe'
    print('Loading models ...', flush=True)
    tools = cli.load_tools(say=lambda s: None)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        tools['memory'] = mem = ScanMemory(path=tmp / 'memory.json')
        a = tmp / 'downloads' / 'setup.exe'
        a.parent.mkdir()
        shutil.copy2(notepad, a)

        def run(path, **opt):
            mem.reset_stats()
            t = time.time()
            r = cli.analyse_one(tools, path, dict(QUICK, **opt))
            cli.save_memory(tools)
            return r, time.time() - t, dict(mem.stats)

        r1, t1, s1 = run(a)
        checks.append(('1 first scan analyses the file', r1.get('status') == 'assessed' and not r1.get('remembered')
                       and s1['new'] == 1, f'score {r1.get("score")}, {t1:.1f} s'))
        r2, t2, s2 = run(a)
        checks.append(('2 unchanged file: earlier result reused', bool(r2.get('remembered')) and s2['reused'] == 1
                       and (r2['score'], r2['level']) == (r1['score'], r1['level']),
                       f'{t2:.2f} s instead of {t1:.1f} s, score {r2.get("score")}'))
        b = tmp / 'elsewhere' / 'setup.exe'
        b.parent.mkdir()
        shutil.copy(a, b)
        r3, _, s3 = run(b)
        checks.append(('3 same contents in a new place: checked again', not r3.get('remembered') and s3['changed'] == 1,
                       'first time at this place'))
        os.utime(a, (time.time(), time.time() + 60))
        r4, _, s4 = run(a)
        checks.append(('4 new modified date: checked again', not r4.get('remembered') and s4['changed'] == 1,
                       'size or date changed'))
        a.unlink()
        data = bytearray(notepad.read_bytes())
        data[-64:] = os.urandom(64)                               # same name, different contents (a "re-download")
        a.write_bytes(bytes(data))
        r5, _, s5 = run(a)
        checks.append(('5 re-download, same name, new contents: checked', not r5.get('remembered') and s5['new'] == 1,
                       f'new fingerprint {r5.get("sha256", "")[:12]}...'))
        r6, _, s6 = run(a, fresh=True)
        checks.append(('6 full re-check ignores the memory', not r6.get('remembered') and s6['reused'] == 0, ''))
        r7, _, s7 = run(a, evidence='all')
        checks.append(('7 deeper scan than before: checked again', not r7.get('remembered') and s7['deeper'] == 1,
                       'evidence none -> all'))
        mem2 = ScanMemory(path=tmp / 'memory.json', engine='different-models')
        got, why = mem2.recall(a.resolve(), r5['sha256'], file_stamp(a), QUICK)
        checks.append(('8 MLWINT updated: memory not used', got is None and 'changed' in why, why))

        # ---- large files (for this test only, the 256 MB limit is lowered to just above notepad's size, and the
        #      'large installer' is notepad with 200 KB of padding at the end)
        big = tmp / 'big' / 'installer.exe'
        big.parent.mkdir()
        big.write_bytes(notepad.read_bytes() + bytes(200_000))
        old_cli, old_pm = cli.MAX_BYTES, pm.MAX_BYTES
        cli.MAX_BYTES = pm.MAX_BYTES = notepad.stat().st_size + 1000
        try:
            r9, _, _ = run(big)
            checks.append(('9 large file without the option: skipped, with a hint', r9.get('status') == 'skipped'
                           and 'Include large files' in r9.get('reason', ''), r9.get('reason', '')[:60]))
            r10, t10, _ = run(big, large=True, fresh=True)
            parts = {p['part']: p for p in r10.get('parts', [])}
            checks.append(('10 large-file check: signature + Defender + half detector', r10.get('large_file') is True
                           and 'defender scan' in parts and 'half weight' in parts['detector']['reason']
                           and r10.get('defender_scan', {}).get('status') in ('clean', 'failed'),
                           f'Defender: {r10.get("defender_scan", {}).get("status")}, score {r10.get("score")}, '
                           f'{t10:.1f} s'))
            order, _ = cli.candidates([str(big.parent), str(a.parent)], False, 100)
            checks.append(('   large files are checked last', order[-1].name == 'installer.exe',
                           ' -> '.join(f.name for f in order)))
        finally:
            cli.MAX_BYTES, pm.MAX_BYTES = old_cli, old_pm

        real_run = subprocess.run
        answers = {'clean': (0, 'Scan starting...\nScan finished.\nScanning x found no threats.\n'),
                   'detected': (2, 'Scan starting...\nScan finished.\nScanning x found 1 threats.\n'
                                   'Threat                  : Trojan:Win32/Example\nResources               : 1 total\n')}
        seen = {}
        for want, (code, text) in answers.items():
            subprocess.run = lambda *x, **k: subprocess.CompletedProcess(x, code, stdout=text, stderr='')
            seen[want] = lf.defender_scan(notepad)
        subprocess.run = real_run
        exe = lf.mpcmdrun
        lf.mpcmdrun = lambda: None
        seen['missing'] = lf.defender_scan(notepad)
        lf.mpcmdrun = exe
        checks.append(('11 Defender answers read correctly', seen['clean']['status'] == 'clean'
                       and seen['detected']['threats'] == ['Trojan:Win32/Example']
                       and seen['missing']['status'] == 'failed',
                       f'scanner: {lf.mpcmdrun()}'))

        # ---- whole PC
        roots = cli.whole_pc_roots()
        checks.append(('12 fixed drives found', bool(roots) and all(r.endswith(':\\') for r in roots), ', '.join(roots)))
        t = tmp / 'pc'
        for d in ('Users/me/Downloads', 'Windows/System32', '$Recycle.Bin/S-1', 'Data'):
            (t / d).mkdir(parents=True)
        for d in ('Users/me/Downloads', 'Windows/System32', '$Recycle.Bin/S-1', 'Data'):
            shutil.copy(notepad, t / d / 'p.exe')
        junction = subprocess.run(['cmd', '/c', 'mklink', '/J', str(t / 'Data' / 'loop'), str(t)],
                                  capture_output=True, text=True).returncode == 0
        excludes = [os.path.normcase(str(t / 'Windows'))]
        found, _ = cli.candidates([str(t)], True, 100, excludes=excludes)
        rel = sorted(str(f.relative_to(t)).replace('\\', '/') for f in found)
        checks.append(('13 walk skips Windows, Recycle Bin and junction loops',
                       rel == ['Data/p.exe', 'Users/me/Downloads/p.exe'],
                       f'{rel} (junction test {"on" if junction else "skipped"})'))
        if junction:
            os.rmdir(t / 'Data' / 'loop')                             # removes only the link, not its target

    ok = True
    for name, passed, detail in checks:
        ok &= bool(passed)
        print(f'{"PASS" if passed else "FAIL"}  {name:<58} {str(detail)[:90]}')
    status = 'MEMORY_CHECKED' if ok else 'MEMORY_FAILED'
    out = ROOT / 'reports/memory/memory-check-v1.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(status=status, checks=[dict(name=n, passed=bool(p), detail=str(d))
                                                          for n, p, d in checks]), indent=1), encoding='utf-8')
    print(f'\n{status}: {out}')


if __name__ == '__main__':
    main()