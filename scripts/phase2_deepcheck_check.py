"""Step 2.4 check of the emulation deep check. Save as MLWINT/scripts/phase2_deepcheck_check.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/phase2_deepcheck_check.py [more files ...]

  1. rules self-test : a made-up emulation report (autostart key, injection, PowerShell, download, keylogger,
                       ransomware-like writes) must give the expected findings; a quiet report must give none
  2. real files      : 64-bit and 32-bit Windows programs are emulated (Speakeasy), a .NET library must come back
                       'not applicable'; each result is added to the threat meter
Read-only (programs are emulated, never run). Writes reports/phase2/deepcheck-check-v1.json.
"""
import argparse, json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase2_deepcheck import (collect, findings_from, coverage, deep_check, needs_deep_check,  # noqa: E402
                                            add_to_meter)
from src.detection.phase2_meter import ThreatMeter, explain  # noqa: E402

DEFAULT_FILES = [Path(r'C:\Windows\System32\whoami.exe'), Path(r'C:\Windows\SysWOW64\whoami.exe'),
                 Path(r'C:\Windows\System32\notepad.exe'),
                 Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Web.Mobile.dll')]

SYNTHETIC = {'sha256': '0' * 64, 'entry_points': [{
    'ep_type': 'module_entry', 'error': {},
    'apis': [{'api_name': 'ADVAPI32.RegOpenKeyExW', 'args': ['HKEY_CURRENT_USER',
                                                              'Software\\Microsoft\\Windows\\CurrentVersion\\Run']},
             {'api_name': 'ADVAPI32.RegSetValueExW', 'args': ['0x80', 'updater', '0x0', 'REG_SZ']},
             {'api_name': 'KERNEL32.WriteProcessMemory', 'args': []},
             {'api_name': 'KERNEL32.CreateRemoteThread', 'args': []},
             {'api_name': 'URLMON.URLDownloadToFileA', 'args': ['0x0', 'http://203.0.113.5/p.exe', 'C:\\t\\p.exe']},
             {'api_name': 'USER32.SetWindowsHookExA', 'args': ['0xd']},
             {'api_name': 'ADVAPI32.CryptEncrypt', 'args': []},
             {'api_name': 'KERNEL32.IsDebuggerPresent', 'args': []}],
    'process_events': [{'event': 'create', 'cmdline': 'powershell -nop -w hidden -c x'}],
    'file_access': [{'event': 'write', 'path': f'C:\\Users\\u\\Documents\\f{i}.docx'} for i in range(12)]
                   + [{'event': 'create', 'path': 'C:\\Users\\u\\AppData\\Roaming\\upd.exe'}],
    'registry_access': [{'event': 'open_key', 'path': 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'}],
    'network_events': {'dns': [{'query': 'bad.example'}], 'traffic': []},
    'dynamic_code_segments': [{'tag': 'x'}]}]}
EXPECTED = {'T1547.001', 'T1055', 'T1105', 'T1071', 'T1059.001', 'T1056.001', 'T1486', 'T1027', 'T1622'}
QUIET = {'sha256': '0' * 64, 'entry_points': [{'ep_type': 'module_entry', 'error': {}, 'apis': [
    {'api_name': 'KERNEL32.GetSystemTimeAsFileTime', 'args': []}, {'api_name': 'KERNEL32.GetCurrentProcessId', 'args': []},
    {'api_name': 'ADVAPI32.RegOpenKeyExA', 'args': ['HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion']},
    {'api_name': 'ADVAPI32.RegQueryValueExA', 'args': ['0x80', 'ProductName']}]}]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='*', type=Path)
    a = ap.parse_args()

    print('1. Rules self-test ...', flush=True)
    found = findings_from(collect(SYNTHETIC))
    got = {t['id'] for f in found for t in f['attack']}
    for f in found:
        print(f'   weight {f["weight"]}  {f["title"]}  {[t["id"] for t in f["attack"]]}')
    quiet = findings_from(collect(QUIET))
    ok = EXPECTED <= got and not quiet and coverage(collect(QUIET))['level'] == 'complete'
    print(f'   expected techniques found: {sorted(EXPECTED & got)}; missing: {sorted(EXPECTED - got) or "none"}; '
          f'quiet report findings: {len(quiet)}')
    if not ok:
        sys.exit('   SELF-TEST FAILED - stop and paste this output')

    print('2. Real files (emulated) ...', flush=True)
    meter = ThreatMeter(verify=False)
    results = []
    for f in DEFAULT_FILES + a.files:
        t0 = time.time()
        m = meter.assess(f)
        want, why = needs_deep_check(m)
        d = deep_check(f)
        r = add_to_meter(m, d) if m.get('status') == 'assessed' else m
        print('\n' + explain(r))
        print(f'  deep check normally run for this file: {"YES" if want else "no"} ({why})')
        for x in d.get('findings', []):
            print(f'    emulation finding (weight {x["weight"]}): {x["title"]} - {x["detail"][:120]}')
        print(f'  ({time.time() - t0:.1f} s)', flush=True)
        results.append(dict(file=str(f), needs_deep_check=want, why=why, deep_check=d,
                            score=r.get('score'), level=r.get('level')))

    out = ROOT / 'reports/phase2/deepcheck-check-v1.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(status='PHASE2_STEP4_CHECKED', self_test=sorted(got), files=results), indent=1,
                              default=str))
    print(f'\nPHASE2_STEP4_CHECKED: {out}')


if __name__ == '__main__':
    main()