"""MLWINT Phase 2 step 2.4: deep check by EMULATION (read-only). Save as MLWINT/src/detection/phase2_deepcheck.py

Mandiant Speakeasy emulates a Windows program in memory: the program is NOT run on this PC. Every Windows API call
it makes is answered by the emulator, which records what the program TRIED to do: files, registry, network,
new processes, writing into other processes, code generated at run time.
Runs in its own environment (experiments/speakeasy/.venv), like capa. Nothing the program "writes" is saved to disk
(no dropped-file or memory-dump options are used).

Limits (said in every result):
  * .NET programs and PDFs cannot be emulated this way -> 'not applicable'
  * the emulator knows only part of the Windows API; many programs stop early ('unsupported API') and some malware
    detects emulators. Finding nothing therefore means "no extra evidence", never "safe".
Which files get a deep check (needs_deep_check): everything the detector flags (MALICIOUS / SUSPICIOUS), plus CLEAN
files without a valid signature that sit in Downloads / Temp / AppData / Desktop.
"""
import hashlib, json, os, subprocess
from pathlib import Path

from .phase1_detectors import detect_format

ROOT = Path(__file__).resolve().parents[2]
SPEAKEASY = ROOT / 'experiments/speakeasy/.venv/Scripts/python.exe'     # the emulator's own Python environment
ENGINE = 'Speakeasy 1.5.11 (emulation)'
MAX_POINTS = 20.0

NETWORK_APIS = {'internetopenurl', 'internetconnect', 'httpopenrequest', 'httpsendrequest', 'winhttpconnect',
                'winhttpsendrequest', 'connect', 'wsaconnect', 'gethostbyname', 'getaddrinfo', 'dnsquery_'}
DOWNLOAD_APIS = {'urldownloadtofile', 'urldownloadtocachefile'}
PROCESS_APIS = {'createprocess', 'createprocessasuser', 'createprocessinternal', 'winexec', 'shellexecute',
                'shellexecuteex'}
INJECT_APIS = {'writeprocessmemory', 'createremotethread', 'createremotethreadex', 'ntwritevirtualmemory',
               'zwwritevirtualmemory', 'queueuserapc', 'ntqueueapcthread', 'setthreadcontext', 'ntmapviewofsection',
               'zwmapviewofsection', 'rtlcreateuserthread'}
ANTI_DEBUG_APIS = {'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
                   'outputdebugstring'}
KEYLOG_APIS = {'setwindowshookex', 'getasynckeystate', 'registerrawinputdevices'}
SCREEN_APIS = {'bitblt', 'getdibits'}
CRYPT_APIS = {'cryptencrypt', 'bcryptencrypt', 'cryptgenkey', 'cryptimportkey', 'bcryptgeneratesymmetrickey'}
CRED_APIS = {'credenumerate', 'cryptunprotectdata', 'credread', 'vaultenumerateitems'}
SERVICE_APIS = {'createservice'}
REG_WRITE_APIS = {'regsetvalue', 'regsetvalueex', 'regcreatekey', 'regcreatekeyex', 'ntsetvaluekey', 'zwsetvaluekey'}
PERSIST_KEYS = ('\\currentversion\\run', '\\currentversion\\runonce', '\\winlogon', 'image file execution options',
                '\\currentversion\\policies\\explorer\\run', '\\services\\')
CRED_PATHS = ('login data', '\\cookies', 'wallet', '\\mozilla\\firefox\\profiles', 'logins.json', 'key4.db',
              'key3.db', '\\microsoft\\credentials', '\\microsoft\\protect')
EXEC_EXT = ('.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.lnk', '.hta')


def short(api_name):
    """'KERNEL32.CreateProcessA' -> 'createprocess' (module and A/W suffix removed)."""
    n = api_name.split('.')[-1]
    if len(n) > 2 and n[-1] in 'AW' and n[-2].islower():
        n = n[:-1]
    return n.lower()


def collect(report):
    """Everything the emulator saw, over all entry points (TLS callbacks, entry point, DLL exports)."""
    seen = dict(apis=[], files=[], registry=[], dns=[], traffic=[], processes=[], dynamic_code=0, errors=[])
    for ep in report.get('entry_points', []):
        seen['apis'] += [(short(a.get('api_name', '')), [str(x) for x in a.get('args') or []])
                         for a in ep.get('apis') or []]
        seen['files'] += ep.get('file_access') or []
        seen['registry'] += ep.get('registry_access') or []
        net = ep.get('network_events') or {}
        seen['dns'] += [d.get('query') for d in net.get('dns') or []]
        seen['traffic'] += net.get('traffic') or []
        seen['processes'] += ep.get('process_events') or []
        seen['dynamic_code'] += len(ep.get('dynamic_code_segments') or [])
        err = ep.get('error') or {}
        if err:
            seen['errors'].append(dict(entry=ep.get('ep_type'), type=err.get('type'), api=err.get('api_name')))
    return seen


def finding(title, weight, attack, detail):
    return dict(title=title, weight=weight, detail=detail,
                attack=[dict(id=i, technique=t, tactic=c) for i, t, c in attack])


def findings_from(seen):
    out, names = [], {n for n, _ in seen['apis']}
    args_of = lambda wanted: [' '.join(a) for n, a in seen['apis'] if n in wanted]
    servers = sorted({str(t.get('server')) for t in seen['traffic'] if t.get('server')} | set(filter(None, seen['dns'])))
    if names & DOWNLOAD_APIS:
        out.append(finding('downloads a file from the internet', 4,
                           [('T1105', 'Ingress Tool Transfer', 'Command and Control')],
                           '; '.join(args_of(DOWNLOAD_APIS))[:300]))
    if servers or names & NETWORK_APIS:
        out.append(finding('contacts the network', 3,
                           [('T1071', 'Application Layer Protocol', 'Command and Control')],
                           'servers: ' + (', '.join(servers[:10]) or 'not resolved')))
    injected = [p for p in seen['processes'] if p.get('event') in ('thread_inject', 'mem_write')]
    if injected or names & INJECT_APIS:
        out.append(finding('writes code into / starts threads in another process (process injection)', 5,
                           [('T1055', 'Process Injection', 'Defense Evasion')],
                           ', '.join(sorted(names & INJECT_APIS)) or f'{len(injected)} injection events'))
    reg_paths = [str(r.get('path', '')).lower() for r in seen['registry']]
    reg_named = ' '.join(reg_paths + [' '.join(a).lower() for n, a in seen['apis'] if n.startswith(('regopen', 'regcreate'))])
    persist = sorted({k for k in PERSIST_KEYS if k in reg_named}) if names & REG_WRITE_APIS else []
    if persist:
        out.append(finding('sets itself to start automatically (registry autostart)', 4,
                           [('T1547.001', 'Registry Run Keys / Startup Folder', 'Persistence')],
                           'keys: ' + ', '.join(persist)))
    if names & SERVICE_APIS:
        out.append(finding('installs a Windows service', 4,
                           [('T1543.003', 'Create or Modify System Process: Windows Service', 'Persistence')],
                           '; '.join(args_of(SERVICE_APIS))[:300]))
    cmdlines = [str(p.get('cmdline') or p.get('path') or '') for p in seen['processes'] if p.get('event') == 'create']
    cmdlines += args_of(PROCESS_APIS)
    if cmdlines:
        low = ' '.join(cmdlines).lower()
        attack = [('T1106', 'Native API', 'Execution')]
        title, weight = 'starts other programs', 2
        if 'powershell' in low:
            attack.append(('T1059.001', 'Command and Scripting Interpreter: PowerShell', 'Execution'))
            title, weight = 'starts PowerShell', 3
        if 'cmd.exe' in low or 'cmd /c' in low:
            attack.append(('T1059.003', 'Command and Scripting Interpreter: Windows Command Shell', 'Execution'))
            title, weight = 'starts the command shell', 3
        if 'schtasks' in low:
            attack.append(('T1053.005', 'Scheduled Task/Job: Scheduled Task', 'Persistence'))
            title, weight = 'creates a scheduled task', 4
        if 'vssadmin' in low or 'shadowcopy' in low or 'bcdedit' in low:
            attack.append(('T1490', 'Inhibit System Recovery', 'Impact'))
            title, weight = 'tries to delete backups / disable recovery', 5
        out.append(finding(title, weight, attack, '; '.join(cmdlines)[:300]))
    written = sorted({str(f.get('path')) for f in seen['files'] if f.get('event') in ('create', 'write')})
    dropped = [p for p in written if p.lower().endswith(EXEC_EXT)]
    if dropped:
        out.append(finding('writes programs or scripts to disk', 3, [], ', '.join(dropped[:8])))
    if names & CRYPT_APIS and len(written) >= 10:
        out.append(finding('encrypts data and writes many files (ransomware-like)', 5,
                           [('T1486', 'Data Encrypted for Impact', 'Impact')], f'{len(written)} files written'))
    elif len(written) >= 25:
        out.append(finding('writes to many files', 2, [], f'{len(written)} files written'))
    touched = ' '.join([str(f.get('path', '')) for f in seen['files']] + reg_paths).lower()
    creds = sorted({c for c in CRED_PATHS if c in touched})
    if creds or names & CRED_APIS:
        out.append(finding('reads saved passwords / browser data', 4,
                           [('T1555', 'Credentials from Password Stores', 'Credential Access')],
                           ', '.join(creds + sorted(names & CRED_APIS))))
    if names & KEYLOG_APIS:
        out.append(finding('watches the keyboard (keylogging)', 3,
                           [('T1056.001', 'Input Capture: Keylogging', 'Collection')], ', '.join(sorted(names & KEYLOG_APIS))))
    if names & SCREEN_APIS:
        out.append(finding('captures the screen', 2, [('T1113', 'Screen Capture', 'Collection')],
                           ', '.join(sorted(names & SCREEN_APIS))))
    if seen['dynamic_code']:
        out.append(finding('runs code it generated in memory (unpacking / hidden code)', 2,
                           [('T1027', 'Obfuscated Files or Information', 'Defense Evasion')],
                           f'{seen["dynamic_code"]} memory regions'))
    if names & ANTI_DEBUG_APIS:
        out.append(finding('checks whether it is being debugged', 1,
                           [('T1622', 'Debugger Evasion', 'Defense Evasion')], ', '.join(sorted(names & ANTI_DEBUG_APIS))))
    if 'adjusttokenprivileges' in names:
        out.append(finding('raises its own privileges', 1,
                           [('T1134', 'Access Token Manipulation', 'Privilege Escalation')], 'AdjustTokenPrivileges'))
    out.sort(key=lambda f: -f['weight'])
    return out


def coverage(seen):
    calls = len(seen['apis'])
    stops = [e for e in seen['errors'] if e['type']]
    if calls == 0:
        level = 'low'
    elif stops and calls < 15:
        level = 'low'
    elif stops:
        level = 'partial'
    else:
        level = 'complete'
    text = {'complete': f'emulation ran to the end ({calls} API calls)',
            'partial': f'emulation stopped early after {calls} API calls',
            'low': f'emulation stopped almost at once ({calls} API calls): this check saw very little'}[level]
    if stops:
        text += ' (' + '; '.join(f'{e["type"]}' + (f' at {e["api"]}' if e['api'] else '') for e in stops[:3]) + ')'
    return dict(level=level, api_calls=calls, stops=stops, text=text)


def speakeasy_config():
    """Speakeasy's default config, except that 32-bit 'decoy' modules come from an empty MLWINT folder.
    Microsoft Defender quarantines Speakeasy's own decoys/x86/default_exe.exe (a false positive); while Defender
    blocks that file, 32-bit emulation crashes. With an empty folder the emulator works without it."""
    base = SPEAKEASY.parents[1] / 'Lib/site-packages/speakeasy/configs/default.json'
    empty = SPEAKEASY.parents[2] / 'decoys-x86-empty'
    target = SPEAKEASY.parents[2] / 'mlwint-speakeasy-config.json'
    empty.mkdir(exist_ok=True)
    config = json.loads(base.read_text(encoding='utf-8'))
    config['modules']['module_directory_x86'] = str(empty)
    text = json.dumps(config, indent=1)
    if not target.is_file() or target.read_text(encoding='utf-8') != text:
        target.write_text(text, encoding='utf-8')
    return target


def run_speakeasy(path, digest, folder, timeout=60):
    if not SPEAKEASY.is_file():
        raise FileNotFoundError(f'Speakeasy environment not found: {SPEAKEASY}')
    folder.mkdir(parents=True, exist_ok=True)
    out, log = folder / 'speakeasy.json', folder / 'speakeasy.log.txt'
    out.unlink(missing_ok=True)
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    with log.open('wb') as lf:                     # only -c / -t / -o / -q: no dropped files, no memory dumps
        # run as "python -m speakeasy" (not Scripts/speakeasy.exe, whose launcher holds a fixed path to Python, so
        # the installed copy of MLWINT works in any folder)
        proc = subprocess.Popen([str(SPEAKEASY), '-m', 'speakeasy', '-c', str(speakeasy_config()), '-t', str(path),
                                 '-o', str(out), '-q', str(timeout)],
                                stdout=lf, stderr=subprocess.STDOUT, cwd=str(folder), creationflags=flags)
        try:
            proc.wait(timeout=timeout + 60)
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True, creationflags=flags)
            else:
                proc.kill()
            proc.wait(timeout=15)
            return dict(status='timeout', engine=ENGINE, reason=f'no result within {timeout + 60} s')
    if not out.is_file():
        tail = log.read_text(errors='replace').strip().splitlines()[-3:]
        return dict(status='failed', engine=ENGINE, reason=' | '.join(tail)[-400:] or 'no report written')
    report = json.loads(out.read_text(encoding='utf-8', errors='replace'))
    if str(report.get('sha256', '')).lower() != digest:
        return dict(status='failed', engine=ENGINE, reason='the emulator analysed different file contents')
    seen = collect(report)
    if not seen['apis'] and not seen['errors']:        # the emulator crashed before running anything
        lines = [l for l in log.read_text(errors='replace').splitlines() if l.strip() and 'pkg_resources' not in l]
        return dict(status='failed', engine=ENGINE, reason='emulation did not start: ' + (lines[-1][-300:] if lines
                                                                                           else 'no details'))
    found = findings_from(seen)
    techniques = sorted({a['id']: a for f in found for a in f['attack']}.values(), key=lambda a: a['id'])
    return dict(status='completed', engine=ENGINE, arch=report.get('arch'), runtime_s=report.get('emulation_total_runtime'),
                coverage=coverage(seen), findings=found, attack_techniques=techniques,
                observed=dict(servers=sorted({str(t.get('server')) for t in seen['traffic']} | set(filter(None, seen['dns']))),
                              files_written=sorted({str(f.get('path')) for f in seen['files']
                                                    if f.get('event') in ('create', 'write')})[:50],
                              registry_keys=sorted({str(r.get('path')) for r in seen['registry']})[:50],
                              processes=[p.get('cmdline') or p.get('path') for p in seen['processes']
                                         if p.get('event') == 'create'][:20]),
                raw_report=str(out))

def deep_check(path, work_dir=None, timeout=60):
    path = Path(path)
    try:
        with open(path, 'rb') as f:                                   # read-only
            data = f.read()
    except OSError as e:
        return dict(path=str(path), status='skipped', reason=f'cannot read: {e.strerror or e}')
    digest = hashlib.sha256(data).hexdigest()
    kind, reason = detect_format(data)
    if kind not in ('win32', 'win64'):
        why = {'dotnet': '.NET programs run on the .NET runtime, which the emulator does not provide',
               'pdf': 'PDFs are documents, not programs'}.get(kind, reason)
        return dict(path=str(path), sha256=digest, status='not applicable', format=kind, reason=why)
    folder = Path(work_dir or ROOT / 'reports/phase2/deepcheck') / digest[:16]
    try:
        result = run_speakeasy(path, digest, folder, timeout)
    except (OSError, ValueError) as e:
        result = dict(status='failed', engine=ENGINE, reason=f'{type(e).__name__}: {e}')
    return dict(path=str(path), sha256=digest, format=kind, **result,
                note='Emulated, not executed. Finding nothing means no extra evidence, not that the file is safe.')


def needs_deep_check(meter_result):
    """(yes/no, why) for one ThreatMeter.assess() result."""
    if meter_result.get('status') != 'assessed':
        return False, 'not assessed'
    if meter_result['format'] not in ('Win32', 'Win64'):
        return False, f'{meter_result["format"]} files cannot be emulated'
    if meter_result['verdict'] != 'CLEAN':
        return True, f'the detector says {meter_result["verdict"]}'
    risky = any(pt['part'] == 'context' and 'download / temporary' in pt['reason'] for pt in meter_result['parts'])
    signed = (meter_result.get('signature') or {}).get('status') == 'Valid'
    if risky and not signed:
        return True, 'clean verdict, but unsigned and stored in a download / temporary / user-profile folder'
    return False, 'clean verdict and signed or in a normal location'


def add_to_meter(meter_result, deep):
    """Adds a 'deep check' part (0-20, halved for CLEAN) to a ThreatMeter result and recomputes score + level."""
    from .phase2_meter import level
    r = dict(meter_result, parts=[p for p in meter_result['parts'] if p['part'] != 'deep check'], deep_check=deep)
    if deep.get('status') != 'completed':
        part = dict(part='deep check', points=0.0, reason=f'{deep.get("status")}: {deep.get("reason", "")}'.strip())
    else:
        raw = min(MAX_POINTS, sum(f['weight'] * 2 for f in deep['findings']))
        factor = 0.5 if r['verdict'] == 'CLEAN' else 1.0
        cov = deep['coverage']['text']
        text = '; '.join(f['title'] for f in deep['findings'][:6])
        part = dict(part='deep check', points=round(raw * factor, 1),
                    reason=(f'emulation saw: {text}' if text else 'emulation saw nothing risky (no extra evidence)')
                    + f' [{cov}]' + (' (halved: the detector says CLEAN)' if factor < 1 and raw else ''))
    r['parts'].append(part)
    floor = r.get('floor', 40 if r['verdict'] == 'MALICIOUS' else 20 if r['verdict'] == 'SUSPICIOUS' else 0)
    r['score'] = int(round(max(floor, min(r.get('cap', 100.0), 100.0, sum(p['points'] for p in r['parts'])))))
    r['level'] = level(r['score'])
    return r