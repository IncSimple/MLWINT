"""MLWINT Phase 3 step 3.1: local context of a file (read-only). Save as MLWINT/src/detection/phase3_context.py

Answers four questions with what Windows already records, without admin rights:
  1. where did it come from?    Mark of the Web (Zone.Identifier): zone + download page / referrer
                                 (query strings are dropped: they can contain session tokens)
  2. has it been run before?    Program Compatibility Assistant store (programs Windows saw starting) and
                                 UserAssist (programs started from Explorer: run count + last time)
  3. is it running / set to start automatically?
                                 running processes; Run / RunOnce keys, Winlogon, Image File Execution Options,
                                 Startup folders (shortcut targets resolved), scheduled tasks, services
  4. what does Microsoft Defender say?   Defender's own detection history for this path
Nothing is changed, started, stopped or sent anywhere. Facts here do not change the threat score; they decide
the advice (step 3.4): "downloaded, never run" needs very different steps from "set to start at every boot".
Limits (reported with every result): without admin rights some processes (elevated / other users) are not
visible and BAM / Prefetch run records cannot be read; a missing record does not prove a file never ran.
"""
import codecs, ctypes, datetime, json, os, struct, subprocess, time, winreg
from ctypes import wintypes
from pathlib import Path
from urllib.parse import urlsplit

ZONES = {0: 'this computer', 1: 'local network (intranet)', 2: 'trusted sites', 3: 'the Internet',
         4: 'restricted sites'}
RUN_KEYS = [(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'),
            (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')]
HIVE = {winreg.HKEY_CURRENT_USER: 'HKCU', winreg.HKEY_LOCAL_MACHINE: 'HKLM'}
PCA = r'Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
USERASSIST = r'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0


def norm(p):
    """Comparable form of a path or command line: env vars expanded, quotes removed, lower case, '\\'."""
    return os.path.expandvars(str(p)).replace('"', '').replace('/', '\\').lower()


def powershell_json(script, timeout=60):
    try:
        r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                            f'@({script}) | ConvertTo-Json -Compress -Depth 4'],
                           capture_output=True, text=True, timeout=timeout, creationflags=NO_WINDOW,
                           encoding='utf-8', errors='replace')
        out = r.stdout.strip()
        if not out:
            return [], (r.stderr.strip()[-200:] or None)
        data = json.loads(out)
        return (data if isinstance(data, list) else [data]), None
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        return [], f'{type(e).__name__}: {e}'


def reg_values(hive, path):
    try:
        with winreg.OpenKey(hive, path) as k:                     # read-only
            out, i = [], 0
            while True:
                try:
                    out.append(winreg.EnumValue(k, i))
                    i += 1
                except OSError:
                    return out
    except OSError:
        return []


def reg_subkeys(hive, path):
    try:
        with winreg.OpenKey(hive, path) as k:
            out, i = [], 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    return out
    except OSError:
        return []


def known_folder(guid):
    """Path of a Windows known folder ({374DE290-...} = Downloads, ...), or None."""
    class GUID(ctypes.Structure):
        _fields_ = [('a', wintypes.DWORD), ('b', wintypes.WORD), ('c', wintypes.WORD), ('d', ctypes.c_ubyte * 8)]
    g = GUID()
    if ctypes.oledll.ole32.CLSIDFromString(ctypes.c_wchar_p(guid), ctypes.byref(g)) != 0:
        return None
    p = ctypes.c_wchar_p()
    try:
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p)) != 0:
            return None
        return p.value
    finally:
        ctypes.windll.ole32.CoTaskMemFree(p)


def filetime(value):
    if not value:
        return None
    try:
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=value / 10)).strftime('%Y-%m-%d %H:%M')
    except (OverflowError, ValueError):
        return None


def clean_url(url):
    """Scheme + host + path only: query strings / fragments can hold session tokens."""
    if not url:
        return None
    s = urlsplit(url.strip())
    if not s.scheme or not s.netloc:
        return url.strip()[:200]
    return f'{s.scheme}://{s.netloc}{s.path}'[:300]


def mark_of_the_web(path):
    try:
        with open(str(path) + ':Zone.Identifier', 'r', encoding='utf-8', errors='replace') as f:   # read-only
            text = f.read()
    except OSError:
        return None
    fields = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    zone = int(fields['ZoneId']) if fields.get('ZoneId', '').strip().isdigit() else None
    host = fields.get('HostUrl', '')
    return dict(zone=zone, zone_name=ZONES.get(zone, 'unknown'), download_url=clean_url(host),
                referrer=clean_url(fields.get('ReferrerUrl')),
                site=urlsplit(host).netloc or None if host else None,
                url_had_query='?' in host)


class ContextChecker:
    """Builds each Windows index once (a few seconds) and answers per file from memory."""

    def __init__(self):
        self._autostart = self._processes = self._defender = self._pca = self._userassist = None
        self._own = set()
        self.notes = {}

    # ---------------- indexes
    def autostart(self):
        if self._autostart is None:
            items = []
            for hive, key in RUN_KEYS:
                for name, value, _ in reg_values(hive, key):
                    items.append(dict(where=f'{HIVE[hive]}\\{key}', name=name, command=str(value)))
            for name, value, _ in reg_values(winreg.HKEY_LOCAL_MACHINE,
                                             r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'):
                if name in ('Shell', 'Userinit'):
                    items.append(dict(where='HKLM Winlogon', name=name, command=str(value)))
            ifeo = r'Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
            for sub in reg_subkeys(winreg.HKEY_LOCAL_MACHINE, ifeo):
                for name, value, _ in reg_values(winreg.HKEY_LOCAL_MACHINE, f'{ifeo}\\{sub}'):
                    if name == 'Debugger':
                        items.append(dict(where='Image File Execution Options (debugger hijack)', name=sub,
                                          command=str(value)))
            svc = r'SYSTEM\CurrentControlSet\Services'
            for sub in reg_subkeys(winreg.HKEY_LOCAL_MACHINE, svc):
                vals = {n: v for n, v, _ in reg_values(winreg.HKEY_LOCAL_MACHINE, f'{svc}\\{sub}')}
                if vals.get('ImagePath'):
                    start = {0: 'boot', 1: 'system', 2: 'automatic', 3: 'manual', 4: 'disabled'}.get(vals.get('Start'))
                    items.append(dict(where=f'service ({start} start)', name=sub, command=str(vals['ImagePath'])))
            folders = [Path(os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')),
                       Path(os.path.expandvars(r'%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp'))]
            for folder in folders:
                for f in (folder.iterdir() if folder.is_dir() else []):
                    items.append(dict(where=f'Startup folder ({folder})', name=f.name, command=str(f)))
            links = [str(f) for folder in folders if folder.is_dir() for f in folder.glob('*.lnk')]
            if links:
                quoted = ','.join("'" + l.replace("'", "''") + "'" for l in links)
                rows, err = powershell_json(f"$w = New-Object -ComObject WScript.Shell; foreach ($l in @({quoted})) "
                                            "{ $s = $w.CreateShortcut($l); [pscustomobject]@{l=$l; t=$s.TargetPath; "
                                            "a=$s.Arguments} }")
                for r in rows:
                    items.append(dict(where='Startup folder shortcut', name=Path(r['l']).name,
                                      command=f'{r.get("t") or ""} {r.get("a") or ""}'.strip()))
            rows, err = powershell_json("Get-ScheduledTask | ForEach-Object { $t = $_; foreach ($a in $t.Actions) "
                                        "{ if ($a.Execute) { [pscustomobject]@{n=$t.TaskPath + $t.TaskName; "
                                        "s=[string]$t.State; e=$a.Execute; a=$a.Arguments} } } }", timeout=90)
            if err:
                self.notes['scheduled tasks'] = err
            for r in rows:
                items.append(dict(where=f'scheduled task ({r.get("s")})', name=r.get('n'),
                                  command=f'{r.get("e") or ""} {r.get("a") or ""}'.strip()))
            for it in items:
                it['_n'] = norm(it['command'])
            self._autostart = items
        return self._autostart

    def processes(self):
        if self._processes is None:
            rows, err = powershell_json('Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, '
                                        'Name, ExecutablePath, CommandLine')
            if err:
                self.notes['processes'] = err
            parent = {r.get('ProcessId'): r.get('ParentProcessId') for r in rows}
            own, pid = set(), os.getpid()              # MLWINT itself and whatever started it (the shell running
            while pid and pid not in own:              # the command has the file path in its command line)
                own.add(pid)
                pid = parent.get(pid)
            self._own = own                            # excluded only from 'opened / used by' below
            self._processes = rows
            hidden = sum(1 for r in rows if not r.get('ExecutablePath'))
            if hidden:
                self.notes['processes hidden'] = (f'{hidden} of {len(rows)} running processes do not show their '
                                                  'path without admin rights')
        return self._processes

    def defender(self):
        if self._defender is None:
            names, err1 = powershell_json('Get-MpThreat | Select-Object ThreatID, ThreatName')
            rows, err2 = powershell_json("Get-MpThreatDetection | Select-Object ThreatID, ActionSuccess, Resources, "
                                         "@{n='InitialDetectionTime'; e={$_.InitialDetectionTime.ToString("
                                         "'yyyy-MM-dd HH:mm')}}")
            if err1 or err2:
                self.notes['Defender'] = err1 or err2
            names = {r.get('ThreatID'): r.get('ThreatName') for r in names}
            self._defender = [dict(threat=names.get(r.get('ThreatID'), f'threat id {r.get("ThreatID")}'),
                                   time=str(r.get('InitialDetectionTime'))[:30], action_ok=r.get('ActionSuccess'),
                                   resources=[norm(x).split('_', 1)[-1] if str(x).startswith('file:_') else norm(x)
                                              for x in (r.get('Resources') or [])]) for r in rows]
        return self._defender

    def pca(self):
        if self._pca is None:
            self._pca = {norm(name) for name, _, _ in reg_values(winreg.HKEY_CURRENT_USER, PCA)}
        return self._pca

    def userassist(self):
        if self._userassist is None:
            out = {}
            for guid in reg_subkeys(winreg.HKEY_CURRENT_USER, USERASSIST):
                for name, data, _ in reg_values(winreg.HKEY_CURRENT_USER, f'{USERASSIST}\\{guid}\\Count'):
                    decoded = codecs.decode(name, 'rot13')
                    if decoded.startswith('{') and '}' in decoded:
                        folder = known_folder(decoded[:decoded.index('}') + 1])
                        if folder:
                            decoded = folder + decoded[decoded.index('}') + 1:]
                    count = last = None
                    if isinstance(data, bytes) and len(data) >= 68:
                        count = struct.unpack_from('<I', data, 4)[0]
                        last = filetime(struct.unpack_from('<Q', data, 60)[0])
                    out[norm(decoded)] = dict(runs=count, last_run=last)
            self._userassist = out
        return self._userassist

    # ---------------- per file
    def check(self, path):
        t0 = time.time()
        path = Path(path).resolve()
        p = norm(path)
        name = path.name.lower()
        origin = mark_of_the_web(path)
        running = [dict(pid=r.get('ProcessId'), name=r.get('Name')) for r in self.processes()
                   if r.get('ExecutablePath') and norm(r['ExecutablePath']) == p]
        loaded_by = [dict(pid=r.get('ProcessId'), name=r.get('Name')) for r in self.processes()
                     if r.get('CommandLine') and p in norm(r['CommandLine']) and r.get('ProcessId') not in self._own
                     and not (r.get('ExecutablePath') and norm(r['ExecutablePath']) == p)]
        autostart = [dict(where=a['where'], name=a['name'], command=a['command'][:300])
                     for a in self.autostart() if p in a['_n']]
        same_name = [dict(where=a['where'], name=a['name'], command=a['command'][:300]) for a in self.autostart()
                     if p not in a['_n'] and ('\\' + name) in a['_n'] and len(name) > 4][:5]
        ua = self.userassist().get(p)
        ran = dict(compatibility_assistant=p in self.pca(), userassist=ua)
        defender = [dict(threat=d['threat'], time=d['time'], action_ok=d['action_ok'])
                    for d in self.defender() if any(p == r or p in r for r in d['resources'])]
        result = dict(path=str(path), origin=origin, ran_before=ran, running=running, loaded_by=loaded_by,
                      autostart=autostart, autostart_same_name_elsewhere=same_name, defender=defender,
                      limits=sorted(set(self.notes.values()) | {'without admin rights Windows run records such as '
                                                                 'Prefetch / BAM cannot be read: no record does not '
                                                                 'prove the file never ran'}),
                      seconds=round(time.time() - t0, 2))
        result['facts'] = facts(result)
        return result


def facts(c):
    """Short plain-language lines for the report."""
    out = []
    o = c['origin']
    if o:
        where = o.get('site') or (o.get('referrer') and urlsplit(o['referrer']).netloc) or None
        out.append(f'came from {o["zone_name"]}' + (f' ({where})' if where else '')
                   + ('' if o['zone'] in (3, 4) or o['zone'] is None else ' - not marked as downloaded from the web'))
    else:
        out.append('no download mark (copied, extracted, created on this PC, or the browser did not mark it)')
    r = c['ran_before']
    if r['userassist']:
        out.append(f'started from Explorer {r["userassist"].get("runs")} time(s), last {r["userassist"].get("last_run")}')
    if r['compatibility_assistant']:
        out.append('Windows recorded this program being started (Program Compatibility Assistant)')
    if not r['userassist'] and not r['compatibility_assistant'] and not c['path'].lower().endswith('.pdf'):
        out.append('no record of it being run (not proof that it never ran)')
    if c['running']:
        out.append('RUNNING NOW: ' + ', '.join(f'{x["name"]} (pid {x["pid"]})' for x in c['running']))
    if c['loaded_by']:
        out.append('opened / used by a running program: ' + ', '.join(f'{x["name"]} (pid {x["pid"]})' for x in c['loaded_by']))
    if c['autostart']:
        out.append('SET TO START AUTOMATICALLY: ' + '; '.join(f'{a["where"]}: {a["name"]}' for a in c['autostart']))
    if c['autostart_same_name_elsewhere']:
        out.append('a file with the same name starts automatically from another folder: '
                   + '; '.join(a['command'][:120] for a in c['autostart_same_name_elsewhere']))
    if c['defender']:
        out.append('Microsoft Defender detected it: ' + '; '.join(f'{d["threat"]} ({d["time"][:10]})'
                                                                  for d in c['defender']))
    return out