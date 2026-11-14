"""Builds the sample data for the MLWINT live demo (the Flutter app on the web, or on Windows with
--dart-define=MLWINT_DEMO=true).

Run: experiments/ember2024/.venv/Scripts/python.exe packaging/make_demo_data.py
Writes mlwint_app/assets/demo/demo.json and mlwint_app/web/sample-report.pdf (made by MLWINT's own PDF report code).

Every file, path, hash, host and fact below is INVENTED for the demo. The fields follow MLWINT's real result format
(scripts/mlwint_analyse.py) so the window shows them exactly as it shows real scans. No real scan data is used.
"""
import hashlib, json, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DL = 'C:\\Users\\demo\\Downloads\\'
DOCS = 'C:\\Users\\demo\\Documents\\Work\\'


def sha(name):
    return hashlib.sha256(('mlwint-demo:' + name).encode()).hexdigest()


def technique(tid, name, tactic, summary, mitigations, sources=('capa',)):
    return dict(id=tid, technique=name, tactic=tactic, sources=list(sources),
                explanation=dict(url=f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}/', summary=summary,
                                 mitigations=[dict(id=m[0], name=m[1]) for m in mitigations]))


def result(path, score, level, fmt, verdict, prob, parts, advice, summary, *, attack=(), behaviours=(), family=None,
           facts=(), signature=None, deep=None, deep_reason=None, floor=0, cap=100.0, seconds=1.2, remembered=None):
    r = dict(status='assessed', path=path, sha256=sha(path), format=fmt, verdict=verdict, probability=prob,
             score=score, level=level, summary=summary, parts=[dict(part=p, points=v, reason=t) for p, v, t in parts],
             attack=list(attack), behaviours=list(behaviours), family=family, floor=floor, cap=cap, advice=advice,
             local_context=dict(facts=list(facts)), signature=signature or dict(status='NotSigned'),
             seconds=seconds, reputation={})
    if deep:
        r['deep_check'] = deep
    if deep_reason:
        r['deep_check_reason'] = deep_reason
    if remembered:
        r['remembered'] = dict(day=remembered)
    return r


def act(priority, action, because, aid):
    return dict(priority=priority, action=action, because=because, id=aid)


NONE = dict(headline='No action needed', actions=[], notes=[])

# ---------------------------------------------------------------------------------------------- the latest scan
CRACK = result(
    DL + 'PhotoEditor_Pro_crack.exe', 88, 'SEVERE', 'Win32', 'MALICIOUS', 0.973,
    [('detector', 58.4, 'Win32 detector says MALICIOUS (malware probability 0.973; suspicious from 0.268, malicious from 0.812)'),
     ('behaviour', 14.2, 'behaves like a trojan and a downloader (right 91% and 86% of the time on test)'),
     ('family', 5.0, 'family "agenttesla" (confidence 81%; right 93% of the time on test)'),
     ('evidence', 7.5, 'capa found 6 ATT&CK techniques, including process injection and a Run-key autostart'),
     ('context', 3.0, 'unsigned; stored in a download folder; ran on this PC'),
     ('deep check', 12.0, 'emulation saw it write a Run key and contact a web server')],
    dict(headline='It may be active on this PC - act now', actions=[
        act(1, 'Disconnect this PC from the internet (Wi-Fi off or cable out)', 'it ran on this PC and contacts a server', 'disconnect'),
        act(1, 'End "PhotoEditor_Pro_crack.exe" in Task Manager (Details tab > End task)', 'it is running now', 'end_process'),
        act(1, 'Remove its autostart: Task Manager > Startup apps > "PhotoUpdate" > Disable', 'it starts with Windows', 'autostart'),
        act(2, 'Run a Microsoft Defender Offline scan: Windows Security > Virus & threat protection > Scan options > Microsoft Defender Offline scan > Scan now', 'it has run on this PC and may have hidden itself', 'offline_scan'),
        act(2, 'After the scan, delete the file yourself if it is still there', 'threat level SEVERE', 'delete_file'),
        act(3, 'From another device, change the passwords you saved in your browser or typed on this PC, starting with e-mail and banking', 'it is tagged as a password stealer and it ran', 'passwords')],
         notes=['MLWINT never deletes or quarantines files: every step is yours to do.']),
    'malware with harmful behaviour',
    attack=[technique('T1055', 'Process Injection', 'Defense Evasion', 'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.', [('M1040', 'Behavior Prevention on Endpoint')], ('capa', 'deep check')),
            technique('T1547.001', 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder', 'Persistence', 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.', [('M1018', 'User Account Management')], ('capa', 'deep check')),
            technique('T1071.001', 'Application Layer Protocol: Web Protocols', 'Command and Control', 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.', [('M1031', 'Network Intrusion Prevention')], ('deep check',)),
            technique('T1555.003', 'Credentials from Password Stores: Credentials from Web Browsers', 'Credential Access', 'Adversaries may acquire credentials from web browsers by reading files specific to the target browser.', [('M1027', 'Password Policies')]),
            technique('T1027', 'Obfuscated Files or Information', 'Defense Evasion', 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.', [('M1049', 'Antivirus/Antimalware')]),
            technique('T1082', 'System Information Discovery', 'Discovery', 'An adversary may attempt to get detailed information about the operating system and hardware.', [])],
    behaviours=[dict(tag='trojan', tier='strong', probability=0.94), dict(tag='downloader', tier='normal', probability=0.88),
                dict(tag='passwordstealer', tier='hint', probability=0.71)],
    family=dict(name='agenttesla', confidence=0.81, test_precision=0.93),
    facts=['came from cdn.free-download.example (Mark of the Web)', 'ran 2 times, last on 13 Nov 2026 22:14',
           'is running now (process id 7412)', 'starts automatically: HKCU Run "PhotoUpdate"',
           'Microsoft Defender has no record of it'],
    deep=dict(status='completed', engine='Speakeasy 1.5.11 (emulation)',
              findings=[dict(title='writes itself to HKCU\\...\\Run ("PhotoUpdate")'),
                        dict(title='downloads a file from a web server'),
                        dict(title='reads browser profile folders')],
              observed=dict(servers=['update-check.example.net'])),
    floor=80, seconds=46.1)

VPN = result(
    DL + 'free_vpn_setup.exe', 64, 'HIGH', 'Win32', 'SUSPICIOUS', 0.61,
    [('detector', 31.8, 'Win32 detector says SUSPICIOUS (malware probability 0.610; suspicious from 0.268, malicious from 0.812)'),
     ('behaviour', 9.8, 'behaves like adware and a potentially unwanted application (right 88% of the time on test)'),
     ('family', 0.0, 'family not identified with enough confidence'),
     ('evidence', 6.0, 'capa found 3 ATT&CK techniques'),
     ('context', 2.0, 'unsigned; stored in a download folder; never run')],
    dict(headline='Do not run it - delete it', actions=[
        act(1, 'Do not open or install it', 'very likely unwanted software and it has not run yet', 'do_not_run'),
        act(2, 'Delete the file (and empty the Recycle Bin)', 'threat level HIGH', 'delete_file')],
         notes=['If you need a VPN, get it from the provider\'s own website or the Microsoft Store.']),
    'very likely malware',
    attack=[technique('T1176', 'Browser Extensions', 'Persistence', 'Adversaries may abuse Internet browser extensions to establish persistent access to victim systems.', [('M1038', 'Execution Prevention')]),
            technique('T1112', 'Modify Registry', 'Defense Evasion', 'Adversaries may interact with the Windows Registry to hide configuration information or remove information as part of cleaning up.', [('M1024', 'Restrict Registry Permissions')]),
            technique('T1105', 'Ingress Tool Transfer', 'Command and Control', 'Adversaries may transfer tools or other files from an external system into a compromised environment.', [('M1031', 'Network Intrusion Prevention')])],
    behaviours=[dict(tag='adware', tier='normal', probability=0.86), dict(tag='pua', tier='normal', probability=0.83)],
    facts=['came from vpn-free.example (Mark of the Web)', 'never run on this PC'],
    deep=dict(status='completed', engine='Speakeasy 1.5.11 (emulation)',
              findings=[dict(title='installs a browser extension'), dict(title='changes the browser start page')],
              observed=dict(servers=['ads.vpn-free.example'])),
    floor=60, seconds=38.4)

INVOICE = result(
    DL + 'invoice_8831.pdf', 47, 'ELEVATED', 'PDF', 'SUSPICIOUS', 0.58,
    [('detector', 26.1, 'PDF detector says SUSPICIOUS (malware probability 0.580; suspicious from 0.141, malicious from 0.712)'),
     ('behaviour', 4.0, 'looks like an exploit document (right 89% of the time on test)'),
     ('evidence', 12.0, 'contains JavaScript (/JS) and an automatic action (/OpenAction)'),
     ('pdf rule', 0.0, 'the PDF holds content that can run, so it is not capped')],
    dict(headline='Do not open it until you know who sent it', actions=[
        act(1, 'Do not open it. If you expected an invoice, ask the sender by phone or a known e-mail address', 'it contains JavaScript that runs when the PDF opens', 'do_not_open'),
        act(2, 'If you are sure it is not genuine, delete it', 'clear warning signs', 'delete_file')], notes=[]),
    'clear warning signs',
    attack=[technique('T1059.007', 'Command and Scripting Interpreter: JavaScript', 'Execution', 'Adversaries may abuse various implementations of JavaScript for execution.', [('M1042', 'Disable or Remove Feature or Program')], ('pdf check',))],
    behaviours=[dict(tag='exploit', tier='normal', probability=0.79)],
    facts=['came as an e-mail attachment (Mark of the Web: Outlook)', 'never opened on this PC'], seconds=2.1)

STATEMENT = result(
    DL + 'bank_statement_october.pdf', 39, 'GUARDED', 'PDF', 'SUSPICIOUS', 0.47,
    [('detector', 26.8, 'PDF detector says SUSPICIOUS (malware probability 0.470; suspicious from 0.141, malicious from 0.712)'),
     ('evidence', 0.0, 'no risky elements'),
     ('pdf rule', -2.0, 'capped at 39: a PDF with nothing that can run')],
    dict(headline='Probably harmless to open - be careful with its links', actions=[
        act(3, 'Do not click links or fill in forms in this PDF unless you expected it; if it asks you to log in or pay, go to the website yourself instead of using the link', 'the detector finds it similar to phishing documents, but it contains nothing that can run', 'pdf_links')], notes=[]),
    'the detector finds it similar to phishing PDFs, but it contains nothing that can run: opening it is low risk - do not trust its links or forms unless you know the sender',
    facts=['came from bank.example (Mark of the Web)'], cap=39.0, seconds=0.9)

LAUNCHER = result(
    DL + 'game_launcher_setup.exe', 27, 'GUARDED', 'Win64', 'SUSPICIOUS', 0.31,
    [('detector', 22.0, 'Win64 detector says SUSPICIOUS (malware probability 0.310; suspicious from 0.233, malicious from 0.790)'),
     ('behaviour', 1.0, 'possibly a potentially unwanted application (right 79% of the time on test)'),
     ('context', -10.0, 'valid digital signature (CN=Example Games Ltd); stored in a download folder')],
    dict(headline='Fine if you expected it', actions=[
        act(4, 'Install it only if you downloaded it from the publisher\'s own website; choose "Custom install" and untick extra offers', 'weak warning signs, but it is signed', 'custom_install')],
         notes=['it carries a valid signature from "Example Games Ltd": if that is the publisher you meant to get it from, this is very likely a false alarm']),
    'weak warning signs',
    behaviours=[dict(tag='pua', tier='hint', probability=0.64)],
    facts=['came from downloads.example-games.example (Mark of the Web)'],
    signature=dict(status='Valid', signer='CN=Example Games Ltd'), deep_reason='signed and not flagged strongly', seconds=21.7)

EDITOR = result(
    DL + 'TextEditor_Setup_8.6.exe', 4, 'LOW', 'Win64', 'CLEAN', 0.031,
    [('detector', 1.9, 'Win64 detector says CLEAN (malware probability 0.031; suspicious from 0.233, malicious from 0.790)'),
     ('context', -10.0, 'valid digital signature (CN=Example Software Foundation)')],
    NONE, 'no meaningful sign of malware', signature=dict(status='Valid', signer='CN=Example Software Foundation'),
    deep_reason='clean verdict and signed or in a normal location', seconds=1.4)

REPORT = result(DL + 'quarterly_report_q3.pdf', 3, 'LOW', 'PDF', 'CLEAN', 0.02,
                [('detector', 1.2, 'PDF detector says CLEAN (malware probability 0.020)'), ('evidence', 0.0, 'no risky elements')],
                NONE, 'no meaningful sign of malware', seconds=0.6)

DOTNET = result(DL + 'Contoso.Data.Helper.dll', 0, 'LOW', '.NET', 'CLEAN', 0.004,
                [('detector', 0.2, '.NET detector says CLEAN (malware probability 0.004; suspicious from 0.212, malicious from 0.684)'),
                 ('context', -10.0, 'valid digital signature (CN=Contoso Ltd)')],
                NONE, 'no meaningful sign of malware', signature=dict(status='Valid', signer='CN=Contoso Ltd'),
                remembered='10 Nov 2026', seconds=0.1)

DRIVER = result(DL + 'usb_driver_tool_x64.exe', 9, 'LOW', 'Win64', 'CLEAN', 0.081,
                [('detector', 4.8, 'Win64 detector says CLEAN (malware probability 0.081)'),
                 ('context', 0.0, 'unsigned; stored in a download folder')],
                NONE, 'no meaningful sign of malware', remembered='10 Nov 2026', seconds=0.1)

BROKEN = dict(status='failed', path=DL + 'unfinished_download.exe', sha256=sha('broken'),
              reason='not a complete Windows program (the download was probably interrupted)', seconds=0.0)

LATEST = [CRACK, VPN, INVOICE, STATEMENT, LAUNCHER, EDITOR, DRIVER, REPORT, DOTNET, BROKEN]


def older_downloads():
    """The previous scan of Downloads: the crack and the VPN were not there yet; the invoice scored lower."""
    inv = json.loads(json.dumps(INVOICE))
    inv.update(score=31, level='GUARDED')
    return [inv, json.loads(json.dumps(STATEMENT)), json.loads(json.dumps(LAUNCHER)), json.loads(json.dumps(EDITOR)),
            json.loads(json.dumps(DRIVER)), json.loads(json.dumps(REPORT)), json.loads(json.dumps(DOTNET)),
            result(DL + 'old_screen_recorder.exe', 12, 'LOW', 'Win32', 'CLEAN', 0.11,
                   [('detector', 6.2, 'Win32 detector says CLEAN (malware probability 0.110)')], NONE,
                   'no meaningful sign of malware')]


WORK = [result(DOCS + n, s, 'LOW', f, 'CLEAN', p, [('detector', round(p * 50, 1), f'{f} detector says CLEAN')], NONE,
               'no meaningful sign of malware')
        for n, s, f, p in (('budget_2027.pdf', 2, 'PDF', 0.03), ('team_handbook.pdf', 1, 'PDF', 0.01),
                           ('ReportBuilder.exe', 6, 'Win64', 0.07), ('PluginHost.dll', 0, '.NET', 0.0))]


def levels_of(rs):
    out = {}
    for r in rs:
        if r.get('status') == 'assessed':
            out[r['level']] = out.get(r['level'], 0) + 1
    return out


def entry(file, started, where, paths, rs, seconds, whole=False, files=None, levels=None, memory=''):
    return dict(file=file, started=started, where=where, paths=[p.lower() for p in paths], whole_pc=whole,
                files=files if files is not None else len(rs), levels=levels or levels_of(rs),
                not_checked=sum(1 for r in rs if r.get('status') != 'assessed'), memory=memory, seconds=seconds)


def main():
    dl = DL.rstrip('\\')
    history = [
        entry('analysis-20261113-214500.json', '2026-11-13 21:45:00', dl, [dl], LATEST, 141,
              memory='Memory: 2 unchanged (earlier result used), 8 checked now'),
        entry('analysis-20261112-091200.json', '2026-11-12 09:12:00', 'Whole PC', [], [], 5160, whole=True, files=1320,
              levels={'LOW': 1311, 'GUARDED': 8, 'ELEVATED': 1}),
        entry('analysis-20261110-183000.json', '2026-11-10 18:30:00', dl, [dl], older_downloads(), 96),
        entry('analysis-20261105-120000.json', '2026-11-05 12:00:00', DOCS.rstrip('\\'), [DOCS.rstrip('\\')], WORK, 18),
    ]
    reports = {'analysis-20261113-214500.json': LATEST, 'analysis-20261110-183000.json': older_downloads(),
               'analysis-20261105-120000.json': WORK}
    health = [dict(part=p, ok=True, detail=d) for p, d in (
        ('Detectors (Phase 1)', 'Win32, Win64, .NET and PDF detectors'), ('Family / behaviour models (Phase 2)', 'loaded'),
        ('capa (code check)', 'capa 9.4.0 with rules'), ('Speakeasy (safe simulation)', 'Speakeasy 1.5.11'),
        ('MITRE ATT&CK data', 'Enterprise ATT&CK, offline'), ('Microsoft Defender scanner (large files)', 'MpCmdRun.exe'),
        ('Easy-to-read PDF reports', 'Qt PDF writer'), ('Hash lookup keys', 'none set (hash lookup stays off)'))]
    version = json.loads((ROOT / 'version.json').read_text(encoding='utf-8'))
    from src.gui.settings_tab import PRIVACY
    data = dict(note='Sample data for the MLWINT live demo: every file, path, hash, host and fact is invented.',
                versions=dict(app=version['app'], models=version['models']), history=history, reports=reports,
                health=health, privacy=PRIVACY, scan=LATEST)
    out = ROOT / 'mlwint_app/assets/demo/demo.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding='utf-8')
    print('demo data:', out, f'{out.stat().st_size // 1024} KB')

    # the easy-to-read PDF of the latest sample scan, made by MLWINT's own report code
    from src.report.plain_report import write_pdf
    with tempfile.TemporaryDirectory() as tmp:
        js = Path(tmp) / 'analysis-20261113-214500.json'
        js.write_text(json.dumps(dict(status='MLWINT_ANALYSIS', started='2026-11-13 21:45:00', paths=[dl],
                                      options=dict(evidence='needed', deep='needed', context='needed'),
                                      counts=levels_of(LATEST), not_checked={}, memory=history[0]['memory'],
                                      results=LATEST)), encoding='utf-8')
        pdf = write_pdf(js, ROOT / 'mlwint_app/web/sample-report.pdf')
    print('sample report:', pdf)


if __name__ == '__main__':
    main()
