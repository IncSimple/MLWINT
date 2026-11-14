"""MLWINT Phase 2 step 2.1: evidence of what a file CAN do (read-only).
Save as MLWINT/src/detection/phase2_evidence.py

  Programs (Win32 / Win64 / .NET): capa 9.4.0 static rules, run in its own environment
      -> capabilities, each with its MITRE ATT&CK technique(s) and MBC behaviours
      (.NET files use capa's .NET analysis, other programs the PE + vivisect analysis)
  PDF: risky-element check in the style of pdfid (counts names such as /JavaScript, /OpenAction, /Launch,
      /EmbeddedFile, also when hidden with #xx escapes), each mapped to the ATT&CK technique it can enable
Evidence says what a file is able to do, not that it is malicious: clean programs also have capabilities
(notepad.exe can hide a window). The threat meter (step 2.3) weighs evidence together with the verdict.
"""
import hashlib, json, os, re, subprocess
from collections import Counter, defaultdict
from pathlib import Path

from .phase1_detectors import detect_format

ROOT = Path(__file__).resolve().parents[2]
CAPA_PYTHON = ROOT / 'experiments/capa/.venv/Scripts/python.exe'
CAPA_SOURCE = ROOT / 'tools/capa-source-v9.4.0'

PDF_INDICATORS = {   # name: (what it means, risk weight 1-3, ATT&CK id, technique, tactic)
    '/JavaScript': ('contains JavaScript', 3, 'T1059.007', 'Command and Scripting Interpreter: JavaScript', 'Execution'),
    '/JS': ('contains JavaScript', 3, 'T1059.007', 'Command and Scripting Interpreter: JavaScript', 'Execution'),
    '/Launch': ('can ask to launch a program or file', 3, 'T1204.002', 'User Execution: Malicious File', 'Execution'),
    '/OpenAction': ('runs an action automatically when opened', 2, 'T1204.002', 'User Execution: Malicious File', 'Execution'),
    '/AA': ('has automatic actions (on page or form events)', 2, 'T1204.002', 'User Execution: Malicious File', 'Execution'),
    '/EmbeddedFile': ('carries an embedded file', 2, 'T1027.009', 'Obfuscated Files or Information: Embedded Payloads', 'Defense Evasion'),
    '/RichMedia': ('embeds rich media (Flash-era exploit surface)', 2, 'T1203', 'Exploitation for Client Execution', 'Execution'),
    '/XFA': ('uses XFA forms (exploit surface)', 1, 'T1203', 'Exploitation for Client Execution', 'Execution'),
    '/URI': ('contains web links', 1, 'T1204.001', 'User Execution: Malicious Link', 'Execution'),
    '/SubmitForm': ('can send form data to a server', 1, 'T1204.001', 'User Execution: Malicious Link', 'Execution'),
    '/GoToR': ('can open another document', 1, 'T1204.001', 'User Execution: Malicious Link', 'Execution'),
    '/ObjStm': ('hides objects inside compressed object streams', 1, 'T1027', 'Obfuscated Files or Information', 'Defense Evasion'),
    '/Encrypt': ('is encrypted', 1, 'T1027', 'Obfuscated Files or Information', 'Defense Evasion'),
}
NAME = re.compile(rb'/[A-Za-z0-9#]+')
HEX = re.compile(rb'#([0-9A-Fa-f]{2})')


# ------------------------------------------------------------------ PDF
def pdf_indicators(data):
    counts, hidden = Counter(), Counter()
    for raw in NAME.findall(data):
        name = HEX.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
        try:
            text = name.decode('latin-1')
        except UnicodeDecodeError:
            continue
        if text in PDF_INDICATORS:
            counts[text] += 1
            if raw != name:
                hidden[text] += 1
    structure = dict(objects=len(re.findall(rb'\d+\s+\d+\s+obj\b', data)), streams=data.count(b'endstream'),
                     end_of_file_markers=data.count(b'%%EOF'), pages=len(re.findall(rb'/Type\s*/Page\b', data)))
    findings = []
    for name, n in sorted(counts.items(), key=lambda kv: -PDF_INDICATORS[kv[0]][1]):
        meaning, risk, tid, technique, tactic = PDF_INDICATORS[name]
        findings.append(dict(indicator=name, count=n, meaning=meaning, risk=risk, hidden_with_escapes=hidden[name],
                             attack=[dict(id=tid, technique=technique, tactic=tactic)]))
    if hidden:
        findings.append(dict(indicator='#xx-escaped names', count=sum(hidden.values()), risk=2,
                             meaning='names are disguised with hex escapes, a common trick to dodge scanners',
                             hidden_with_escapes=sum(hidden.values()),
                             attack=[dict(id='T1027', technique='Obfuscated Files or Information',
                                          tactic='Defense Evasion')]))
    if structure['end_of_file_markers'] > 1:
        findings.append(dict(indicator='incremental updates', count=structure['end_of_file_markers'], risk=1,
                             meaning='the document was changed after it was first saved (normal for edited or '
                                     'signed PDFs, also used to append hidden content)', hidden_with_escapes=0,
                             attack=[]))
    return dict(status='completed', engine='MLWINT PDF indicator check', structure=structure, findings=findings,
                interpretation='Risky elements say what the PDF can do when opened. Many clean PDFs contain links '
                               'or forms; JavaScript, launch actions and embedded files deserve the most attention.')


# ------------------------------------------------------------------ programs (capa)
def summarize_capa(document, expected_hash):
    """Same rules as the existing MLWINT capa summary: static capa 9.4.0, same file, library rules skipped."""
    meta = document['meta']
    if meta['version'] != '9.4.0' or meta['flavor'] != 'static':
        raise ValueError('Expected static capa 9.4.0 output.')
    if meta['sample']['sha256'].lower() != expected_hash:
        raise ValueError('capa analysed different file contents; results were not used.')
    capabilities, limitations = [], []
    for name, rule in sorted(document['rules'].items()):
        info = rule['meta']
        if info.get('lib') or info.get('capa/subscope') or info.get('is_subscope_rule') or not rule['matches']:
            continue
        finding = dict(rule_name=name, namespace=info.get('namespace'), match_count=len(rule['matches']),
                       attack=info.get('att&ck', info.get('attack', [])), mbc=info.get('mbc', []))
        (limitations if (info.get('namespace') or '').startswith('internal/limitation') else capabilities).append(finding)
    return dict(engine='capa 9.4.0', capabilities=capabilities, detected_analysis_limitations=limitations,
                interpretation='Static rule matches indicate possible capabilities, including legitimate '
                               'functionality. They do not prove execution or malicious intent, and an empty '
                               'result does not prove capabilities are absent.')


def run_capa(path, file_hash, kind, folder, timeout=300):
    if not CAPA_PYTHON.is_file():
        raise FileNotFoundError(f'capa environment not found: {CAPA_PYTHON}')
    fmt = ['-f', 'dotnet'] if kind == 'dotnet' else ['-f', 'pe', '-b', 'vivisect']
    command = [str(CAPA_PYTHON), '-m', 'capa.main', '-j', '-q', *fmt,
               '-r', str(CAPA_SOURCE / 'rules'), '-s', str(CAPA_SOURCE / 'sigs'), str(path)]
    folder.mkdir(parents=True, exist_ok=True)
    out, err = folder / 'capa.json', folder / 'capa.stderr.txt'
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    with out.open('wb') as so, err.open('wb') as se:
        proc = subprocess.Popen(command, stdout=so, stderr=se, env=dict(os.environ, CAPA_SAVE_WORKSPACE='0'),
                                cwd=str(CAPA_PYTHON.parent), creationflags=flags)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True, creationflags=flags)
            else:
                proc.kill()
            proc.wait(timeout=15)
            return dict(status='timeout', engine='capa 9.4.0', reason=f'no result within {timeout} s')
    if code != 0:
        return dict(status='failed', engine='capa 9.4.0', reason=err.read_text(errors='replace')[-800:])
    summary = summarize_capa(json.loads(out.read_text(encoding='utf-8-sig')), file_hash)
    caps = [dict(name=c['rule_name'], namespace=c['namespace'], matches=c['match_count'],
                 attack=[dict(id=a.get('id'), technique=' :: '.join(p for p in a.get('parts', [])[1:]),
                              tactic=a.get('tactic')) for a in c['attack']],
                 mbc=[m.get('id') or m.get('objective') for m in c['mbc']]) for c in summary['capabilities']]
    return dict(status='completed', engine=summary['engine'], analysis_format=kind, capabilities=caps,
                limitations=[l['rule_name'] for l in summary['detected_analysis_limitations']],
                interpretation=summary['interpretation'], raw_output=str(out))


def attack_summary(findings, key):
    """Group ATT&CK techniques across findings: id -> technique, tactic, which findings point to it."""
    by = defaultdict(lambda: dict(technique='', tactic='', evidence=[]))
    for f in findings:
        for a in f['attack']:
            entry = by[a['id']]
            entry['technique'], entry['tactic'] = a['technique'], a['tactic']
            entry['evidence'].append(f[key])
    techniques = [dict(id=i, **v) for i, v in sorted(by.items())]
    tactics = Counter(t['tactic'] for t in techniques)
    return techniques, dict(sorted(tactics.items(), key=lambda kv: -kv[1]))


def evidence_for_file(path, work_dir=None, timeout=300):
    path = Path(path)
    try:
        with open(path, 'rb') as f:                                # read-only
            data = f.read()
    except OSError as e:                                           # missing, locked or no permission: skip, don't crash
        return dict(path=str(path), status='skipped', reason=f'cannot read: {e.strerror or e}')
    digest = hashlib.sha256(data).hexdigest()
    kind, reason = detect_format(data)
    if kind is None:
        return dict(path=str(path), sha256=digest, status='unsupported', reason=reason)
    if kind == 'pdf':
        ev = pdf_indicators(data)
        techniques, tactics = attack_summary(ev['findings'], 'indicator')
    else:
        folder = Path(work_dir or ROOT / 'reports/phase2/evidence') / digest[:16]
        try:
            ev = run_capa(path, digest, kind, folder, timeout)
        except (OSError, ValueError) as e:                         # capa missing, or its output didn't match this file
            ev = dict(status='failed', engine='capa 9.4.0', reason=f'{type(e).__name__}: {e}')
        techniques, tactics = attack_summary(ev.get('capabilities', []), 'name') if ev['status'] == 'completed' \
            else ([], {})
    return dict(path=str(path), sha256=digest, status='analysed', format=kind, format_reason=reason, evidence=ev,
                attack_techniques=techniques, attack_tactics=tactics)