"""MLWINT easy-to-read report (PDF) for people who are not security experts.
Save as MLWINT/src/report/plain_report.py   (and an empty MLWINT/src/report/__init__.py)

Reads one analysis-<stamp>.json (written by mlwint_analyse / the GUI) and writes analysis-<stamp>.pdf next to it:
  page 1  the answer in one sentence, a traffic-light count, and the few things to do now
  then    one section per level, in plain words:
            Act now (HIGH / SEVERE) and Be careful (ELEVATED): one card per file - what it is, what to do, why
            Worth a look (GUARDED): files with the same advice are grouped, so 40 similar PDFs are one block
            Looks fine (LOW): just the names
            Could not check / Skipped by your choice: what was not looked at, and why
  last    what the words mean
The technical .txt / .json reports stay as they are (for experts and for MLWINT itself).
Uses Qt's own PDF writer (PySide6, already installed for the GUI): no extra package. Read-only: it only reads the
.json report and writes the .pdf.
"""
import html, json, sys, time
from collections import Counter, OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_APP = None                            # the Qt application used for fonts when run without the GUI
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.detection.phase2_meter import TAG_TEXT  # noqa: E402

GROUPS = OrderedDict([                 # level -> (title, colour, background, one line for the legend)
    ('act', ('Act now', '#b71c1c', '#fdecea', 'very likely harmful - follow the steps for these first')),
    ('careful', ('Be careful', '#e65100', '#fff3e0', 'clear warning signs - do not open until you know the source')),
    ('look', ('Worth a look', '#1565c0', '#e8f1fb', 'weak warning signs - most are fine if you expected the file')),
    ('fine', ('Looks fine', '#2e7d32', '#e8f5e9', 'no meaningful sign of malware')),
    ('failed', ('Could not check', '#555555', '#f2f2f2', 'MLWINT could not look inside these files')),
])
LEVEL_GROUP = {'SEVERE': 'act', 'HIGH': 'act', 'ELEVATED': 'careful', 'GUARDED': 'look', 'LOW': 'fine'}
KIND_WORD = {'Win32': 'program', 'Win64': 'program', '.NET': 'program', 'PDF': 'PDF document'}
PRIORITY = {1: 'Do now', 2: 'Important', 3: 'To stay safe', 4: 'Good to check'}
TEXT = '#1f1f1f'                       # dark text on white paper (never the Windows theme colour)
STYLE = f'body, p, td, li, h1, h2, h3 {{ color: {TEXT}; }}'
PDF_WORDS = {
    '/JS': 'contains JavaScript - small programs that can run when the PDF is opened',
    '/JavaScript': 'contains JavaScript - small programs that can run when the PDF is opened',
    '/OpenAction': 'does something automatically as soon as it is opened',
    '/AA': 'does something automatically when pages are opened or closed',
    '/Launch': 'can try to start another program on your PC',
    '/EmbeddedFile': 'has another file hidden inside it',
    '/RichMedia': 'contains Flash or other media that can run',
    '/XFA': 'contains a special interactive form (XFA) that can run code',
    '/URI': 'contains web links',
    '/Encrypt': 'is locked or password-protected (common for official documents, also used to hide content)',
}
TACTIC_WORDS = {
    'Execution': 'starts other programs or commands', 'Discovery': 'looks around your PC (system details, files)',
    'Defense Evasion': 'tries to hide or avoid security tools', 'Stealth': 'tries to hide or avoid security tools',
    'Persistence': 'can set itself to start automatically', 'Privilege Escalation': 'tries to get administrator rights',
    'Credential Access': 'tries to read passwords', 'Collection': 'collects data from your PC',
    'Command and Control': 'can talk to a remote server', 'Exfiltration': 'can send data out of your PC',
    'Impact': 'can damage, lock or delete files', 'Lateral Movement': 'can spread to other computers',
    'Initial Access': 'is built to get into a PC', 'Resource Development': 'prepares tools for an attack',
}
NOT_CHECKED_WORDS = {'win32': '32-bit programs', 'win64': '64-bit programs', 'dotnet': '.NET programs',
                     'pdf': 'PDF documents', 'program': 'programs'}


def e(x):
    return html.escape(str(x if x is not None else ''))


def cap(text):
    return text[:1].upper() + text[1:]


def name_of(r):
    return Path(str(r.get('path', ''))).name


def folder_of(r):
    return str(Path(str(r.get('path', ''))).parent)


def came_from(r):
    for f in (r.get('local_context') or {}).get('facts', []):
        if f.startswith('came from the Internet (') and f.endswith(')'):
            return f[len('came from the Internet ('):-1]
    return ''


def signer(r):
    s = (r.get('signature') or {}).get('signer') or ''
    for part in s.split(','):
        part = part.strip()
        if part.startswith('O='):
            return part[2:].strip('"')
    return s[3:].split(',')[0].strip('"') if s.startswith('CN=') else s


def was_run(r):
    """True when Windows has a record of the program being started, or it is running / starts automatically now."""
    lc = r.get('local_context') or {}
    rb = lc.get('ran_before') or {}
    ran = any(bool(v) for v in rb.values()) if isinstance(rb, dict) else bool(rb)
    return ran or bool(lc.get('running')) or bool(lc.get('autostart'))


def plain_failure(reason):
    reason = str(reason or '')
    if 'too large even' in reason:
        return 'too large even for the large-file check (over 4 GB). Check it with Windows Security: right-click ' \
               'the file > Scan with Microsoft Defender'
    if 'larger than' in reason:
        return 'larger than 256 MB, so not part of the normal check. Tick "Include large files" (about 5 minutes ' \
               'per GB) to check it, or right-click the file > Scan with Microsoft Defender'
    if 'cannot read' in reason or 'Permission' in reason:
        return 'Windows did not let MLWINT read it (it may be in use or protected)'
    if 'not a PE' in reason or 'invalid PE' in reason:
        return 'it looks like a program but its inside is damaged or unusual, so it could not be checked'
    return reason or 'unknown reason'


def reasons(r):
    """Why MLWINT thinks what it thinks, as short plain sentences (most important first)."""
    out, kind = [], KIND_WORD.get(r.get('format'), 'file')
    parts = {p['part']: p for p in r.get('parts', [])}
    verdict, prob = r.get('verdict'), r.get('probability')
    pct = f' ({prob:.0%} match)' if isinstance(prob, (int, float)) else ''
    if verdict == 'MALICIOUS':
        out.append(f'Our trained detector finds this {kind} very similar to known malware{pct}.')
    elif verdict == 'SUSPICIOUS':
        out.append(f'Our trained detector finds this {kind} somewhat similar to known malware{pct}.')
    else:
        out.append(f'Our trained detector finds this {kind} similar to normal, safe files.')
    for b in r.get('behaviours') or []:
        text = TAG_TEXT.get(b['tag'], b['tag'])
        sure = {'strong': 'It behaves like', 'normal': 'It is likely', 'hint': 'It is possibly'}.get(b.get('tier'),
                                                                                                    'It may be')
        out.append(f'{sure} {text}.')
    fam = r.get('family')
    if fam and fam.get('name'):
        out.append(f'It resembles the malware family "{fam["name"]}".')
    ev = r.get('evidence') or {}
    for ind in ev.get('pdf_findings') or []:
        if ind in PDF_WORDS:
            out.append(f'The PDF {PDF_WORDS[ind]}.')
    tactics = sorted({t.get('tactic') for t in r.get('attack', []) if t.get('tactic') in TACTIC_WORDS})
    if tactics and r.get('format') != 'PDF':                     # PDF findings are already explained above
        out.append('Its code shows it ' + '; '.join(dict.fromkeys(TACTIC_WORDS[t] for t in tactics)) + '.')
    if ev.get('status') in ('timeout', 'failed') or 'capabilities unknown' in parts.get('evidence', {}).get('reason', ''):
        out.append('The detailed code check took too long, so what the program can do is unknown (not "nothing").')
    sig = (r.get('signature') or {}).get('status')
    if sig == 'Valid':
        out.append(f'It is digitally signed by {signer(r) or "a known publisher"} - a good sign that it really '
                   f'comes from that company.')
    elif sig and sig not in ('NotSigned', 'not checked', 'UnknownError'):
        out.append('Its digital signature is broken or not trusted - a bad sign for a program.')
    elif sig == 'NotSigned' and r.get('format') != 'PDF':
        out.append('It is not digitally signed, so its publisher cannot be confirmed.')
    if 'download / temporary' in parts.get('context', {}).get('reason', ''):
        out.append('It is in a Downloads / temporary folder, where unwanted files usually arrive.')
    if 'pdf rule' in parts or r.get('pdf_active_content') == []:
        if r.get('format') == 'PDF' and verdict != 'CLEAN':
            out.append('It contains nothing that can run, so simply opening it is low risk.')
    dc = r.get('deep_check') or {}
    if dc.get('status') == 'completed' and dc.get('findings'):
        out.append('In a safe simulation (the file was never really run) it: '
                   + '; '.join(f['title'] for f in dc['findings'][:5]) + '.')
    ds = r.get('defender_scan') or {}
    if ds.get('status') == 'detected':
        out.insert(0, 'Microsoft Defender detects it as ' + ', '.join(ds.get('threats', [])) + '.')
    elif ds.get('status') == 'clean':
        out.append('Microsoft Defender found no threat in it (scan only - nothing was changed).')
    if r.get('large_file'):
        out.append('It is a very large file, so MLWINT used its large-file check; its detector counts only half '
                   'here.')
    opinion = parts.get('outside opinion')
    if opinion:
        out.append(f'Outside check of its fingerprint: {opinion["reason"]}.')
    for f in (r.get('local_context') or {}).get('facts', []):
        if f.startswith('came from the Internet') or f.startswith('no download mark'):
            continue                                             # shown as "downloaded from" / not useful here
        out.append(f[0].upper() + f[1:] + ('.' if not f.endswith('.') else ''))
    return out


def actions(r):
    return sorted((r.get('advice') or {}).get('actions') or [], key=lambda a: a.get('priority', 9))


def headline(r):
    return (r.get('advice') or {}).get('headline') or r.get('summary') or ''


# ------------------------------------------------------------------------------------------------- html pieces
def box(inner, colour, background, width='100%'):
    return (f'<table width="{width}" cellpadding="10" cellspacing="0" bgcolor="{background}" '
            f'style="border-left: 6px solid {colour}; margin-top:6px; margin-bottom:6px;"><tr><td>{inner}</td></tr>'
            f'</table>')


def action_rows(acts):
    rows = ''
    for a in acts:
        rows += (f'<tr><td valign="top" width="110"><b>{e(PRIORITY.get(a.get("priority"), ""))}</b></td>'
                 f'<td>{e(a.get("action"))}<br><span style="color:#666666;">Why: {e(a.get("because"))}</span>'
                 f'</td></tr>')
    return f'<table cellpadding="3" cellspacing="0" width="100%">{rows}</table>' if rows else ''


def file_card(r, colour, background):
    where = came_from(r)
    head = (f'<p style="font-size:13pt; margin:0;"><b>{e(name_of(r))}</b></p>'
            f'<p style="color:#555555; margin:0;">{e(cap(KIND_WORD.get(r.get("format"), "file")))} in '
            f'{e(folder_of(r))}' + (f' &middot; downloaded from {e(where)}' if where else '')
            + f' &middot; threat score {r.get("score")}/100'
            + (f' &middot; unchanged since {e(r["remembered"]["day"])}' if r.get('remembered') else '') + '</p>')
    body = f'<p style="font-size:12pt; margin-top:8px;"><b>{e(headline(r))}</b></p>'
    acts = actions(r)
    if acts:
        body += '<p style="margin-bottom:2px;"><b>What to do</b></p>' + action_rows(acts)
    why = reasons(r)
    if why:
        body += ('<p style="margin-bottom:2px;"><b>Why MLWINT thinks so</b></p><ul style="margin-top:0;">'
                 + ''.join(f'<li>{e(w)}</li>' for w in why) + '</ul>')
    return box(head + body, colour, background)


def group_key(r):
    return (r.get('level'), KIND_WORD.get(r.get('format'), 'file'), headline(r),
            tuple(a.get('id') for a in actions(r)))


def common_actions(rs):
    """The actions of a group, each in its most common wording (site-specific wording is shown per file)."""
    by_id = OrderedDict()
    for r in rs:
        for a in actions(r):
            by_id.setdefault(a.get('id'), Counter())[(a.get('priority'), a.get('action'), a.get('because'))] += 1
    out = []
    for counts in by_id.values():
        (p, act, because), _ = counts.most_common(1)[0]
        out.append(dict(priority=p, action=act, because=because))
    return sorted(out, key=lambda a: a.get('priority', 9))


def group_block(rs, colour, background):
    """Several files with the same advice: one explanation, then a list of the files."""
    first = rs[0]
    kind = KIND_WORD.get(first.get('format'), 'file')
    counts = Counter(w for r in rs for w in dict.fromkeys(reasons(r)) if not w.startswith('Our trained detector'))
    shared = [w if n == len(rs) else f'{w[:-1] if w.endswith(".") else w} ({n} of {len(rs)} files).'
              for w, n in counts.most_common() if n * 2 >= len(rs)][:6]               # what most of them share
    shared.insert(0, f'Our trained detector finds these {kind}s somewhat or very similar to known malware.')
    title = f'{len(rs)} {kind}s: {headline(first)}' if len(rs) > 1 else None
    if title is None:
        return file_card(first, colour, background)
    body = f'<p style="font-size:12pt; margin:0;"><b>{e(title)}</b></p>'
    if first.get('format') == 'PDF':
        body += ('<p style="color:#555555;">MLWINT\'s PDF checker is still being improved and is cautious: everyday '
                 'documents such as bills, certificates, forms and payslips often land here.</p>')
    acts = common_actions(rs)
    if acts:
        body += '<p style="margin-bottom:2px;"><b>What to do</b></p>' + action_rows(acts)
    if shared:
        body += ('<p style="margin-bottom:2px;"><b>Why MLWINT thinks so</b></p><ul style="margin-top:0;">'
                 + ''.join(f'<li>{e(w)}</li>' for w in shared) + '</ul>')
    rows = ''.join(f'<tr><td>{e(name_of(r))}</td><td>{e(came_from(r) or "not recorded")}</td>'
                   f'<td align="right">{r.get("score")}</td></tr>' for r in sorted(rs, key=lambda r: -r['score']))
    body += ('<table width="100%" cellpadding="3" cellspacing="0" border="1" style="border-color:#cccccc; '
             'border-collapse:collapse; margin-top:6px;"><tr bgcolor="#ffffff"><td><b>File</b></td>'
             f'<td><b>Downloaded from</b></td><td align="right"><b>Score</b></td></tr>{rows}</table>')
    return box(body, colour, background)


def name_columns(rs, columns=3):
    names = sorted((name_of(r) for r in rs), key=str.lower)
    per = -(-len(names) // columns)
    cols = [names[i * per:(i + 1) * per] for i in range(columns)]
    cells = ''.join(f'<td valign="top" width="{100 // columns}%">' + '<br>'.join(e(n) for n in c) + '</td>'
                    for c in cols)
    return f'<table width="100%" cellpadding="4" style="font-size:9pt;"><tr>{cells}</tr></table>'


def overall(groups, skipped_n):
    n = {k: len(v) for k, v in groups.items()}
    running = [r for r in groups['act'] + groups['careful'] if was_run(r)]
    if n['act']:
        s = (f'MLWINT found {n["act"]} file{"s" if n["act"] > 1 else ""} that '
             f'{"are" if n["act"] > 1 else "is"} very likely harmful. Start with "Act now" below.')
    elif n['careful']:
        s = (f'Nothing looks clearly dangerous, but {n["careful"]} file{"s" if n["careful"] > 1 else ""} '
             f'need{"" if n["careful"] > 1 else "s"} care before you open {"them" if n["careful"] > 1 else "it"}.')
    elif n['look']:
        s = f'Nothing dangerous was found. {n["look"]} files show weak warning signs; most are probably fine.'
    else:
        s = 'Nothing worrying was found in the files MLWINT checked.'
    if running:
        s += f' {len(running)} of the flagged files may already have been run on this PC - see their steps.'
    if n['failed'] or skipped_n:
        s += ' Some files were not checked (see the end of the report).'
    return s

def memory_line(report, results):
    n = sum(1 for r in results if r.get('remembered'))
    if not n:
        return ''
    return (f'{n} of these files were unchanged since an earlier MLWINT check (same contents, size and dates), so '
            f'their earlier result was used; whether they have been run, are running or start automatically was '
            f'checked again now.')


def build_html(report, source_name=''):
    results = report.get('results', [])
    groups = {k: [] for k in GROUPS}
    for r in results:
        groups[LEVEL_GROUP.get(r.get('level'), 'failed') if r.get('status') == 'assessed' else 'failed'].append(r)
    for k in groups:
        groups[k].sort(key=lambda r: -(r.get('score') or 0))
    skipped = report.get('not_checked') or {}
    skipped_n = sum(skipped.values())
    started = report.get('started', '')
    paths = report.get('paths') or []
    h = ['<html><body style="font-family:\'Segoe UI\'; font-size:10pt;">']
    h.append('<table width="100%" cellpadding="14" cellspacing="0" bgcolor="#0b120b"><tr><td>'
             '<span style="color:#7cf05a; font-size:9pt; letter-spacing:2px;">[ MLWINT - MALWARE INTELLIGENCE ]'
             '</span><br><span style="color:#e9f2e9; font-size:20pt;">Your file check</span></td>'
             '<td align="right" valign="middle"><span style="color:#8a9c8a; font-size:8pt;">read-only check<br>'
             'nothing was deleted, moved,<br>run or uploaded</span></td></tr></table>')
    if memory_line(report, results):
        h.append(f'<p style="color:#555555;">{e(memory_line(report, results))}</p>')
    h.append(f'<p style="color:#555555; margin-top:2px;">{e(started)} &middot; checked: {e(", ".join(paths))}</p>')
    h.append(box(f'<p style="font-size:14pt; margin:0;"><b>{e(overall(groups, skipped_n))}</b></p>',
                 '#333333', '#f7f7f7'))

    # traffic-light counts
    cells = ''
    for k, (title, colour, bg, _) in GROUPS.items():
        cells += (f'<td bgcolor="{bg}" align="center" style="border-top: 5px solid {colour};">'
                  f'<span style="font-size:20pt; color:{colour};"><b>{len(groups[k])}</b></span><br>{e(title)}</td>')
    if skipped_n:
        cells += (f'<td bgcolor="#f2f2f2" align="center" style="border-top: 5px solid #999999;">'
                  f'<span style="font-size:20pt; color:#777777;"><b>{skipped_n}</b></span><br>Skipped by you</td>')
    h.append(f'<table width="100%" cellpadding="8" cellspacing="6"><tr>{cells}</tr></table>')

    # the few things to do now
    todo = []
    for r in groups['act'] + groups['careful']:
        a = actions(r)
        if a:
            todo.append(f'<li><b>{e(name_of(r))}</b>: {e(a[0]["action"])}</li>')
    if groups['look']:
        todo.append(f'<li>{len(groups["look"])} files are "Worth a look": nothing urgent - read their section when '
                    f'you have time.</li>')
    if todo:
        h.append('<h2>What to do now</h2><ol>' + ''.join(todo[:12]) + '</ol>'
                 + ('<p>... and more below.</p>' if len(todo) > 12 else ''))
    h.append('<p style="color:#555555;">MLWINT only reads your files: it never deletes, moves, runs or uploads '
             'anything. Every step in this report is for you to do. A score is a warning based on what MLWINT can '
             'see, not proof - well-known programs are sometimes flagged, and new malware can be missed.</p>')

    # how to read
    legend = ''.join(f'<tr><td width="18" bgcolor="{c}"></td><td width="110"><b>{e(t)}</b></td><td>{e(d)}</td></tr>'
                     for t, c, _, d in GROUPS.values())
    h.append('<h3>How to read this report</h3><table cellpadding="4" cellspacing="2">' + legend + '</table>'
             '<p style="color:#555555;">Each file gets a threat score from 0 (no sign of malware) to 100. '
             'Act now = 60 or more, Be careful = 40-59, Worth a look = 20-39, Looks fine = below 20.</p>')

    # sections
    for k in ('act', 'careful', 'look'):
        rs = groups[k]
        if not rs:
            continue
        title, colour, bg, desc = GROUPS[k]
        h.append(f'<h2 style="color:{colour}; page-break-before: always;">{e(title)} ({len(rs)})</h2>'
                 f'<p>{e(desc[0].upper() + desc[1:])}.</p>')
        if k in ('act', 'careful') and len(rs) <= 25:
            h += [file_card(r, colour, bg) for r in rs]
        else:
            buckets = OrderedDict()
            for r in rs:
                buckets.setdefault(group_key(r), []).append(r)
            for members in sorted(buckets.values(), key=lambda m: (-max(x['score'] for x in m), -len(m))):
                h.append(group_block(members, colour, bg))

    fine = groups['fine']
    if fine:
        title, colour, bg, desc = GROUPS['fine']
        kinds = Counter(KIND_WORD.get(r.get('format'), 'file') for r in fine)
        h.append(f'<h2 style="color:{colour}; page-break-before: always;">{e(title)} ({len(fine)})</h2>'
                 f'<p>No meaningful sign of malware in ' + ', '.join(f'{n} {k}{"s" if n > 1 else ""}'
                                                                   for k, n in kinds.most_common())
                 + '. This is not a guarantee, but nothing needs doing.</p>' + name_columns(fine))

    failed = groups['failed']
    if failed or skipped_n:
        title, colour, bg, desc = GROUPS['failed']
        h.append(f'<h2 style="color:{colour};">Not checked</h2>')
        why = OrderedDict()
        for r in failed:
            why.setdefault(plain_failure(r.get('reason')), []).append(r)
        for text, rs in why.items():
            n = len(rs)
            h.append(box(f'<p style="margin:0;"><b>{n} file{"s" if n > 1 else ""}</b>: {e(cap(text))}.</p>'
                         + name_columns(rs, 2), colour, bg))
        if skipped_n:
            h.append('<p><b>Skipped because of your file-type choice:</b> '
                     + ', '.join(f'{n} {NOT_CHECKED_WORDS.get(k, k)}' for k, n in skipped.items() if n)
                     + '. These have no result at all - they were not looked at.</p>')

    # words
    words = [('Threat score', 'MLWINT\'s 0-100 summary of all warning signs it found for one file.'),
             ('Detector', 'a model trained on hundreds of thousands of known safe and harmful files; it says how '
                          'similar a file is to known malware.'),
             ('Phishing document', 'a document that pretends to be a bill, delivery note, bank or login page to '
                                   'make you click a link or type a password.'),
             ('JavaScript in a PDF', 'small programs inside a PDF. Normal documents rarely need them; harmful PDFs '
                                     'use them to attack the PDF reader.'),
             ('Digital signature', 'a seal from the software publisher. A valid one shows who made the program; it '
                                   'does not prove the program is wanted.'),
             ('Potentially unwanted program', 'not a virus, but software that adds ads, toolbars or extra offers.'),
             ('Safe simulation', 'MLWINT can imitate Windows to watch what a program would try to do, without ever '
                                 'really running it.'),
             ('Downloaded from', 'Windows marks files downloaded by your browser with the website they came from.')]
    h.append('<h2 style="page-break-before: always;">Words used in this report</h2><table cellpadding="4">'
             + ''.join(f'<tr><td valign="top" width="170"><b>{e(w)}</b></td><td>{e(d)}</td></tr>' for w, d in words)
             + '</table>')
    if source_name:
        h.append(f'<p style="color:#888888;">Technical details for experts: {e(source_name)} and the .txt '
                 f'report with the same name. Made by MLWINT on {time.strftime("%Y-%m-%d %H:%M")}.</p>')
    h.append('</body></html>')
    return ''.join(h)


def make_document(report, source_name=''):
    """The report as a Qt text document (used for the PDF, and for previews)."""
    global _APP
    from PySide6.QtGui import QFont, QGuiApplication, QTextDocument
    _APP = QGuiApplication.instance() or QGuiApplication(['mlwint-report'])   # Qt needs one for fonts; kept alive
    doc = QTextDocument()
    doc.setDefaultFont(QFont('Segoe UI', 10))
    doc.setDefaultStyleSheet(STYLE)
    doc.setHtml(build_html(report, source_name))
    return doc


def write_pdf(json_path, pdf_path=None):
    """analysis-<stamp>.json -> analysis-<stamp>.pdf (same folder unless pdf_path is given). Returns the path."""
    from PySide6.QtCore import QMarginsF
    from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter
    json_path = Path(json_path)
    report = json.loads(json_path.read_text(encoding='utf-8'))
    pdf_path = Path(pdf_path) if pdf_path else json_path.with_suffix('.pdf')
    doc = make_document(report, json_path.name)
    writer = QPdfWriter(str(pdf_path))
    writer.setPageSize(QPageSize(QPageSize.A4))
    writer.setPageMargins(QMarginsF(15, 15, 15, 15), QPageLayout.Millimeter)
    writer.setTitle('MLWINT file check ' + str(report.get('started', '')))
    writer.setCreator('MLWINT')
    doc.print_(writer)
    del writer                                                    # closes the file
    return pdf_path