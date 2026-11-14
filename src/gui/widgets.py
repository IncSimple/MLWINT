"""MLWINT GUI building blocks (G1b + G2). Save as MLWINT/src/gui/widgets.py
  TypePicker   - which kinds of file to check, in plain words (Programs: 32-bit / 64-bit / .NET, PDF documents)
  ThreatGauge  - the 0-100 threat meter as a half-circle dial
  DetailPanel  - everything MLWINT found about one file: what to do, why this score, what it can do (ATT&CK),
                 facts from this PC, family / behaviour, deep check, outside opinion
Plain look on purpose: the visual design comes later (before G5); these widgets only decide WHAT is shown.
"""
import html
from pathlib import Path

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QTextBrowser, QToolButton, QVBoxLayout, QWidget

LEVEL_STRONG = {'LOW': '#2e8b57', 'GUARDED': '#3a78c2', 'ELEVATED': '#c99a06', 'HIGH': '#e07020',
                'SEVERE': '#c62828'}
MUTED = '#8a8a8a'                     # secondary text, readable on light and dark backgrounds
PRIORITY = {1: 'Now', 2: 'Clean up', 3: 'Protect', 4: 'Check'}
PROGRAM_KINDS = ('win32', 'win64', 'dotnet')


# ---------------------------------------------------------------------------------------------- file types
class TypePicker(QWidget):
    """Check: [x] Everything  [x] Programs (+ details: 32-bit / 64-bit / .NET)  [x] PDF documents"""
    changed = Signal()

    def __init__(self):
        super().__init__()
        self.everything = QCheckBox('Everything')
        self.programs = QCheckBox('Programs and installers (.exe, .dll, .msi setup files ...)')
        self.programs.setTristate(True)
        self.more = QToolButton()
        self.more.setText('choose kinds')
        self.more.setCheckable(True)
        self.more.setToolTip('Choose 32-bit, 64-bit or .NET programs separately')
        self.kind = {'win32': QCheckBox('32-bit programs'), 'win64': QCheckBox('64-bit programs'),
                     'dotnet': QCheckBox('.NET programs'), 'pdf': QCheckBox('PDF documents')}
        self.kind['pdf'].setToolTip('PDF checking is still being improved: ordinary PDFs with links can score '
                                    'GUARDED. Untick to check programs only.')
        self.kind['dotnet'].setToolTip('Programs written in C# / VB.NET (they need the .NET runtime)')
        for c in self.kind.values():
            c.setChecked(True)
        self.everything.clicked.connect(self._everything_clicked)
        self.programs.clicked.connect(self._programs_clicked)
        for c in self.kind.values():
            c.toggled.connect(self._refresh)
        self.more.toggled.connect(self._show_more)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(QLabel('Check:'))
        for w in (self.everything, self.programs, self.more, self.kind['pdf']):
            row.addWidget(w)
        row.addStretch()
        self.sub = QWidget()
        sub = QHBoxLayout(self.sub)
        sub.setContentsMargins(60, 0, 0, 0)
        for k in PROGRAM_KINDS:
            sub.addWidget(self.kind[k])
        sub.addStretch()
        self.sub.setVisible(False)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        lay.addLayout(row)
        lay.addWidget(self.sub)
        self._refresh()

    def types(self):
        return {k for k, c in self.kind.items() if c.isChecked()}

    def set_types(self, kinds):
        for k, c in self.kind.items():
            c.setChecked(k in kinds)

    def _everything_clicked(self):
        on = self.everything.isChecked()
        for c in self.kind.values():
            c.setChecked(on)

    def _programs_clicked(self):
        on = not all(self.kind[k].isChecked() for k in PROGRAM_KINDS)     # partial or none -> all on
        for k in PROGRAM_KINDS:
            self.kind[k].setChecked(on)

    def _show_more(self, on):
        self.sub.setVisible(on)
        self.more.setText('hide kinds' if on else 'choose kinds')

    def _refresh(self, *_):
        n = sum(self.kind[k].isChecked() for k in PROGRAM_KINDS)
        self.programs.setCheckState(Qt.Checked if n == 3 else Qt.Unchecked if n == 0 else Qt.PartiallyChecked)
        if 0 < n < 3:
            self.sub.setVisible(True)
            self.more.setChecked(True)
        self.everything.setChecked(len(self.types()) == len(self.kind))
        self.changed.emit()


# ---------------------------------------------------------------------------------------------- gauge
class ThreatGauge(QWidget):
    def __init__(self):
        super().__init__()
        self.score, self.level = None, ''
        self.setMinimumSize(170, 110)

    def set_result(self, score, level):
        self.score, self.level = score, level
        self.update()

    def clear(self):
        self.set_result(None, '')

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        size = min(w - 20, (h - 20) * 2)
        rect = QRectF((w - size) / 2, 10, size, size)
        pen = QPen(QColor('#dddddd'), 14, Qt.SolidLine, Qt.FlatCap)
        p.setPen(pen)
        p.drawArc(rect, 180 * 16, -180 * 16)
        if self.score is not None:
            colour = QColor(LEVEL_STRONG.get(self.level, '#888888'))
            pen.setColor(colour)
            p.setPen(pen)
            p.drawArc(rect, 180 * 16, -int(180 * 16 * max(0, min(100, self.score)) / 100))
            p.setPen(self.palette().windowText().color())     # readable in light and dark Windows themes
            f = QFont()
            f.setPointSize(20)
            f.setBold(True)
            p.setFont(f)
            centre_y = rect.center().y()
            p.drawText(QRectF(0, centre_y - 34, w, 34), Qt.AlignHCenter | Qt.AlignBottom, str(self.score))
            f.setPointSize(10)
            p.setFont(f)
            p.setPen(colour)
            p.drawText(QRectF(0, centre_y, w, 22), Qt.AlignHCenter | Qt.AlignTop, self.level)
        p.end()


# ---------------------------------------------------------------------------------------------- details
def _e(x):
    return html.escape(str(x if x is not None else ''))


def _section(title, body):
    return f'<h3 style="margin-top:14px; margin-bottom:4px;">{_e(title)}</h3>{body}' if body else ''


def detail_html(r):
    """Everything about one result as simple HTML (the look is styled later)."""
    if r.get('status') != 'assessed':
        return (f'<h2>{_e(Path(str(r.get("path"))).name)}</h2><p>{_e(r.get("path"))}</p>'
                f'<p><b>Not analysed</b> ({_e(r.get("status"))}): {_e(r.get("reason"))}</p>')
    out = []
    adv = r.get('advice') or {}
    out.append(f'<p style="font-size:13pt;"><b>{_e(adv.get("headline") or r.get("summary"))}</b></p>')
    if adv.get('headline') and r.get('summary'):
        out.append(f'<p>{_e(r["summary"])}</p>')

    # what to do
    acts = adv.get('actions') or []
    if acts:
        rows = ''.join(f'<tr><td valign="top" style="padding-right:8px; white-space:nowrap;"><b>'
                       f'{_e(PRIORITY.get(a.get("priority"), a.get("priority")))}</b></td>'
                       f'<td>{_e(a.get("action"))}<br><span style="color:{MUTED};">because {_e(a.get("because"))}'
                       f'</span></td></tr>' for a in acts)
        out.append(_section('What to do', f'<table cellspacing="4">{rows}</table>'))
    notes = adv.get('notes') or []
    if notes:
        out.append('<ul>' + ''.join(f'<li>{_e(n)}</li>' for n in notes) + '</ul>')

    # why this score
    rows = ''
    for pt in r.get('parts', []):
        colour = '#e04848' if pt['points'] > 0 else '#2fa35a' if pt['points'] < 0 else MUTED
        rows += (f'<tr><td align="right" style="color:{colour}; padding-right:8px;"><b>{pt["points"]:+.1f}</b></td>'
                 f'<td style="padding-right:8px;">{_e(pt["part"])}</td><td>{_e(pt["reason"])}</td></tr>')
    limits = []
    if r.get('floor'):
        limits.append(f'never below {r["floor"]:g} (detector verdict {r.get("verdict")})')
    if r.get('cap', 100) < 100:
        limits.append(f'capped at {r["cap"]:g}: a PDF with nothing that can run')
    body = f'<table cellspacing="2">{rows}</table>' + (f'<p style="color:{MUTED};">{_e("; ".join(limits))}</p>'
                                                       if limits else '')
    prob = r.get('probability')
    head = (f'<p>{_e(r.get("format"))} file, detector verdict <b>{_e(r.get("verdict"))}</b>'
            + (f' (malware probability {prob:.1%})' if isinstance(prob, (int, float)) else '') + '</p>')
    out.append(_section('Why this score', head + body))

    # family / behaviour
    fam, beh = r.get('family'), r.get('behaviours') or []
    fb = ''
    if fam:
        fb += (f'<p>Family: <b>{_e(fam.get("name"))}</b> (confidence {fam.get("confidence", 0):.0%}; right '
               f'{fam.get("test_precision", 0):.0%} of the time on test)</p>')
    if beh:
        fb += '<p>Behaves like: ' + ', '.join(f'<b>{_e(b["tag"])}</b> ({_e(b.get("tier"))})' for b in beh) + '</p>'
    out.append(_section('Family and behaviour', fb))

    # ATT&CK
    items = ''
    for t in r.get('attack', []):
        e = t.get('explanation') or {}
        link = e.get('url') or f'https://attack.mitre.org/techniques/{t["id"].replace(".", "/")}/'
        summary = e.get('summary') or ''
        summary = summary[:280] + ('...' if len(summary) > 280 else '')
        mit = '; '.join(f'{m["id"]} {m["name"]}' for m in (e.get('mitigations') or [])[:3])
        items += (f'<li><a href="{_e(link)}">{_e(t["id"])}</a> <b>{_e(t["technique"])}</b> '
                  f'<span style="color:{MUTED};">({_e(t.get("tactic"))}; seen by {_e("/".join(sorted(set(t["sources"]))))})'
                  f'</span>' + (f'<br>{_e(summary)}' if summary else '')
                  + (f'<br><span style="color:{MUTED};">MITRE mitigations: {_e(mit)}</span>' if mit else '') + '</li>')
    out.append(_section('What it can do (MITRE ATT&CK)', f'<ul>{items}</ul>' if items else ''))

    # this PC
    facts = (r.get('local_context') or {}).get('facts') or []
    out.append(_section('On this PC', '<ul>' + ''.join(f'<li>{_e(f)}</li>' for f in facts) + '</ul>' if facts else ''))

    # deep check
    dc = r.get('deep_check')
    if dc:
        txt = f'<p>Emulation: {_e(dc.get("status"))}'
        if dc.get('status') != 'completed':
            txt += f' - {_e(dc.get("reason"))}'
        txt += '</p>'
        found = dc.get('findings') or []
        if found:
            txt += '<ul>' + ''.join(f'<li>{_e(f.get("title"))}</li>' for f in found[:10]) + '</ul>'
        servers = (dc.get('observed') or {}).get('servers') or []
        if servers:
            txt += f'<p>Tried to contact: {_e(", ".join(servers[:10]))}</p>'
        out.append(_section('Deep check', txt))
    elif r.get('deep_check_reason'):
        out.append(_section('Deep check', f'<p style="color:{MUTED};">not run: {_e(r["deep_check_reason"])}</p>'))

    # outside opinion links
    links = [(s, v.get('link')) for s, v in (r.get('reputation') or {}).items() if v.get('link')]
    if links:
        out.append(_section('Outside opinion', '<p>' + ' &nbsp; '.join(
            f'<a href="{_e(u)}">{_e(s)}</a>' for s, u in links) + '</p>'))

    # file facts
    sig = r.get('signature') or {}
    facts = [f'path: {r.get("path")}', f'SHA-256: {r.get("sha256")}']
    if r.get('remembered'):
        facts.insert(0, f'remembered: unchanged since the check on {r["remembered"]["day"]} - that result was '
                        f'used; PC facts refreshed now')
    if r.get('large_file'):
        ds = r.get('defender_scan') or {}
        facts.insert(0, 'large-file check: signature, report-only Microsoft Defender scan ('
                        + {'clean': 'no threat found', 'detected': 'DETECTED: ' + ', '.join(ds.get('threats', []))}
                        .get(ds.get('status'), 'not available') + '), detector at half weight')
    if sig.get('status') and sig.get('status') != 'not checked':
        facts.append(f'digital signature: {sig.get("status")}' + (f' ({sig["signer"]})' if sig.get('signer') else ''))
    out.append(_section('File', f'<p style="color:{MUTED};">' + '<br>'.join(_e(f) for f in facts) + '</p>'))
    return ''.join(out)


class DetailPanel(QWidget):
    def __init__(self):
        super().__init__()
        from .fx import ThreatOrb                               # the living orb replaces the old dial
        self.gauge = ThreatOrb(compact=True)
        self.gauge.setFixedSize(190, 196)
        self.title = QLabel('Select a file to see what MLWINT found.')
        self.title.setWordWrap(True)
        self.title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.body = QTextBrowser()
        self.body.setOpenExternalLinks(True)                    # MITRE / MalwareBazaar / VirusTotal pages
        top = QHBoxLayout()
        top.addWidget(self.gauge)
        top.addWidget(self.title, 1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(top)
        lay.addWidget(self.body, 1)
        self.result = None

    def show_result(self, r):
        self.result = r
        if r is None:
            self.gauge.clear()
            self.title.setText('Select a file to see what MLWINT found.')
            self.body.clear()
            return
        ok = r.get('status') == 'assessed'
        self.gauge.set_result(r['score'], r['level']) if ok else self.gauge.clear()
        name = Path(str(r.get('path'))).name
        sub = f'{r.get("format")} - {r.get("level")}' if ok else str(r.get('status', '')).upper()
        self.title.setText(f'<span style="font-size:17pt; font-weight:300;">{_e(name)}</span><br>'
                           f'<span style="color:{MUTED};">{_e(sub)}</span>')
        self.body.setHtml(detail_html(r))