"""MLWINT Dashboard (home page). Save as MLWINT/src/gui/dashboard.py
  - hero: the protection status in a big two-tone headline that reveals word by word, quick actions, and the
    threat orb showing the highest score of the last scan (calm green when safe, red and restless when not)
  - the last scan in numbers: five [ 01 ]..[ 05 ] columns that count up
  - recent findings (the worst files of the last scan) and MLWINT's parts as floating glass tiles
Read-only like the rest: it only reads MLWINT's own reports, memory and settings.
"""
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget, QFrame

from . import fx, theme
from .history import HistoryIndex

DOWNLOADS = Path.home() / 'Downloads'
STALE_DAYS = 7
GROUPS = (('Act now', ('SEVERE', 'HIGH'), theme.LEVEL['HIGH']), ('Be careful', ('ELEVATED',), theme.LEVEL['ELEVATED']),
          ('Worth a look', ('GUARDED',), theme.LEVEL['GUARDED']), ('Looks fine', ('LOW',), theme.LEVEL['LOW']))


def days_ago(started):
    try:
        return (datetime.now() - datetime.strptime(started, '%Y-%m-%d %H:%M:%S')).days
    except (TypeError, ValueError):
        return None


def status_of(entry):
    """(headline first part, second part, sentence, glow colour) for the hero, from the newest scan's summary."""
    if entry is None:
        return ('Welcome to', 'MLWINT - run your first check', 'A quick scan of your Downloads folder takes a few '
                'minutes. Nothing is ever deleted, moved, run or uploaded.', theme.ACCENT)
    lv = entry['levels']
    act = lv.get('SEVERE', 0) + lv.get('HIGH', 0)
    careful = lv.get('ELEVATED', 0)
    when = f'Last scan {entry["started"]} - {entry["where"]}.'
    age = days_ago(entry['started'])
    old = f' It is {age} days old: scan again to stay up to date.' if age is not None and age >= STALE_DAYS else ''
    if act:
        return (f'{act} file{"s" if act > 1 else ""} need{"" if act > 1 else "s"}', 'your attention now',
                f'Very likely harmful. Open the findings below and follow the steps. {when}{old}',
                theme.LEVEL['SEVERE'])
    if careful:
        return (f'{careful} file{"s" if careful > 1 else ""} to', 'handle with care',
                f'Clear warning signs: do not open {"them" if careful > 1 else "it"} until you know the source. '
                f'{when}{old}', theme.LEVEL['ELEVATED'])
    return ('Your PC looks', 'safe and quiet', f'Your last scan found no file that needs action. {when}{old}',
            theme.ACCENT)


class Dashboard(QWidget):
    quick_scan = Signal()          # scan Downloads now
    choose_files = Signal()        # go to the Scan page
    whole_pc = Signal()            # start a whole-PC scan
    open_report = Signal(str)      # report file name -> History page
    open_pdf = Signal(str)         # report file name -> its PDF

    def __init__(self, reports_folder=None, memory_count=None, health=None, keys=None):
        """memory_count / health / keys: functions giving the number of remembered files, the health rows and the
        saved keys (passed in by the window so this page never loads models itself)."""
        super().__init__()
        self.index = HistoryIndex(reports_folder)
        self.memory_count, self.health, self.keys = memory_count, health, keys
        self.latest = None

        # ---- hero
        self.hero = fx.StreakPanel()
        self.hero.setMinimumHeight(400)
        hl = QHBoxLayout(self.hero)
        hl.setContentsMargins(46, 34, 40, 34)
        left = QVBoxLayout()
        left.setSpacing(12)
        tag = QLabel('[ PROTECTION STATUS ]')
        tag.setObjectName('tag')
        self.title = fx.RevealTitle(size=40, icon='shield')
        self.hero_text = QLabel()
        self.hero_text.setObjectName('soft')
        self.hero_text.setWordWrap(True)
        self.hero_text.setMaximumWidth(640)
        self.quick_btn = theme.PillButton('Quick scan: Downloads', 'primary')
        self.quick_btn.setToolTip(str(DOWNLOADS))
        self.choose_btn = theme.PillButton('Choose files', 'ghost', 'scan')
        self.pc_btn = theme.PillButton('Whole PC', 'ghost', 'shield')
        self.pc_btn.setToolTip('Every fixed drive. The first time can take hours; later scans only check new or '
                               'changed files.')
        self.quick_btn.clicked.connect(self.quick_scan.emit)
        self.choose_btn.clicked.connect(self.choose_files.emit)
        self.pc_btn.clicked.connect(self.whole_pc.emit)
        actions = QHBoxLayout()
        actions.setSpacing(10)
        for b in (self.quick_btn, self.choose_btn, self.pc_btn):
            actions.addWidget(b)
        actions.addStretch()
        left.addWidget(tag)
        left.addWidget(self.title)
        left.addWidget(self.hero_text)
        left.addStretch()
        left.addLayout(actions)
        self.orb = fx.ThreatOrb(caption='highest score in your last scan')
        hl.addLayout(left, 3)
        hl.addWidget(self.orb, 2)

        # ---- the last scan in numbers
        numbers = QHBoxLayout()
        numbers.setSpacing(0)
        self.stats = {}
        for i, (name, _, colour) in enumerate(GROUPS + (('Not checked', (), theme.MUTED),)):
            f, n = theme.stat_card('-', name, colour, f'[ 0{i + 1} ]')
            self.stats[name] = n
            numbers.addWidget(f, 1)

        # ---- recent findings
        self.findings_card, fl = theme.card('Recent findings', '[ LAST SCAN ]')
        self.findings_box = QVBoxLayout()
        self.findings_box.setSpacing(2)
        fl.addLayout(self.findings_box)
        fl.addStretch()
        buttons = QHBoxLayout()
        self.history_btn = theme.PillButton('See the whole scan', 'ghost', 'clock')
        self.pdf_btn = theme.PillButton('Open last report (PDF)', 'ghost', 'doc')
        self.history_btn.clicked.connect(lambda: self.latest and self.open_report.emit(self.latest['file']))
        self.pdf_btn.clicked.connect(lambda: self.latest and self.open_pdf.emit(self.latest['file']))
        buttons.addWidget(self.history_btn)
        buttons.addWidget(self.pdf_btn)
        buttons.addStretch()
        fl.addLayout(buttons)

        # ---- MLWINT's parts as floating tiles
        parts = QWidget()
        pl = QVBoxLayout(parts)
        pl.setContentsMargins(0, 0, 0, 0)
        t = QLabel('[ ENGINES ]')
        t.setObjectName('tag')
        h = QLabel('Working for you')
        h.setObjectName('cardTitle')
        pl.addWidget(t)
        pl.addWidget(h)
        self.tile_grid = QGridLayout()
        self.tile_grid.setSpacing(4)
        pl.addLayout(self.tile_grid)
        self.tiles = []

        lower = QHBoxLayout()
        lower.setSpacing(22)
        lower.addWidget(self.findings_card, 3)
        lower.addWidget(parts, 2)

        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(40, 6, 40, 110)
        lay.setSpacing(26)
        lay.addWidget(self.hero)
        lay.addLayout(numbers)
        lay.addWidget(fx.glass_line())
        lay.addLayout(lower)
        lay.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self.refresh()

    def refresh(self):
        entries = [e for e in self.index.load() if e['files']]    # an empty or stopped-at-once scan says nothing
        self.latest = entries[0] if entries else None
        first, second, text, glow = status_of(self.latest)
        self.title.set_text(first, second, 'shield')
        self.hero_text.setText(text)
        self.hero.set_glow(glow)
        lv = self.latest['levels'] if self.latest else {}
        for name, levels, _ in GROUPS:
            if self.latest:
                fx.count_up(self.stats[name], sum(lv.get(l, 0) for l in levels))
            else:
                self.stats[name].setText('-')
        if self.latest:
            fx.count_up(self.stats['Not checked'], self.latest['not_checked'])
        else:
            self.stats['Not checked'].setText('-')
        self.history_btn.setEnabled(self.latest is not None)
        self.pdf_btn.setEnabled(self.latest is not None)
        results = self.fill_findings()
        worst = max((r for r in results if r.get('status') == 'assessed'), key=lambda r: r['score'], default=None)
        if worst:
            self.orb.set_result(worst['score'], worst['level'])
        else:
            self.orb.clear()
        self.fill_tiles()

    def fill_findings(self):
        while self.findings_box.count():
            item = self.findings_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not self.latest:
            self.findings_box.addWidget(self._soft('No scan yet. Start with a quick scan of your Downloads.'))
            return []
        try:
            results = self.index.read(self.latest['file']).get('results', [])
        except (OSError, ValueError):
            results = []
        flagged = sorted((r for r in results if r.get('status') == 'assessed' and r.get('level') != 'LOW'),
                         key=lambda r: -r['score'])
        if not flagged:
            self.findings_box.addWidget(self._soft('Nothing above "Looks fine" in the last scan.'))
            return results
        for r in flagged[:6]:
            line = QFrame()
            ll = QHBoxLayout(line)
            ll.setContentsMargins(0, 7, 0, 7)
            score = QLabel(str(r['score']))
            score.setFixedWidth(42)
            score.setStyleSheet(f'color: {theme.LEVEL[r["level"]]}; font-family: "{theme.DISPLAY}"; '
                                f'font-size: 17pt; font-weight: 300;')
            ll.addWidget(score)
            col = QVBoxLayout()
            col.setSpacing(0)
            name = QLabel(Path(str(r['path'])).name)
            name.setToolTip(str(r['path']))
            what = QLabel((r.get('advice') or {}).get('headline') or r.get('summary', ''))
            what.setObjectName('muted')
            col.addWidget(name)
            col.addWidget(what)
            ll.addLayout(col, 1)
            ll.addWidget(theme.chip(theme.LEVEL_WORDS[r['level']], theme.LEVEL[r['level']]))
            line.setStyleSheet('QFrame { border-bottom: 1px solid rgba(124,240,90,0.07); }'
                               'QLabel { border: none; }')
            self.findings_box.addWidget(line)
        if len(flagged) > 6:
            self.findings_box.addWidget(self._soft(f'... and {len(flagged) - 6} more in the whole scan.'))
        return results

    def fill_tiles(self):
        while self.tile_grid.count():
            item = self.tile_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        rows = self.health() if self.health else []
        ok = {name.split(' (')[0]: good for name, good, _ in rows}
        n = self.memory_count() if self.memory_count else 0
        keys = self.keys() if self.keys else []
        tiles = [('Read-only', 'nothing is ever changed', True),
                 ('Detector', 'ready' if ok.get('Detectors', True) else 'missing', False),
                 ('capa', 'code check ' + ('ready' if ok.get('capa', True) else 'missing'), False),
                 ('Speakeasy', 'safe simulation ' + ('ready' if ok.get('Speakeasy', True) else 'missing'), False),
                 ('Memory', f'{n:,} files remembered', False),
                 ('Hash lookup', 'keys saved' if keys else 'off - no keys', False)]
        for i, (title, sub, lit) in enumerate(tiles):
            t = fx.FloatingTile(title, sub, lit, phase=i * 0.9)
            self.tile_grid.addWidget(t, i // 2, i % 2)

    @staticmethod
    def _soft(text):
        lbl = QLabel(text)
        lbl.setObjectName('soft')
        lbl.setWordWrap(True)
        return lbl