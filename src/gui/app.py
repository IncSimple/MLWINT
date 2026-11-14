"""MLWINT main window. Save as MLWINT/src/gui/app.py   (start it with scripts/mlwint_gui.py)
Layout: a top bar (logo + live status pill), the pages, and a floating pill navigation at the bottom:
  Dashboard (dashboard.py)  Scan (here)  History (history.py)  Settings (settings_tab.py)  Help (help_page.py)
Look: theme.py (colours, fonts, buttons); motion: fx.py (threat orb, light streaks, word reveal, page slides).
Scan: choose what to check (files and folders, or the whole PC) -> options -> Start scan. Results appear while the
scan runs, sorted worst first at the end; click a row to see everything MLWINT found about that file.
Unchanged files come from the memory (src/detection/scan_memory.py) and are marked 'remembered'.
The same reports as the command line are written to reports/analyse/ (easy-to-read PDF, technical .txt, .json).
READ-ONLY: no button deletes, moves, quarantines or runs a scanned file. Right-click -> Show in Explorer only
highlights a file in its folder; links in the detail panel open MITRE / MalwareBazaar / VirusTotal pages.
"""
import json, os, sys
from pathlib import Path

from PySide6.QtCore import QPointF, QSize, Qt, QThread
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QRadialGradient
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout,
                               QLabel, QListWidget, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QRadioButton, QScrollArea, QSpinBox, QTabWidget, QToolButton,
                               QVBoxLayout, QWidget)

from src.app_settings import load_settings, models_dir as app_models_dir, save_settings
from . import fx, theme
from .dashboard import DOWNLOADS, Dashboard
from .help_page import VERSION, HelpPage
from .history import HistoryTab
from .settings_tab import SettingsTab, health
from .results_view import ResultsView, how_checked, show_in_explorer  # noqa: F401  (show_in_explorer: old name)
from .widgets import TypePicker
from .worker import ScanWorker, cli

CHOICES = dict(evidence=['needed', 'all', 'none'], deep=['needed', 'all', 'none'],
               context=['needed', 'all', 'none'], reputation=['off', 'flagged', 'all'])
TIPS = dict(evidence='capa / PDF check. needed = flagged files, risky places and all PDFs (capa: ~20-40 s a program)',
            deep='Speakeasy emulation. needed = flagged files and unsigned files in Downloads / Temp / AppData / Desktop',
            context='where it came from, run before, running now, autostart, Defender history. needed = above LOW',
            reputation='hash lookup with YOUR API keys: sends ONLY the SHA-256. flagged = only files above LOW')
WHOLE_PC_WARNING = ('A whole-PC check looks at every file on all your fixed drives (the Windows folder is skipped '
                    'unless you tick it).\n\nThe first time can take several hours. You can press Stop at any time - '
                    'a report is still written - and later scans only check new or changed files.\n\nStart now?')
PAGES = ('Dashboard', 'Scan', 'History', 'Settings', 'Help & About')
NAV = (('Dashboard', 'home'), ('Scan', 'scan'), ('History', 'clock'), ('Settings', 'gear'), ('Help', 'help'))
DASHBOARD, SCAN, HISTORY, SETTINGS, HELP = range(len(PAGES))
NAV_SPACE = 96            # room at the bottom of every page for the floating navigation


class Backdrop(QWidget):
    """The window background: deep green-black with soft spotlight beams from the top (drawn once per size)."""
    def __init__(self):
        super().__init__()
        self._cache = None

    def resizeEvent(self, e):
        self._cache = None
        super().resizeEvent(e)

    def paintEvent(self, _):
        if self._cache is None or self._cache.size() != self.size():
            from PySide6.QtGui import QPixmap
            pm = QPixmap(self.size())
            pm.fill(QColor(theme.BG))
            p = QPainter(pm)
            p.setRenderHint(QPainter.Antialiasing)
            w, h = self.width(), self.height()
            for x, rad, alpha in ((0.55, 0.55, 46), (0.30, 0.35, 22), (0.82, 0.30, 18)):
                g = QRadialGradient(QPointF(w * x, -h * 0.08), h * rad * 1.4)
                c0 = QColor(theme.ACCENT)
                c0.setAlpha(alpha)
                c1 = QColor(theme.ACCENT)
                c1.setAlpha(0)
                g.setColorAt(0, c0)
                g.setColorAt(1, c1)
                p.fillRect(self.rect(), g)
            floor = QLinearGradient(0, h * 0.75, 0, h)
            floor.setColorAt(0, QColor(0, 0, 0, 0))
            floor.setColorAt(1, QColor(20, 40, 18, 90))
            p.fillRect(self.rect(), floor)
            p.end()
            self._cache = pm
        p = QPainter(self)
        p.drawPixmap(0, 0, self._cache)
        p.end()


class MainWindow(QMainWindow):
    def __init__(self, models=None, reports_folder=None, settings_path=None):
        super().__init__()
        theme.apply_theme()
        self.settings_path = settings_path
        self.settings = load_settings(settings_path)
        fx.set_animate(self.settings.get('animations', True))
        self.models, self.tools_cache = models or app_models_dir(self.settings), {}
        self.thread = self.worker = None
        self.last_report = self.last_pdf = None
        self.last_info = self.last_error = None                    # how the last scan ended
        self.confirm_whole_pc = True                               # ask before a whole-PC scan
        self.setWindowTitle('MLWINT - read-only malware check')
        self.setWindowIcon(theme.app_icon())
        self.resize(1480, 940)
        self.setMinimumSize(1180, 760)
        self.setAcceptDrops(True)

        scan_page = self.build_scan_page()
        self.history = HistoryTab(reports_folder, memory_getter=self.memory)
        self.settings_tab = SettingsTab(memory_getter=self.memory, settings_path=settings_path)
        self.settings_tab.changed.connect(self.on_settings_changed)
        self.dashboard = Dashboard(reports_folder, memory_count=self.memory_count, health=health,
                                   keys=self.saved_key_names)
        self.dashboard.quick_scan.connect(self.quick_scan)
        self.dashboard.choose_files.connect(lambda: self.go(SCAN))
        self.dashboard.whole_pc.connect(self.whole_pc_scan)
        self.dashboard.open_report.connect(self.show_report)
        self.dashboard.open_pdf.connect(self.show_report_pdf)
        self.help = HelpPage()

        self.tabs = QTabWidget()                                   # the pages; the floating navigation switches
        self.tabs.tabBar().hide()
        self.tabs.setDocumentMode(True)
        pages = (self.dashboard, scan_page,
                 self.wrap(self.history, ('Every scan,', 'and what changed since the one before'), 'PAST SCANS',
                           'clock'),
                 self.wrap(self.settings_tab, ('Settings,', 'keys, memory and health'), 'PREFERENCES', 'gear'),
                 self.help)
        for page, name in zip(pages, PAGES):
            self.tabs.addTab(page, name)
        self.tabs.currentChanged.connect(self.on_tab)

        self.backdrop = Backdrop()
        root = QVBoxLayout(self.backdrop)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self.build_topbar())
        root.addWidget(self.tabs, 1)
        self.setCentralWidget(self.backdrop)
        self.floatnav = self.build_nav(self.backdrop)
        if self.settings['remember_options'] and self.settings['scan_options']:
            self.apply_scan_options(self.settings['scan_options'])       # your choices from last time
        self.update_statusbar()

    # ------------------------------------------------------------------ frame
    def build_topbar(self):
        bar = QFrame()
        bar.setObjectName('topbar')
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(34, 18, 34, 6)
        logo = QLabel()
        logo.setPixmap(theme.logo_pixmap(34))
        brand = QLabel('MLWINT')
        brand.setObjectName('brand')
        sub = QLabel('MALWARE  INTELLIGENCE')
        sub.setObjectName('num')
        lay.addWidget(logo)
        lay.addWidget(brand)
        lay.addSpacing(10)
        lay.addWidget(sub)
        lay.addStretch()
        pill = QFrame()
        pill.setObjectName('statusPill')
        pl = QHBoxLayout(pill)
        pl.setContentsMargins(14, 6, 16, 6)
        pl.setSpacing(4)
        self.sb_safe = QLabel(f'<span style="color:{theme.ACCENT}">●</span>&nbsp; Read-only')
        self.sb_lookup = QLabel()
        self.sb_memory = QLabel()
        for i, w in enumerate((self.sb_safe, self.sb_lookup, self.sb_memory)):
            if i:
                dot = QLabel('·')
                dot.setObjectName('muted')
                pl.addWidget(dot)
            pl.addWidget(w)
        lay.addWidget(pill)
        return bar

    def build_nav(self, parent):
        nav = QFrame(parent)
        nav.setObjectName('floatnav')
        lay = QHBoxLayout(nav)
        lay.setContentsMargins(7, 7, 7, 7)
        lay.setSpacing(4)
        self.nav = QButtonGroup(self)
        self.nav.setExclusive(True)
        for i, (name, icon) in enumerate(NAV):
            btn = QPushButton(f'  {name}')                      # a little room after the dotted icon
            btn.setObjectName('navpill')
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setIcon(QIcon(theme.dot_pixmap(icon, 18)))
            btn.setIconSize(QSize(16, 16))
            self.nav.addButton(btn, i)
            lay.addWidget(btn)
        self.nav.button(DASHBOARD).setChecked(True)
        self.nav.idClicked.connect(self.go)
        nav.adjustSize()
        nav.raise_()
        return nav

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if hasattr(self, 'floatnav'):
            self._place_nav()

    def showEvent(self, e):
        super().showEvent(e)
        self._place_nav()

    def _place_nav(self):
        """Keep the floating navigation centred at the bottom of the window."""
        self.floatnav.adjustSize()
        self.floatnav.move((self.backdrop.width() - self.floatnav.width()) // 2,
                           self.backdrop.height() - self.floatnav.height() - 22)
        self.floatnav.raise_()

    @staticmethod
    def wrap(widget, title, tag, icon):
        """A page = small tag + big two-tone headline + the widget, inside page margins."""
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(40, 6, 40, NAV_SPACE)
        lay.setSpacing(6)
        t = QLabel(f'[ {tag} ]')
        t.setObjectName('tag')
        lay.addWidget(t)
        lay.addWidget(fx.RevealTitle(title[0], title[1], 30, icon))
        lay.addWidget(widget, 1)
        return page

    # ------------------------------------------------------------------ scan page
    def build_scan_page(self):
        # ---- options panel: [01] where  [02] what  [03] how deeply
        opts, ol = theme.card()
        ol.setSpacing(12)

        def section(tag, title):
            h = QHBoxLayout()
            t = QLabel(tag)
            t.setObjectName('tag')
            n = QLabel(title)
            n.setObjectName('cardTitle')
            h.addWidget(t)
            h.addSpacing(6)
            h.addWidget(n)
            h.addStretch()
            return h

        self.scope_files = QRadioButton('Files and folders in this list')
        self.scope_pc = QRadioButton('Whole PC (all drives)')
        self.scope_files.setChecked(True)
        self.scope_group = QButtonGroup(self)
        self.scope_group.addButton(self.scope_files)
        self.scope_group.addButton(self.scope_pc)
        self.include_windows = QCheckBox('also the Windows folder (very slow)')
        self.include_windows.setEnabled(False)
        self.scope_pc.toggled.connect(self.update_scope)
        scope = QHBoxLayout()
        for w in (self.scope_files, self.scope_pc, self.include_windows):
            scope.addWidget(w)
        scope.addStretch()
        self.paths = QListWidget()
        self.paths.setMaximumHeight(84)
        self.paths.setToolTip('Files and folders to scan (you can also drag them onto this window)')
        add_files = theme.PillButton('Add files', 'ghost', 'doc')
        add_dir = theme.PillButton('Add folder', 'ghost', 'scan')
        clear = theme.PillButton('Clear', 'ghost')
        add_files.clicked.connect(self.pick_files)
        add_dir.clicked.connect(self.pick_folder)
        clear.clicked.connect(self.paths.clear)
        self.input_buttons = [add_files, add_dir, clear]
        pick = QVBoxLayout()
        for b in self.input_buttons:
            pick.addWidget(b)
        pick.addStretch()
        lists = QHBoxLayout()
        lists.addWidget(self.paths, 1)
        lists.addLayout(pick)

        self.types = TypePicker()
        self.types.changed.connect(self.update_scan_button)
        self.recursive = QCheckBox('Include sub-folders')
        self.deep_all = QCheckBox('Deep check (slower)')
        self.deep_all.setToolTip('Check the code of every program (capa) and watch it in a safe simulation '
                                 '(emulation), not only the files that look suspicious. Much slower.')
        self.large = QCheckBox('Include large files (over 256 MB)')
        self.large.setToolTip('Large-file check, about 5 minutes per GB: digital signature, a report-only Microsoft '
                              'Defender scan (Defender changes nothing) and the detector at half weight')
        self.fresh = QCheckBox('Full re-check (ignore memory)')
        self.fresh.setToolTip('Analyse every file again, even the ones that are unchanged since an earlier scan')
        self.deep_all.toggled.connect(self.update_deep)
        self.combos = {}
        rep = QComboBox()
        rep.addItems(CHOICES['reputation'])
        rep.setToolTip(TIPS['reputation'])
        self.combos['reputation'] = rep
        self.more = QToolButton()
        self.more.setText('More options')
        self.more.setCheckable(True)
        o1 = QHBoxLayout()
        for w in (self.recursive, self.deep_all, self.large, self.fresh):
            o1.addWidget(w)
        o1.addStretch()
        o2 = QHBoxLayout()
        o2.addWidget(QLabel('Hash lookup'))
        o2.addWidget(rep)
        self.banner = QLabel()
        self.banner.setWordWrap(True)
        o2.addWidget(self.banner, 1)
        o2.addWidget(self.more)
        self.advanced = QWidget()
        adv = QHBoxLayout(self.advanced)
        adv.setContentsMargins(0, 0, 0, 0)
        for name, label in (('evidence', 'Evidence'), ('deep', 'Emulation'), ('context', 'PC context')):
            c = QComboBox()
            c.addItems(CHOICES[name])
            c.setToolTip(TIPS[name])
            self.combos[name] = c
            adv.addWidget(QLabel(label))
            adv.addWidget(c)
        self.max_files = QSpinBox()
        self.max_files.setRange(1, cli.WHOLE_PC_MAX)
        self.max_files.setValue(2000)
        adv.addWidget(QLabel('Max files'))
        adv.addWidget(self.max_files)
        adv.addStretch()
        self.advanced.setVisible(False)
        self.more.toggled.connect(self.advanced.setVisible)
        rep.currentTextChanged.connect(self.update_banner)

        ol.addLayout(section('[ 01 ]', 'Where to look'))
        ol.addLayout(scope)
        ol.addLayout(lists)
        ol.addWidget(fx.glass_line())
        ol.addLayout(section('[ 02 ]', 'What to check'))
        ol.addWidget(self.types)
        ol.addWidget(fx.glass_line())
        ol.addLayout(section('[ 03 ]', 'How deeply'))
        ol.addLayout(o1)
        ol.addLayout(o2)
        ol.addWidget(self.advanced)
        self.update_banner()

        # ---- the scanner: orb + start / stop + reports
        self.scan_panel = fx.StreakPanel()
        sl = QVBoxLayout(self.scan_panel)
        sl.setContentsMargins(26, 20, 26, 22)
        self.orb = fx.ThreatOrb(caption='highest score in this scan')
        self.orb.setMinimumSize(QSize(280, 280))
        self.scan_btn = theme.PillButton('Start scan', 'primary')
        self.stop_btn = theme.PillButton('Stop', 'ghost')
        self.report_btn = theme.PillButton('Open report (PDF)', 'ghost', 'doc')
        self.report_btn.setToolTip('The easy-to-read report of the last scan')
        self.tech_btn = theme.PillButton('Technical report', 'ghost')
        self.tech_btn.setToolTip('The full technical text report of the last scan')
        self.tech_btn.setEnabled(False)
        self.tech_btn.clicked.connect(self.open_tech_report)
        self.stop_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.report_btn.clicked.connect(self.open_report)
        self.progress = QProgressBar()
        self.progress.setFormat('%v / %m files')
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.status = QLabel('Ready. Nothing is deleted, moved, run or uploaded.')
        self.status.setWordWrap(True)
        self.status.setObjectName('soft')
        self.status.setAlignment(Qt.AlignCenter)
        b1 = QHBoxLayout()
        b1.addStretch()
        b1.addWidget(self.scan_btn)
        b1.addWidget(self.stop_btn)
        b1.addStretch()
        b2 = QHBoxLayout()
        b2.addStretch()
        b2.addWidget(self.report_btn)
        b2.addWidget(self.tech_btn)
        b2.addStretch()
        sl.addWidget(self.orb, 1)
        sl.addWidget(self.progress)
        sl.addWidget(self.status)
        sl.addLayout(b1)
        sl.addLayout(b2)

        top = QHBoxLayout()
        top.setSpacing(18)
        top.addWidget(opts, 3)
        top.addWidget(self.scan_panel, 2)

        # ---- results + log
        self.view = ResultsView()
        self.table, self.detail = self.view.table, self.view.detail          # short names (used by checks)
        self.search, self.show_combo, self.shown_label = self.view.search, self.view.show_combo, self.view.shown_label
        res, rl = theme.card()
        head = QHBoxLayout()
        t = QLabel('[ 04 ]')
        t.setObjectName('tag')
        n = QLabel('Results')
        n.setObjectName('cardTitle')
        self.log_btn = QToolButton()
        self.log_btn.setText('Scan log')
        self.log_btn.setCheckable(True)
        head.addWidget(t)
        head.addSpacing(6)
        head.addWidget(n)
        head.addStretch()
        head.addWidget(self.log_btn)
        self.log = QPlainTextEdit()
        self.log.setObjectName('log')
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setMaximumHeight(150)
        self.log.setVisible(False)
        self.log_btn.toggled.connect(self.log.setVisible)
        self.view.setMinimumHeight(540)
        rl.addLayout(head)
        rl.addWidget(self.view, 1)
        rl.addWidget(self.log)

        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(40, 6, 40, NAV_SPACE)
        lay.setSpacing(16)
        t = QLabel('[ CHECK FILES ]')
        t.setObjectName('tag')
        lay.addWidget(t)
        lay.addWidget(fx.RevealTitle('Check your files,', 'nothing is changed, run or uploaded', 30, 'scan'))
        lay.addLayout(top)
        lay.addWidget(res, 1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        scroll.setFrameShape(QFrame.NoFrame)
        return scroll

    # ------------------------------------------------------------------ navigation
    def go(self, index):
        self.tabs.setCurrentIndex(index)

    def on_tab(self, i):
        btn = self.nav.button(i)
        if btn and not btn.isChecked():
            btn.setChecked(True)
        page = self.tabs.widget(i)
        if i == DASHBOARD:
            self.dashboard.refresh()
        elif i == HISTORY:
            self.history.refresh()
        elif i == SETTINGS:
            self.settings_tab.refresh()
        fx.fade_in(page)
        for title in page.findChildren(fx.RevealTitle):
            title.reveal()
        self.floatnav.raise_()

    def quick_scan(self):
        """Dashboard: scan the Downloads folder (and its sub-folders) now."""
        self.scope_files.setChecked(True)
        self.paths.clear()
        self.add_paths([DOWNLOADS])
        self.recursive.setChecked(True)
        self.go(SCAN)
        self.start_scan()

    def whole_pc_scan(self):
        self.scope_pc.setChecked(True)
        self.go(SCAN)
        self.start_scan()

    def show_report(self, name):
        self.go(HISTORY)
        self.history.refresh()
        for row in range(self.history.list.rowCount()):
            if self.history.list.item(row, 0).data(Qt.UserRole) == name:
                self.history.list.selectRow(row)
                break

    def show_report_pdf(self, name):
        self.show_report(name)
        self.history.open_pdf()

    # ------------------------------------------------------------------ settings
    DEFAULT_OPTIONS = dict(scope='files', include_windows=False, paths=[], types=list(cli.KINDS), recursive=False,
                           deep_all=False, large=False, reputation='off', evidence='needed', deep='needed',
                           context='needed', max_files=2000)

    def scan_options(self):
        """The Scan page's choices, as kept in the settings (Full re-check is never kept)."""
        return dict(scope='pc' if self.scope_pc.isChecked() else 'files',
                    include_windows=self.include_windows.isChecked(),
                    paths=[self.paths.item(i).text() for i in range(self.paths.count())],
                    types=sorted(self.types.types()), recursive=self.recursive.isChecked(),
                    deep_all=self.deep_all.isChecked(), large=self.large.isChecked(),
                    reputation=self.combos['reputation'].currentText(),
                    evidence=self.combos['evidence'].currentText(), deep=self.combos['deep'].currentText(),
                    context=self.combos['context'].currentText(), max_files=self.max_files.value())

    def apply_scan_options(self, saved):
        o = dict(self.DEFAULT_OPTIONS, **{k: v for k, v in (saved or {}).items() if k in self.DEFAULT_OPTIONS})
        (self.scope_pc if o['scope'] == 'pc' else self.scope_files).setChecked(True)
        self.include_windows.setChecked(bool(o['include_windows']))
        self.paths.clear()
        self.add_paths([p for p in o['paths'] if Path(p).exists()])
        self.types.set_types(set(o['types']) or set(cli.KINDS))
        self.recursive.setChecked(bool(o['recursive']))
        self.large.setChecked(bool(o['large']))
        self.fresh.setChecked(False)
        for name in ('reputation', 'evidence', 'deep', 'context'):
            self.combos[name].setCurrentText(o[name])
        self.deep_all.blockSignals(True)
        self.deep_all.setChecked(bool(o['deep_all']))
        self.deep_all.blockSignals(False)
        for name in ('evidence', 'deep'):
            self.combos[name].setEnabled(not o['deep_all'])
        self.max_files.setValue(int(o['max_files']))
        self.update_scope()
        self.update_banner()

    def keep_scan_options(self):
        self.settings = load_settings(self.settings_path)
        if self.settings['remember_options']:
            self.settings['scan_options'] = self.scan_options()
            save_settings(self.settings, self.settings_path)

    def on_settings_changed(self, what):
        self.settings = load_settings(self.settings_path)
        if what in ('keys', 'models'):
            self.models = app_models_dir(self.settings)
            self.tools_cache.clear()                                 # reloaded with the new keys / models
            self.status.setText('Settings changed: the next scan uses the new '
                                + ('keys.' if what == 'keys' else 'models folder.'))
        elif what == 'reset-options':
            self.apply_scan_options({})
            self.settings['scan_options'] = {}
            save_settings(self.settings, self.settings_path)
            self.status.setText('Scan options reset to the defaults.')
        elif what == 'memory':
            self.history.update_memory()
        elif what == 'appearance':
            fx.set_animate(self.settings.get('animations', True))
        self.update_statusbar()

    # ------------------------------------------------------------------ small helpers
    @property
    def results(self):
        return self.view.results

    def result_at(self, row):
        return self.view.result_at(row)

    def memory(self):
        tools = self.tools_cache.get('tools')
        return tools.get('memory') if tools else None

    def memory_count(self):
        mem = self.memory()
        if mem is not None:
            return len(mem)
        from src.detection.scan_memory import MEMORY_FILE
        try:
            return len(json.loads(MEMORY_FILE.read_text(encoding='utf-8')).get('files', {}))
        except (OSError, ValueError):
            return 0

    @staticmethod
    def saved_key_names():
        from src.detection.phase3_reputation import load_keys
        return sorted(load_keys())

    def update_statusbar(self):
        mode = self.combos['reputation'].currentText()
        self.sb_lookup.setText('Hash lookup off' if mode == 'off' else f'Hash lookup ON ({mode})')
        self.sb_memory.setText(f'Memory {self.memory_count():,} files')

    # ------------------------------------------------------------------ inputs
    def add_paths(self, paths):
        have = {self.paths.item(i).text() for i in range(self.paths.count())}
        for p in paths:
            p = str(Path(p))
            if p not in have:
                self.paths.addItem(p)
                have.add(p)

    def pick_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, 'Files to scan')
        self.add_paths(files)

    def pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, 'Folder to scan')
        if d:
            self.add_paths([d])

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls() and self.stop_btn.isEnabled() is False:
            e.acceptProposedAction()

    def dropEvent(self, e):
        self.go(SCAN)
        self.scope_files.setChecked(True)
        self.add_paths([u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()])

    def options(self):
        o = {k: c.currentText() for k, c in self.combos.items()}
        whole = self.scope_pc.isChecked()
        o.update(recursive=self.recursive.isChecked() or whole, types=sorted(self.types.types()),
                 large=self.large.isChecked(), fresh=self.fresh.isChecked(), whole_pc=whole,
                 include_windows=whole and self.include_windows.isChecked())
        return o

    def update_scope(self, *_):
        whole = self.scope_pc.isChecked()
        self.include_windows.setEnabled(whole and not self.stop_btn.isEnabled())
        self.paths.setEnabled(not whole)
        for b in self.input_buttons:
            b.setEnabled(not whole and not self.stop_btn.isEnabled())
        self.recursive.setEnabled(not whole and not self.stop_btn.isEnabled())

    def update_deep(self, on):
        for name in ('evidence', 'deep'):
            self.combos[name].setCurrentText('all' if on else 'needed')
            self.combos[name].setEnabled(not on)

    def update_banner(self):
        if self.combos['reputation'].currentText() == 'off':
            self.banner.setText('Hash lookup is OFF: nothing leaves this PC.')
            self.banner.setStyleSheet(f'color: {theme.ACCENT};')
        else:
            self.banner.setText('Hash lookup is ON: only SHA-256 fingerprints are sent to MalwareBazaar / '
                                'VirusTotal with your own API keys. No file, name or path is sent.')
            self.banner.setStyleSheet(f'color: {theme.LEVEL["ELEVATED"]};')
        if hasattr(self, 'sb_lookup'):
            self.update_statusbar()

    def update_scan_button(self):
        running = self.stop_btn.isEnabled()
        self.scan_btn.setEnabled(not running and bool(self.types.types()))
        self.scan_btn.setToolTip('' if self.types.types() else 'Tick at least one kind of file to check')

    # ------------------------------------------------------------------ scanning
    def start_scan(self):
        paths = [self.paths.item(i).text() for i in range(self.paths.count())]
        whole = self.scope_pc.isChecked()
        if not paths and not whole:
            QMessageBox.information(self, 'MLWINT', 'Add a file or folder first (or drag one onto the window), '
                                                    'or choose "Whole PC".')
            return
        if not self.types.types():
            QMessageBox.information(self, 'MLWINT', 'Tick at least one kind of file to check.')
            return
        if whole and self.confirm_whole_pc and \
                QMessageBox.question(self, 'MLWINT - whole PC', WHOLE_PC_WARNING) != QMessageBox.Yes:
            return
        self.keep_scan_options()
        self.last_info = self.last_error = None
        self.view.clear()
        self.orb.set_scanning(0, 1)
        self.progress.setRange(0, 0)                               # busy until the files are counted
        self.set_running(True)
        self.status.setText('Looking for Windows programs and PDFs ...')
        self.thread = QThread(self)
        self.worker = ScanWorker(paths, self.options(), self.max_files.value(), self.models, self.tools_cache)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.message.connect(self.log.appendPlainText)
        self.worker.searching.connect(self.on_searching)
        self.worker.counted.connect(self.on_counted)
        self.worker.file_done.connect(self.on_file)
        self.worker.finished.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.stop_btn.setEnabled(False)
            self.status.setText('Stopping after the current file (a report is still written) ...')

    def set_running(self, running):
        self.stop_btn.setEnabled(running)
        for w in list(self.combos.values()) + [self.max_files, self.types, self.scope_files, self.scope_pc,
                                               self.deep_all, self.large, self.fresh, self.history.forget_btn,
                                               self.settings_tab, self.dashboard.quick_btn, self.dashboard.pc_btn]:
            w.setEnabled(not running)
        if not running and self.deep_all.isChecked():
            for name in ('evidence', 'deep'):                       # set by "Deep check": keep them locked
                self.combos[name].setEnabled(False)
        self.update_scope()
        self.update_scan_button()

    def on_searching(self, seen, found):
        self.status.setText(f'Looking for Windows programs and PDFs ... {seen:,} files looked at, '
                            f'{found:,} to analyse')

    def on_counted(self, n, cut, note):
        self.progress.setRange(0, max(n, 1))
        self.progress.setValue(0)
        self.orb.set_scanning(0, n)
        self.status.setText(f'{n:,} files to analyse' + (f' (stopped at max files {self.max_files.value()})'
                                                         if cut else '') + (f'. {note}' if note else ''))

    def on_file(self, i, r):
        self.progress.setValue(i)
        self.orb.set_scanning(i, self.progress.maximum())
        self.view.add_result(r)
        shown = f'{r["score"]:>3}/100 {r["level"]}' if r.get('status') == 'assessed' else r.get('status', '?')
        how = how_checked(r)
        self.status.setText(f'Checking ... {Path(str(r.get("path"))).name}')
        self.log.appendPlainText(f'[{i}/{self.progress.maximum()}] {shown}  {r["seconds"]} s  {r.get("path")}'
                                 + (f'  ({how})' if how and how != 'checked now' else ''))

    def on_finished(self, info):
        self.last_info = info
        self.set_running(False)
        self.last_report = info['txt']
        self.last_pdf = cli.easy_report(info['json'], say=self.log.appendPlainText)   # made here: Qt work
        info['pdf'] = str(self.last_pdf) if self.last_pdf else None
        self.report_btn.setEnabled(bool(self.last_pdf))
        self.tech_btn.setEnabled(True)
        self.view.finish()
        worst = max((r for r in self.view.results if r.get('status') == 'assessed'), key=lambda r: r['score'],
                    default=None)
        if worst:
            self.orb.set_result(worst['score'], worst['level'])
        else:
            self.orb.clear()
        self.status.setText(('Stopped. ' if info['stopped'] else 'Done. ') + info['head'][1]
                            + (f'. {info["memory"]}' if info.get('memory') else '')
                            + (f'. {info["skipped"]}' if info.get('skipped') else ''))
        self.log.appendPlainText('\n'.join(info['head'][:2]) + (f'\n{info["memory"]}' if info.get('memory') else '')
                                 + f'\nEasy-to-read report: {info["pdf"]}\n'
                                 f'Technical report: {info["txt"]}\nAll details: {info["json"]}')
        self.history.refresh(select_newest=True)                   # the new scan appears in History
        self.dashboard.refresh()
        self.update_statusbar()

    def on_failed(self, msg):
        self.last_error = msg
        self.set_running(False)
        self.progress.setRange(0, 1)
        self.orb.clear()
        self.status.setText('The scan stopped with an error (see the log).')
        self.log.appendPlainText('ERROR: ' + msg)
        QMessageBox.warning(self, 'MLWINT', 'The scan stopped with an error:\n' + msg)

    def open_report(self):
        if self.last_pdf and Path(self.last_pdf).is_file():
            os.startfile(self.last_pdf)                             # MLWINT's own report, not a scanned file

    def open_tech_report(self):
        if self.last_report and Path(self.last_report).is_file():
            os.startfile(self.last_report)

    def closeEvent(self, e):
        self.keep_scan_options()
        if self.thread is not None and self.thread.isRunning():
            if QMessageBox.question(self, 'MLWINT', 'A scan is running. Stop it and close?') != QMessageBox.Yes:
                e.ignore()
                return
            self.worker.stop()
            self.thread.quit()
            self.thread.wait(180000)                                # lets the current file and the report finish
        e.accept()


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description='MLWINT desktop window')
    ap.add_argument('paths', nargs='*', help='files / folders to put in the list')
    ap.add_argument('--models', type=Path, default=None, help='folder holding phase1/ and phase2/')
    a = ap.parse_args(argv)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    theme.apply_theme(app)
    w = MainWindow(a.models)
    if a.paths:
        w.add_paths(a.paths)
        w.go(SCAN)
    w.show()
    return app.exec()