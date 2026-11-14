"""MLWINT GUI step G3: History tab. Save as MLWINT/src/gui/history.py
  - every earlier scan (reports/analyse/analysis-*.json), newest first: when, where, how many files at each level
  - open one: its results in the same table + detail panel as the Scan tab, without scanning again
  - 'Since last scan': each file compared with the previous scan of the same place:
        new  /  worse (was 20 GUARDED)  /  better (was 47 ELEVATED)  /  changed (same name, new contents)
    plus how many files from last time are gone
  - Open report (PDF; made now if an older report has none), Technical report, Open reports folder
  - the memory: how many files are remembered, and a button to forget them
Read-only: only MLWINT's own report files are read (and a missing PDF is written).
"""
import json, os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton,
                               QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .results_view import NumberItem, ResultsView
from .worker import ROOT, cli
from .theme import PillButton

REPORTS = ROOT / 'reports/analyse'
INDEX_NAME = 'history-index.json'
RANK = {'LOW': 0, 'GUARDED': 1, 'ELEVATED': 2, 'HIGH': 3, 'SEVERE': 4}
GROUPS = [('Act now', ('SEVERE', 'HIGH')), ('Be careful', ('ELEVATED',)), ('Worth a look', ('GUARDED',)),
          ('Looks fine', ('LOW',))]
LIST_COLUMNS = ['When', 'Looked in', 'Files', 'Act now', 'Be careful', 'Worth a look', 'Looks fine',
                'Not checked', 'Took']


def _norm(p):
    return os.path.normcase(os.path.abspath(str(p)))


def summarise(path, data):
    """Small summary of one report, kept in the index so the list opens fast."""
    results = data.get('results', [])
    levels = {}
    for r in results:
        if r.get('status') == 'assessed':
            levels[r['level']] = levels.get(r['level'], 0) + 1
    failed = sum(1 for r in results if r.get('status') != 'assessed')
    skipped = sum((data.get('not_checked') or {}).values())
    opts = data.get('options') or {}
    where = 'Whole PC' if opts.get('whole_pc') else ', '.join(str(p) for p in data.get('paths', []))
    return dict(file=path.name, started=data.get('started', ''), where=where,
                paths=[_norm(p) for p in data.get('paths', [])], whole_pc=bool(opts.get('whole_pc')),
                files=len(results), levels=levels, not_checked=failed + skipped,
                memory=data.get('memory', ''), seconds=_seconds(path))


def _seconds(path):
    """The '(123 s)' from the first line of the .txt report, if it is there."""
    txt = path.with_suffix('.txt')
    try:
        first = txt.read_text(encoding='utf-8', errors='replace').split('\n', 1)[0]
        return int(first.rsplit('(', 1)[1].split(' s)')[0])
    except (OSError, IndexError, ValueError):
        return None


class HistoryIndex:
    """Summaries of all reports in a folder; a report is only re-read when its file changed."""
    def __init__(self, folder=None):
        self.folder = Path(folder) if folder else REPORTS
        self.index_file = self.folder / INDEX_NAME

    def load(self):
        try:
            cache = json.loads(self.index_file.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            cache = {}
        out, changed = [], False
        for js in sorted(self.folder.glob('analysis-*.json'), reverse=True):     # newest first (time in name)
            st = js.stat()
            key = f'{js.name}|{st.st_size}|{int(st.st_mtime)}'
            entry = cache.get(js.name)
            if not entry or entry.get('key') != key:
                try:
                    data = json.loads(js.read_text(encoding='utf-8'))
                except (OSError, ValueError):
                    continue
                if data.get('status') != 'MLWINT_ANALYSIS':
                    continue
                entry = dict(summarise(js, data), key=key)
                cache[js.name] = entry
                changed = True
            out.append(entry)
        names = {e['file'] for e in out}
        if changed or set(cache) - names:
            try:
                self.index_file.write_text(json.dumps({k: v for k, v in cache.items() if k in names}),
                                           encoding='utf-8')
            except OSError:
                pass
        return out

    def read(self, name):
        return json.loads((self.folder / name).read_text(encoding='utf-8'))

    def previous(self, entries, entry):
        """The newest earlier scan that looked at the same place (same folders, or both whole PC)."""
        older = entries[entries.index(entry) + 1:] if entry in entries else []
        for e in older:
            if e['whole_pc'] == entry['whole_pc'] and (entry['whole_pc'] or set(e['paths']) == set(entry['paths'])):
                return e
        return None


def compare(results, earlier):
    """Marks every result with 'change' compared with the earlier results; returns how many earlier files are gone."""
    before = {_norm(r.get('path')): r for r in earlier}
    for r in results:
        old = before.pop(_norm(r.get('path')), None)
        if old is None:
            r['change'] = 'new'
            continue
        if old.get('sha256') and r.get('sha256') and old['sha256'] != r['sha256']:
            r['change'] = 'changed (new contents)'
        a, b = RANK.get(old.get('level'), -1), RANK.get(r.get('level'), -1)
        if r.get('status') == 'assessed' and old.get('status') == 'assessed' and a != b:
            was = f'was {old.get("score")} {old.get("level")}'
            r['change'] = (f'worse ({was})' if b > a else f'better ({was})') + \
                (', new contents' if r.get('change', '').startswith('changed') else '')
        elif r.get('status') != old.get('status') and 'change' not in r:
            r['change'] = 'checked now' if r.get('status') == 'assessed' else 'not checked now'
        r.setdefault('change', '')
    return len(before)


class HistoryTab(QWidget):
    def __init__(self, folder=None, memory_getter=None):
        """memory_getter: returns the ScanMemory in use (or None) - for the memory box."""
        super().__init__()
        self.index = HistoryIndex(folder)
        self.memory_getter = memory_getter
        self.entries, self.current, self.data = [], None, None

        self.list = QTableWidget(0, len(LIST_COLUMNS))
        self.list.setHorizontalHeaderLabels(LIST_COLUMNS)
        self.list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.list.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list.verticalHeader().setVisible(False)
        h = self.list.horizontalHeader()
        for col in range(len(LIST_COLUMNS)):
            h.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        self.list.itemSelectionChanged.connect(self.on_pick)

        self.refresh_btn = PillButton('Refresh', 'ghost', 'clock')
        self.pdf_btn = PillButton('Open report (PDF)', 'ghost', 'doc')
        self.txt_btn = PillButton('Technical report', 'ghost', 'doc')
        self.folder_btn = PillButton('Open reports folder', 'ghost', 'doc')
        self.refresh_btn.clicked.connect(self.refresh)
        self.pdf_btn.clicked.connect(self.open_pdf)
        self.txt_btn.clicked.connect(self.open_txt)
        self.folder_btn.clicked.connect(lambda: os.startfile(self.index.folder))
        self.memory_label = QLabel('')
        self.forget_btn = PillButton('Forget remembered results', 'ghost')
        self.forget_btn.clicked.connect(self.forget)
        bar = QHBoxLayout()
        for w in (self.refresh_btn, self.pdf_btn, self.txt_btn, self.folder_btn):
            bar.addWidget(w)
        bar.addStretch()
        bar.addWidget(self.memory_label)
        bar.addWidget(self.forget_btn)

        self.summary = QLabel('Pick a scan to see its results.')
        self.summary.setWordWrap(True)
        self.view = ResultsView(compare=True)
        top = QWidget()
        tl = QVBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.addLayout(bar)
        tl.addWidget(self.list)
        bottom = QWidget()
        bl = QVBoxLayout(bottom)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(self.summary)
        bl.addWidget(self.view, 1)
        split = QSplitter(Qt.Vertical)
        split.addWidget(top)
        split.addWidget(bottom)
        split.setSizes([220, 560])
        QVBoxLayout(self).addWidget(split)
        self.set_buttons()

    # ------------------------------------------------------------------ list
    def refresh(self, select_newest=False):
        keep = self.current['file'] if self.current and not select_newest else None
        self.entries = self.index.load()
        self.list.blockSignals(True)
        self.list.setRowCount(0)
        for e in self.entries:
            row = self.list.rowCount()
            self.list.insertRow(row)
            lv = e['levels']
            counts = [sum(lv.get(l, 0) for l in levels) for _, levels in GROUPS]
            took = e.get('seconds')
            cells = [QTableWidgetItem(e['started']), QTableWidgetItem(e['where']), NumberItem(e['files'])] + \
                    [NumberItem(n) for n in counts] + \
                    [NumberItem(e['not_checked']),
                     QTableWidgetItem('' if took is None else (f'{took // 60} min' if took >= 120 else f'{took} s'))]
            for col, item in enumerate(cells):
                item.setData(Qt.UserRole, e['file'])
                if col == 1:
                    item.setToolTip(e['where'] + (f'\n{e["memory"]}' if e.get('memory') else ''))
                self.list.setItem(row, col, item)
            if counts[0]:
                f = cells[3].font()
                f.setBold(True)
                cells[3].setFont(f)
        self.list.blockSignals(False)
        self.update_memory()
        target = keep or (self.entries[0]['file'] if self.entries else None)
        for row in range(self.list.rowCount()):
            if self.list.item(row, 0).data(Qt.UserRole) == target:
                self.list.selectRow(row)
                break
        if not self.entries:
            self.summary.setText('No scans yet. Run one on the Scan tab.')
            self.view.clear()
            self.current = self.data = None
            self.set_buttons()

    def on_pick(self):
        rows = {i.row() for i in self.list.selectedItems()}
        if not rows:
            return
        name = self.list.item(rows.pop(), 0).data(Qt.UserRole)
        self.open(name)

    def open(self, name):
        entry = next((e for e in self.entries if e['file'] == name), None)
        if entry is None:
            return
        try:
            data = self.index.read(name)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, 'MLWINT', f'This report cannot be read: {e}')
            return
        self.current, self.data = entry, data
        results = data.get('results', [])
        prev = self.index.previous(self.entries, entry)
        gone = None
        if prev is not None:
            try:
                gone = compare(results, self.index.read(prev['file']).get('results', []))
            except (OSError, ValueError):
                prev = None
        changed = [r for r in results if r.get('change')]
        worse = sum(1 for r in changed if r['change'].startswith('worse'))
        new = sum(1 for r in changed if r['change'] == 'new')
        text = f'<b>{entry["started"]}</b> - {entry["where"]} - {entry["files"]} files'
        if entry.get('memory'):
            text += f'<br>{entry["memory"]}'
        if prev is None:
            text += '<br>No earlier scan of the same place to compare with.'
        else:
            text += (f'<br>Since the scan of {prev["started"]}: {new} new, {worse} worse, '
                     f'{len(changed) - new - worse} other changes, {gone} gone. '
                     f'Use "Show: {self.view.show_combo.itemText(3)}" to see only these.')
        self.summary.setText(text)
        self.view.set_results(results)
        self.set_buttons()

    # ------------------------------------------------------------------ buttons
    def set_buttons(self):
        have = self.current is not None
        self.pdf_btn.setEnabled(have)
        self.txt_btn.setEnabled(have and (self.index.folder / self.current['file']).with_suffix('.txt').is_file()
                                if have else False)

    def pdf_path(self):
        """The current report's PDF; made now if it is missing (older reports). None if it cannot be made."""
        if not self.current:
            return None
        js = self.index.folder / self.current['file']
        pdf = js.with_suffix('.pdf')
        if not pdf.is_file():
            pdf = cli.easy_report(js, say=lambda s: QMessageBox.warning(self, 'MLWINT', s))
        return pdf

    def open_pdf(self):
        pdf = self.pdf_path()
        if pdf and Path(pdf).is_file():
            os.startfile(pdf)                                       # MLWINT's own report, not a scanned file

    def open_txt(self):
        if self.current:
            txt = (self.index.folder / self.current['file']).with_suffix('.txt')
            if txt.is_file():
                os.startfile(txt)

    def update_memory(self):
        mem = self.memory_getter() if self.memory_getter else None
        if mem is None:
            from src.detection.scan_memory import MEMORY_FILE
            try:
                n = len(json.loads(MEMORY_FILE.read_text(encoding='utf-8')).get('files', {}))
            except (OSError, ValueError):
                n = 0
        else:
            n = len(mem)
        self.memory_label.setText(f'Memory: {n:,} files remembered')

    def forget(self):
        if QMessageBox.question(self, 'MLWINT', 'Forget all remembered results? The next scan will analyse every '
                                                'file again. (Only MLWINT\'s own memory file is cleared.)') \
                != QMessageBox.Yes:
            return
        mem = self.memory_getter() if self.memory_getter else None
        if mem is None:
            from src.detection.scan_memory import ScanMemory
            mem = ScanMemory()
        mem.forget()
        self.update_memory()