"""MLWINT GUI: the results table + find box + filter + detail panel, shared by the Scan and History tabs.
Save as MLWINT/src/gui/results_view.py
Rows are sorted worst first; clicking a row shows everything MLWINT found about that file on the right.
Right-click: plain text, Show in Explorer (only highlights the file, never opens it), copy path / SHA-256.
"""
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMenu, QPlainTextEdit, QSplitter, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QWidget)

from . import theme
from .widgets import DetailPanel
from .worker import cli

LEVEL_COLOUR = theme.LEVEL                     # level colours come from the theme
COLUMNS = ['Score', 'Level', 'Format', 'File', 'What it means', 'Folder', 'Checked', 'Seconds']
SHOW = ['All results', 'Needs attention (above LOW)', 'Not analysed']
SHOW_CHANGED = 'Changed since last scan'


class NumberItem(QTableWidgetItem):
    """Table cell that sorts by number, not by text."""
    def __init__(self, value, text=None):
        super().__init__(text if text is not None else str(value))
        self.value = value

    def __lt__(self, other):
        return self.value < getattr(other, 'value', 0)


def how_checked(r):
    if r.get('status') != 'assessed':
        return ''
    if r.get('remembered'):
        return f'remembered ({r["remembered"]["day"]})'
    return 'large-file check' if r.get('large_file') else 'checked now'


def show_in_explorer(path):
    """Highlights the file in its folder. Explorer does not open or run it."""
    subprocess.Popen(f'explorer /select,"{Path(path)}"')


class ResultsView(QWidget):
    def __init__(self, compare=False):
        """compare=True adds a 'Since last scan' column (History tab)."""
        super().__init__()
        self.compare = compare
        self.columns = COLUMNS + (['Since last scan'] if compare else [])
        self.results = []

        self.search = QLineEdit()
        self.search.setPlaceholderText('Find in results: part of a file name or folder')
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.apply_filter)
        self.show_combo = QComboBox()
        self.show_combo.addItems(SHOW + ([SHOW_CHANGED] if compare else []))
        self.show_combo.currentIndexChanged.connect(self.apply_filter)
        self.shown_label = QLabel('')
        flt = QHBoxLayout()
        flt.addWidget(self.search, 1)
        flt.addWidget(QLabel('Show:'))
        flt.addWidget(self.show_combo)
        flt.addWidget(self.shown_label)

        self.table = QTableWidget(0, len(self.columns))
        self.table.setHorizontalHeaderLabels(self.columns)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)        # airy rows
        self.table.setShowGrid(False)
        self.table.verticalHeader().setDefaultSectionSize(40)        # airy rows
        self.table.setShowGrid(False)
        h = self.table.horizontalHeader()
        for col in (0, 1, 2, 6, 7) + ((8,) if compare else ()):
            h.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        for col in (3, 4):
            h.setSectionResizeMode(col, QHeaderView.Interactive)
        h.setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setColumnWidth(3, 230)
        self.table.setColumnWidth(4, 280)
        self.table.setWordWrap(False)                              # long names end in '...', not 'C:...'
        self.table.setTextElideMode(Qt.ElideMiddle)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.row_menu)
        self.table.itemSelectionChanged.connect(self.on_select)
        self.detail = DetailPanel()

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addLayout(flt)
        ll.addWidget(self.table, 1)
        split = QSplitter(Qt.Horizontal)
        split.addWidget(left)
        split.addWidget(self.detail)
        split.setSizes([820, 560])
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(split)

    # ------------------------------------------------------------------ filling
    def clear(self):
        self.results = []
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.detail.show_result(None)
        self.shown_label.setText('')

    def add_result(self, r):
        self.results.append(r)
        row = self.table.rowCount()
        self.table.insertRow(row)
        ok = r.get('status') == 'assessed'
        adv = r.get('advice') or {}
        cells = [NumberItem(r['score'] if ok else -1, str(r['score']) if ok else '-'),
                 QTableWidgetItem(f'●  {r["level"]}' if ok else str(r.get('status', '?')).upper()),
                 QTableWidgetItem(r.get('format', '') if ok else ''),
                 QTableWidgetItem(Path(str(r.get('path'))).name),
                 QTableWidgetItem((adv.get('headline') or r.get('summary', '')) if ok else str(r.get('reason', ''))),
                 QTableWidgetItem(str(Path(str(r.get('path'))).parent)),
                 QTableWidgetItem(how_checked(r)),
                 NumberItem(r.get('seconds', 0))]
        if self.compare:
            cells.append(QTableWidgetItem(r.get('change', '')))
        level_colour = QColor(LEVEL_COLOUR.get(r.get('level'), theme.MUTED) if ok else theme.MUTED)
        tint = QColor(level_colour)
        tint.setAlpha(34 if ok and r['level'] != 'LOW' else 0)       # flagged rows get a soft tint of their level
        for col, item in enumerate(cells):
            item.setBackground(tint)
            item.setForeground(QColor(theme.TEXT))
            item.setData(Qt.UserRole, len(self.results) - 1)       # index into self.results
            if col in (3, 4, 5):
                item.setToolTip(str(r.get('path')) if col != 4 else item.text())
            self.table.setItem(row, col, item)
        bold = QFont()
        bold.setBold(True)
        cells[1].setForeground(level_colour)
        cells[0].setForeground(level_colour)
        if ok and r['level'] != 'LOW':
            cells[1].setFont(bold)
        if self.compare and r.get('change', '').startswith(('worse', 'new')):
            cells[-1].setFont(bold)
        self.apply_filter()

    def set_results(self, results):
        """Fill the table at once (History tab), worst first, and show the worst file."""
        self.clear()
        self.table.setUpdatesEnabled(False)
        for r in results:
            self.add_result(r)
        self.table.setUpdatesEnabled(True)
        self.finish()

    def finish(self):
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.DescendingOrder)                # worst first
        self.apply_filter()
        if self.table.rowCount() and not self.table.selectedItems():
            first = next((i for i in range(self.table.rowCount()) if not self.table.isRowHidden(i)), None)
            if first is not None:
                self.table.selectRow(first)

    # ------------------------------------------------------------------ looking
    def result_at(self, row):
        item = self.table.item(row, 0)
        return self.results[item.data(Qt.UserRole)] if item is not None else None

    def row_visible(self, r):
        text = self.search.text().strip().lower()
        if text and text not in str(r.get('path', '')).lower():
            return False
        show = self.show_combo.currentText()
        ok = r.get('status') == 'assessed'
        if show == SHOW[1]:
            return ok and r['level'] != 'LOW'
        if show == SHOW[2]:
            return not ok
        if show == SHOW_CHANGED:
            return bool(r.get('change'))
        return True

    def apply_filter(self, *_):
        shown = 0
        for row in range(self.table.rowCount()):
            r = self.result_at(row)
            visible = r is not None and self.row_visible(r)
            self.table.setRowHidden(row, not visible)
            shown += visible
        total = self.table.rowCount()
        self.shown_label.setText(f'showing {shown} of {total}' if total else '')

    def on_select(self):
        rows = {i.row() for i in self.table.selectedItems()}
        self.detail.show_result(self.result_at(rows.pop()) if rows else None)

    def show_text(self, row):
        """MLWINT's plain-text report for this file (the same text as in the .txt report)."""
        r = self.result_at(row)
        if not r:
            return
        d = QDialog(self)
        d.setWindowTitle('MLWINT report - ' + Path(str(r.get('path'))).name)
        d.resize(900, 600)
        t = QPlainTextEdit(cli.text_block(r))
        t.setReadOnly(True)
        t.setFont(QFont('Consolas', 9))
        QVBoxLayout(d).addWidget(t)
        d.exec()

    def row_menu(self, pos):
        row = self.table.rowAt(pos.y())
        r = self.result_at(row) if row >= 0 else None
        if not r:
            return
        m = QMenu(self)
        m.addAction('Show as plain text', lambda: self.show_text(row))
        m.addAction('Show in Explorer (does not open the file)', lambda: show_in_explorer(r['path']))
        m.addAction('Copy path', lambda: QApplication.clipboard().setText(str(r['path'])))
        if r.get('sha256'):
            m.addAction('Copy SHA-256', lambda: QApplication.clipboard().setText(r['sha256']))
        m.exec(self.table.viewport().mapToGlobal(pos))