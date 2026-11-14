"""GUI step G3 check: the History tab, without clicking (built off-screen). Save as MLWINT/scripts/history_check.py
Run from the MLWINT folder:
    experiments/ember2024/.venv/Scripts/python.exe scripts/history_check.py
Uses three made-up reports in a temp folder (your real reports are only read in the last check):
  A  10 Nov  Downloads:  a.exe LOW 5, b.pdf GUARDED 39, c.exe ELEVATED 45, gone.exe LOW 0
  C  11 Nov  Desktop:    other.exe LOW 0                      (a different place)
  B  12 Nov  Downloads:  a.exe GUARDED 25, b.pdf GUARDED 39, c.exe LOW 10, d.exe HIGH 70, e.pdf with new contents
Checks: list newest first with the right counts; B is compared with A (not C, which looked elsewhere); a = worse,
c = better, d = new, e = changed, b = unchanged, 1 gone; the 'Changed since last scan' filter; a scan with no
earlier one says so; the PDF of an old report is made on request; the index cache is written; the History tab is in
the main window; and every report in your reports/analyse folder opens without an error.
Writes reports/gui/history-check-g3.json.
"""
import json, os, sys, tempfile
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from PySide6.QtWidgets import QApplication  # noqa: E402
from src.gui.history import HistoryTab, HistoryIndex, INDEX_NAME  # noqa: E402
from src.gui.app import MainWindow  # noqa: E402

DL, DESK = r'C:\Users\someone\Downloads', r'C:\Users\someone\Desktop'


def res(folder, name, score, level, sha, fmt='Win32'):
    return dict(status='assessed', path=os.path.join(folder, name), score=score, level=level, format=fmt,
                verdict='CLEAN' if level == 'LOW' else 'SUSPICIOUS', sha256=sha, parts=[], seconds=0.1,
                summary=f'{level} test', advice=dict(headline=f'{level} test', actions=[], notes=[]))


def report(folder, stamp, started, paths, results):
    data = dict(status='MLWINT_ANALYSIS', started=started, paths=paths, options=dict(whole_pc=False),
                counts={}, not_checked={}, memory='', results=results)
    (Path(folder) / f'analysis-{stamp}.json').write_text(json.dumps(data), encoding='utf-8')
    (Path(folder) / f'analysis-{stamp}.txt').write_text(f'MLWINT analysis  {started}  (42 s)\n', encoding='utf-8')


def main():
    app = QApplication.instance() or QApplication(sys.argv[:1])
    checks = []
    with tempfile.TemporaryDirectory() as tmp:
        report(tmp, '20261110-100000', '2026-11-10 10:00:00', [DL],
               [res(DL, 'a.exe', 5, 'LOW', 'a1'), res(DL, 'b.pdf', 39, 'GUARDED', 'b1', 'PDF'),
                res(DL, 'c.exe', 45, 'ELEVATED', 'c1'), res(DL, 'gone.exe', 0, 'LOW', 'g1'),
                res(DL, 'e.pdf', 0, 'LOW', 'e1', 'PDF')])
        report(tmp, '20261111-100000', '2026-11-11 10:00:00', [DESK], [res(DESK, 'other.exe', 0, 'LOW', 'o1')])
        report(tmp, '20261112-100000', '2026-11-12 10:00:00', [DL],
               [res(DL, 'a.exe', 25, 'GUARDED', 'a1'), res(DL, 'b.pdf', 39, 'GUARDED', 'b1', 'PDF'),
                res(DL, 'c.exe', 10, 'LOW', 'c1'), res(DL, 'd.exe', 70, 'HIGH', 'd1'),
                res(DL, 'e.pdf', 0, 'LOW', 'e2', 'PDF')])

        h = HistoryTab(tmp)
        h.refresh(select_newest=True)
        when = [h.list.item(r, 0).text() for r in range(h.list.rowCount())]
        b_row = [h.list.item(0, c).text() for c in range(h.list.columnCount())]
        checks.append(('1 scans listed newest first, with counts', when == ['2026-11-12 10:00:00', '2026-11-11 10:00:00',
                                                                             '2026-11-10 10:00:00']
                       and b_row[2:8] == ['5', '1', '0', '2', '2', '0'] and b_row[8] == '42 s', ' | '.join(b_row)))
        ch = {Path(r['path']).name: r.get('change', '') for r in h.view.results}
        checks.append(('2 compared with the same place (A, not C)', 'Since the scan of 2026-11-10' in h.summary.text(),
                       h.summary.text()[-120:]))
        ok = (ch['a.exe'].startswith('worse (was 5 LOW') and ch['c.exe'].startswith('better (was 45 ELEVATED')
              and ch['d.exe'] == 'new' and ch['e.pdf'].startswith('changed') and ch['b.pdf'] == ''
              and '1 gone' in h.summary.text())
        checks.append(('3 new / worse / better / changed / gone are right', ok, str(ch)))
        h.view.show_combo.setCurrentText('Changed since last scan')
        shown = sorted(Path(h.view.result_at(r)['path']).name for r in range(h.view.table.rowCount())
                       if not h.view.table.isRowHidden(r))
        checks.append(('4 "Changed since last scan" shows only those', shown == ['a.exe', 'c.exe', 'd.exe', 'e.pdf'],
                       str(shown)))
        h.view.show_combo.setCurrentIndex(0)
        sel = h.view.table.selectedItems()
        top = h.view.result_at(sel[0].row()) if sel else None
        checks.append(('5 worst file selected, detail panel filled', top is not None and top['score'] == 70
                       and h.view.detail.result is top, Path(top['path']).name if top else '-'))
        h.list.selectRow(2)                                      # A: the oldest, nothing earlier
        checks.append(('6 a scan with nothing earlier says so', 'No earlier scan' in h.summary.text(),
                       h.summary.text()[-60:]))
        pdf = h.pdf_path()
        checks.append(('7 PDF of an old report made on request', pdf is not None and Path(pdf).is_file()
                       and Path(pdf).read_bytes()[:5] == b'%PDF-', Path(pdf).name if pdf else 'not made'))
        idx = Path(tmp) / INDEX_NAME
        again = HistoryIndex(tmp).load()
        checks.append(('8 index cache written and reused', idx.is_file() and len(again) == 3
                       and all('key' in e for e in again), f'{idx.name}, {len(again)} entries'))

    settings_dir = tempfile.TemporaryDirectory()
    w = MainWindow(settings_path=Path(settings_dir.name) / 'settings.json')
    names = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    checks.append(('9 main window has all pages', names == ['Dashboard', 'Scan', 'History', 'Settings', 'Help & About'],
                   str(names)))
    errors, n = [], 0
    real = HistoryTab()
    real.refresh()
    for row in range(real.list.rowCount()):
        real.list.selectRow(row)
        n += 1
        if real.current is None or real.list.item(row, 0).data(0x0100) != real.current['file']:
            errors.append(real.list.item(row, 0).text())
    checks.append(('10 every report in reports/analyse opens', not errors,
                   errors[0] if errors else f'{n} reports opened'))
    w.close()
    settings_dir.cleanup()

    ok = True
    for name, passed, detail in checks:
        ok &= bool(passed)
        print(f'{"PASS" if passed else "FAIL"}  {name:<52} {str(detail)[:100]}')
    status = 'GUI_G3_CHECKED' if ok else 'GUI_G3_FAILED'
    out = ROOT / 'reports/gui/history-check-g3.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(status=status, checks=[dict(name=n, passed=bool(p), detail=str(d))
                                                          for n, p, d in checks]), indent=1), encoding='utf-8')
    print(f'\n{status}: {out}')


if __name__ == '__main__':
    main()