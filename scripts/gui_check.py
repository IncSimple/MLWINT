"""GUI check (G1 + G1b file types + G2 detail panel), without clicking: the window is built off-screen.
Save as MLWINT/scripts/gui_check.py. Run from the MLWINT folder:
    experiments/ember2024/.venv/Scripts/python.exe scripts/gui_check.py
  1. window: no delete / quarantine / run button; hash lookup starts OFF; file-type picker logic
  2. scan of harmless files (Windows' own 32-bit + 64-bit notepad.exe and a tiny PDF, copied to a temp folder):
     table, progress, reports, same scores as the command-line code
  3. file types: PDF unticked -> the PDF is NOT analysed and is reported as 'not checked'
  4. results: find box and 'Needs attention' filter; clicking a row fills the detail panel and the gauge
  5. detail panel can show every result in your earlier reports (reports/analyse/*.json) without an error
  6. Stop at once still writes a report
  7. the easy-to-read PDF report is written after a scan
  8. memory: scanning the same folder again uses the remembered results (a temporary memory file is used here,
     your real memory is not touched); 'Whole PC' and 'Deep check' set the right options
Writes reports/gui/gui-check-g2.json (its test scans' reports go to a temp folder, not to your History).
"""
import json, os, shutil, sys, tempfile, time
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402
from src.gui.app import MainWindow  # noqa: E402
from src.gui.widgets import detail_html  # noqa: E402
from src.gui.worker import cli  # noqa: E402
from src.detection.scan_memory import ScanMemory  # noqa: E402

TINY_PDF = (b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n'
            b'3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]/Contents 4 0 R>>endobj\n'
            b'4 0 obj<</Length 35>>stream\nBT /F1 12 Tf 20 100 Td (hello) Tj ET\nendstream endobj\n'
            b'trailer<</Root 1 0 R/Size 5>>\n%%EOF\n')
FAST = dict(evidence='none', deep='none', context='none', reputation='off')


def wait_for(window, timeout=600):
    """Lets the window work until its scan has ended and the window has shown the result."""
    app, end = QApplication.instance(), time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if (window.last_info or window.last_error) and not window.thread.isRunning():
            break
        time.sleep(0.05)
    app.processEvents()
    return dict(info=window.last_info) if window.last_info else dict(error=window.last_error or 'timed out')


def visible_rows(w):
    return [r for r in range(w.table.rowCount()) if not w.table.isRowHidden(r)]


def main():
    app = QApplication.instance() or QApplication(sys.argv[:1])
    checks = []
    mem_dir = tempfile.TemporaryDirectory()
    w = MainWindow(settings_path=Path(mem_dir.name) / 'settings.json')    # your real settings are not touched
    tools = cli.load_tools(say=lambda s: None)                           # models once, with a temporary memory
    tools['memory'] = ScanMemory(path=Path(mem_dir.name) / 'memory.json')
    w.tools_cache.update(key=(str(None), 'off'), tools=tools)
    cli.REPORTS_DIR = Path(mem_dir.name) / 'reports'                     # test scans stay out of your History

    # ---- simple options
    w.deep_all.setChecked(True)
    deep_on = (w.combos['evidence'].currentText(), w.combos['deep'].currentText()) == ('all', 'all') \
        and not w.combos['deep'].isEnabled()
    w.deep_all.setChecked(False)
    deep_off = (w.combos['evidence'].currentText(), w.combos['deep'].currentText()) == ('needed', 'needed')
    w.scope_pc.setChecked(True)
    o = w.options()
    pc_ok = o['whole_pc'] and o['recursive'] and not w.paths.isEnabled() and w.include_windows.isEnabled()
    w.scope_files.setChecked(True)
    back = not w.options()['whole_pc'] and w.paths.isEnabled() and not w.include_windows.isEnabled()
    checks.append(('"Deep check" and "Whole PC" set the right options', deep_on and deep_off and pc_ok and back,
                   f'deep {deep_on}/{deep_off}, whole PC {pc_ok}, back {back}'))
    buttons = [b.text().lower() for b in w.findChildren(QPushButton)]
    bad = [b for b in buttons if any(x in b for x in ('delete', 'quarantine', 'remove file', 'run', 'execute'))]
    checks.append(('no delete / quarantine / run buttons', not bad, ', '.join(buttons)))
    checks.append(('hash lookup starts OFF', w.options()['reputation'] == 'off' and 'OFF' in w.banner.text(),
                   w.banner.text()))

    # ---- file-type picker logic (what a user's clicks do)
    tp = w.types
    start_all = tp.types() == set(cli.KINDS) and tp.everything.isChecked()
    tp.kind['win64'].setChecked(False)
    partial = tp.programs.checkState().name if hasattr(tp.programs.checkState(), 'name') else tp.programs.checkState()
    tp.programs.click()                                                   # partial -> all programs on
    all_on = {'win32', 'win64', 'dotnet'} <= tp.types()
    tp.everything.click()                                                 # everything off
    none = not tp.types() and not w.scan_btn.isEnabled()
    tp.everything.click()                                                 # everything on again
    checks.append(('type picker: everything / programs / partial work',
                   start_all and 'Partially' in str(partial) and all_on and none and tp.types() == set(cli.KINDS),
                   f'partial shown as {partial}; empty choice disables Scan: {none}'))

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        sysroot = Path(os.environ.get('SystemRoot', r'C:\Windows'))
        shutil.copy(sysroot / 'System32' / 'notepad.exe', tmp / 'notepad64.exe')
        if (sysroot / 'SysWOW64' / 'notepad.exe').is_file():
            shutil.copy(sysroot / 'SysWOW64' / 'notepad.exe', tmp / 'notepad32.exe')
        (tmp / 'tiny-test.pdf').write_bytes(TINY_PDF)
        (tmp / 'notes.txt').write_text('not a program', encoding='utf-8')
        n_files = len([f for f in tmp.iterdir() if f.suffix in ('.exe', '.pdf')])
        w.add_paths([str(tmp), str(tmp)])                                 # duplicates must be ignored
        checks.append(('file list ignores duplicates', w.paths.count() == 1, f'{w.paths.count()} entries'))
        for k, v in FAST.items():
            w.combos[k].setCurrentText(v)

        # ---- scan 1: everything
        t0 = time.time()
        w.start_scan()
        out = wait_for(w)
        info = out.get('info') or {}
        checks.append(('scan finished without error', 'info' in out, out.get('error', f'{time.time() - t0:.0f} s')))
        rows = w.table.rowCount()
        checks.append(('one row per program / PDF (text file passed over)', rows == n_files, f'{rows} rows'))
        checks.append(('progress bar reached the end', w.progress.value() == w.progress.maximum() == n_files,
                       f'{w.progress.value()} / {w.progress.maximum()}'))
        scores = [w.table.item(i, 0).value for i in range(rows)]
        checks.append(('sorted worst first', scores == sorted(scores, reverse=True), str(scores)))
        js = Path(info.get('json', ''))
        rep = json.loads(js.read_text(encoding='utf-8')) if js.is_file() else {}
        checks.append(('reports written (options + types saved)', Path(info.get('txt', '')).is_file()
                       and rep.get('options', {}).get('types') == sorted(cli.KINDS), js.name))
        pdf = Path(info.get('pdf') or '')
        checks.append(('easy-to-read PDF written, Open report button on', pdf.is_file()
                       and pdf.read_bytes()[:5] == b'%PDF-' and w.report_btn.isEnabled(),
                       f'{pdf.name} ({pdf.stat().st_size // 1024 if pdf.is_file() else 0} KB)'))
        tools = w.tools_cache.get('tools')
        same = []
        for r in w.results:
            if r.get('status') == 'assessed':
                c = cli.analyse_one(tools, r['path'], dict(FAST, recursive=False))
                same.append((r['score'], r['level']) == (c['score'], c['level']))
        checks.append(('same scores as the command-line code', bool(same) and all(same),
                       '; '.join(f'{Path(str(r.get("path"))).name}: {r.get("score")} {r.get("level")}'
                                 for r in w.results)))
        # ---- the same folder again: everything comes from the memory
        t1 = time.time()
        w.start_scan()
        info_m = wait_for(w).get('info') or {}
        how = [w.table.item(i, 6).text() for i in range(w.table.rowCount())]
        checks.append(('same folder again: results remembered', how and all(h.startswith('remembered') for h in how)
                       and 'unchanged' in info_m.get('memory', ''), f'{info_m.get("memory")} ({time.time() - t1:.1f} s)'))
        # ---- detail panel follows the selected row
        sel = w.table.selectedItems()
        r0 = w.result_at(sel[0].row()) if sel else None
        checks.append(('worst file selected and shown on the right', r0 is not None and w.detail.result is r0
                       and w.detail.gauge.score == r0['score'] and 'Why this score' in w.detail.body.toHtml(),
                       f'{Path(str(r0.get("path"))).name if r0 else None}: gauge {w.detail.gauge.score}'))

        # ---- find box + show filter
        w.search.setText('notepad')
        names = [Path(str(w.result_at(i)['path'])).name for i in visible_rows(w)]
        find_ok = names and all('notepad' in n for n in names) and 'showing' in w.shown_label.text()
        w.search.clear()
        w.show_combo.setCurrentIndex(1)
        attention = [w.result_at(i) for i in visible_rows(w)]
        show_ok = all(r['level'] != 'LOW' for r in attention)
        w.show_combo.setCurrentIndex(0)
        checks.append(('find box and "needs attention" filter', bool(find_ok and show_ok and
                                                                    len(visible_rows(w)) == rows),
                       f'find: {names}; above LOW: {len(attention)}'))

        # ---- scan 2: programs only (PDF unticked)
        tp.kind['pdf'].setChecked(False)
        w.start_scan()
        info2 = wait_for(w).get('info') or {}
        kinds = {w.result_at(i).get('format') for i in range(w.table.rowCount())}
        rep2 = json.loads(Path(info2['json']).read_text(encoding='utf-8')) if info2.get('json') else {}
        checks.append(('PDF unticked: PDF not analysed, reported as not checked',
                       'PDF' not in kinds and rep2.get('not_checked') == {'pdf': 1}
                       and 'NO verdict' in info2.get('skipped', '') and 'Not checked' in open(
                           info2['txt'], encoding='utf-8').read(), info2.get('skipped', '')))
        tp.kind['pdf'].setChecked(True)

        # ---- Stop at once
        w.start_scan()
        w.stop_scan()
        info3 = wait_for(w).get('info') or {}
        checks.append(('Stop works and still writes a report', info3.get('stopped') is True
                       and info3.get('count', 9) <= 1 and Path(info3.get('txt', '')).is_file(),
                       f'{info3.get("count")} file(s) before stopping'))
        checks.append(('buttons usable again after the scan', w.scan_btn.isEnabled() and not w.stop_btn.isEnabled()
                       and w.types.isEnabled(), ''))
        w.combos['reputation'].setCurrentText('flagged')
        checks.append(('banner warns when hash lookup is ON', 'only SHA-256' in w.banner.text(), ''))

    # ---- detail panel on every earlier result
    n_res, errors, levels = 0, [], set()
    for f in sorted((ROOT / 'reports/analyse').glob('analysis-*.json')):
        try:
            for r in json.loads(f.read_text(encoding='utf-8')).get('results', []):
                n_res += 1
                levels.add(r.get('level'))
                try:
                    w.detail.show_result(r)
                    detail_html(r)
                except Exception as e:
                    errors.append(f'{f.name}: {type(e).__name__}: {e}')
        except ValueError:
            pass
    checks.append(('detail panel shows all earlier results', not errors,
                   errors[0] if errors else f'{n_res} results, levels {sorted(l for l in levels if l)}'))
    w.close()
    mem_dir.cleanup()
    ok = True
    for name, passed, detail in checks:
        ok &= bool(passed)
        print(f'{"PASS" if passed else "FAIL"}  {name:<55} {str(detail)[:100]}')
    status = 'GUI_G2_CHECKED' if ok else 'GUI_G2_FAILED'
    out = ROOT / 'reports/gui/gui-check-g2.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(status=status, checks=[dict(name=n, passed=bool(p), detail=str(d))
                                                          for n, p, d in checks]), indent=1), encoding='utf-8')
    print(f'\n{status}: {out}')


if __name__ == '__main__':
    main()