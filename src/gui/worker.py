"""MLWINT GUI: the scan runs here, in a background thread. Save as MLWINT/src/gui/worker.py
Uses exactly the same code as scripts/mlwint_analyse.py (candidates, load_tools, analyse_one, write_report), so the
window and the command line always give the same scores, use the same memory and write the same reports.
Read-only, like the command.
"""
import sys, time
from collections import Counter
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import mlwint_analyse as cli  # noqa: E402


class ScanWorker(QObject):
    message = Signal(str)             # a line for the log
    searching = Signal(int, int)      # files looked at, files to analyse (while searching)
    counted = Signal(int, bool, str)  # files found, stopped at max-files?, 'not checked' text ('' if none)
    file_done = Signal(int, dict)     # index (1-based), result
    finished = Signal(dict)           # dict(txt, json, head, stopped, count, skipped, memory)
    failed = Signal(str)

    def __init__(self, paths, options, max_files, models=None, tools_cache=None):
        super().__init__()
        self.paths, self.options, self.max_files, self.models = list(paths), dict(options), max_files, models
        self.tools_cache = tools_cache if tools_cache is not None else {}
        self._stop = False

    def stop(self):
        self._stop = True             # takes effect after the file being analysed now

    @Slot()
    def run(self):
        tools = None
        try:
            started, t_all = time.strftime('%Y-%m-%d %H:%M:%S'), time.time()
            self.message.emit('MLWINT analyse (read-only: nothing is deleted, moved, run or uploaded)')
            whole = self.options.get('whole_pc')
            paths = cli.whole_pc_roots() if whole else self.paths
            excludes = cli.default_excludes(self.options.get('include_windows')) if whole else ()
            if whole:
                self.message.emit(f'Whole PC: {", ".join(paths)} (skipping: {", ".join(excludes)})')
            skipped = Counter()
            files, cut = cli.candidates(paths, self.options['recursive'] or whole,
                                        cli.WHOLE_PC_MAX if whole else self.max_files,
                                        set(self.options.get('types') or cli.KINDS), skipped, excludes,
                                        progress=self.searching.emit)
            note = cli.skipped_text(skipped)
            self.counted.emit(len(files), cut, note)
            if note:
                self.message.emit(note)
            key = (str(self.models), self.options['reputation'])
            if self.tools_cache.get('key') != key:            # models load once, then are reused between scans
                self.message.emit('Loading models ...')
                self.tools_cache.clear()
                self.tools_cache.update(key=key, tools=cli.load_tools(self.models, self.options['reputation'],
                                                                      say=self.message.emit))
            tools = self.tools_cache['tools']
            if tools.get('memory') is not None:
                tools['memory'].reset_stats()
            results = []
            for i, f in enumerate(files, 1):
                if self._stop:
                    self.message.emit(f'Stopped by you after {len(results)} of {len(files)} files')
                    break
                r = cli.analyse_one(tools, f, self.options)
                results.append(r)
                self.file_done.emit(i, r)
            cli.save_memory(tools)
            mem_note = tools['memory'].summary() if tools.get('memory') is not None else ''
            txt, js, head, _ = cli.write_report(results, paths, self.options, started, time.time() - t_all,
                                                skipped, pdf=False, memory_note=mem_note)  # PDF: made by the window
            self.finished.emit(dict(txt=str(txt), json=str(js), head=head, stopped=self._stop, count=len(results),
                                    skipped=note, memory=mem_note))
        except Exception as e:                                  # shown in the window, never a silent crash
            if tools is not None:
                try:
                    cli.save_memory(tools)
                except Exception:
                    pass
            self.failed.emit(f'{type(e).__name__}: {e}')