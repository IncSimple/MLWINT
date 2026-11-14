"""MLWINT engine for the Flutter window. Save as MLWINT/scripts/mlwint_engine.py
The Flutter app (mlwint_app/) starts this with the EMBER2024 environment and talks to it through stdin / stdout,
one JSON object per line. No network port is opened. It uses the same code as the command line
(scripts/mlwint_analyse.py), so the window and the command line give the same scores, share the memory and write
the same reports.
Read-only: nothing is deleted, moved, quarantined, run or uploaded.

  app -> engine   {"id": 7, "cmd": "history"}
  engine -> app   {"id": 7, "ok": true, "data": [...]}          or  {"id": 7, "ok": false, "error": "..."}
  engine -> app   {"event": "file", "i": 3, "n": 40, "result": {...}}     (while a scan runs)
Anything else printed (by MLWINT or by a library) goes to stderr, which the app shows in its log.

Try it by hand:  experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_engine.py   then type  {"id":1,"cmd":"hello"}
"""
import json, os, queue, subprocess, sys, threading, time, traceback
from collections import Counter
from pathlib import Path


class _QuietStream:
    """stderr for everything except the protocol: a log line that cannot be written is dropped, never an error
    (a failed write must not stop a scan)."""
    def __init__(self, stream):
        self.stream = stream

    def write(self, text):
        try:
            return self.stream.write(text)
        except (OSError, ValueError, AttributeError):
            return len(text)

    def flush(self):
        try:
            self.stream.flush()
        except (OSError, ValueError, AttributeError):
            pass

    def __getattr__(self, name):
        return getattr(self.stream, name)


# The protocol gets private copies of stdin and stdout. Everything else sees NUL as stdin and stderr as stdout, so
# no tool MLWINT starts (PowerShell, capa, Speakeasy, Defender) inherits the app's pipes: Windows ends the process
# when something touches the stdin pipe that the reader thread is waiting on.
_PROTO = os.fdopen(os.dup(1), 'w', encoding='utf-8', buffering=1, newline='\n')
_IN = os.fdopen(os.dup(0), 'r', encoding='utf-8', errors='replace')
os.dup2(os.open(os.devnull, os.O_RDONLY), 0)
os.dup2(2, 1)
sys.stdin = open(os.devnull, encoding='utf-8')
try:
    sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
except AttributeError:
    pass
sys.stderr = sys.stdout = _QuietStream(sys.stderr)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
import mlwint_analyse as cli  # noqa: E402
from src.app_settings import MEMORY_DAYS_RANGE, load_settings, models_dir, models_problem, save_settings  # noqa
from src.detection import scan_memory  # noqa: E402

ENGINE_VERSION = 1
DOWNLOADS = Path.home() / 'Downloads'
OPTION_DEFAULTS = dict(scope='files', include_windows=False, paths=[], types=list(cli.KINDS), recursive=True,
                       deep_all=False, large=False, reputation='off', evidence='needed', deep='needed',
                       context='needed', max_files=2000)
CHOICES = dict(evidence=('needed', 'all', 'none'), deep=('needed', 'all', 'none'),
               context=('needed', 'all', 'none'), reputation=('off', 'flagged', 'all'))

_lock = threading.Lock()


def send(obj):
    line = json.dumps(obj, default=str, ensure_ascii=False)
    with _lock:
        _PROTO.write(line + '\n')
        _PROTO.flush()


def event(name, **data):
    send(dict(event=name, **data))


def say(text):
    event('log', text=str(text))


# ---------------------------------------------------------------------------------------------- state
class Engine:
    def __init__(self, jobs):
        self.jobs = jobs                       # the main thread's queue (commands, and work that needs Qt)
        self.settings = load_settings()
        scan_memory.MAX_AGE_DAYS = self.settings['memory_days']
        self.tools_cache = {}
        self.scan = None

    # -------------------------------------------------- helpers
    def memory(self):
        tools = self.tools_cache.get('tools')
        return tools.get('memory') if tools else None

    def memory_count(self):
        mem = self.memory()
        if mem is not None:
            return len(mem)
        try:
            return len(json.loads(scan_memory.MEMORY_FILE.read_text(encoding='utf-8')).get('files', {}))
        except (OSError, ValueError):
            return 0

    @staticmethod
    def keys_state():
        from src.detection.phase3_reputation import KEYS_FILE
        from src.gui.settings_tab import SERVICES, mask
        try:
            saved = {k: v for k, v in json.loads(KEYS_FILE.read_text(encoding='utf-8')).items() if v}
        except (OSError, ValueError):
            saved = {}
        return [dict(name=name, label=label, help=help_, state=mask(saved.get(name, '')), saved=bool(saved.get(name)),
                     env=env if os.environ.get(env) else '') for name, label, env, help_ in SERVICES]

    def scan_options(self):
        saved = self.settings.get('scan_options') or {}
        o = dict(OPTION_DEFAULTS, **{k: v for k, v in saved.items() if k in OPTION_DEFAULTS})
        o['paths'] = [p for p in o['paths'] if Path(p).exists()]
        return o

    def history(self):
        from src.gui.history import HistoryIndex
        return HistoryIndex(cli.REPORTS_DIR)

    # -------------------------------------------------- commands
    @staticmethod
    def versions():
        """version.json: the app and models versions of this copy of MLWINT (written by packaging/build_release.py)."""
        try:
            v = json.loads((ROOT / 'version.json').read_text(encoding='utf-8'))
        except (OSError, ValueError):
            v = {}
        return dict(app=str(v.get('app', 'dev')), models=str(v.get('models', 'dev')))

    def cmd_hello(self, _):
        from src.gui.settings_tab import PRIVACY
        return dict(version=ENGINE_VERSION, versions=self.versions(), root=str(ROOT), downloads=str(DOWNLOADS), kinds=list(cli.KINDS),
                    kind_names=cli.KIND_NAMES, choices=CHOICES, settings=self.public_settings(),
                    scan_options=self.scan_options(), memory=self.memory_count(), keys=self.keys_state(),
                    reports=str(cli.REPORTS_DIR), privacy=PRIVACY, memory_days_range=list(MEMORY_DAYS_RANGE),
                    large_mb=cli.MAX_BYTES // 1024 ** 2)

    def public_settings(self):
        s = dict(self.settings)
        s.pop('scan_options', None)
        s['models_state'] = ('default models' if not s.get('models_dir') else
                             (f'problem: {models_problem(s["models_dir"])}' if models_problem(s['models_dir'])
                              else 'OK'))
        return s

    def cmd_health(self, _):
        from src.gui.settings_tab import health
        return [dict(part=p, ok=bool(ok), detail=str(d)) for p, ok, d in health()]

    def cmd_status(self, _):
        return dict(memory=self.memory_count(), keys=self.keys_state(), settings=self.public_settings(),
                    scanning=self.scan is not None and self.scan.is_alive())

    def cmd_history(self, _):
        return [e for e in self.history().load()]

    def cmd_report(self, a):
        """One earlier scan: its results, each compared with the previous scan of the same place."""
        from src.gui.history import compare
        index = self.history()
        entries = index.load()
        entry = next((e for e in entries if e['file'] == a['file']), None)
        if entry is None:
            raise ValueError('that report is no longer there')
        data = index.read(entry['file'])
        results = data.get('results', [])
        prev = index.previous(entries, entry)
        gone = None
        if prev:
            try:
                gone = compare(results, index.read(prev['file']).get('results', []))
            except (OSError, ValueError):
                prev = None
        js = index.folder / entry['file']
        return dict(entry=entry, results=results, previous=prev, gone=gone,
                    has_pdf=js.with_suffix('.pdf').is_file(), has_txt=js.with_suffix('.txt').is_file(),
                    not_checked=data.get('not_checked') or {})

    def report_file(self, name, suffix):
        """Only MLWINT's own report files can be opened, never a scanned file."""
        folder = cli.REPORTS_DIR.resolve()
        p = (folder / Path(name).name).with_suffix(suffix)
        if p.parent != folder or not Path(name).name.startswith('analysis-'):
            raise ValueError('not an MLWINT report')
        return p

    def cmd_open_report(self, a):
        kind = a.get('kind', 'pdf')
        p = self.report_file(a['file'], '.' + kind)
        if kind == 'pdf' and not p.is_file():
            made = cli.easy_report(p.with_suffix('.json'), say=say)        # older reports: made now (Qt, main thread)
            if not made:
                raise ValueError('the easy-to-read PDF could not be made')
        if not p.is_file():
            raise ValueError(f'{p.name} is missing')
        os.startfile(str(p))                                               # MLWINT's own report
        return str(p)

    def cmd_open_reports_folder(self, _):
        cli.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(cli.REPORTS_DIR))
        return str(cli.REPORTS_DIR)

    def cmd_reveal(self, a):
        """Highlights a scanned file in Explorer. Explorer does not open or run it."""
        p = Path(a['path'])
        if not p.exists():
            raise ValueError('the file is no longer there')
        subprocess.Popen(f'explorer /select,"{p}"')
        return True

    def cmd_text(self, a):
        return cli.text_block(a['result'])

    # settings
    def cmd_set(self, a):
        """Change one setting: memory_days / remember_options / animations / models_dir."""
        name, value = a['name'], a['value']
        if name == 'memory_days':
            lo, hi = MEMORY_DAYS_RANGE
            value = max(lo, min(hi, int(value)))
            scan_memory.MAX_AGE_DAYS = value
        elif name == 'models_dir':
            problem = models_problem(value) if value else ''
            if problem:
                raise ValueError(f'this folder cannot be used: {problem}')
            self.tools_cache.clear()                                       # reloaded with the new models
        elif name in ('remember_options', 'animations'):
            value = bool(value)
        else:
            raise ValueError(f'unknown setting {name}')
        self.settings[name] = value
        if name == 'remember_options' and not value:
            self.settings['scan_options'] = {}
        save_settings(self.settings)
        return self.public_settings()

    def cmd_keep_options(self, a):
        if self.settings.get('remember_options'):
            o = {k: v for k, v in (a.get('options') or {}).items() if k in OPTION_DEFAULTS}
            self.settings['scan_options'] = o
            save_settings(self.settings)
        return True

    def cmd_reset_options(self, _):
        self.settings['scan_options'] = {}
        save_settings(self.settings)
        return self.scan_options()

    def cmd_keys_save(self, a):
        from src.detection.phase3_reputation import KEYS_FILE
        typed = {k: str(v).strip() for k, v in (a.get('keys') or {}).items() if str(v or '').strip()}
        if not typed:
            raise ValueError('type or paste a key first')
        bad = [n for n, v in typed.items() if len(v) < 16 or any(c.isspace() for c in v)]
        if bad:
            raise ValueError('that does not look like a whole key (too short or contains spaces): ' + ', '.join(bad))
        try:
            saved = {k: v for k, v in json.loads(KEYS_FILE.read_text(encoding='utf-8')).items() if v}
        except (OSError, ValueError):
            saved = {}
        saved.update(typed)
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEYS_FILE.write_text(json.dumps(saved, indent=1), encoding='utf-8')
        self.tools_cache.clear()
        return self.keys_state()

    def cmd_keys_remove(self, _):
        from src.detection.phase3_reputation import KEYS_FILE
        if KEYS_FILE.is_file():
            KEYS_FILE.write_text('{}', encoding='utf-8')
        self.tools_cache.clear()
        return self.keys_state()

    def cmd_keys_test(self, _):
        """Sends ONE harmless public fingerprint (the EICAR test file) to each service with a key."""
        from src.detection.phase3_reputation import Reputation, load_keys, opinion
        from src.gui.settings_tab import EICAR_SHA256
        keys = load_keys()
        if not keys:
            raise ValueError('no key saved yet')
        res = Reputation(keys=keys).lookup(EICAR_SHA256)
        lines = []
        for service, r in res.items():
            if r['status'] == 'found':
                lines.append(f'{service}: works (knows the EICAR test file)')
            elif r['status'] == 'not_found':
                lines.append(f'{service}: works (answered: not known)')
            else:
                lines.append(f'{service}: problem - {r.get("reason")}')
        return dict(lines=lines, meter=opinion(res)[2])

    def cmd_forget(self, _):
        if self.scan is not None and self.scan.is_alive():
            raise ValueError('wait until the scan has finished')
        mem = self.memory() or scan_memory.ScanMemory()
        mem.forget()
        return self.memory_count()

    # scanning
    def cmd_scan(self, a):
        if self.scan is not None and self.scan.is_alive():
            raise ValueError('a scan is already running')
        o = dict(OPTION_DEFAULTS, **{k: v for k, v in (a.get('options') or {}).items() if k in OPTION_DEFAULTS})
        for k, allowed in CHOICES.items():
            if o[k] not in allowed:
                raise ValueError(f'{k} must be one of {", ".join(allowed)}')
        whole = o['scope'] == 'pc'
        if o['deep_all']:
            o['evidence'] = o['deep'] = 'all'
        options = dict(evidence=o['evidence'], deep=o['deep'], context=o['context'], reputation=o['reputation'],
                       recursive=bool(o['recursive']) or whole, types=sorted(set(o['types']) & set(cli.KINDS)),
                       large=bool(o['large']), fresh=bool(a.get('fresh')), whole_pc=whole,
                       include_windows=whole and bool(o['include_windows']))
        if not options['types']:
            raise ValueError('tick at least one kind of file to check')
        paths = [str(p) for p in o['paths']]
        if not whole and not paths:
            raise ValueError('add a file or folder first, or choose Whole PC')
        missing = [p for p in paths if not Path(p).exists()]
        if missing:
            raise ValueError('not found: ' + ', '.join(missing))
        self.cmd_keep_options(dict(options=o))
        self.settings = load_settings()
        self.scan = Scan(self, paths, options, int(o['max_files']), models_dir(self.settings))
        self.scan.start()
        return True

    def cmd_stop(self, _):
        if self.scan is not None:
            self.scan.stop = True                          # takes effect after the file being analysed now
        return True

    def cmd_quit(self, _):
        self.cmd_stop(None)
        self.jobs.put(('quit', None))
        return True

    # -------------------------------------------------- main thread
    def handle(self, line):
        try:
            msg = json.loads(line)
        except ValueError:
            say(f'engine: ignored a line that is not JSON: {line[:80]!r}')
            return
        rid, cmd = msg.get('id'), msg.get('cmd', '')
        fn = getattr(self, 'cmd_' + cmd, None)
        if fn is None:
            send(dict(id=rid, ok=False, error=f'unknown command {cmd!r}'))
            return
        try:
            send(dict(id=rid, ok=True, data=fn(msg)))
        except Exception as e:                             # shown in the window, never a silent crash
            print(traceback.format_exc(), file=sys.stderr)
            send(dict(id=rid, ok=False, error=f'{e}' if isinstance(e, ValueError) else f'{type(e).__name__}: {e}'))

    def finish_scan(self, info):
        """Runs on the main thread: the PDF is Qt work."""
        try:
            pdf = cli.easy_report(info['json'], say=say)
        except Exception as e:                             # the technical reports are written already
            say(f'Note: the easy-to-read PDF could not be made ({type(e).__name__}: {e})')
            pdf = None
        info['pdf'] = str(pdf) if pdf else None
        info['file'] = Path(info['json']).name
        info['memory_count'] = self.memory_count()
        event('finished', **info)


class Scan(threading.Thread):
    """The scan itself, exactly like the Qt window's worker (src/gui/worker.py)."""
    def __init__(self, engine, paths, options, max_files, models):
        super().__init__(daemon=True)
        self.engine, self.paths, self.options, self.max_files, self.models = engine, paths, options, max_files, models
        self.stop = False

    def run(self):
        tools, cache = None, self.engine.tools_cache
        try:
            started, t_all = time.strftime('%Y-%m-%d %H:%M:%S'), time.time()
            say('MLWINT analyse (read-only: nothing is deleted, moved, run or uploaded)')
            whole = self.options.get('whole_pc')
            paths = cli.whole_pc_roots() if whole else self.paths
            excludes = cli.default_excludes(self.options.get('include_windows')) if whole else ()
            if whole:
                say(f'Whole PC: {", ".join(paths)} (skipping: {", ".join(excludes)})')
            event('phase', text='Looking for Windows programs and PDFs')
            skipped, last = Counter(), [0.0]

            def searching(seen, found):
                now = time.time()
                if now - last[0] > 0.25:                      # at most 4 updates a second
                    last[0] = now
                    event('searching', seen=seen, found=found)

            files, cut = cli.candidates(paths, self.options['recursive'] or whole,
                                        cli.WHOLE_PC_MAX if whole else self.max_files,
                                        set(self.options.get('types') or cli.KINDS), skipped, excludes,
                                        progress=searching)
            note = cli.skipped_text(skipped)
            event('counted', n=len(files), cut=cut, note=note, max_files=self.max_files)
            if note:
                say(note)
            key = (str(self.models), self.options['reputation'])
            if cache.get('key') != key:                       # models load once, then are reused between scans
                event('phase', text='Loading models')
                say('Loading models ...')
                cache.clear()
                cache.update(key=key, tools=cli.load_tools(self.models, self.options['reputation'], say=say))
            tools = cache['tools']
            if tools.get('memory') is not None:
                tools['memory'].reset_stats()
            event('phase', text='Checking files')
            results = []
            for i, f in enumerate(files, 1):
                if self.stop:
                    say(f'Stopped by you after {len(results)} of {len(files)} files')
                    break
                event('checking', i=i, n=len(files), path=str(f))
                r = cli.analyse_one(tools, f, self.options)
                results.append(r)
                event('file', i=i, n=len(files), result=r)
            cli.save_memory(tools)
            mem_note = tools['memory'].summary() if tools.get('memory') is not None else ''
            txt, js, head, _ = cli.write_report(results, paths, self.options, started, time.time() - t_all,
                                                skipped, pdf=False, memory_note=mem_note)
            self.engine.jobs.put(('finished', dict(txt=str(txt), json=str(js), head=list(head), stopped=self.stop,
                                                   count=len(results), skipped=note, memory=mem_note)))
        except BaseException as e:                          # also SystemExit from a library: never a silent stop
            event('failed', error=f'{type(e).__name__}: {e}')  # the window is told first
            print(traceback.format_exc(), file=sys.stderr)
            if tools is not None:
                try:
                    cli.save_memory(tools)
                except Exception:
                    pass


def main():
    jobs = queue.Queue()
    engine = Engine(jobs)
    # any thread that stops with an error tells the window (a scan never looks "stuck")
    threading.excepthook = lambda a: event('failed', error=f'{a.exc_type.__name__}: {a.exc_value}')

    def reader():
        for line in _IN:
            if line.strip():
                jobs.put(('cmd', line))
        jobs.put(('quit', None))                          # the window closed: stop

    threading.Thread(target=reader, daemon=True).start()
    event('ready', version=ENGINE_VERSION)
    while True:
        kind, data = jobs.get()
        if kind == 'cmd':
            engine.handle(data)
        elif kind == 'finished':
            engine.finish_scan(data)
        elif kind == 'quit':
            if engine.scan is not None and engine.scan.is_alive():
                engine.scan.stop = True
                engine.scan.join(timeout=60)              # lets the memory be saved
            break
    return 0


if __name__ == '__main__':
    sys.exit(main())