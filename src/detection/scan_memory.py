"""MLWINT scan memory: remember results so unchanged files are not analysed again.
Save as MLWINT/src/detection/scan_memory.py

A file's earlier result is reused only when ALL of these hold:
  1. same contents     - SHA-256 fingerprint of the whole file (a new download with the same NAME but different
                         bytes has a different fingerprint, so it is always checked)
  2. same place, size and dates - the file at this path has the same size, creation date (when it arrived on this
                         PC, e.g. downloaded) and modified date as when it was checked; a re-download, copy or edit
                         changes them, and then the file is fully checked again even if the bytes are identical
  3. same MLWINT       - the models, rules and analysis code are unchanged (otherwise everything is checked again)
  4. recent enough     - checked within the last MAX_AGE_DAYS days
  5. checked at least as deeply as now asked (e.g. an earlier quick scan does not count for a deep check)
What is reused: the slow, unchanging parts (detector, family / behaviour, capa evidence, emulation). What is always
refreshed: everything that can change over time (run before? running? autostart? Defender history, hash lookup).
The memory is MLWINT's own file (reports/memory/scan-memory.json); scanned files are never changed.
"""
import hashlib, json, os, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MEMORY_FILE = ROOT / 'reports/memory/scan-memory.json'
MEMORY_VERSION = 1
MAX_AGE_DAYS = 30
DEPTH = {'none': 0, 'needed': 1, 'all': 2}
SLOW_KEYS = ('status', 'reason', 'path', 'sha256', 'bytes', 'format', 'format_reason', 'verdict', 'probability',
             'score', 'level', 'parts', 'floor', 'cap', 'family', 'family_note', 'behaviours', 'hidden_behaviours',
             'note', 'signature', 'evidence', 'deep_check', 'deep_check_reason', 'pdf_active_content',
             'large_file', 'defender_scan')


def file_sha256(path, block=8 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as f:                                    # read-only
        for chunk in iter(lambda: f.read(block), b''):
            h.update(chunk)
    return h.hexdigest()


def file_stamp(path):
    """size + creation date (arrived on this PC) + modified date, in nanoseconds."""
    st = os.stat(path)
    created = getattr(st, 'st_birthtime_ns', None) or st.st_ctime_ns          # Windows: creation time
    return dict(size=st.st_size, created=int(created), modified=int(st.st_mtime_ns))


def engine_fingerprint(models_dir=None):
    """Changes whenever the models, rules or analysis code change -> the whole memory is then ignored."""
    h = hashlib.sha256(f'memory-v{MEMORY_VERSION}'.encode())
    models = Path(models_dir) if models_dir else ROOT / 'models'
    for m in sorted(models.glob('phase*/manifest.json')):
        h.update(m.read_bytes())
    for src in sorted((ROOT / 'src/detection').glob('*.py')):
        h.update(src.name.encode() + src.read_bytes())
    analyse = ROOT / 'scripts/mlwint_analyse.py'
    if analyse.is_file():
        h.update(analyse.read_bytes())
    return h.hexdigest()[:16]


def _day(ns_or_s):
    t = ns_or_s / 1e9 if ns_or_s > 1e12 else ns_or_s
    return time.strftime('%d %b %Y', time.localtime(t))


class ScanMemory:
    def __init__(self, path=None, engine=None, models_dir=None):
        self.path = Path(path) if path else MEMORY_FILE
        self.engine = engine or engine_fingerprint(models_dir)
        self.data = self._load()
        self.reset_stats()

    def reset_stats(self):
        self.stats = dict(reused=0, new=0, changed=0, outdated=0, engine_changed=0, deeper=0)

    def _load(self):
        if self.path.is_file():
            try:
                d = json.loads(self.path.read_text(encoding='utf-8'))
                if d.get('version') == MEMORY_VERSION:
                    return d
            except ValueError:
                pass
        return dict(version=MEMORY_VERSION, files={})

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + '.pending')
        tmp.write_text(json.dumps(self.data), encoding='utf-8')
        tmp.replace(self.path)

    def forget(self):
        self.data = dict(version=MEMORY_VERSION, files={})
        self.save()

    def __len__(self):
        return len(self.data['files'])

    def recall(self, path, sha, stamp, options):
        """(earlier slow result, None) when it can be reused, else (None, why it cannot)."""
        e = self.data['files'].get(sha)
        if e is None:
            self.stats['new'] += 1
            return None, 'new file'
        if e['engine'] != self.engine:
            self.stats['engine_changed'] += 1
            return None, 'MLWINT models or rules changed since it was checked'
        seen = e['seen'].get(os.path.normcase(str(path)))
        if seen is None or any(seen.get(k) != stamp[k] for k in ('size', 'created', 'modified')):
            self.stats['changed'] += 1
            return None, ('first time at this place' if seen is None
                          else 'size or date changed (downloaded, copied or edited again)')
        if time.time() - e['checked'] > MAX_AGE_DAYS * 86400:
            self.stats['outdated'] += 1
            return None, f'last checked more than {MAX_AGE_DAYS} days ago'
        done = e['options']
        for k in ('evidence', 'deep'):
            if DEPTH.get(done.get(k), 0) < DEPTH.get(options.get(k), 0):
                self.stats['deeper'] += 1
                return None, f'earlier check was lighter ({k} {done.get(k)} < {options.get(k)})'
        self.stats['reused'] += 1
        r = json.loads(json.dumps(e['result']))                  # a fresh copy
        r['path'] = str(path)
        r['remembered'] = dict(checked=e['checked'], day=_day(e['checked']))
        return r, None

    def remember(self, path, sha, stamp, slow_result, options):
        if slow_result.get('status') != 'assessed':
            return                                                # failures are always retried
        keep = {k: slow_result[k] for k in SLOW_KEYS if k in slow_result}
        old = self.data['files'].get(sha)
        seen = old['seen'] if old and old['engine'] == self.engine else {}
        seen[os.path.normcase(str(path))] = dict(stamp)
        self.data['files'][sha] = dict(engine=self.engine, checked=time.time(), seen=seen,
                                       options={k: options.get(k) for k in ('evidence', 'deep')}, result=keep)

    def summary(self):
        s = self.stats
        parts = [f'{s["reused"]} unchanged (earlier result used)'] if s['reused'] else []
        if s['new']:
            parts.append(f'{s["new"]} new')
        if s['changed']:
            parts.append(f'{s["changed"]} changed or downloaded again')
        if s['engine_changed']:
            parts.append(f'{s["engine_changed"]} re-checked because MLWINT was updated')
        if s['outdated']:
            parts.append(f'{s["outdated"]} re-checked after {MAX_AGE_DAYS} days')
        if s['deeper']:
            parts.append(f'{s["deeper"]} re-checked more deeply')
        return 'Memory: ' + ', '.join(parts) if parts else ''