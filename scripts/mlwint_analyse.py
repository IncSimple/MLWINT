"""MLWINT analyse: one command for the whole analysis. Save as MLWINT/scripts/mlwint_analyse.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_analyse.py <file or folder> [more ...]
    experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_analyse.py --whole-pc
What to check:
    --recursive      also look inside sub-folders
    --whole-pc       every fixed drive (C:, D:, ...), all sub-folders. Skips the Windows folder, the Recycle Bin,
                     System Volume Information and MLWINT itself (--include-windows to also check the Windows
                     folder). The first whole-PC scan can take hours; later scans only check new or changed files.
    --types all|programs|pdf|win32,win64,dotnet   which kinds of file to check (default all); files left out
                     are counted in the report as 'not checked' - they get no verdict
    --large          also check files over 256 MB with the large-file check (signature + report-only Microsoft
                     Defender scan + detector at half weight; about 5 minutes per GB)
    --max-files N    stop after N files (default 2000; --whole-pc: no practical limit)
How deeply:
    --evidence all|needed|none   capa / PDF check (default 'needed': flagged files, risky files and all PDFs;
                     capa takes ~20-40 s per program, so 'all' is slow on big folders)
    --deep needed|all|none       Speakeasy emulation (default 'needed': flagged files and unsigned files in
                     Downloads / Temp / AppData / Desktop)
    --context needed|all|none    local context (Phase 3.1, default 'needed' = files above LOW): where it came
                     from, run before?, running now?, set to start automatically?, Defender history
    --reputation off|flagged|all  hash lookup (Phase 3.3, default OFF): sends ONLY the SHA-256 to MalwareBazaar /
                     VirusTotal with your own API keys; 'flagged' = only files above LOW
Memory (reports/memory/scan-memory.json):
    An unchanged file (same SHA-256 fingerprint, same place, size, creation and modified date, same MLWINT
    models and rules, checked in the last 30 days, at least as deeply) is not analysed again: its earlier result is
    used, and the parts that change over time (run before? running? autostart? Defender history, hash lookup) are
    refreshed. --fresh ignores the memory for this scan (the memory is still updated).
For every Windows program (Win32 / Win64 / .NET) and PDF:
    1. detector verdict (Phase 1)       2. evidence: capa ATT&CK or PDF risky elements (when needed)
    3. family + behaviour (if flagged)  4. deep check by emulation (when needed)
    -> one 0-100 threat score with a written reason for every point, plus all ATT&CK techniques found.
READ-ONLY: files are only read. Nothing is deleted, moved, quarantined, run or uploaded.
Reports: reports/analyse/analysis-<date-time>.pdf (easy to read, for everyone), .txt (technical) and .json
(everything).
"""
import argparse, ctypes, json, os, string, sys, time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase1_detectors import MAX_BYTES, detect_format  # noqa: E402
from src.detection.phase2_meter import ThreatMeter, explain  # noqa: E402
from src.detection.phase2_evidence import evidence_for_file  # noqa: E402
from src.detection.phase2_deepcheck import deep_check, needs_deep_check, add_to_meter  # noqa: E402
from src.detection.phase3_context import ContextChecker  # noqa: E402
from src.detection.phase3_attack import AttackKnowledge  # noqa: E402
from src.detection.phase3_advice import advise, advice_text  # noqa: E402
from src.detection.phase3_reputation import Reputation, add_to_meter as add_opinion  # noqa: E402
from src.detection.scan_memory import ScanMemory, file_sha256, file_stamp  # noqa: E402
from src.detection.large_files import large_check  # noqa: E402
from src.detection import scan_memory  # noqa: E402
from src.app_settings import load_settings, models_dir as app_models_dir  # noqa: E402

SUMMARY = {'LOW': 'no meaningful sign of malware',
           'GUARDED': 'some weak signals; fine if you expected this file, otherwise take a closer look',
           'ELEVATED': 'clear signs of malware or risky behaviour; do not open it until you know where it came from',
           'HIGH': 'very likely malware',
           'SEVERE': 'malware with harmful behaviour'}
PDF_PHISHING_LIKE = ('the detector finds it similar to phishing PDFs, but it contains nothing that can run: '
                     'opening it is low risk - do not trust its links or forms unless you know the sender')
KINDS = ('win32', 'win64', 'dotnet', 'pdf')       # what --types can choose
PROGRAM_KINDS = {'win32', 'win64', 'dotnet'}
KIND_NAMES = {'win32': '32-bit program', 'win64': '64-bit program', 'dotnet': '.NET program', 'pdf': 'PDF',
              'program': 'program'}
CAPA_TIMEOUT = 120        # seconds; big installers can take capa much longer (then: capabilities unknown)
LARGE_NOTE = (f'larger than {MAX_BYTES // 1024**2} MB - not part of the normal check; use "Include large files" '
              f'(--large) for the large-file check')
WHOLE_PC_MAX = 10_000_000
SAVE_EVERY = 20           # files between memory saves
REPORTS_DIR = ROOT / 'reports/analyse'      # where scan reports go (the checks use a temp folder)

# ----------------------------------------------------------------------------------------------- finding files
def file_kind(head):
    """'win32' / 'win64' / 'dotnet' / 'pdf' from the first 4 KB (the same rule the detectors use),
    'program' for an MZ file whose header cannot be read here (the detector decides later), None for anything else."""
    if b'%PDF' in head[:1024]:
        return 'pdf'
    if head[:2] != b'MZ':
        return None
    try:
        kind, _ = detect_format(head)
    except Exception:
        kind = None
    return kind or 'program'


def whole_pc_roots():
    """Every fixed (non-removable, non-network) drive, e.g. ['C:\\', 'D:\\']."""
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    roots = []
    for i, letter in enumerate(string.ascii_uppercase):
        if mask >> i & 1:
            root = f'{letter}:\\'
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:          # DRIVE_FIXED
                roots.append(root)
    return roots


def default_excludes(include_windows=False):
    out = [str(ROOT)]                                                    # MLWINT itself (models, tools, tests)
    if not include_windows:
        out.append(os.environ.get('SystemRoot', r'C:\Windows'))
    return [os.path.normcase(os.path.abspath(p)) for p in out]


SKIP_DIR_NAMES = {'$recycle.bin', 'system volume information', '$windows.~bt', '$windows.~ws', 'config.msi'}


def walk_files(folder, recursive, excludes=()):
    """Files in a folder (sorted), optionally all sub-folders; never follows links / junctions; skips excluded and
    unreadable folders without stopping."""
    folder = os.path.abspath(folder)
    if not recursive:
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            return
        for n in names:
            yield Path(folder, n)
        return
    for top, dirs, files in os.walk(folder, onerror=lambda e: None):
        keep = []
        for d in sorted(dirs):
            full = os.path.join(top, d)
            if d.lower() in SKIP_DIR_NAMES or os.path.normcase(full) in excludes:
                continue
            if os.path.islink(full) or (hasattr(os.path, 'isjunction') and os.path.isjunction(full)):
                continue
            keep.append(d)
        dirs[:] = keep
        for n in sorted(files):
            yield Path(top, n)


def candidates(paths, recursive, limit, types=None, skipped=None, excludes=(), progress=None):
    """Windows programs and PDFs to analyse (large files last); everything else is passed over quickly.
    types: set of kinds to include (default all). skipped: optional Counter, filled with kinds left out by choice.
    excludes: folders not to enter. progress(seen, found): called now and then while searching."""
    types = set(types or KINDS)
    found, seen, n_seen, cut = [], set(), 0, False
    for p in paths:
        p = Path(p)
        items = walk_files(p, recursive, excludes) if p.is_dir() else [p]
        for f in items:
            n_seen += 1
            if progress and n_seen % 2000 == 0:
                progress(n_seen, len(found))
            try:
                if not f.is_file() or f.resolve() in seen:
                    continue
                with open(f, 'rb') as h:                               # read-only
                    head = h.read(4096)
            except OSError:
                if not p.is_dir():
                    found.append(f)                                    # reported as 'skipped' later
                continue
            kind = file_kind(head)
            if kind is None:
                continue
            wanted = kind in types or (kind == 'program' and types & PROGRAM_KINDS)
            if not wanted:
                if skipped is not None:
                    skipped[kind] += 1
                continue
            seen.add(f.resolve())
            found.append(f)
            if len(found) >= limit:
                cut = True
                break
        if cut:
            break
    if progress:
        progress(n_seen, len(found))

    def size(f):
        try:
            return f.stat().st_size
        except OSError:
            return 0
    found.sort(key=lambda f: size(f) > MAX_BYTES)                        # large files last (stable order)
    return found, cut


def techniques(result):
    """All ATT&CK techniques from capa / PDF evidence and from the deep check, with where they came from."""
    out = {}
    ev = result.get('evidence') or {}
    for t in ev.get('attack_techniques', []):
        out.setdefault(t['id'], dict(id=t['id'], technique=t['technique'], tactic=t['tactic'], sources=[]))
        out[t['id']]['sources'].append('capa' if ev.get('format') != 'pdf' else 'PDF check')
    dc = result.get('deep_check') or {}
    for t in dc.get('attack_techniques', []):
        out.setdefault(t['id'], dict(id=t['id'], technique=t['technique'], tactic=t['tactic'], sources=[]))
        out[t['id']]['sources'].append('emulation')
    return sorted(out.values(), key=lambda t: t['id'])


# ----------------------------------------------------------------------------------------------- analysing
def analyse_slow(meter, path, evidence_mode, deep_mode, large=False):
    """The slow part, which gives the same answer for the same file and models (so it can be remembered):
    detector, family / behaviour, capa / PDF evidence, emulation - or the large-file check."""
    path = Path(path).resolve()                       # capa / emulation run from other folders
    if path.is_file() and path.stat().st_size > MAX_BYTES:
        return large_check(meter, path) if large else dict(path=str(path), status='skipped', reason=LARGE_NOTE)
    r = meter.assess(path)
    if r['status'] != 'assessed':
        return r
    want_deep, why_deep = needs_deep_check(r)
    want_ev = (evidence_mode == 'all' or
               (evidence_mode == 'needed' and (r['verdict'] != 'CLEAN' or want_deep or r['format'] == 'PDF')))
    if want_ev:
        ev = evidence_for_file(path, timeout=CAPA_TIMEOUT)
        r = meter.assess(path, evidence=ev)                           # same file, now with its evidence part
        r['evidence'] = dict(status=ev.get('status'), format=ev.get('format'),
                             engine=(ev.get('evidence') or {}).get('engine'),
                             attack_techniques=ev.get('attack_techniques', []),
                             attack_tactics=ev.get('attack_tactics', {}),
                             capabilities=[c['name'] for c in (ev.get('evidence') or {}).get('capabilities', [])],
                             pdf_findings=[f['indicator'] for f in (ev.get('evidence') or {}).get('findings', [])])
    if deep_mode == 'all' or (deep_mode == 'needed' and want_deep):
        r = add_to_meter(r, deep_check(path))
    r['deep_check_reason'] = why_deep
    return r


def finish(r, context, context_mode, kb=None, rep=None, rep_mode='off'):
    """The quick part, refreshed on every scan because it can change over time: hash lookup, ATT&CK explanations,
    PC context (run before? running? autostart? Defender history), summary and advice."""
    if rep and (rep_mode == 'all' or (rep_mode == 'flagged' and r['level'] != 'LOW')):
        r = add_opinion(r, rep.lookup(r['sha256']))      # only the SHA-256 leaves the PC
    r['attack'] = techniques(r)
    if context_mode == 'all' or (context_mode == 'needed' and r['level'] != 'LOW'):
        r['local_context'] = context.check(Path(r['path']))   # facts only: the score does not change
    if kb and r['level'] != 'LOW':                          # ATT&CK explanations (offline, Phase 3.2)
        for t in r['attack']:
            t['explanation'] = kb.explain(t['id'])
            t['line'] = kb.short(t['id'])
    r['summary'] = (PDF_PHISHING_LIKE if r['format'] == 'PDF' and r['verdict'] != 'CLEAN'
                    and r.get('pdf_active_content') == [] else SUMMARY[r['level']])
    r['advice'] = advise(r)                              # what YOU can do (Phase 3.4); MLWINT changes nothing
    return r


def analyse(meter, path, evidence_mode, deep_mode, context, context_mode, kb=None, rep=None, rep_mode='off',
            large=False):
    r = analyse_slow(meter, path, evidence_mode, deep_mode, large)
    return finish(r, context, context_mode, kb, rep, rep_mode) if r.get('status') == 'assessed' else r


def text_block(r):
    if r.get('status') != 'assessed':
        return f'{r.get("path")}\n  {r.get("status", "?").upper()}: {r.get("reason")}'
    lines = [explain(r), f'  => {r["summary"]}']
    if r.get('remembered'):
        lines.append(f'  memory   : unchanged since the check on {r["remembered"]["day"]} - that result was used; '
                     f'PC facts refreshed now')
    if r.get('large_file'):
        lines.append('  large    : checked with the large-file check (signature, report-only Defender scan, '
                     'detector at half weight)')
    if r.get('advice') and r['level'] != 'LOW':
        lines.append(advice_text(r['advice']))
    if r.get('family'):
        lines.append(f'  family   : {r["family"]["name"]} (confidence {r["family"]["confidence"]:.0%}, right '
                     f'{r["family"]["test_precision"]:.0%} of the time on test)')
    if r.get('behaviours'):
        lines.append('  behaviour: ' + ', '.join(f'{b["tag"]} ({b["tier"]})' for b in r['behaviours']))
    if r.get('attack'):
        lines.append('  ATT&CK   : ' + '; '.join(f'{t["id"]} {t["technique"]} [{"/".join(sorted(set(t["sources"])))}]'
                                               for t in r['attack'][:15])
                     + (f' ... +{len(r["attack"]) - 15} more' if len(r['attack']) > 15 else ''))
    dc = r.get('deep_check')
    explained = [t['line'] for t in r.get('attack', []) if t.get('line')]
    if explained:
        lines.append('  ATT&CK explained (MITRE):')
        lines += [f'    - {x}' for x in explained[:12]]
    for fact in (r.get('local_context') or {}).get('facts', []):
        lines.append(f'  on this PC: {fact}')
    if dc and dc.get('status') == 'completed' and dc.get('observed', {}).get('servers'):
        lines.append('  contacts : ' + ', '.join(dc['observed']['servers'][:10]))
    return '\n'.join(lines)


def load_tools(models=None, reputation='off', say=print, memory=True):
    """Everything a scan needs, loaded once (shared by this command and the GUI). Settings (config/
    mlwint_settings.json): the models folder when none is given, and how many days remembered results are used."""
    settings = load_settings()
    models = models or app_models_dir(settings)
    scan_memory.MAX_AGE_DAYS = settings['memory_days']
    meter = ThreatMeter(Path(models) / 'phase1', Path(models) / 'phase2') if models else ThreatMeter()
    try:
        kb = AttackKnowledge()
        say(f'ATT&CK Enterprise v{kb.version} loaded (offline)')
    except FileNotFoundError as e:
        kb = None
        say(f'Note: {e} - reports will list technique ids without explanations')
    rep = None
    if reputation != 'off':
        rep = Reputation()
        if rep.sources:
            say(f'Hash lookup ON ({reputation}): only SHA-256 fingerprints are sent to '
                f'{", ".join(rep.sources)}; nothing else leaves this PC')
        else:
            rep = None
            say('Hash lookup requested, but no API key is set (see phase3_reputation.py) - continuing without it')
    mem = ScanMemory(models_dir=models) if memory else None
    if mem is not None:
        say(f'Memory: {len(mem)} files remembered from earlier scans')
    return dict(meter=meter, context=ContextChecker(), kb=kb, rep=rep, memory=mem, unsaved=0)


def analyse_one(tools, path, options):
    """One file -> result dict; never raises (one bad file must not stop a scan). Uses and updates the memory."""
    t0 = time.time()
    mem = tools.get('memory')
    try:
        path = Path(path).resolve()
        slow = sha = stamp = None
        if mem is not None and path.is_file():
            stamp, sha = file_stamp(path), file_sha256(path)
            if not options.get('fresh'):
                slow, why = mem.recall(path, sha, stamp, options)
        if slow is None:
            slow = analyse_slow(tools['meter'], path, options['evidence'], options['deep'], options.get('large'))
            if mem is not None and sha and slow.get('sha256') == sha:
                mem.remember(path, sha, stamp, slow, options)
                tools['unsaved'] = tools.get('unsaved', 0) + 1
                if tools['unsaved'] >= SAVE_EVERY:
                    save_memory(tools)
        r = (finish(slow, tools['context'], options['context'], tools['kb'], tools['rep'], options['reputation'])
             if slow.get('status') == 'assessed' else slow)
    except Exception as e:
        r = dict(path=str(path), status='failed', reason=f'{type(e).__name__}: {e}')
    r['seconds'] = round(time.time() - t0, 1)
    return r


def save_memory(tools):
    if tools.get('memory') is not None:
        tools['memory'].save()
        tools['unsaved'] = 0


def parse_types(text):
    """'all' / 'programs' / 'pdf' / 'win32,win64' ... -> set of kinds."""
    out = set()
    for t in text.lower().replace(' ', '').split(','):
        if t == 'all':
            out |= set(KINDS)
        elif t == 'programs':
            out |= PROGRAM_KINDS
        elif t in KINDS:
            out.add(t)
        elif t:
            raise ValueError(f'unknown file type {t!r} (use all, programs, win32, win64, dotnet, pdf)')
    if not out:
        raise ValueError('choose at least one file type')
    return out


def skipped_text(skipped):
    """Line for files left out by the user's file-type choice ('' when none)."""
    if not skipped or not sum(skipped.values()):
        return ''
    parts = ', '.join(f'{n} {KIND_NAMES.get(k, k)}{"s" if n > 1 else ""}' for k, n in sorted(skipped.items()) if n)
    return f'Not checked (left out by your file-type choice): {parts} - these have NO verdict'


def write_report(results, paths, options, started, seconds, skipped=None, pdf=True, memory_note=''):
    """Writes reports/analyse/analysis-<stamp>.txt + .json (+ the easy-to-read .pdf when pdf=True);
    returns (txt path, json path, headline lines, done)."""
    stamp = time.strftime('%Y%m%d-%H%M%S')
    done = sorted((r for r in results if r.get('status') == 'assessed'), key=lambda r: -r['score'])
    other = [r for r in results if r.get('status') != 'assessed']
    levels = Counter(r['level'] for r in done)
    head = [f'MLWINT analysis  {started}  ({seconds:.0f} s)',
            f'Analysed {len(done)} files: ' + ', '.join(f'{levels[l]} {l}' for l in
                                                        ('SEVERE', 'HIGH', 'ELEVATED', 'GUARDED', 'LOW') if levels[l])
            + (f'; {len(other)} not analysed' if other else ''),
            'Read-only: nothing was deleted, moved, run or uploaded. The score explains risk; it is not a guarantee.',
            '=' * 100]
    for extra in (memory_note, skipped_text(skipped)):
        if extra:
            head.insert(2, extra)
    body = [text_block(r) for r in done + other]
    out = REPORTS_DIR
    out.mkdir(parents=True, exist_ok=True)
    txt, js = out / f'analysis-{stamp}.txt', out / f'analysis-{stamp}.json'
    txt.write_text('\n'.join(head) + '\n' + '\n\n'.join(body) + '\n', encoding='utf-8')
    js.write_text(json.dumps(dict(status='MLWINT_ANALYSIS', started=started, paths=[str(p) for p in paths],
                                  options=options, counts=dict(levels), not_checked=dict(skipped or {}),
                                  memory=memory_note, results=done + other), indent=1, default=str),
                  encoding='utf-8')
    if pdf:
        easy_report(js)
    return txt, js, head, done


def easy_report(js, say=print):
    """analysis-<stamp>.json -> analysis-<stamp>.pdf (plain language). Returns the path, or None if it failed."""
    try:
        from src.report.plain_report import write_pdf
        return write_pdf(js)
    except Exception as e:                       # the technical reports are already written
        say(f'Note: the easy-to-read PDF could not be made ({type(e).__name__}: {e})')
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--recursive', action='store_true')
    ap.add_argument('--whole-pc', action='store_true', help='every fixed drive, all sub-folders')
    ap.add_argument('--include-windows', action='store_true', help='with --whole-pc: also the Windows folder')
    ap.add_argument('--evidence', choices=['needed', 'all', 'none'], default='needed')
    ap.add_argument('--deep', choices=['needed', 'all', 'none'], default='needed')
    ap.add_argument('--max-files', type=int, default=None)
    ap.add_argument('--context', choices=['needed', 'all', 'none'], default='needed')
    ap.add_argument('--reputation', choices=['off', 'flagged', 'all'], default='off')
    ap.add_argument('--types', default='all', help='all (default), programs, pdf, or a list like win32,win64,dotnet')
    ap.add_argument('--large', action='store_true', help='also check files over 256 MB (large-file check)')
    ap.add_argument('--fresh', action='store_true', help='ignore remembered results for this scan')
    ap.add_argument('--models', type=Path, default=None, help='folder holding phase1/ and phase2/ (default MLWINT/models)')
    a = ap.parse_args()
    if not a.paths and not a.whole_pc:
        ap.error('give a file or folder, or --whole-pc')
    try:
        types = parse_types(a.types)
    except ValueError as e:
        ap.error(str(e))
    paths = whole_pc_roots() if a.whole_pc else a.paths
    recursive = a.recursive or a.whole_pc
    limit = a.max_files or (WHOLE_PC_MAX if a.whole_pc else 2000)
    excludes = default_excludes(a.include_windows) if a.whole_pc else ()
    options = dict(recursive=recursive, evidence=a.evidence, deep=a.deep, context=a.context,
                   reputation=a.reputation, types=sorted(types), large=a.large, fresh=a.fresh,
                   whole_pc=a.whole_pc, include_windows=a.include_windows)

    started = time.strftime('%Y-%m-%d %H:%M:%S')
    print('MLWINT analyse (read-only: nothing is deleted, moved, run or uploaded)', flush=True)
    if a.whole_pc:
        print(f'Whole PC: {", ".join(paths)} (skipping: {", ".join(excludes)})', flush=True)
    skipped = Counter()
    files, cut = candidates(paths, recursive, limit, types, skipped, excludes,
                            progress=(lambda s, f: print(f'  looked at {s} files, {f} to analyse ...', flush=True))
                            if a.whole_pc else None)
    print(f'{len(files)} Windows program / PDF files to analyse' + (f' (stopped at --max-files {limit})'
                                                                     if cut else ''), flush=True)
    if skipped_text(skipped):
        print(skipped_text(skipped), flush=True)
    tools = load_tools(a.models, a.reputation, say=lambda s: print(s, flush=True))
    results, t_all = [], time.time()
    try:
        for i, f in enumerate(files, 1):
            r = analyse_one(tools, f, options)
            results.append(r)
            shown = (f'{r["score"]:>3}/100 {r["level"]:<8} {r["verdict"]:<10}' if r.get('status') == 'assessed'
                     else f'{r.get("status", "?"):<29}')
            how = ' (remembered)' if r.get('remembered') else ' (large-file check)' if r.get('large_file') else ''
            print(f'[{i}/{len(files)}] {shown} {r["seconds"]:>5.1f} s  {f}{how}', flush=True)
    except KeyboardInterrupt:
        print('\nStopped by you - writing the report for the files done so far.')
    save_memory(tools)
    note = tools['memory'].summary() if tools.get('memory') is not None else ''

    txt, js, head, done = write_report(results, paths, options, started, time.time() - t_all, skipped,
                                       memory_note=note)
    print('\n' + '\n'.join(h for h in head[:4] if not h.startswith(('Read-only', '='))))
    for r in done[:10]:
        if r['level'] != 'LOW':
            adv = r.get('advice') or {}
            first = (adv.get('actions') or [{}])[0].get('action')
            print(f'  {r["score"]:>3}/100 {r["level"]:<8} {r["path"]}\n          {adv.get("headline", r["summary"])}'
                  + (f'\n          first step: {first}' if first else ''))
    if not any(r['level'] != 'LOW' for r in done):
        print('  Nothing above LOW.')
    pdf = Path(js).with_suffix('.pdf')
    if pdf.is_file():
        print(f'\nEasy-to-read report: {pdf}')
    print(f'Technical report: {txt}\nAll details: {js}')


if __name__ == '__main__':
    main()