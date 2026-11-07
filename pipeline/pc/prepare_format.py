"""Run on the PC with the EMBER2024 environment. Save as MLWINT/scripts/prepare_format.py
Usage:  python scripts/prepare_format.py PDF download | prepare | export
        (formats: PDF, Dot_Net, ELF)

Builds the complete dataset of one EMBER2024 format for the Phase 1 four-way comparison, with the
same extractor, the same 2,568 features and the same clean-up rules as Win32 / Win64
(EMBER2024 stores every format in the same feature layout; PE-only groups are simply empty):
  part 1  inner_fit   weeks 0-35   (model fitting)
  part 2  inner_stop  weeks 36-39  (round selection / SVM tuning)
  part 3  development weeks 40-51  (calibration, thresholds, ranking)
  part 4  test        weeks 52-63  (official test archive of the format; NEVER seen by any model yet)

Leakage rules (earlier period always wins, later periods lose the overlap):
  * a file is kept only if its first-submission date lies inside its period's date window
  * the same SHA-256 must have the same label, vector and date everywhere (otherwise stop)
  * inside a period: one row per unique SHA-256; vectors shared by benign AND malicious files are
    removed; one row per identical vector (same select_rows as Win32)
  * development drops any SHA-256 or vector that appears anywhere in weeks 0-39
  * test drops any SHA-256 or vector that appears anywhere in weeks 0-51
  * chronology: inner_fit < inner_stop < development < test (checked)
Test labels are stored for the final scoring but are never printed or summarised here.

Stages (each resumes safely; rerun the same command after a stop):
  download  fetch <format>_test.zip from the pinned EMBER2024 revision and verify its checksum
  prepare   vectorise all 64 weeks, week by week, then audit and split
  export    pack 20k-row shards for Google Drive -> MLWINT-colab/inputs/<format>-v1  (e.g. pdf-v1)
Writes only data/raw/ember2024/archives/<format>_test.zip, data/processed/ember2024/<format>-v1,
reports/ember2024/<format>-v1 and the export folder.
"""
import argparse, gc, hashlib, inspect, json, shutil, zipfile
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

import numpy as np
from thrember.features import PEFeatureExtractor

from vectorize_ember2024_pilot import FEATURE_COUNT, FEATURE_GROUPS, feature_hash, save_json, save_npy, save_npz, sha256
from prepare_full_ember2024_win32 import checked_hash, label_counts, metadata_schema, read_json, relative, select_rows

REPOSITORY, REVISION = 'joyce8/EMBER2024', '3d23efef7c0f0b702c5024400cfff4c3744a3832'
SIZES = {      # train bytes, train sha256, test bytes, test sha256 (Hugging Face, pinned revision)
    'PDF': (122602464, '83a52378e9e5ea2478832443ff449ecba85050bbda111df074b633f822c8a2de',
            28833740, '953742edb8bbe1f729f32b546c142f8600811a16652822473222e48fc9e826dc'),
    'Dot_Net': (937108923, 'b9f6e90ab75293a7ceb9339700586dd033a03d19766282755ee31dfa0836e625',
                220481493, 'b74c4181dbd77565fce16ba47c8ab0f7c7044ae6d880d859ec2c27365dea6299'),
    'ELF': (69249829, 'dd22c65c1a4b6b1c0680717814c74c1569256cf4ef6e7629c1b2b94b8e11afe3',
            16763975, 'c86fa72164d7ac5d47ac4798d27b65978402f39f8cad0b2186b01ba55d528bfe'),
}
FORMAT = RUN = TAG = None
ARCHIVES = {}


def configure(fmt):
    """FORMAT = file_type in the records; RUN = output folder name; TAG = status prefix."""
    global FORMAT, RUN, TAG, ARCHIVES
    tb, ts, sb, ss = SIZES[fmt]
    FORMAT, RUN, TAG = fmt, f'{fmt.lower().replace("_", "")}-v1', fmt.upper().replace('_', '')
    ARCHIVES = {   # name, bytes, sha256, member suffix, number of weeks, first week number
        'train': (f'{fmt}_train.zip', tb, ts, f'_{fmt}_train.jsonl', 52, 0),
        'test': (f'{fmt}_test.zip', sb, ss, f'_{fmt}_test.jsonl', 12, 52),
    }
PARTS = {1: ('inner_fit', 0, 36), 2: ('inner_stop', 36, 40), 3: ('development', 40, 52), 4: ('test', 52, 64)}
CHUNK_ROWS, SHARD_ROWS = 5000, 20000
MAX_LINE_BYTES, MIN_FREE_BYTES = 32 * 1024 * 1024, 8 * 1024**3
WIN32_REPORT = 'reports/ember2024/full-win32-v1/preparation.json'


def part_of_week(week):
    return next(p for p, (_, lo, hi) in PARTS.items() if lo <= week < hi)


def week_start(member):
    return datetime.strptime(Path(member).name[:10], '%Y-%m-%d').replace(tzinfo=timezone.utc)


def paths(root, out_root):
    base = out_root or root
    return base, base / 'data/processed/ember2024' / RUN, base / 'reports/ember2024' / RUN / 'preparation.json'


def download(root):
    from huggingface_hub import hf_hub_download
    name, size, digest = ARCHIVES['test'][:3]
    folder = root / 'data/raw/ember2024/archives'
    target = folder / name
    if not target.exists():
        print(f'Downloading {name} ({size / 1024**3:.2f} GiB) from {REPOSITORY} @ {REVISION[:8]} ...', flush=True)
        hf_hub_download(repo_id=REPOSITORY, repo_type='dataset', filename=name, revision=REVISION,
                        local_dir=str(folder))
    print('Verifying size and SHA-256 ...', flush=True)
    if target.stat().st_size != size:
        raise ValueError(f'{name}: size {target.stat().st_size} != {size}. Delete the file and run download again.')
    checked_hash(target, digest)
    print(f'{TAG}_TEST_ARCHIVE_VERIFIED {target}')
    print(f'Next: python scripts/prepare_format.py {FORMAT} prepare')


def read_week(base, folder, archive, member, week, extractor, offset, limit, file_type):
    """Vectorise one weekly file: one row per unique SHA-256 (repeats checked, not stored)."""
    folder.mkdir(parents=True, exist_ok=True)
    start = week_start(member)
    low, high = int(start.timestamp()), int((start + timedelta(days=7)).timestamp())
    vectors, records, chunks, seen = [], [], [], {}
    stats = dict(source_rows=0, unique_sha_rows=0, repeated_sha_rows=0, raw_feature_variants_checked=0,
                 outside_named_week_dates=0, stored_rows=0)

    def flush():
        if not vectors:
            return
        if shutil.disk_usage(folder).free < MIN_FREE_BYTES:
            raise RuntimeError('Less than 8 GiB free on this drive. Free space, then rerun.')
        n = len(chunks)
        x_path, m_path = folder / f'chunk_{n:03d}.npy', folder / f'chunk_{n:03d}.metadata.npz'
        meta = metadata_schema(len(records))
        for i, record in enumerate(records):
            for name, value in zip(meta, record):
                meta[name][i] = value
        save_npy(x_path, np.stack(vectors).astype(np.float32, copy=False))
        save_npz(m_path, **meta)
        chunks.append(dict(x_file=relative(base, x_path), x_sha256=sha256(x_path),
                           metadata_file=relative(base, m_path), metadata_sha256=sha256(m_path),
                           rows=len(records), offset=offset + stats['stored_rows']))
        stats['stored_rows'] += len(records)
        vectors.clear(); records.clear()

    with archive.open(member) as stream:
        line_number = 0
        while True:
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line or (limit and stats['source_rows'] >= limit):
                break
            line_number += 1
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f'Oversized JSON record: {member}:{line_number}')
            raw = json.loads(line)
            label, timestamp = raw['label'], raw['first_submission_date']
            if type(label) is not int or label not in (0, 1):
                raise ValueError(f'Unexpected label: {member}:{line_number}')
            if raw['file_type'] != file_type or raw['week_id'] != week or type(timestamp) is not int:
                raise ValueError(f'Unexpected file type/week/date: {member}:{line_number}')
            identity = bytes.fromhex(raw['sha256'])
            if len(identity) != 32:
                raise ValueError('Invalid SHA256 length.')
            stats['source_rows'] += 1
            features = {name: raw[name] for name in FEATURE_GROUPS}
            raw_hash = hashlib.sha256(json.dumps(features, sort_keys=True, separators=(',', ':'),
                                                 ensure_ascii=True, allow_nan=False).encode('utf-8')).digest()
            previous = seen.get(identity)
            if previous is not None:
                if previous[:2] != (label, timestamp):
                    raise ValueError(f'Conflicting repeated file: {raw["sha256"]}')
                stats['repeated_sha_rows'] += 1
                if previous[2] != raw_hash:
                    vector = np.asarray(extractor.process_raw_features(features), dtype=np.float32)
                    if (vector.shape != (FEATURE_COUNT,) or not np.isfinite(vector).all()
                            or feature_hash(vector).tobytes() != previous[3]):
                        raise ValueError(f'Inconsistent repeated vector: {raw["sha256"]}')
                    stats['raw_feature_variants_checked'] += 1
                continue
            vector = np.asarray(extractor.process_raw_features(features), dtype=np.float32)
            if vector.shape != (FEATURE_COUNT,) or not np.isfinite(vector).all():
                raise ValueError(f'Invalid feature vector: {member}:{line_number}')
            digest = feature_hash(vector).tobytes()
            seen[identity] = (label, timestamp, raw_hash, digest)
            stats['unique_sha_rows'] += 1
            if not low <= timestamp < high:
                stats['outside_named_week_dates'] += 1      # decided by the period window in the audit
            vectors.append(vector)
            records.append((np.void(identity), np.void(digest), label, timestamp, week, line_number))
            if len(vectors) >= CHUNK_ROWS:
                flush()
            if stats['source_rows'] % 10000 == 0:
                print(f'  read {stats["source_rows"]:,} records; unique files {stats["unique_sha_rows"]:,}', flush=True)
    flush()
    if stats['source_rows'] == 0:
        raise ValueError(f'Empty source week: {member}')
    return dict(week=week, source_member=member, week_start=int(start.timestamp()), stats=stats, chunks=chunks)



def audit_and_split(meta, starts):
    """starts: week number -> UTC start timestamp. Returns final indices per part + audit numbers."""
    n = len(meta['label'])
    part = np.array([part_of_week(int(w)) for w in range(64)], dtype=np.int8)[meta['week']]
    edge = lambda w: starts[w] if w < 64 else starts[63] + 7 * 86400
    lo = np.array([0] + [edge(PARTS[p][1]) for p in (1, 2, 3, 4)], dtype=np.int64)[part]
    hi = np.array([0] + [edge(PARTS[p][2]) for p in (1, 2, 3, 4)], dtype=np.int64)[part]
    in_window = (meta['timestamp'] >= lo) & (meta['timestamp'] < hi)

    # The same SHA-256 must agree everywhere (label, vector, date), across all 64 weeks.
    order = np.argsort(meta['sha256'], kind='stable')
    a, b = order[:-1], order[1:]
    same = meta['sha256'][a] == meta['sha256'][b]
    bad = same & ((meta['label'][a] != meta['label'][b]) | (meta['feature_hash'][a] != meta['feature_hash'][b])
                  | (meta['timestamp'][a] != meta['timestamp'][b]))
    if bad.any():
        raise ValueError('Same SHA-256 with a different label, vector or date: '
                         + meta['sha256'][b[np.flatnonzero(bad)[0]]].tobytes().hex())

    def choose(candidates):
        sub = {k: v[candidates] for k, v in meta.items()}
        local, info = select_rows(sub)
        return candidates[local], info

    audit, final = {}, {}
    earlier = np.zeros(n, dtype=bool)            # every physical row of the earlier periods
    for group, parts in (('training', (1, 2)), ('development', (3,)), ('test', (4,))):
        mine = np.isin(part, parts)
        sha_hit = np.isin(meta['sha256'], meta['sha256'][earlier]) if earlier.any() else np.zeros(n, bool)
        vec_hit = np.isin(meta['feature_hash'], meta['feature_hash'][earlier]) if earlier.any() else np.zeros(n, bool)
        outside = mine & ~in_window
        sha_out = mine & in_window & sha_hit
        vec_out = mine & in_window & ~sha_hit & vec_hit
        candidates = np.flatnonzero(mine & in_window & ~sha_hit & ~vec_hit)
        chosen, info = choose(candidates)
        audit[group] = dict(physical_rows=int(mine.sum()), outside_period_dates_removed=int(outside.sum()),
                            earlier_period_sha_overlap_removed=int(sha_out.sum()),
                            earlier_period_vector_overlap_removed=int(vec_out.sum()), **info,
                            kept=int(len(chosen)))
        for p in parts:
            final[p] = np.sort(chosen[part[chosen] == p])
        earlier |= mine

    ts = meta['timestamp']
    for p, q in ((1, 2), (2, 3), (3, 4)):
        if not len(final[p]) or not len(final[q]) or ts[final[p]].max() >= ts[final[q]].min():
            raise ValueError(f'Chronology failed between {PARTS[p][0]} and {PARTS[q][0]}.')
    for p in (1, 2, 3, 4):
        if len(np.unique(meta['label'][final[p]])) != 2:
            raise ValueError(f'Both classes are required in {PARTS[p][0]}.')
    # Final exact-overlap proof across all four parts.
    for p in (1, 2, 3, 4):
        for q in range(p + 1, 5):
            if (np.isin(meta['sha256'][final[q]], meta['sha256'][final[p]]).any()
                    or np.isin(meta['feature_hash'][final[q]], meta['feature_hash'][final[p]]).any()):
                raise ValueError(f'Exact overlap remains between {PARTS[p][0]} and {PARTS[q][0]}.')
    return final, audit


def prepare(root, out_root, limit, archive_dir):
    base, output, report_path = paths(root, out_root)
    win32 = read_json(root / WIN32_REPORT)
    extractor = PEFeatureExtractor()
    extractor_hash = sha256(Path(inspect.getfile(PEFeatureExtractor)))
    packages = {name: version(name) for name in win32['protocol']['packages']}
    if (extractor.dim != FEATURE_COUNT or list(FEATURE_GROUPS) != win32['protocol']['feature_groups']
            or extractor_hash != win32['protocol']['extractor_code_sha256'] or packages != win32['protocol']['packages']):
        raise ValueError('Use the same extractor and package versions as the Win32 preparation.')
    archive_dir = archive_dir or root / 'data/raw/ember2024/archives'
    protocol = dict(run=RUN, file_type=FORMAT, repository=REPOSITORY, revision=REVISION,
                    archives={k: dict(file=v[0], bytes=v[1], sha256=v[2]) for k, v in ARCHIVES.items()},
                    script_sha256=sha256(Path(__file__)), feature_count=FEATURE_COUNT,
                    extractor_code_sha256=extractor_hash, packages=packages,
                    parts={str(p): dict(name=v[0], weeks=[v[1], v[2] - 1]) for p, v in PARTS.items()},
                    chunk_rows=CHUNK_ROWS, record_limit_per_week=limit or None,
                    cleanup='period date window; SHA-256 agrees everywhere; select_rows inside each period; '
                            'development drops SHA/vector seen in weeks 0-39; test drops SHA/vector seen in 0-51')

    state = dict(status='preparing', protocol=protocol, weeks=[])
    if report_path.exists():
        state = read_json(report_path)
        if state['protocol'] != protocol:
            raise ValueError('Existing run uses a different protocol (script or settings changed). '
                             'Do not overwrite it: restore the script or use a new RUN name.')
    print('Verifying completed chunks ...', flush=True)
    offset = 0
    for w in state['weeks']:
        for c in w['chunks']:
            if c['offset'] != offset:
                raise ValueError('Checkpoint row offsets are inconsistent.')
            checked_hash(base / c['x_file'], c['x_sha256']); checked_hash(base / c['metadata_file'], c['metadata_sha256'])
            offset += c['rows']
    if state['status'] in ('complete', 'TEST_ONLY_complete'):
        print(json.dumps(state['summary'], indent=2)); print(f'Already complete: {report_path}')
        return
    report_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(report_path, state)

    for key, (name, size, digest, suffix, count, first) in ARCHIVES.items():
        path = archive_dir / name
        if not path.exists():
            raise SystemExit(f'{path} is missing. Run: python scripts/prepare_format.py {FORMAT} download')
        if not limit:
            print(f'Verifying {name} checksum (a few minutes) ...', flush=True)
            if path.stat().st_size != size:
                raise ValueError(f'{name}: size changed.')
            checked_hash(path, digest)
        with zipfile.ZipFile(path) as archive:
            members = sorted(m for m in archive.namelist() if m.endswith(suffix))
            if len(members) != count:
                raise ValueError(f'{name}: expected {count} weekly files, found {len(members)}.')
            for i, member in enumerate(members):
                week = first + i
                if any(w['week'] == week for w in state['weeks']):
                    continue
                print(f'\nWeek {week:02d} ({PARTS[part_of_week(week)][0]}): {member}', flush=True)
                result = read_week(base, output / f'week_{week:02d}', archive, member, week, extractor,
                                   offset, limit, FORMAT)
                state = dict(state, weeks=state['weeks'] + [result])
                save_json(report_path, state)
                offset += result['stats']['stored_rows']
                print(f'Week {week:02d} saved: {result["stats"]}', flush=True)
                gc.collect()

    weeks = sorted(state['weeks'], key=lambda w: w['week'])
    if [w['week'] for w in weeks] != list(range(64)):
        raise ValueError('Not all 64 weeks are prepared.')
    starts = {w['week']: w['week_start'] for w in weeks}
    if any(starts[w + 1] - starts[w] != 7 * 86400 for w in range(63)):
        raise ValueError('Weekly files are not consecutive weeks.')

    print('\nAuditing all 64 weeks and splitting ...', flush=True)
    chunks = [c for w in state['weeks'] for c in w['chunks']]
    meta = metadata_schema(offset)
    for c in chunks:
        with np.load(base / c['metadata_file'], allow_pickle=False) as saved:
            for name in meta:
                meta[name][c['offset']:c['offset'] + c['rows']] = saved[name]
    final, audit = audit_and_split(meta, starts)

    index_path = output / 'row_index.npz'
    save_npz(index_path, **meta, inner_fit_indices=final[1], inner_stop_indices=final[2],
             development_indices=final[3], test_indices=final[4])
    source = {k: int(sum(w['stats'][k] for w in state['weeks'])) for k in state['weeks'][0]['stats']}
    ts = meta['timestamp']
    summary = dict(
        source=source, audit=audit, physical_stored_rows=offset,
        rows={PARTS[p][0]: int(len(final[p])) for p in PARTS},
        labels={PARTS[p][0]: label_counts(meta['label'][final[p]]) for p in (1, 2, 3)},
        test_labels='sealed (not read or printed until the four-way roles are frozen)',
        development_per_week={int(w): label_counts(meta['label'][final[3]][meta['week'][final[3]] == w])
                              for w in range(40, 52)},
        test_rows_per_week={int(w): int((meta['week'][final[4]] == w).sum()) for w in range(52, 64)},
        date_ranges={PARTS[p][0]: [int(ts[final[p]].min()), int(ts[final[p]].max())] for p in PARTS},
        stored_vector_gib=round(sum((base / c['x_file']).stat().st_size for c in chunks) / 1024**3, 3),
        note='Exact SHA-256/vector separation between all four periods and chronological order were checked. '
             'Near-duplicate and family separation are not established.')
    state = dict(state, status='complete' if not limit else 'TEST_ONLY_complete', summary=summary,
                 row_index_file=relative(base, index_path), row_index_sha256=sha256(index_path))
    save_json(report_path, state)
    print(f'\n{TAG} PREPARATION SUMMARY\n' + json.dumps(summary, indent=2))
    print(f'Report: {report_path}\nNext: python scripts/prepare_format.py {FORMAT} export')


def export(root, out_root, target):
    base, output, report_path = paths(root, out_root)
    state = read_json(report_path)
    if state['status'] not in ('complete', 'TEST_ONLY_complete'):
        raise ValueError('Run the prepare stage first.')
    if (target / 'manifest.json').exists():
        raise SystemExit(f'{target} already has a finished export; delete the folder to redo it.')
    checked_hash(base / state['row_index_file'], state['row_index_sha256'])
    with np.load(base / state['row_index_file'], allow_pickle=False) as z:
        meta = {k: z[k] for k in z.files}
    part = np.zeros(len(meta['label']), dtype=np.int8)
    for p, key in ((1, 'inner_fit_indices'), (2, 'inner_stop_indices'), (3, 'development_indices'), (4, 'test_indices')):
        part[meta[key]] = p
    split_of = {1: 'train', 2: 'train', 3: 'dev', 4: 'test'}
    buffers = {s: [] for s in ('train', 'dev', 'test')}
    pending = dict.fromkeys(buffers, 0)
    numbers = dict.fromkeys(buffers, 0)
    files = {}
    for s in buffers:
        (target / s).mkdir(parents=True, exist_ok=True)

    def write_shard(s):
        parts = buffers[s]
        cat = lambda k: np.concatenate([q[k] for q in parts])
        name = f'{s}/{s}-{numbers[s]:04d}.npz'
        save_npz(target / name, X=cat('X'), y=cat('y').astype(np.int8), row=cat('row'), part=cat('part'),
                 sha256=np.frombuffer(cat('sha256').tobytes(), np.uint8).reshape(-1, 32),
                 feature_hash=np.frombuffer(cat('feature_hash').tobytes(), np.uint8).reshape(-1, 32),
                 week=cat('week').astype(np.int16), timestamp=cat('timestamp').astype(np.int64))
        files[name] = dict(sha256=sha256(target / name), bytes=(target / name).stat().st_size,
                           rows=int(sum(len(q['y']) for q in parts)))
        print(f'  wrote {name} ({files[name]["rows"]:,} rows)', flush=True)
        numbers[s] += 1
        buffers[s], pending[s] = [], 0

    for w in sorted(state['weeks'], key=lambda w: w['week']):
        for c in w['chunks']:
            checked_hash(base / c['x_file'], c['x_sha256'])
            g = np.arange(c['offset'], c['offset'] + c['rows'])
            X = np.load(base / c['x_file'], mmap_mode='r')
            if X.shape != (c['rows'], FEATURE_COUNT) or X.dtype != np.float32:
                raise ValueError(f'Unexpected matrix {c["x_file"]}')
            for s in buffers:
                sel = np.isin(part[g], [p for p, t in split_of.items() if t == s])
                if not sel.any():
                    continue
                rows = g[sel]
                buffers[s].append(dict(X=np.asarray(X[sel]), y=meta['label'][rows], row=rows, part=part[rows],
                                       sha256=meta['sha256'][rows], feature_hash=meta['feature_hash'][rows],
                                       week=meta['week'][rows], timestamp=meta['timestamp'][rows]))
                pending[s] += int(sel.sum())
                if pending[s] >= SHARD_ROWS:
                    write_shard(s)
    for s in buffers:
        if buffers[s]:
            write_shard(s)

    sm = state['summary']
    counts = dict(train_rows=sum(f['rows'] for k, f in files.items() if k.startswith('train/')),
                  inner_fit=sm['rows']['inner_fit'], inner_stop=sm['rows']['inner_stop'],
                  dev_rows=sum(f['rows'] for k, f in files.items() if k.startswith('dev/')),
                  test_rows=sum(f['rows'] for k, f in files.items() if k.startswith('test/')))
    if (counts['train_rows'] != counts['inner_fit'] + counts['inner_stop']
            or counts['dev_rows'] != sm['rows']['development'] or counts['test_rows'] != sm['rows']['test']):
        raise ValueError(f'Exported row counts do not match the preparation: {counts}')
    manifest = dict(file_type=FORMAT, status=f'{TAG}_EXPORT_READY' if state['status'] == 'complete' else 'TEST_EXPORT_ONLY',
                    features=FEATURE_COUNT, counts=counts, labels=sm['labels'], test_labels=sm['test_labels'],
                    development_per_week=sm['development_per_week'], test_rows_per_week=sm['test_rows_per_week'],
                    part_codes={'1': 'inner_fit weeks 0-35 (fitting)', '2': 'inner_stop weeks 36-39 (round selection, SVM tuning)',
                                '3': 'development weeks 40-51 (calibration, thresholds, ranking)',
                                '4': f'official {FORMAT} test weeks 52-63 (UNSEEN; score only after roles are frozen)'},
                    sources=dict(preparation_report=dict(path=relative(base, report_path), sha256=sha256(report_path)),
                                 row_index=dict(path=state['row_index_file'], sha256=state['row_index_sha256'])),
                    audit=sm['audit'], files=files,
                    total_gib=round(sum(f['bytes'] for f in files.values()) / 1024**3, 2))
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ('status', 'counts', 'total_gib')}, indent=2))
    print(f'Upload this whole folder to Google Drive -> MLWINT-colab/inputs/: {target}')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('format', choices=sorted(SIZES))
    ap.add_argument('stage', choices=['download', 'prepare', 'export'])
    ap.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument('--out', type=Path, default=None, help='export folder (default exports/colab/<format>-v1)')
    ap.add_argument('--test-output-root', type=Path, default=None, help='testing only: write everything here')
    ap.add_argument('--test-records-per-week', type=int, default=0, help='testing only')
    ap.add_argument('--test-archive-dir', type=Path, default=None, help='testing only')
    a = ap.parse_args()
    root = a.project_root.resolve()
    configure(a.format)
    if a.stage == 'download':
        download(root)
    elif a.stage == 'prepare':
        prepare(root, a.test_output_root, a.test_records_per_week, a.test_archive_dir)
    else:
        export(root, a.test_output_root, a.out or (a.test_output_root or root) / 'exports/colab' / RUN)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped. Rerun the same command to resume.')
        raise SystemExit(130)