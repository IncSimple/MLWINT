"""Run on the PC with the EMBER2024 environment. Save as MLWINT/scripts/prepare_full_development_win32.py

Vectorises ALL Win32 files of weeks 40-51 (official training archive) as the full development
set that replaces the 23,616-file pilot sample for calibration, thresholds and ranking.
Same extractor, same checks and the same clean-up rules as full-win32-v1:
  * one row per unique, consistent SHA-256; vectors shared by benign AND malicious files are
    removed; one row per identical vector
  * excluded if its SHA-256 or its feature vector also occurs in training weeks 0-39
  * excluded if its SHA-256 or its feature vector also occurs in the official test weeks
    (only test identities, vector hashes and dates are compared; test labels are not read)
  * kept only if dated after every training file and before every primary test file
  * every pilot development file must be recovered with the same label and the same vector
Stage `prepare` resumes week by week. Stage `export` packs 20k-row shards for Google Drive.
Writes only data/processed/ember2024/full-development-win32-v1,
reports/ember2024/full-development-win32-v1 and the export folder.
"""
import argparse, gc, hashlib, inspect, json, shutil, zipfile
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

import numpy as np
from thrember.features import PEFeatureExtractor

from vectorize_ember2024_pilot import FEATURE_COUNT, FEATURE_GROUPS, feature_hash, save_json, save_npy, save_npz, sha256
from prepare_full_ember2024_win32 import checked_hash, label_counts, metadata_schema, read_json, relative, select_rows

RUN = 'full-development-win32-v1'
WEEKS = range(40, 52)
CHUNK_ROWS, SHARD_ROWS = 5000, 20000
MAX_LINE_BYTES, MIN_FREE_BYTES = 32 * 1024 * 1024, 8 * 1024**3


def prepare_week(root, folder, archive, member, week, extractor, train_sha, train_features, offset, limit):
    folder.mkdir(parents=True, exist_ok=True)
    start = datetime.strptime(Path(member).name[:10], '%Y-%m-%d').replace(tzinfo=timezone.utc)
    low, high = int(start.timestamp()), int((start + timedelta(days=7)).timestamp())
    vectors, records, chunks, seen = [], [], [], {}
    stats = dict(source_rows=0, unique_sha_rows=0, repeated_sha_rows=0, raw_feature_variants_checked=0,
                 outside_named_week_dates=0, training_sha_rows_excluded=0, training_vector_rows_excluded=0,
                 stored_rows=0)

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
        chunks.append(dict(x_file=relative(root, x_path), x_sha256=sha256(x_path),
                           metadata_file=relative(root, m_path), metadata_sha256=sha256(m_path),
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
            if raw['file_type'] != 'Win32' or raw['week_id'] != week or type(timestamp) is not int:
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
                stats['outside_named_week_dates'] += 1          # kept; chronology is checked at the end
            if identity in train_sha:
                if train_sha[identity] != (label, digest):
                    raise ValueError(f'Same file has a different label/vector in training: {raw["sha256"]}')
                stats['training_sha_rows_excluded'] += 1
            elif digest in train_features:
                stats['training_vector_rows_excluded'] += 1
            else:
                vectors.append(vector)
                records.append((np.void(identity), np.void(digest), label, timestamp, week, line_number))
                if len(vectors) >= CHUNK_ROWS:
                    flush()
            if stats['source_rows'] % 10000 == 0:
                print(f'  read {stats["source_rows"]:,} records; unique files {stats["unique_sha_rows"]:,}', flush=True)
    flush()
    if stats['source_rows'] == 0:
        raise ValueError(f'Empty source week: {member}')
    return dict(week=week, source_member=member, stats=stats, chunks=chunks)


def paths(root, out_root):
    base = out_root or root
    return (base / 'data/processed/ember2024' / RUN, base / 'reports/ember2024' / RUN / 'preparation.json')


def prepare(root, out_root, limit):
    archive_path = root / 'data/raw/ember2024/archives/Win32_train.zip'
    verified = read_json(root / 'reports/ember2024/train_archive_verified_v1.json')
    pilot_report = read_json(root / 'reports/ember2024/pilot-v1/vectorized-v1.json')
    train_report_path = root / 'reports/ember2024/full-win32-v1/preparation.json'
    train_report = read_json(train_report_path)
    test_report_path = root / 'reports/ember2024/independent-win32-v1/test_preparation.json'
    test_report = read_json(test_report_path)
    pilot = root / 'data/processed/ember2024/pilot-v1/vectorized-v1'
    output, report_path = paths(root, out_root)
    if verified['status'] != 'verified' or train_report['status'] != 'complete' or test_report['status'] != 'complete':
        raise ValueError('Archive, training preparation or test preparation is not complete.')
    extractor = PEFeatureExtractor()
    extractor_hash = sha256(Path(inspect.getfile(PEFeatureExtractor)))
    packages = {name: version(name) for name in pilot_report['protocol']['packages']}
    if (extractor.dim != FEATURE_COUNT or list(FEATURE_GROUPS) != pilot_report['protocol']['feature_groups']
            or extractor_hash != pilot_report['protocol']['extractor_code_sha256']
            or packages != pilot_report['protocol']['packages']
            or train_report['protocol']['extractor_code_sha256'] != extractor_hash):
        raise ValueError('Use the same extractor and package versions as the pilot and the training preparation.')
    protocol = dict(run=RUN, archive_sha256=verified['sha256'], dataset_revision=verified['revision'],
        script_sha256=sha256(Path(__file__)), training_report_sha256=sha256(train_report_path),
        training_row_index_sha256=train_report['row_index_sha256'],
        test_report_sha256=sha256(test_report_path), test_rows_sha256=test_report['test_rows_sha256'],
        pilot_validation_sha256=pilot_report['summary']['partitions']['validation']['files']['validation_provenance.npz'],
        feature_count=FEATURE_COUNT, extractor_code_sha256=extractor_hash, packages=packages,
        weeks=list(WEEKS), chunk_rows=CHUNK_ROWS, record_limit_per_week=limit or None,
        cleanup='unique consistent SHA; exclude conflicting vector groups; one row per vector; exclude SHA or '
                'vector seen in training weeks 0-39 or in official test weeks; training_max < date < test_primary_min')

    state = dict(status='preparing', protocol=protocol, weeks=[])
    if report_path.exists():
        state = read_json(report_path)
        if state['protocol'] != protocol:
            raise ValueError('Existing run uses a different protocol. Do not overwrite it.')
    print('Verifying completed chunks ...', flush=True)
    offset = 0
    for w in state['weeks']:
        for c in w['chunks']:
            if c['offset'] != offset:
                raise ValueError('Checkpoint row offsets are inconsistent.')
            base = out_root or root
            checked_hash(base / c['x_file'], c['x_sha256']); checked_hash(base / c['metadata_file'], c['metadata_sha256'])
            offset += c['rows']
    if state['status'] in ('complete', 'TEST_ONLY_complete'):
        print(json.dumps(state['summary'], indent=2)); print(f'Already complete: {report_path}')
        return
    report_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(report_path, state)

    print('Verifying the archive checksum (several minutes) ...', flush=True)
    if archive_path.stat().st_size != verified['size_bytes']:
        raise ValueError('Archive size changed.')
    checked_hash(archive_path, verified['sha256'])
    print('Loading training identities and vector hashes ...', flush=True)
    train_index = root / train_report['row_index_file']
    checked_hash(train_index, train_report['row_index_sha256'])
    with np.load(train_index, allow_pickle=False) as t:
        train_sha = {s.tobytes(): (int(y), h.tobytes()) for s, y, h in zip(t['sha256'], t['label'], t['feature_hash'])}
        train_features = {h.tobytes() for h in t['feature_hash']}
        train_max = int(t['timestamp'].max())

    base = out_root or root
    with zipfile.ZipFile(archive_path) as archive:
        members = sorted(n for n in archive.namelist() if n.endswith('_Win32_train.jsonl'))
        if len(members) != 52:
            raise ValueError('Unexpected archive members.')
        for week in WEEKS:
            if any(w['week'] == week for w in state['weeks']):
                continue
            print(f'\nPreparing week {week}: {members[week]}', flush=True)
            result = prepare_week(base, output / f'week_{week:02d}', archive, members[week], week, extractor,
                                  train_sha, train_features, offset, limit)
            state = dict(state, weeks=state['weeks'] + [result])
            save_json(report_path, state)
            offset += result['stats']['stored_rows']
            print(f'Week {week} saved: {result["stats"]}', flush=True)
            gc.collect()
    del train_sha, train_features; gc.collect()

    print('\nAuditing all development weeks ...', flush=True)
    chunks = [c for w in state['weeks'] for c in w['chunks']]
    meta = metadata_schema(offset)
    for c in chunks:
        with np.load(base / c['metadata_file'], allow_pickle=False) as saved:
            for name in meta:
                meta[name][c['offset']:c['offset'] + c['rows']] = saved[name]
    valid, audit = select_rows(meta)

    test_rows = root / 'data/processed/ember2024/independent-win32-v1/test-vectorized-v1/test_rows.npz'
    checked_hash(test_rows, test_report['test_rows_sha256'])
    with np.load(test_rows, allow_pickle=False) as t:            # labels deliberately not loaded
        test_sha, test_vec = t['sha256'], t['feature_hash']
        test_primary_min = int(t['timestamp'][t['primary_indices']].min())
    in_test_sha = np.isin(meta['sha256'][valid], test_sha)
    in_test_vec = np.isin(meta['feature_hash'][valid], test_vec) & ~in_test_sha
    ts = meta['timestamp'][valid]
    too_early, too_late = ts <= train_max, ts >= test_primary_min
    keep = ~(in_test_sha | in_test_vec | too_early | too_late)
    dev = valid[keep]
    audit.update(test_sha_overlap_removed=int(in_test_sha.sum()), test_vector_overlap_removed=int(in_test_vec.sum()),
                 not_after_training_removed=int((too_early & ~in_test_sha & ~in_test_vec).sum()),
                 not_before_test_removed=int((too_late & ~too_early & ~in_test_sha & ~in_test_vec).sum()))
    if len(np.unique(meta['label'][dev])) != 2:
        raise ValueError('Both classes are required.')

    with np.load(pilot / 'validation_provenance.npz', allow_pickle=False) as p:
        pilot_ids = np.array([np.void(bytes.fromhex(s.decode('ascii'))) for s in p['sha256']], dtype='V32')
        pilot_label, pilot_vec = p['label'], p['feature_hash']
    found = np.isin(pilot_ids, meta['sha256'])
    order = np.argsort(meta['sha256'], kind='stable')
    rows = order[np.searchsorted(meta['sha256'][order], pilot_ids[found])]
    pilot_check = dict(pilot_files=int(len(pilot_ids)), recovered=int(found.sum()),
                       same_label=int((meta['label'][rows] == pilot_label[found]).sum()),
                       same_vector=int((meta['feature_hash'][rows] == pilot_vec[found]).sum()),
                       kept_in_full_development=int(np.isin(pilot_ids, meta['sha256'][dev]).sum()))
    if not limit and (pilot_check['recovered'] != len(pilot_ids) or pilot_check['same_label'] != len(pilot_ids)
                      or pilot_check['same_vector'] != len(pilot_ids)):
        raise ValueError(f'Pilot development files not reproduced exactly: {pilot_check}')

    index_path = output / 'row_index.npz'
    save_npz(index_path, **meta, development_indices=dev)
    totals = {k: int(sum(w['stats'][k] for w in state['weeks'])) for k in state['weeks'][0]['stats']}
    per_week = {int(w): label_counts(meta['label'][dev][meta['week'][dev] == w]) for w in WEEKS}
    summary = dict(source=totals, audit=audit, physical_stored_rows=offset, development_rows=int(len(dev)),
                   development_labels=label_counts(meta['label'][dev]), per_week=per_week, pilot_check=pilot_check,
                   training_max_timestamp=train_max, test_primary_min_timestamp=test_primary_min,
                   development_timestamp_range=[int(meta['timestamp'][dev].min()), int(meta['timestamp'][dev].max())],
                   stored_vector_gib=round(sum((base / c['x_file']).stat().st_size for c in chunks) / 1024**3, 3),
                   note='Exact SHA-256/vector separation from training and test; near-duplicate and family '
                        'separation are not established. Use development_indices when loading chunks.')
    state = dict(state, status='complete' if not limit else 'TEST_ONLY_complete', summary=summary,
                 row_index_file=relative(base, index_path), row_index_sha256=sha256(index_path))
    save_json(report_path, state)
    print('\nFULL DEVELOPMENT PREPARATION SUMMARY\n' + json.dumps(summary, indent=2))
    print(f'Report: {report_path}\nNext: python scripts/prepare_full_development_win32.py export')


def export(root, out_root, target):
    output, report_path = paths(root, out_root)
    base = out_root or root
    state = read_json(report_path)
    if state['status'] not in ('complete', 'TEST_ONLY_complete'):
        raise ValueError('Run the prepare stage first.')
    target.mkdir(parents=True, exist_ok=True)
    if (target / 'manifest.json').exists():
        raise SystemExit(f'{target} already has a finished export; delete the folder to redo it.')
    checked_hash(base / state['row_index_file'], state['row_index_sha256'])
    with np.load(base / state['row_index_file'], allow_pickle=False) as z:
        meta = {k: z[k] for k in z.files}
    keep = np.zeros(len(meta['label']), dtype=bool)
    keep[meta['development_indices']] = True
    chunks = [c for w in state['weeks'] for c in w['chunks']]
    (target / 'dev').mkdir(exist_ok=True)
    buf, files, number = [], {}, 0

    def write_shard(parts):
        nonlocal number
        cat = lambda k: np.concatenate([p[k] for p in parts])
        name = f'dev/dev-{number:04d}.npz'
        np.savez_compressed(target / name, X=cat('X'), y=cat('y').astype(np.int8), row=cat('row'),
                            part=np.full(sum(len(p['y']) for p in parts), 3, np.int8),
                            sha256=np.frombuffer(cat('sha256').tobytes(), np.uint8).reshape(-1, 32),
                            feature_hash=np.frombuffer(cat('feature_hash').tobytes(), np.uint8).reshape(-1, 32),
                            week=cat('week').astype(np.int16), timestamp=cat('timestamp').astype(np.int64))
        files[name] = dict(sha256=sha256(target / name), bytes=(target / name).stat().st_size)
        print(f'  wrote {name}', flush=True)
        number += 1

    pending = 0
    for c in chunks:
        checked_hash(base / c['x_file'], c['x_sha256'])
        g = np.arange(c['offset'], c['offset'] + c['rows'])
        sel = keep[g]
        if not sel.any():
            continue
        X = np.load(base / c['x_file'], mmap_mode='r')
        buf.append(dict(X=np.asarray(X[sel]), y=meta['label'][g][sel], row=g[sel], sha256=meta['sha256'][g][sel],
                        feature_hash=meta['feature_hash'][g][sel], week=meta['week'][g][sel],
                        timestamp=meta['timestamp'][g][sel]))
        pending += int(sel.sum())
        if pending >= SHARD_ROWS:
            write_shard(buf); buf, pending = [], 0
    if buf:
        write_shard(buf)
    s = state['summary']
    manifest = dict(status='WIN32_FULL_DEV_READY' if state['status'] == 'complete' else 'TEST_EXPORT_ONLY',
        features=FEATURE_COUNT, counts=dict(dev_rows=s['development_rows'], **s['development_labels']),
        per_week=s['per_week'], part_codes={'3': 'full development weeks 40-51 (calibration, thresholds, ranking)'},
        sources=dict(preparation_report=dict(path=relative(base, report_path), sha256=sha256(report_path)),
                     row_index=dict(path=state['row_index_file'], sha256=state['row_index_sha256'])),
        audit=s['audit'], pilot_check=s['pilot_check'], files=files,
        total_gib=round(sum(f['bytes'] for f in files.values()) / 1024**3, 2))
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ('status', 'counts', 'total_gib')}, indent=2))
    print(f'Upload this whole folder to Google Drive -> MLWINT-colab/inputs/: {target}')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('stage', choices=['prepare', 'export'])
    ap.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument('--out', type=Path, default=None, help='export folder (default exports/colab/win32-dev-full-v1)')
    ap.add_argument('--test-output-root', type=Path, default=None, help='testing only: write everything here')
    ap.add_argument('--test-records-per-week', type=int, default=0, help='testing only')
    a = ap.parse_args()
    root = a.project_root.resolve()
    if a.stage == 'prepare':
        prepare(root, a.test_output_root, a.test_records_per_week)
    else:
        export(root, a.test_output_root, a.out or (a.test_output_root or root) / 'exports/colab/win32-dev-full-v1')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped. Rerun the same command to reuse completed weeks.')
        raise SystemExit(130)