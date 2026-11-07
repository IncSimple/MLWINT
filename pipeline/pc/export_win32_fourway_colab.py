"""Run on the PC (VS Code, EMBER2024 venv), from the MLWINT project folder.

Packs everything the Win32 4-way comparison needs into one folder for Google Drive:
  train/  all 1,199,974 usable training rows (inner_fit=1, inner_stop=2), 20k-row shards
  dev/    the 23,616 development-validation rows
  test/   the 359,991 official-test 'primary' rows, 20k-row shards
  models/ frozen XGBoost (2000 rounds) and improved LightGBM v2 (2000 rounds)
  manifest.json  checksums + counts (Colab verifies every file against it)
Only reads the project; writes only to the output folder. Row order and labels are
checked against the saved row indexes while packing.
"""
import argparse, hashlib, json, shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

FEATURES, CHUNK, SHARD_CHUNKS = 2568, 5000, 4
FULL = 'data/processed/ember2024/full-win32-v1'
TEST = 'data/processed/ember2024/independent-win32-v1/test-vectorized-v1'
DEV = 'data/processed/ember2024/pilot-v1/vectorized-v1'
MODELS = {
    'xgboost.ubj': ('src/models/candidates/ember2024/challenger-full-temporal-v1/xgboost_challenger_full.ubj',
                    'd067841d7fbdabeb51c05b59ab1e49fbbcdc67c1888cb8c8facd7c7515a859be'),
    'lightgbm.txt': ('src/models/candidates/ember2024/lightgbm-full-temporal-v2/lightgbm_primary_full.txt',
                     'ef94d30817a401ecd5e09d97d5b5d5201a0b510f283de9dbb72bfed1d9a3e60c'),
    # Round selectors (fitted on inner_fit only, 2000 rounds): starting points for the
    # longer-training runs, which choose the new round count on inner_stop.
    'xgboost_round_selector.ubj': ('src/models/candidates/ember2024/challenger-full-temporal-v1/xgboost_round_selector.ubj',
                                   '6d67bbf39a5cdca90629359c32eb84664b74fea243ac08b0a8623219403bb439'),
    'lightgbm_round_selector.txt': ('src/models/candidates/ember2024/lightgbm-full-temporal-v2/lightgbm_round_selector.txt',
                                    '0d53e891bdbd3aaa23e630a3ee31d3b155aa1b0ead64530802f80a1c01f08281'),
}
SOURCES = {   # recorded so Colab-side results stay traceable to these exact files
    'row_index': f'{FULL}/row_index.npz',
    'test_rows': f'{TEST}/test_rows.npz',
    'dev_X': f'{DEV}/X_validation.npy',
    'dev_y': f'{DEV}/y_validation.npy',
    'dev_provenance': f'{DEV}/validation_provenance.npz',
    'preparation_report': 'reports/ember2024/full-win32-v1/preparation.json',
    'test_protocol': 'reports/ember2024/independent-win32-v1/frozen_protocol.json',
    'xgboost_report': 'reports/ember2024/full-win32-v1/challenger-full-temporal-v1/report.json',
    'lightgbm_report': 'reports/ember2024/full-win32-v1/lightgbm-full-temporal-v2/report.json',
}


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def as_bytes32(a):
    """SHA-256 / feature hashes as an (n, 32) uint8 array, from raw V32 or hex S64."""
    a = np.asarray(a)
    if a.dtype.kind == 'S':
        return np.frombuffer(b''.join(bytes.fromhex(x.decode()) for x in a), np.uint8).reshape(-1, 32)
    return np.frombuffer(a.tobytes(), np.uint8).reshape(-1, 32)


def chunk_files(base, weeks):
    files = []
    for w in weeks:
        names = sorted(p for p in (base / f'week_{w:02d}').glob('chunk_*.npy'))
        if len(names) != 6:
            raise ValueError(f'Expected 6 chunks in week {w}')
        files += names
    return files


def pack(root, files, index, keep_rows, part_of, out_dir, prefix, max_shards):
    """Shards of SHARD_CHUNKS source chunks; keeps only rows in keep_rows."""
    keep = np.zeros(len(index['sha256']), dtype=bool)
    keep[keep_rows] = True
    sizes = [len(np.load(f.with_name(f.stem + '.metadata.npz'))['label']) for f in files]
    if sum(sizes) != len(index['sha256']):
        raise ValueError('Chunk sizes do not add up to the row index')
    offset = dict(zip(files, np.r_[0, np.cumsum(sizes)[:-1]]))
    jobs = [files[i:i + SHARD_CHUNKS] for i in range(0, len(files), SHARD_CHUNKS)]
    if max_shards:
        jobs = jobs[:max_shards]

    def one(args):
        number, group = args
        Xs, ys, rows, parts, shas, fhs, weeks, times = [], [], [], [], [], [], [], []
        for f in group:
            start = int(offset[f])
            meta = np.load(f.with_name(f.stem + '.metadata.npz'))
            n = len(meta['sha256'])
            g = np.arange(start, start + n)
            if (not np.array_equal(meta['sha256'], index['sha256'][g])
                    or not np.array_equal(meta['label'], index['label'][g])):
                raise ValueError(f'Row order/label mismatch in {f}')
            X = np.load(f, mmap_mode='r')
            if X.shape != (n, FEATURES) or X.dtype != np.float32:
                raise ValueError(f'Unexpected matrix {f}: {X.shape} {X.dtype}')
            sel = keep[g]
            Xs.append(np.asarray(X[sel])); ys.append(meta['label'][sel]); rows.append(g[sel])
            parts.append(part_of[g[sel]])
            shas.append(as_bytes32(meta['sha256'][sel])); fhs.append(as_bytes32(meta['feature_hash'][sel]))
            weeks.append(meta['week'][sel]); times.append(meta['timestamp'][sel])
        name = f'{prefix}-{number:04d}.npz'
        np.savez_compressed(out_dir / name, X=np.concatenate(Xs), y=np.concatenate(ys).astype(np.int8),
                            row=np.concatenate(rows), part=np.concatenate(parts).astype(np.int8),
                            sha256=np.concatenate(shas), feature_hash=np.concatenate(fhs),
                            week=np.concatenate(weeks).astype(np.int16),
                            timestamp=np.concatenate(times).astype(np.int64))
        rows_n = int(sum(len(r) for r in rows))
        print(f'  {prefix}: shard {number + 1}/{len(jobs)} ({rows_n} rows)', flush=True)
        return dict(file=f'{out_dir.name}/{name}', rows=rows_n)

    with ThreadPoolExecutor(8) as pool:
        records = list(pool.map(one, enumerate(jobs)))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.', help='MLWINT project folder')
    ap.add_argument('--out', default='exports/colab/win32-fourway-v1')
    ap.add_argument('--max-shards', type=int, default=0, help='testing only: limit shards')
    args = ap.parse_args()
    root, out = Path(args.root).resolve(), Path(args.out).resolve()
    if (out / 'manifest.json').exists():
        raise SystemExit(f'{out} already has a finished export; delete the folder to redo it.')
    for d in ('train', 'dev', 'test', 'models'):
        (out / d).mkdir(parents=True, exist_ok=True)

    print('Checking frozen models...', flush=True)
    for name, (src, expected) in MODELS.items():
        if sha(root / src) != expected:
            raise ValueError(f'Model checksum mismatch: {src}')
        shutil.copyfile(root / src, out / 'models' / name)

    idx = dict(np.load(root / SOURCES['row_index']))
    valid, fit, stop = idx['valid_indices'], idx['inner_fit_indices'], idx['inner_stop_indices']
    if (len(valid), len(fit), len(stop)) != (1199974, 1079988, 119986) or \
            not np.array_equal(np.sort(np.r_[fit, stop]), np.sort(valid)):
        raise ValueError('Unexpected training partitions')
    part = np.zeros(len(idx['sha256']), dtype=np.int8)
    part[fit], part[stop] = 1, 2
    print('Packing training rows (40 weeks)...', flush=True)
    train = pack(root, chunk_files(root / FULL, range(40)), idx, valid, part, out / 'train', 'train',
                 args.max_shards)

    tidx = dict(np.load(root / SOURCES['test_rows']))
    primary = tidx['primary_indices']
    if len(primary) != 359991:
        raise ValueError('Unexpected test population size')
    print('Packing official-test primary rows (weeks 52-63)...', flush=True)
    test = pack(root, chunk_files(root / TEST, range(52, 64)), tidx, primary,
                np.full(len(tidx['sha256']), 4, dtype=np.int8), out / 'test', 'test', args.max_shards)

    Xd = np.load(root / SOURCES['dev_X'])
    yd = np.load(root / SOURCES['dev_y'])
    prov = np.load(root / SOURCES['dev_provenance'])
    if Xd.shape != (23616, FEATURES) or len(yd) != 23616 or not np.array_equal(prov['label'], yd):
        raise ValueError('Unexpected development validation set')
    np.savez_compressed(out / 'dev' / 'dev.npz', X=Xd.astype(np.float32), y=yd.astype(np.int8),
                        row=np.arange(len(yd)), part=np.full(len(yd), 3, dtype=np.int8),
                        sha256=as_bytes32(prov['sha256']), feature_hash=as_bytes32(prov['feature_hash']),
                        week=prov['week'].astype(np.int16), timestamp=prov['timestamp'].astype(np.int64))

    files = {}
    for p in sorted(out.rglob('*')):
        if p.is_file() and p.name != 'manifest.json':
            files[p.relative_to(out).as_posix()] = dict(sha256=sha(p), bytes=p.stat().st_size)
    manifest = dict(status='WIN32_EXPORT_READY' if not args.max_shards else 'TEST_EXPORT_ONLY',
        features=FEATURES,
        counts=dict(train_rows=sum(r['rows'] for r in train), inner_fit=int(len(fit)),
                    inner_stop=int(len(stop)), dev_rows=int(len(yd)), test_rows=sum(r['rows'] for r in test)),
        part_codes={'1': 'inner_fit (SVM training)', '2': 'inner_stop (SVM tuning)',
                    '3': 'development validation (calibration, thresholds, ranking)',
                    '4': 'official test primary population (benchmark; consulted 2026-10-29)'},
        models={k: v[1] for k, v in MODELS.items()},
        sources={k: dict(path=v, sha256=sha(root / v)) for k, v in SOURCES.items()},
        files=files, total_gib=round(sum(f['bytes'] for f in files.values()) / 1024**3, 2))
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ('status', 'counts', 'total_gib')}, indent=2))
    print(f'Upload this whole folder to Google Drive: {out}')


if __name__ == '__main__':
    main()