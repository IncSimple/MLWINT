"""Colab CPU (standard). Win64 data-leakage audit, run BEFORE any Win64 training.

Partitions: 1 inner_fit (weeks 0-35), 2 inner_stop (36-39), 3 development (40-51), 4 test (52-63).
Checks
  1. every file's checksum and the row counts match the export manifest
  2. the same file (SHA-256) in two partitions, or twice in one
  3. the same feature vector (hash of the actual 2,568 numbers) in two partitions,
     and identical vectors that carry different labels
  4. time order: fit < stop < development < test
  5. "too good" single features: one feature alone separating malware from benign almost
     perfectly (AUC >= 0.99, on a training sample) would suggest a label leaking into features
The Win64 test set has never been scored: its labels are only used for check 3 (a yes/no
conflict count) and are not counted or printed. Training starts only on WIN64_SEPARATION_PASSED.
Not covered: near-duplicates, repacked versions of the same malware, family overlap.
"""
import hashlib, json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

DATA = Path('/content/drive/MyDrive/MLWINT-colab/inputs/win64-v1')
OUT = Path('/content/drive/MyDrive/MLWINT-colab/experiments/win64-fourway-v1/leakage-audit-v1')
NAMES = {1: 'inner_fit', 2: 'inner_stop', 3: 'development', 4: 'test'}
AUC_FLAG, SAMPLE, SEED = 0.99, 200_000, 42


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def row_hashes(X):
    X = np.ascontiguousarray(X, dtype=np.float32)
    X[X == 0] = 0.0                                   # -0.0 and 0.0 hash the same
    return np.array([hashlib.blake2b(r.tobytes(), digest_size=16).digest() for r in X], dtype='S16')


def single_feature_auc(X, y):
    from scipy.stats import rankdata
    pos = y == 1
    n1, n0 = pos.sum(), (~pos).sum()
    out = np.empty(X.shape[1])
    for j in range(X.shape[1]):
        r = rankdata(X[:, j])
        out[j] = (r[pos].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)
    return out


def main(data=DATA, out=OUT):
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((data / 'manifest.json').read_text())
    strict = manifest['status'] == 'WIN64_EXPORT_READY'
    shards = sorted(n for n in manifest['files'] if n.endswith('.npz'))
    print(f'Verifying {len(shards)} files ...', flush=True)
    for name in shards:
        if sha(data / name) != manifest['files'][name]['sha256']:
            raise ValueError(f'Checksum mismatch: {name} (re-upload it)')
    cols = {k: [] for k in ('part', 'y', 'sha', 'vec', 'week', 'time')}
    rng = np.random.default_rng(SEED)
    total_train = manifest['counts']['train_rows']
    sample_X, sample_y = [], []
    for i, name in enumerate(shards, 1):
        with np.load(data / name) as z:
            X, part = z['X'], z['part']
            cols['part'].append(part); cols['y'].append(z['y'])
            cols['sha'].append(z['sha256'].view('S32').ravel()); cols['vec'].append(row_hashes(X))
            cols['week'].append(z['week']); cols['time'].append(z['timestamp'])
            if name.startswith('train/'):
                take = rng.random(len(part)) < SAMPLE / total_train
                sample_X.append(X[take]); sample_y.append(z['y'][take])
        print(f'Read and hashed {i}/{len(shards)} files', flush=True)
    c = {k: np.concatenate(v) for k, v in cols.items()}
    report = dict(created_utc=datetime.now(timezone.utc).isoformat(), manifest_sha256=sha(data / 'manifest.json'),
                  checks={}, problems=[])
    P = report['problems']

    # 1. counts (test: rows only, labels stay sealed)
    counts = {NAMES[p]: dict(rows=int((c['part'] == p).sum())) for p in NAMES}
    for p in (1, 2, 3):
        counts[NAMES[p]]['malicious'] = int(c['y'][c['part'] == p].sum())
    counts['test']['labels'] = 'sealed'
    report['checks']['counts'] = counts
    if strict:
        want = manifest['counts']
        got = tuple(counts[NAMES[p]]['rows'] for p in NAMES)
        if got != (want['inner_fit'], want['inner_stop'], want['dev_rows'], want['test_rows']):
            P.append(f'Row counts differ from the manifest: {got}')

    # 2 + 3. identity and feature-vector overlap
    for key, label in (('sha', 'same_file_sha256'), ('vec', 'same_feature_vector')):
        sets = {p: set(c[key][c['part'] == p].tolist()) for p in NAMES}
        pairs = {}
        for a in NAMES:
            for b in NAMES:
                if a < b:
                    n = len(sets[a] & sets[b])
                    pairs[f'{NAMES[a]}~{NAMES[b]}'] = n
                    if n:
                        P.append(f'{n} {label} overlaps between {NAMES[a]} and {NAMES[b]}')
        within = {NAMES[p]: int((c['part'] == p).sum() - len(sets[p])) for p in NAMES}
        report['checks'][label] = dict(across_partitions=pairs, repeated_within_partition=within)
        for p, n in within.items():
            if n:
                P.append(f'{n} repeated {label} inside {p}')
    order = np.argsort(c['vec'], kind='stable')
    v, y = c['vec'][order], c['y'][order]
    conflicts = int(((v[1:] == v[:-1]) & (y[1:] != y[:-1])).sum())
    report['checks']['identical_vectors_with_different_labels'] = conflicts
    if conflicts:
        P.append(f'{conflicts} identical feature vectors carry different labels')

    # 4. time order
    span = {NAMES[p]: dict(first_week=int(c['week'][c['part'] == p].min()), last_week=int(c['week'][c['part'] == p].max()),
                           first_time=int(c['time'][c['part'] == p].min()), last_time=int(c['time'][c['part'] == p].max()))
            for p in NAMES if (c['part'] == p).any()}
    report['checks']['time_span'] = span
    present = [NAMES[p] for p in NAMES if NAMES[p] in span]
    if strict and len(present) != 4:
        P.append('A partition is empty')
    for a, b in zip(present, present[1:]):
        if span[a]['last_time'] >= span[b]['first_time']:
            P.append(f'Time overlap: {a} ends after {b} starts')

    # 5. single-feature separation (training sample only)
    Xs, ys = np.concatenate(sample_X), np.concatenate(sample_y)
    print(f'Single-feature check on {len(ys):,} training rows (a few minutes) ...', flush=True)
    auc = single_feature_auc(Xs, ys)
    strength = np.maximum(auc, 1 - auc)
    top = np.argsort(-strength)[:15]
    report['checks']['single_feature_auc'] = dict(sample_rows=int(len(ys)), flag_at=AUC_FLAG,
        strongest=[dict(feature=int(j), auc=float(auc[j])) for j in top],
        flagged=[int(j) for j in np.flatnonzero(strength >= AUC_FLAG)])
    if (strength >= AUC_FLAG).any():
        P.append(f'{int((strength >= AUC_FLAG).sum())} single features separate the classes almost perfectly')

    report['status'] = ('WIN64_SEPARATION_PASSED' if strict else 'TEST_AUDIT_PASSED') if not P else 'REVIEW_NEEDED'
    report['not_covered'] = ['near-duplicate or repacked files', 'malware-family overlap across partitions',
                             'label noise in the source dataset']
    (out / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in ('status', 'problems')}, indent=2))
    print(json.dumps(report['checks'], indent=1)[:4000])
    return report


if __name__ == '__main__':
    main()
