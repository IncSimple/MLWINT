"""PDF real-world retrain, step R2 (Google Colab, standard CPU runtime): clean, split and audit the SafeDocs data.

Input : inputs/safedocs-v1/shards/*.npz   (step R1, real-world PDFs from the public web)
        inputs/pdf-v1                     (EMBER2024 PDF data, weeks 0-63)
        experiments/phase1-closeout-v1/verdict_policy_pdf.json  (the PDF detector shipped in MLWINT 1.0.0)

1. Clean    : drop SafeDocs files seen twice (same SHA-256), files that are also in EMBER, and files whose feature
              vector equals an EMBER malware vector (a label conflict). PDFs with active content (/JS, /JavaScript,
              /Launch, /EmbeddedFile, /RichMedia, /XFA) never go on the clean side: they are kept apart, unlabelled.
2. Split    : by ZIP, never by file (files in one zip were crawled together): 70 % fit, 15 % judge, 15 % holdout,
              seeded shuffle of the zip numbers. Vectors in judge/holdout that also occur in fit are dropped there.
3. Baseline : the shipped 1.0.0 PDF detector scored on every SafeDocs PDF -> today's real-world false alarms.
4. Audit    : how easily "where a PDF came from" (EMBER clean vs SafeDocs clean) can be told apart, per feature and
              with a small LightGBM, using fit-split SafeDocs and EMBER weeks 0-51 only (the EMBER test weeks 52-63
              are not used here).
              Rule fixed now, before any training: a feature is SOURCE-ONLY when it separates the two clean sources
              strongly (AUC >= 0.90 or <= 0.10) but says almost nothing about malware inside EMBER (AUC within
              0.40-0.60). Step R3 trains with and without these features and picks on the judge split, never on
              the holdout.

Output: inputs/pdf-rw-v1/      safedocs_{fit,judge,holdout}.npz (clean side), safedocs_active.npz, manifest.json
        experiments/pdf-realworld-v1/audit-v1/  report.json, features.csv          status PDF_RW_AUDIT_DONE
Re-running is safe: finished output is checked and reused.
"""
import csv, hashlib, json, os, sys, time
from pathlib import Path

import numpy as np

ROOT = Path(os.environ.get('MLWINT_COLAB_ROOT', '/content/drive/MyDrive/MLWINT-colab'))
SD = ROOT / 'inputs/safedocs-v1'
EM = ROOT / 'inputs/pdf-v1'
CARD = ROOT / 'experiments/phase1-closeout-v1/verdict_policy_pdf.json'
DATA = ROOT / 'inputs/pdf-rw-v1'
OUT = ROOT / 'experiments/pdf-realworld-v1/audit-v1'
FEATURES, SEED = 2568, 42
SPLIT = (0.70, 0.15, 0.15)
ACTIVE = ('/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/RichMedia', '/XFA')      # MLWINT's PDF_ACTIVE
SOURCE_AUC, MALWARE_BAND, SAMPLE = 0.90, 0.10, 20000
GROUPS = [('general', 0, 7), ('histogram', 7, 256), ('byteentropy', 263, 256), ('strings', 519, 177),
          ('header', 696, 74), ('section', 770, 224), ('imports', 994, 1282), ('exports', 2276, 129),
          ('datadirectories', 2405, 34), ('richheader', 2439, 33), ('authenticode', 2472, 8),
          ('pefilewarnings', 2480, 88)]                     # thrember PEFeatureExtractor layout (2,568 values)


def feature_name(i):
    for name, start, dim in GROUPS:
        if start <= i < start + dim:
            return f'{name}[{i - start}]'
    raise IndexError(i)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.pending')
    tmp.write_text(json.dumps(value, indent=2, allow_nan=False))
    tmp.replace(path)


def save_npz(path, **arrays):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.stem + '.part.npz')
    np.savez_compressed(tmp, **arrays)
    tmp.replace(path)
    return sha(path)


def row_hashes(X):
    X = np.ascontiguousarray(X, dtype=np.float32)
    return np.array([hashlib.blake2b(r.tobytes(), digest_size=16).hexdigest() for r in X])


def log(msg):
    print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)


# ---------------------------------------------------------------------------------------------- loading
def load_safedocs():
    status = read(SD / 'status.json')
    if status.get('status') != 'SAFEDOCS_FEATURES_DONE':
        raise SystemExit(f'Step R1 is not finished (status: {status.get("status")})')
    shards = sorted((SD / 'shards').glob('*.npz'))
    parts, skipped = [], 0
    for f in shards:
        with np.load(f) as z:
            cols = [str(c) for c in z['indicator_columns']]
            n = len(z['sha256'])
            parts.append(dict(X=z['X'].astype(np.float32), sha256=z['sha256'].astype('U64'),
                              name=z['name'].astype('U32'), bytes=z['bytes'], indicators=z['indicators'],
                              zip_id=np.full(n, str(z['zip_id']), dtype='U8')))
            skipped += len(json.loads(str(z['skipped'])))
    d = {k: np.concatenate([p[k] for p in parts]) for k in parts[0]}
    if d['X'].shape[1] != FEATURES:
        raise ValueError(f'SafeDocs vectors have {d["X"].shape[1]} values, expected {FEATURES}')
    active_idx = [cols.index(c) for c in ACTIVE]
    d['active'] = d['indicators'][:, active_idx].sum(1) > 0
    d['indicator_columns'] = np.array(cols)
    log(f'SafeDocs: {len(shards)} shards, {len(d["sha256"]):,} PDFs ({skipped:,} skipped in R1), '
        f'{int(d["active"].sum()):,} with active content')
    return d, len(shards), skipped


def load_ember():
    manifest = read(EM / 'manifest.json')
    if manifest.get('status') != 'PDF_EXPORT_READY':
        raise SystemExit('inputs/pdf-v1 is not the finished PDF export')
    parts = []
    for name, info in sorted(manifest['files'].items()):
        if not name.endswith('.npz'):
            continue
        if sha(EM / name) != info['sha256']:
            raise ValueError(f'Checksum failed: {EM / name}')
        with np.load(EM / name) as z:
            parts.append({k: z[k] for k in ('X', 'y', 'week', 'sha256')})
    d = {k: np.concatenate([p[k] for p in parts]) for k in parts[0]}
    d['X'] = d['X'].astype(np.float32)
    d['y'] = d['y'].astype(int)
    d['sha256'] = (np.array([bytes(r).hex() for r in d['sha256']]) if d['sha256'].ndim == 2
                   else d['sha256'].astype('U64'))         # EMBER stores SHA-256 as 32 raw bytes
    log(f'EMBER PDF: {len(d["y"]):,} files ({int((d["y"] == 1).sum()):,} malware), weeks '
        f'{int(d["week"].min())}-{int(d["week"].max())}')
    return d, sha(EM / 'manifest.json')


# ---------------------------------------------------------------------------------------------- shipped detector
def shipped_probability(X):
    import lightgbm as lgb, xgboost as xgb
    from scipy.special import expit
    card = read(CARD)
    ens = card['ensemble']
    prob = np.zeros(len(X))
    for m, w in ens['weights'].items():
        info = card['models'][m]
        path = ROOT / info['file']
        if sha(path) != info['sha256']:
            raise ValueError(f'Model checksum failed: {path}')
        if m == 'xgb':
            margin = xgb.Booster(model_file=str(path)).inplace_predict(X, predict_type='margin')
        elif m == 'lgbm':
            margin = lgb.Booster(model_file=str(path)).predict(X, raw_score=True)
        else:
            raise ValueError(f'Unexpected model in the shipped PDF ensemble: {m}')
        c = ens['calibration'][m]
        prob += w * expit(c['slope'] * np.asarray(margin, np.float64) + c['intercept'])
    v = card['verdicts']
    return prob, float(v['malicious']['threshold']), float(v['suspicious']['threshold']), sha(CARD)


def tier_counts(prob, mal, sus):
    n = max(1, len(prob))
    m, s = int((prob >= mal).sum()), int(((prob >= sus) & (prob < mal)).sum())
    return dict(files=int(len(prob)), malicious=m, suspicious=s, malicious_rate=m / n, flagged_rate=(m + s) / n)


# ---------------------------------------------------------------------------------------------- audit
def column_auc(Xa, Xb):
    """AUC of every column for telling b (positive) from a: 0.5 = no difference, 1 or 0 = perfect."""
    from scipy.stats import rankdata
    Z = np.vstack([Xa, Xb]).astype(np.float64)
    ranks = rankdata(Z, axis=0)
    n0, n1 = len(Xa), len(Xb)
    return (ranks[n0:].sum(0) - n1 * (n1 + 1) / 2) / (n0 * n1)


def sample(X, n, rng):
    return X[rng.choice(len(X), size=min(n, len(X)), replace=False)]


def source_model(Xa, Xb, columns, rng):
    """Small LightGBM telling b from a; AUC on a 30 % hold-back and the most used features."""
    import lightgbm as lgb
    from sklearn.metrics import roc_auc_score
    X = np.vstack([Xa, Xb])[:, columns]
    y = np.r_[np.zeros(len(Xa)), np.ones(len(Xb))]
    order = rng.permutation(len(y))
    cut = int(0.7 * len(y))
    tr, te = order[:cut], order[cut:]
    model = lgb.train(dict(objective='binary', learning_rate=0.1, num_leaves=31, feature_fraction=0.8, seed=SEED,
                           verbosity=-1, num_threads=os.cpu_count()), lgb.Dataset(X[tr], y[tr]), 200)
    auc = float(roc_auc_score(y[te], model.predict(X[te])))
    gain = model.feature_importance('gain')
    top = np.argsort(gain)[::-1][:20]
    total = float(gain.sum()) or 1.0
    return auc, [dict(feature=feature_name(int(columns[i])), share_of_gain=round(float(gain[i]) / total, 4))
                 for i in top if gain[i] > 0]


# ---------------------------------------------------------------------------------------------- main
def main():
    if (OUT / 'report.json').exists() and read(OUT / 'report.json').get('status') == 'PDF_RW_AUDIT_DONE':
        print('Already finished:\n' + (OUT / 'report.json').read_text())
        return
    rng = np.random.default_rng(SEED)
    sd, n_shards, r1_skipped = load_safedocs()
    em, em_manifest_sha = load_ember()
    steps = dict(r1_pdfs=int(len(sd['sha256'])), r1_skipped=r1_skipped)

    # ---- 1. clean ----
    keep = np.ones(len(sd['sha256']), bool)
    order = np.lexsort((sd['name'], sd['zip_id']))
    _, first = np.unique(sd['sha256'][order], return_index=True)
    dup = np.ones(len(keep), bool)
    dup[order[first]] = False
    keep &= ~dup
    steps['duplicate_sha256_removed'] = int(dup.sum())
    in_ember = np.isin(sd['sha256'], em['sha256'])
    steps['also_in_ember_removed'] = int((in_ember & keep).sum())
    keep &= ~in_ember
    log('Hashing feature vectors ...')
    sd_vec = row_hashes(sd['X'])
    em_vec = row_hashes(em['X'])
    conflict = np.isin(sd_vec, em_vec[em['y'] == 1])
    steps['same_vector_as_ember_malware_removed'] = int((conflict & keep).sum())
    keep &= ~conflict
    steps['same_vector_as_ember_clean_kept'] = int((np.isin(sd_vec, em_vec[em['y'] == 0]) & keep).sum())

    # ---- 2. split by zip ----
    zips = np.array(sorted(set(sd['zip_id'].tolist())))
    shuffled = zips[rng.permutation(len(zips))]
    n_fit = int(round(SPLIT[0] * len(zips)))
    n_judge = int(round(SPLIT[1] * len(zips)))
    split_of = {z: 'fit' for z in shuffled[:n_fit]}
    split_of.update({z: 'judge' for z in shuffled[n_fit:n_fit + n_judge]})
    split_of.update({z: 'holdout' for z in shuffled[n_fit + n_judge:]})
    split = np.array([split_of[z] for z in sd['zip_id']])
    fit_vectors = set(sd_vec[keep & (split == 'fit') & ~sd['active']].tolist())
    leak = keep & (split != 'fit') & np.array([v in fit_vectors for v in sd_vec])
    steps['judge_holdout_vector_also_in_fit_removed'] = int(leak.sum())
    keep &= ~leak

    # ---- 3. shipped detector on every SafeDocs PDF ----
    log('Scoring SafeDocs with the shipped 1.0.0 PDF detector ...')
    prob, mal, sus, card_sha = shipped_probability(sd['X'])
    baseline = dict(thresholds=dict(malicious=mal, suspicious=sus), detector_card_sha256=card_sha,
                    no_active_content=tier_counts(prob[keep & ~sd['active']], mal, sus),
                    with_active_content=tier_counts(prob[keep & sd['active']], mal, sus),
                    by_split={s: tier_counts(prob[keep & ~sd['active'] & (split == s)], mal, sus)
                              for s in ('fit', 'judge', 'holdout')})

    # ---- write the datasets ----
    files = {}
    clean = keep & ~sd['active']
    for s in ('fit', 'judge', 'holdout'):
        m = clean & (split == s)
        files[f'safedocs_{s}.npz'] = dict(rows=int(m.sum()), sha256=save_npz(
            DATA / f'safedocs_{s}.npz', X=sd['X'][m], sha256=sd['sha256'][m], name=sd['name'][m],
            zip_id=sd['zip_id'][m], bytes=sd['bytes'][m], shipped_probability=prob[m]))
    m = keep & sd['active']
    files['safedocs_active.npz'] = dict(rows=int(m.sum()), sha256=save_npz(
        DATA / 'safedocs_active.npz', X=sd['X'][m], sha256=sd['sha256'][m], name=sd['name'][m],
        zip_id=sd['zip_id'][m], bytes=sd['bytes'][m], split=split[m], indicators=sd['indicators'][m],
        indicator_columns=sd['indicator_columns'], shipped_probability=prob[m]))
    counts = {s: dict(zips=int(sum(v == s for v in split_of.values())), clean_pdfs=int((clean & (split == s)).sum()),
                      active_pdfs=int((keep & sd['active'] & (split == s)).sum())) for s in ('fit', 'judge', 'holdout')}
    write(DATA / 'manifest.json', dict(
        status='PDF_RW_DATA_READY', script_sha256=sha(__file__), safedocs_shards=n_shards,
        ember_manifest_sha256=em_manifest_sha, split_rule=f'by zip, seeded shuffle (seed {SEED}), 70/15/15',
        zips={s: sorted(z for z, v in split_of.items() if v == s) for s in ('fit', 'judge', 'holdout')},
        counts=counts, cleaning=steps, active_content_names=list(ACTIVE), files=files))
    log(f'Datasets written to {DATA}')

    # ---- 4. source audit (EMBER weeks 0-51 only) ----
    log('Source audit ...')
    early = em['week'] <= 51
    em_clean = sample(em['X'][early & (em['y'] == 0)], SAMPLE, rng)
    em_mal = sample(em['X'][early & (em['y'] == 1)], SAMPLE, rng)
    sd_fit = sample(sd['X'][clean & (split == 'fit')], SAMPLE, rng)
    varying = np.where(np.vstack([em_clean, em_mal, sd_fit]).std(0) > 0)[0]
    src = np.full(FEATURES, 0.5)
    mw = np.full(FEATURES, 0.5)
    src[varying] = column_auc(em_clean[:, varying], sd_fit[:, varying])        # high = larger in SafeDocs
    mw[varying] = column_auc(em_clean[:, varying], em_mal[:, varying])         # high = larger in malware
    sd_vs_mal = np.full(FEATURES, 0.5)
    sd_vs_mal[varying] = column_auc(sd_fit[:, varying], em_mal[:, varying])
    strong_source = np.abs(src - 0.5) >= SOURCE_AUC - 0.5
    weak_malware = np.abs(mw - 0.5) < MALWARE_BAND
    source_only = np.where(strong_source & weak_malware)[0]
    OUT.mkdir(parents=True, exist_ok=True)
    only = set(source_only.tolist())
    with open(OUT / 'features.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['index', 'feature', 'source_auc_safedocs_vs_ember_clean', 'malware_auc_ember',
                    'safedocs_clean_vs_ember_malware_auc', 'source_only'])
        for i in varying:
            w.writerow([int(i), feature_name(int(i)), round(float(src[i]), 4), round(float(mw[i]), 4),
                        round(float(sd_vs_mal[i]), 4), bool(i in only)])
    log('Small source models ...')
    keep_cols = np.setdiff1d(varying, source_only)
    models = dict(
        ember_clean_vs_safedocs=source_model(em_clean, sd_fit, varying, rng),
        ember_clean_vs_safedocs_without_source_only=source_model(em_clean, sd_fit, keep_cols, rng),
        ember_clean_vs_ember_malware=source_model(em_clean, em_mal, varying, rng),
        safedocs_vs_ember_malware=source_model(sd_fit, em_mal, varying, rng),
        safedocs_vs_ember_malware_without_source_only=source_model(sd_fit, em_mal, keep_cols, rng))
    by_group = {}
    for i in source_only:
        g = feature_name(int(i)).split('[')[0]
        by_group[g] = by_group.get(g, 0) + 1
    ranked = np.argsort(-np.abs(src - 0.5))[:25]
    report = dict(
        status='PDF_RW_AUDIT_DONE', script_sha256=sha(__file__), data_manifest_sha256=sha(DATA / 'manifest.json'),
        counts=counts, cleaning=steps, shipped_detector_on_safedocs=baseline,
        audit=dict(
            samples=dict(ember_clean_weeks_0_51=len(em_clean), ember_malware_weeks_0_51=len(em_mal),
                         safedocs_fit_clean=len(sd_fit), varying_features=int(len(varying))),
            rule=f'source-only = |AUC(SafeDocs vs EMBER clean) - 0.5| >= {SOURCE_AUC - 0.5:.2f} and '
                 f'|AUC(EMBER malware vs clean) - 0.5| < {MALWARE_BAND:.2f}; R3 tries with and without them, '
                 'chosen on the judge split',
            strong_source_features=int(strong_source[varying].sum()),
            source_only_features=int(len(source_only)), source_only_by_group=by_group,
            source_only_indices=[int(i) for i in source_only],
            most_source_revealing=[dict(feature=feature_name(int(i)), source_auc=round(float(src[i]), 4),
                                        malware_auc=round(float(mw[i]), 4)) for i in ranked],
            small_models={k: dict(holdback_auc=round(a, 5), top_features=t) for k, (a, t) in models.items()}),
        note='EMBER test weeks 52-63 were not used. SafeDocs PDFs are assumed clean (web PDFs, not sanitised); '
             'PDFs with active content are kept apart and never labelled clean.')
    write(OUT / 'report.json', report)

    # ---- summary ----
    b = baseline['no_active_content']
    print('\n=== Step R2 summary ===')
    print(f'Clean SafeDocs PDFs: fit {counts["fit"]["clean_pdfs"]:,} / judge {counts["judge"]["clean_pdfs"]:,} / '
          f'holdout {counts["holdout"]["clean_pdfs"]:,}   (zips {counts["fit"]["zips"]}/{counts["judge"]["zips"]}/'
          f'{counts["holdout"]["zips"]}); active content kept apart: {files["safedocs_active.npz"]["rows"]:,}')
    print('Removed: ' + ', '.join(f'{k} {v:,}' for k, v in steps.items() if k.endswith('removed')))
    print(f'Shipped 1.0.0 detector on clean real-world PDFs: MALICIOUS {100 * b["malicious_rate"]:.2f}%  '
          f'flagged (malicious + suspicious) {100 * b["flagged_rate"]:.2f}%  of {b["files"]:,}')
    print(f'Source audit: {report["audit"]["strong_source_features"]} strongly source-revealing features, '
          f'{len(source_only)} source-only {by_group}')
    for k, (a, _) in models.items():
        print(f'  small model {k:<48} AUC {a:.4f}')
    print(f'\nPDF_RW_AUDIT_DONE  report: {OUT / "report.json"}')


if __name__ == '__main__':
    main()
