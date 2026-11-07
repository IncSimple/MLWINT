"""CPU High-RAM runtime. Win32 Phase 1: the 4-way comparison on the FULL development set.

Candidates (all frozen; nothing is retrained here):
  A  XGBoost extended (5,529 rounds)          B  LightGBM extended (6,011 rounds)
  C  0.5 XGBoost + 0.5 SVM (calibrated)        D  0.5 LightGBM + 0.5 SVM (calibrated)
  references: SVM alone, old XGBoost (2,000), old LightGBM (2,000)
Order (enforced in code):
  1. score a 120k training sample and the 359,990 development files (weeks 40-51)
  2. re-check separation: development vs training vs test (SHA-256 and feature-vector hashes)
  3. on development only: Platt calibration per model, threshold at <=1% false alarms,
     ranking (recall, then AP) -> primary, challenger, 50/50 ensemble. Frozen in roles.json.
  4. only then score the 359,991 test files (weeks 52-63) once, with everything frozen
Outputs: test table, per-week recall / false-alarm table, train / dev / test gap table,
paired error counts, two graphs (PNG + PDF), CSVs. Scores are cached per shard on Drive;
re-running resumes.
"""
import csv, hashlib, json, os, shutil, time
from pathlib import Path

import numpy as np

ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
DATA = ROOT / 'inputs/win32-fourway-v1'
DEV = ROOT / 'inputs/win32-dev-full-v1'
EXP = ROOT / 'experiments/win32-fourway-v1'
AUDIT = EXP / 'leakage-audit-v1/report.json'
JOBS = dict(xgb=(EXP / 'xgboost-extended-v1', 'WIN32_XGB_EXTENDED'),
            lgbm=(EXP / 'lightgbm-extended-v1', 'WIN32_LGBM_EXTENDED'),
            svm=(EXP / 'svm-raw-v2', 'WIN32_SVM_TRAINED'))
OUT = EXP / 'four-way-full-dev-v1'
WORK = Path('/content/MLWINT-work/win32-fourway')
TRAIN_SAMPLE, SEED, FPR = 0.1, 42, 0.01
MODELS = ('xgb', 'lgbm', 'svm', 'xgb_old', 'lgbm_old')
NAMES = {'A': 'A XGBoost', 'B': 'B LightGBM', 'C': 'C XGBoost + SVM', 'D': 'D LightGBM + SVM',
         'SVM': 'SVM alone (reference)', 'XGB_OLD': 'Old XGBoost 2,000 (reference)',
         'LGBM_OLD': 'Old LightGBM 2,000 (reference)'}
MIX = {'A': {'xgb': 1.0}, 'B': {'lgbm': 1.0}, 'C': {'xgb': .5, 'svm': .5}, 'D': {'lgbm': .5, 'svm': .5},
       'SVM': {'svm': 1.0}, 'XGB_OLD': {'xgb_old': 1.0}, 'LGBM_OLD': {'lgbm_old': 1.0}}


# ------------------------------------------------------------------ helpers
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


def copy_checked(src, dst, checksum):
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and sha(dst) == checksum:
        return dst
    tmp = dst.with_name(dst.name + '.pending')
    shutil.copyfile(src, tmp)
    if sha(tmp) != checksum:
        raise ValueError(f'Copy checksum failed: {src}')
    tmp.replace(dst)
    return dst


def frozen(path, value):
    if path.exists() and read(path) != value:
        raise ValueError(f'Frozen protocol changed: {path}')
    write(path, value)


def expit(x):
    from scipy.special import expit as f
    return f(x)


def threshold(score, y):
    benign = np.sort(score[y == 0])[::-1]
    allowed = int(np.floor(FPR * len(benign)))
    value = float(np.nextafter(benign[allowed], np.inf))
    return dict(threshold=value, benign_rows=len(benign), allowed_false_positives=allowed,
                actual_fpr=float(np.mean(benign >= value)))


def calibrate(margin, y):          # same Platt method as the APK comparison
    from sklearn.linear_model import LogisticRegression
    mean, scale = float(margin.mean()), float(margin.std())
    if scale <= 0:
        raise ValueError('Constant calibration scores')
    fit = LogisticRegression(C=1e6, solver='lbfgs', max_iter=2000, tol=1e-10)
    fit.fit(((margin - mean) / scale)[:, None], y)
    if fit.n_iter_[0] >= 2000 or fit.coef_[0, 0] <= 0:
        raise ValueError('Calibration did not converge with increasing scores')
    slope = float(fit.coef_[0, 0] / scale)
    return dict(slope=slope, intercept=float(fit.intercept_[0] - slope * mean))


def metrics(name, y, score, prob, cut):
    from sklearn.metrics import average_precision_score, roc_auc_score, log_loss, brier_score_loss
    pred = score >= cut
    tp, fn = int((pred & (y == 1)).sum()), int((~pred & (y == 1)).sum())
    fp, tn = int((pred & (y == 0)).sum()), int((~pred & (y == 0)).sum())
    p = np.clip(prob, 1e-15, 1 - 1e-15)
    return dict(model=name, rows=int(len(y)), recall=tp / (tp + fn), false_alarm_rate=fp / (fp + tn),
                fp=fp, fn=fn, tp=tp, tn=tn, average_precision=float(average_precision_score(y, score)),
                roc_auc=float(roc_auc_score(y, score)), log_loss=float(log_loss(y, p, labels=[0, 1])),
                brier=float(brier_score_loss(y, prob)), threshold=cut), pred


# ------------------------------------------------------------------ scoring
class Scorer:
    def __init__(self, models, svm):
        import lightgbm as lgb, xgboost as xgb
        self.threads = os.cpu_count() or 2
        self.models = models
        for k in ('xgb', 'xgb_old'):
            models[k].set_param({'nthread': self.threads})
        self.svm = svm

    def svm_margin(self, X):
        s = self.svm
        Z = np.sign(X) * np.log1p(np.abs(X))
        Z[~np.isfinite(Z)] = 0
        Z -= s['mean']; Z *= s['inverse_std']
        np.clip(Z, -s['clip'], s['clip'], out=Z)
        return Z @ s['coefficient'].astype(np.float32) + s['intercept']

    def __call__(self, X):
        out = {}
        for k in ('xgb', 'xgb_old'):
            out[k] = np.asarray(self.models[k].inplace_predict(X, predict_type='margin'), np.float64)
        for k in ('lgbm', 'lgbm_old'):
            out[k] = self.models[k].predict(X, raw_score=True, num_threads=self.threads).astype(np.float64)
        out['svm'] = self.svm_margin(X).astype(np.float64)
        return out


def score_split(split, shards, scorer, pick=None):
    """shards: list of (name, local_path). Cached per shard under OUT/scores/<split>/."""
    folder = OUT / 'scores' / split
    folder.mkdir(parents=True, exist_ok=True)
    started = time.time()
    for number, (name, path) in enumerate(shards, 1):
        target = folder / (Path(name).stem + '.npz')
        if target.exists():
            continue
        with np.load(path()) as z:
            keep = pick(name, z) if pick else np.ones(len(z['y']), bool)
            X = np.ascontiguousarray(z['X'][keep])
            info = dict(y=z['y'][keep].astype(np.int8), week=z['week'][keep], sha256=z['sha256'][keep],
                        feature_hash=z['feature_hash'][keep], part=z['part'][keep])
        margins = scorer(X)
        tmp = target.with_name(target.stem + '.pending.npz')
        np.savez(tmp, **info, **margins)
        tmp.replace(target)
        print(f'  [{split}] shard {number}/{len(shards)} ({len(X):,} rows); {(time.time() - started) / 60:.1f} min',
              flush=True)
    parts = [np.load(folder / (Path(n).stem + '.npz')) for n, _ in shards]
    return {k: np.concatenate([p[k] for p in parts]) for k in parts[0].files}


# ------------------------------------------------------------------ graphs
def plot_main(rows, curves, y, weekly, path, title):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, precision_recall_curve
    colors = {'A': '#1967d2', 'B': '#e8710a', 'C': '#188038', 'D': '#a142f4', 'ENS': '#d93025',
              'SVM': '#9aa0a6', 'XGB_OLD': '#8ab4f8', 'LGBM_OLD': '#fcc934'}
    fig, ax = plt.subplots(2, 3, figsize=(21, 11), constrained_layout=True)
    low = 100.0
    for key, label, score in curves:
        ref = key in ('SVM', 'XGB_OLD', 'LGBM_OLD')
        st = dict(color=colors[key], ls='--' if ref else '-', lw=1.2 if ref else 1.8)
        fpr, tpr, _ = roc_curve(y, score)
        ax[0, 0].plot(100 * fpr, 100 * tpr, label=label, **st)
        prec, rec, _ = precision_recall_curve(y, score)
        ax[0, 1].plot(100 * rec, 100 * prec, label=label, **st)
        if not ref:
            low = min(low, 100 * np.interp(0.001, fpr, tpr))
    lo = max(0, np.floor(low / 2) * 2 - 2)
    ax[0, 0].axvline(100 * FPR, color='gray', ls=':', lw=1, label='1% false-alarm target')
    ax[0, 0].set(xlim=(0, 3), ylim=(lo, 100), xlabel='False-alarm rate (%)', ylabel='Malware caught (%)',
                 title='ROC (zoomed to 0-3% false alarms)')
    ax[0, 1].set(xlim=(lo, 100), ylim=(lo, 100), xlabel='Recall (%)', ylabel='Precision (%)',
                 title='Precision-recall (zoomed)')
    x, w = np.arange(len(rows)), 0.38
    labels = [r['short'] for r in rows]
    b1 = ax[0, 2].bar(x - w / 2, [r['fp'] for r in rows], w, label='False alarms', color='#9aa0a6')
    b2 = ax[0, 2].bar(x + w / 2, [r['fn'] for r in rows], w, label='Missed malware', color='#d93025')
    ax[0, 2].bar_label(b1, fontsize=7); ax[0, 2].bar_label(b2, fontsize=7)
    ax[0, 2].set(title='Test errors at the development-chosen threshold'); ax[0, 2].legend()
    b3 = ax[1, 0].bar(x, [100 * r['recall'] for r in rows], color=[colors[r['key']] for r in rows])
    ax[1, 0].bar_label(b3, labels=[f'{100*r["recall"]:.2f}%\nFPR {100*r["false_alarm_rate"]:.2f}%' for r in rows],
                       fontsize=7)
    ax[1, 0].set(ylim=(max(0, np.floor(100 * min(r['recall'] for r in rows) / 5) * 5 - 5), 101),
                 ylabel='Malware caught (%)', title='Test recall at the frozen ~1% threshold')
    for a in (ax[0, 2], ax[1, 0]):
        a.set_xticks(x, labels, rotation=20, ha='right', fontsize=8)
    weeks = sorted(weekly)
    for key, label, _ in curves:
        st = dict(color=colors[key], ls='--' if key in ('SVM', 'XGB_OLD', 'LGBM_OLD') else '-', marker='o', ms=3)
        ax[1, 1].plot(weeks, [100 * weekly[wk][key]['recall'] for wk in weeks], label=label, **st)
        ax[1, 2].plot(weeks, [100 * weekly[wk][key]['false_alarm_rate'] for wk in weeks], label=label, **st)
    ax[1, 2].axhline(100 * FPR, color='gray', ls=':', lw=1)
    ax[1, 1].set(xlabel='Test week', ylabel='Malware caught (%)', title='Recall week by week (test)')
    ax[1, 2].set(xlabel='Test week', ylabel='False alarms (%)', title='False-alarm rate week by week (test)')
    for a in ax.flat:
        a.grid(alpha=.2); a.set_axisbelow(True)
    ax[0, 0].legend(loc='lower right', fontsize=7); ax[0, 1].legend(loc='lower left', fontsize=7)
    ax[1, 1].legend(fontsize=7)
    fig.suptitle(title)
    for ext in ('png', 'pdf'):
        fig.savefig(f'{path}.{ext}', dpi=170)
    plt.close(fig)


def plot_gap(gap, path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    models = list(dict.fromkeys(g['model'] for g in gap))
    splits = ['training sample', 'development', 'test']
    fig, ax = plt.subplots(1, 2, figsize=(16, 5.5), constrained_layout=True)
    x, w = np.arange(len(models)), 0.26
    for i, s in enumerate(splits):
        rows = [next(g for g in gap if g['model'] == m and g['split'] == s) for m in models]
        b = ax[0].bar(x + (i - 1) * w, [r['log_loss'] for r in rows], w, label=s)
        ax[0].bar_label(b, fmt='%.3f', fontsize=6)
        b = ax[1].bar(x + (i - 1) * w, [100 * (1 - r['average_precision']) for r in rows], w, label=s)
        ax[1].bar_label(b, fmt='%.2f', fontsize=6)
    ax[0].set(title='Log loss (lower is better)', ylabel='Log loss')
    ax[1].set(title='Ranking error = 100 x (1 - AP) (lower is better)', ylabel='Ranking error')
    for a in ax:
        a.set_xticks(x, models, rotation=15, ha='right', fontsize=8); a.legend(); a.grid(alpha=.2)
    fig.suptitle('Win32 overfitting check: training rows vs development (weeks 40-51) vs test (weeks 52-63)')
    for ext in ('png', 'pdf'):
        fig.savefig(f'{path}.{ext}', dpi=170)
    plt.close(fig)


# ------------------------------------------------------------------ main
def main():
    import lightgbm as lgb, scipy, sklearn, xgboost as xgb
    from sklearn.metrics import average_precision_score
    if lgb.__version__ != '4.7.0' or xgb.__version__ != '3.4.1':
        raise RuntimeError('Install lightgbm==4.7.0 and xgboost==3.4.1 (the training versions)')
    if read(AUDIT)['status'] != 'WIN32_SEPARATION_PASSED':
        raise ValueError('Leakage audit has not passed')
    manifest, dev_manifest = read(DATA / 'manifest.json'), read(DEV / 'manifest.json')
    if dev_manifest['status'] != 'WIN32_FULL_DEV_READY':
        raise ValueError('Full development export is not ready')
    reports = {}
    for k, (job, status) in JOBS.items():
        r = read(job / 'report.json')
        if r['status'] != status or sha(job / r['model_file']) != r['model_sha256']:
            raise ValueError(f'{job.name}: not finished or model checksum failed')
        reports[k] = r
    for name in ('xgboost.ubj', 'lightgbm.txt'):
        if sha(DATA / 'models' / name) != manifest['models'][name]:
            raise ValueError(f'Old model checksum failed: {name}')
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    protocol = dict(version='win32-four-way-full-dev-v1', script_sha256=sha(__file__),
        manifest_sha256=sha(DATA / 'manifest.json'), dev_manifest_sha256=sha(DEV / 'manifest.json'),
        audit_sha256=sha(AUDIT), models={k: reports[k]['model_sha256'] for k in reports},
        old_models={k: manifest['models'][k] for k in ('xgboost.ubj', 'lightgbm.txt')},
        lightgbm=lgb.__version__, xgboost=xgb.__version__, sklearn=sklearn.__version__, scipy=scipy.__version__,
        numpy=np.__version__, candidates={k: NAMES[k] for k in 'ABCD'}, false_alarm_limit=FPR,
        training_sample=dict(fraction=TRAIN_SAMPLE, seed=SEED),
        calibration='Platt (logistic) per model on all development files (weeks 40-51)',
        ranking='Development recall at the <=1% development false-alarm threshold, then development AP',
        final_pipeline='Primary + challenger calibrated probabilities averaged 50/50; threshold on development',
        test_policy='Test files (weeks 52-63) scored only after calibration, thresholds and roles are frozen')
    frozen(OUT / 'protocol.json', protocol)
    if (OUT / 'report.json').exists():
        report = read(OUT / 'report.json')
        for n, c in report['artifacts'].items():
            if sha(OUT / n) != c:
                raise ValueError(f'Saved artifact checksum failed: {n}')
        print('Completed comparison verified:\n' + json.dumps({k: report[k] for k in
              ('status', 'primary', 'challenger', 'ensemble_effective_weights')}, indent=2))
        return

    models = dict(xgb=xgb.Booster(model_file=str(JOBS['xgb'][0] / reports['xgb']['model_file'])),
                  xgb_old=xgb.Booster(model_file=str(DATA / 'models/xgboost.ubj')),
                  lgbm=lgb.Booster(model_file=str(JOBS['lgbm'][0] / reports['lgbm']['model_file'])),
                  lgbm_old=lgb.Booster(model_file=str(DATA / 'models/lightgbm.txt')))
    with np.load(JOBS['svm'][0] / reports['svm']['model_file']) as z:
        svm = dict(coefficient=z['coefficient'], intercept=float(z['intercept'][0]), mean=z['mean'],
                   inverse_std=z['inverse_std'], clip=float(z['clip'][0]))
        if str(z['transform'][0]) != 'signed_log1p':
            raise ValueError('Unexpected SVM preprocessing')
    scorer = Scorer(models, svm)

    def local(src_root, name, checksum):
        def get():
            return copy_checked(src_root / name, WORK / src_root.name / name, checksum)
        return get

    def shard_list(src_root, man, prefix):
        return [(n, local(src_root, n, f['sha256'])) for n, f in sorted(man['files'].items())
                if n.startswith(prefix) and n.endswith('.npz')]

    def sample(name, z):
        rng = np.random.default_rng([SEED, int(Path(name).stem.split('-')[-1])])
        return rng.random(len(z['y'])) < TRAIN_SAMPLE

    # ---- 1. training sample + development ----
    print('Scoring a 10% training sample (for the overfitting gap) ...', flush=True)
    tr = score_split('train_sample', shard_list(DATA, manifest, 'train/'), scorer, sample)
    print('Scoring the full development set (weeks 40-51) ...', flush=True)
    dv = score_split('dev', shard_list(DEV, dev_manifest, 'dev/'), scorer)
    if len(dv['y']) != dev_manifest['counts']['dev_rows']:
        raise ValueError('Development row count mismatch')

    # ---- 2. separation re-check (hashes only; test labels not used) ----
    print('Re-checking separation between training, development and test ...', flush=True)
    as_void = lambda a: np.ascontiguousarray(a).view('V32').ravel()
    train_sha, train_vec, test_sha, test_vec = [], [], [], []
    for n, f in sorted(manifest['files'].items()):
        if n.endswith('.npz') and (n.startswith('train/') or n.startswith('test/')):
            with np.load(DATA / n) as z:
                (train_sha if n.startswith('train/') else test_sha).append(as_void(z['sha256']))
                (train_vec if n.startswith('train/') else test_vec).append(as_void(z['feature_hash']))
    train_sha, train_vec = np.concatenate(train_sha), np.concatenate(train_vec)
    test_sha, test_vec = np.concatenate(test_sha), np.concatenate(test_vec)
    dsha, dvec = as_void(dv['sha256']), as_void(dv['feature_hash'])
    separation = dict(dev_train_sha=int(np.isin(dsha, train_sha).sum()), dev_train_vector=int(np.isin(dvec, train_vec).sum()),
                      dev_test_sha=int(np.isin(dsha, test_sha).sum()), dev_test_vector=int(np.isin(dvec, test_vec).sum()),
                      dev_duplicate_sha=int(len(dsha) - len(np.unique(dsha))),
                      dev_weeks=[int(dv['week'].min()), int(dv['week'].max())])
    if any(separation[k] for k in ('dev_train_sha', 'dev_train_vector', 'dev_test_sha', 'dev_test_vector',
                                   'dev_duplicate_sha')) or separation['dev_weeks'] != [40, 51]:
        raise ValueError(f'Separation check failed: {separation}')
    print('  separation OK:', separation, flush=True)
    del train_sha, train_vec

    # ---- 3. calibration, thresholds, roles: development only ----
    dy = dv['y'].astype(int)
    if (OUT / 'roles.json').exists():
        roles = read(OUT / 'roles.json')
    else:
        cal = {m: calibrate(dv[m], dy) for m in MODELS}
        P = lambda split, m: expit(cal[m]['slope'] * split[m] + cal[m]['intercept'])
        dp = {m: P(dv, m) for m in MODELS}
        blend = lambda probs, w: sum(v * probs[k] for k, v in w.items())
        cuts = {key: threshold(blend(dp, w), dy) for key, w in MIX.items()}
        ranking = []
        for key in 'ABCD':
            s = blend(dp, MIX[key])
            ranking.append(dict(key=key, candidate=NAMES[key],
                development_recall=float(np.mean(s[dy == 1] >= cuts[key]['threshold'])),
                development_false_alarm_rate=float(np.mean(s[dy == 0] >= cuts[key]['threshold'])),
                development_ap=float(average_precision_score(dy, s))))
        ranking.sort(key=lambda r: (r['development_recall'], r['development_ap']), reverse=True)
        primary, challenger = ranking[0]['key'], ranking[1]['key']
        weights = {}
        for key in (primary, challenger):
            for m, v in MIX[key].items():
                weights[m] = weights.get(m, 0) + 0.5 * v
        cuts['ENS'] = threshold(blend(dp, weights), dy)
        roles = dict(primary=primary, challenger=challenger, primary_name=NAMES[primary],
                     challenger_name=NAMES[challenger], ensemble_effective_weights=weights,
                     calibration=cal, thresholds=cuts, ranking=ranking, separation=separation,
                     development_rows=int(len(dy)),
                     rule='Chosen on development files (weeks 40-51) before any test scoring')
        frozen(OUT / 'roles.json', roles)
    print('Roles frozen from development files:', json.dumps({k: roles[k] for k in
          ('primary_name', 'challenger_name', 'ensemble_effective_weights')}), flush=True)

    # ---- 4. test, scored once with everything frozen ----
    print('Scoring the test files (weeks 52-63) ...', flush=True)
    te = score_split('test', shard_list(DATA, manifest, 'test/'), scorer)
    if len(te['y']) != manifest['counts']['test_rows']:
        raise ValueError('Test row count mismatch')
    cal, cuts, weights = roles['calibration'], roles['thresholds'], roles['ensemble_effective_weights']
    mix = dict(MIX, ENS=weights)
    names = dict(NAMES, ENS=f'Final ensemble ({roles["primary_name"]} + {roles["challenger_name"]})')
    shorts = dict(A='A XGBoost', B='B LightGBM', C='C XGB+SVM', D='D LGBM+SVM', SVM='SVM alone',
                  XGB_OLD='Old XGB 2000', LGBM_OLD='Old LGBM 2000', ENS='Final ensemble')
    prob = lambda split, key: sum(v * expit(cal[m]['slope'] * split[m] + cal[m]['intercept'])
                                  for m, v in mix[key].items())
    order = ['A', 'B', 'C', 'D', 'ENS', 'SVM', 'XGB_OLD', 'LGBM_OLD']
    ty = te['y'].astype(int)
    rows, preds, tprob = [], {}, {}
    for key in order:
        tprob[key] = prob(te, key)
        r, preds[key] = metrics(names[key], ty, tprob[key], tprob[key], cuts[key]['threshold'])
        r.update(key=key, short=shorts[key], development_false_alarm_rate=cuts[key]['actual_fpr'])
        rows.append(r)
    weekly = {}
    for wk in sorted(np.unique(te['week']).tolist()):
        m = te['week'] == wk
        weekly[int(wk)] = {k: dict(recall=float(np.mean(preds[k][m & (ty == 1)])),
                                   false_alarm_rate=float(np.mean(preds[k][m & (ty == 0)])),
                                   files=int(m.sum())) for k in order}
    gap = []
    for key in ('A', 'B', 'C', 'D', 'ENS', 'SVM'):
        for split, data in (('training sample', tr), ('development', dv), ('test', te)):
            y = data['y'].astype(int)
            p = prob(data, key)
            r, _ = metrics(names[key], y, p, p, cuts[key]['threshold'])
            gap.append(dict(model=shorts[key], split=split, rows=r['rows'], log_loss=r['log_loss'],
                            average_precision=r['average_precision'], roc_auc=r['roc_auc'],
                            recall=r['recall'], false_alarm_rate=r['false_alarm_rate']))
    wrong = {k: v != ty for k, v in preds.items()}
    shared = wrong['A'] & wrong['B']
    paired = dict(files_wrong_for_both_A_and_B=int(shared.sum()),
                  of_those_svm_alone_right=int((shared & ~wrong['SVM']).sum()),
                  of_those_ensemble_right=int((shared & ~wrong['ENS']).sum()),
                  B_vs_A=dict(fixes=int((wrong['A'] & ~wrong['B']).sum()), adds=int((~wrong['A'] & wrong['B']).sum())),
                  ENS_vs_primary=dict(fixes=int((wrong[roles['primary']] & ~wrong['ENS']).sum()),
                                      adds=int((~wrong[roles['primary']] & wrong['ENS']).sum())),
                  C_vs_A=dict(fixes=int((wrong['A'] & ~wrong['C']).sum()), adds=int((~wrong['A'] & wrong['C']).sum())),
                  D_vs_B=dict(fixes=int((wrong['B'] & ~wrong['D']).sum()), adds=int((~wrong['B'] & wrong['D']).sum())),
                  new_vs_old_xgb=dict(fixes=int((wrong['XGB_OLD'] & ~wrong['A']).sum()),
                                      adds=int((~wrong['XGB_OLD'] & wrong['A']).sum())),
                  new_vs_old_lgbm=dict(fixes=int((wrong['LGBM_OLD'] & ~wrong['B']).sum()),
                                       adds=int((~wrong['LGBM_OLD'] & wrong['B']).sum())))

    def save_csv(name, records):
        with open(OUT / name, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(records[0])); w.writeheader(); w.writerows(records)
    save_csv('test_comparison.csv', [{k: v for k, v in r.items() if k != 'short'} for r in rows])
    save_csv('development_ranking.csv', roles['ranking'])
    save_csv('test_weekly.csv', [dict(week=wk, model=shorts[k], **v) for wk, d in weekly.items() for k, v in d.items()])
    save_csv('overfitting_gap.csv', gap)
    local_pred = WORK / 'test_predictions.npz'
    np.savez_compressed(local_pred, sha256=te['sha256'], week=te['week'], y=te['y'],
                        **{f'{k}_probability': tprob[k] for k in order})
    copy_checked(local_pred, OUT / 'test_predictions.npz', sha(local_pred))
    main_keys = ['A', 'B', 'C', 'D', 'ENS']
    plot_main([r for r in rows if r['key'] in main_keys + ['XGB_OLD', 'LGBM_OLD']],
              [(k, names[k], tprob[k]) for k in main_keys + ['SVM', 'XGB_OLD', 'LGBM_OLD']], ty,
              weekly, OUT / 'win32_four_way',
              f'Win32 specialist (EMBER2024): 4-way comparison on {len(ty):,} test files (weeks 52-63)\n'
              f'Calibration, thresholds and roles chosen on {len(dy):,} development files (weeks 40-51) only')
    plot_gap(gap, OUT / 'win32_overfitting_gap')
    files = ['protocol.json', 'roles.json', 'test_comparison.csv', 'development_ranking.csv', 'test_weekly.csv',
             'overfitting_gap.csv', 'test_predictions.npz', 'win32_four_way.png', 'win32_four_way.pdf',
             'win32_overfitting_gap.png', 'win32_overfitting_gap.pdf']
    brief = lambda r: {k: r[k] for k in ('model', 'recall', 'false_alarm_rate', 'fp', 'fn', 'average_precision',
                                         'roc_auc', 'log_loss', 'development_false_alarm_rate')}
    report = dict(status='WIN32_FOUR_WAY_COMPLETE', primary=roles['primary_name'], challenger=roles['challenger_name'],
        ensemble_effective_weights=weights, development_rows=int(len(dy)), test_rows=int(len(ty)),
        development_ranking=roles['ranking'], test=[brief(r) for r in rows],
        worst_test_week={k: min(weekly, key=lambda wk: weekly[wk][k]['recall']) for k in main_keys},
        weekly_recall_range={shorts[k]: [min(weekly[w][k]['recall'] for w in weekly),
                                         max(weekly[w][k]['recall'] for w in weekly)] for k in main_keys},
        overfitting_gap=gap, paired_errors=paired, separation=roles['separation'],
        scope='Temporal: train weeks 0-39, development 40-51, test 52-63; exact SHA/vector separation; '
              'family/near-duplicate separation not established; test previously viewed on 2026-10-29 for the '
              'old models (benchmark, not a fresh test)',
        artifacts={n: sha(OUT / n) for n in files})
    write(OUT / 'report.json', report)
    print(json.dumps({k: report[k] for k in ('status', 'primary', 'challenger', 'ensemble_effective_weights',
                                              'development_ranking', 'test', 'weekly_recall_range',
                                              'paired_errors')}, indent=2))


if __name__ == '__main__':
    main()
