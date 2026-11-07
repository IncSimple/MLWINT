"""Retrain one format on ALL labelled weeks before the test (0-51).  Usage:  !python retrain_format.py pdf
Runs on a T4 runtime (XGBoost on the GPU) or any CPU runtime.

Procedure, fixed before running (nothing below is chosen by looking at the test):
  1. select  : fit on weeks 0-47, judge on the newest weeks 48-51 (unseen by the fit)
               - XGBoost / LightGBM: rounds by the same plateau rule (100 rounds without a 1e-5 drop)
               - SVM: alpha and epochs by average precision on weeks 48-51 (patience 3)
               Same parameters as every earlier model.
  2. final   : the chosen settings retrained on all weeks 0-51
  3. roles   : Platt calibration, <=1% false-alarm thresholds and the primary / challenger / ensemble
               ranking from the weeks 0-47 models' scores on weeks 48-51 (the final models have seen
               those weeks, so their own scores there would be too optimistic). Frozen in roles.json.
  4. test    : weeks 52-63 scored once with everything frozen. Compared with the frozen weeks 0-39
               pipeline (four-way-v1) file by file.
The test was opened once before (four-way-v1); the decision to retrain was made after seeing that
drift. Every setting here is fixed in advance, so this is a fair second look (a benchmark), and the
report says so. Checkpoints after each stage; re-running resumes.
"""
import csv, gc, hashlib, json, os, shutil, sys, time
from pathlib import Path

import numpy as np

FMT = sys.argv[1].lower() if len(sys.argv) > 1 else ''
if FMT not in ('pdf', 'elf', 'dotnet', 'win64'):
    raise SystemExit('Usage: python retrain_format.py pdf|elf|dotnet')
TAG = FMT.upper()
ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
DATA = ROOT / f'inputs/{FMT}-v1'
EXP = ROOT / f'experiments/{FMT}-fourway-v1'
OLD = EXP / 'four-way-v1'
OUT = EXP / 'retrain-0-51-v1'
WORK = Path(f'/content/MLWINT-work/{FMT}-retrain')
FEATURES, SEED, FPR = 2568, 42, 0.01
FIT_LAST, STOP_FIRST, STOP_LAST = 47, 48, 51
LIMIT, PATIENCE, GAIN = 10000, 100, 1e-5
ALPHAS = (1e-9, 1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2)
SVM_EPOCHS, SVM_PATIENCE, SVM_GAIN, BATCH, CLIP = 30, 3, 1e-4, 50000, 10.0
XGB_PARAMS = dict(objective='binary:logistic', eval_metric='logloss', tree_method='hist', grow_policy='depthwise',
                  eta=0.05, max_depth=6, min_child_weight=1, reg_lambda=1.0, reg_alpha=0.0, gamma=0.0,
                  colsample_bytree=0.8, subsample=1.0, max_bin=256, max_cached_hist_node=64, seed=42,
                  validate_parameters=True, verbosity=1)
LGB_PARAMS = dict(objective='binary', metric='binary_logloss', learning_rate=0.05, num_leaves=31, max_depth=-1,
                  min_data_in_leaf=20, lambda_l1=0.0, lambda_l2=0.0, feature_fraction=0.8, bagging_fraction=1.0,
                  bagging_freq=0, max_bin=255, bin_construct_sample_cnt=200000, histogram_pool_size=512, seed=42,
                  force_col_wise=True, verbosity=-1)
DEVICE = 'cuda' if shutil.which('nvidia-smi') else 'cpu'
NAMES = {'A': 'A XGBoost', 'B': 'B LightGBM', 'C': 'C XGBoost + SVM', 'D': 'D LightGBM + SVM'}
MIX = {'A': {'xgb': 1.0}, 'B': {'lgbm': 1.0}, 'C': {'xgb': .5, 'svm': .5}, 'D': {'lgbm': .5, 'svm': .5}}


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


def save(local, name):
    """Copy a finished local file to Drive (checked) and return its checksum."""
    checksum = sha(local)
    copy_checked(local, OUT / name, checksum)
    return checksum


def load(files):
    parts = []
    for f in files:
        with np.load(f) as z:
            parts.append({k: z[k] for k in ('X', 'y', 'week', 'sha256')})
    return {k: np.concatenate([p[k] for p in parts]) for k in parts[0]}


def expit(x):
    from scipy.special import expit as f
    return f(x)


def calibrate(margin, y):
    from sklearn.linear_model import LogisticRegression
    mean, scale = float(margin.mean()), float(margin.std())
    fit = LogisticRegression(C=1e6, solver='lbfgs', max_iter=2000, tol=1e-10)
    fit.fit(((margin - mean) / scale)[:, None], y)
    if fit.n_iter_[0] >= 2000 or fit.coef_[0, 0] <= 0:
        raise ValueError('Calibration did not converge with increasing scores')
    slope = float(fit.coef_[0, 0] / scale)
    return dict(slope=slope, intercept=float(fit.intercept_[0] - slope * mean))


def threshold(score, y):
    benign = np.sort(score[y == 0])[::-1]
    allowed = int(np.floor(FPR * len(benign)))
    value = float(np.nextafter(benign[allowed], np.inf))
    return dict(threshold=value, benign_rows=len(benign), allowed_false_positives=allowed,
                actual_fpr=float(np.mean(benign >= value)))


def metrics(name, y, prob, cut):
    from sklearn.metrics import average_precision_score, roc_auc_score, log_loss
    pred = prob >= cut
    tp, fn = int((pred & (y == 1)).sum()), int((~pred & (y == 1)).sum())
    fp, tn = int((pred & (y == 0)).sum()), int((~pred & (y == 0)).sum())
    return dict(model=name, recall=tp / (tp + fn), false_alarm_rate=fp / (fp + tn), fp=fp, fn=fn,
                average_precision=float(average_precision_score(y, prob)), roc_auc=float(roc_auc_score(y, prob)),
                log_loss=float(log_loss(y, np.clip(prob, 1e-15, 1 - 1e-15), labels=[0, 1]))), pred


class Plateau:
    def __init__(self):
        self.best, self.best_round, self.anchor, self.waiting, self.history = 1e308, 0, 1e308, 0, []

    def track(self, rnd, fit, stop):
        self.history.append(dict(round=rnd, fit_logloss=fit, stop_logloss=stop))
        if stop < self.best:
            self.best, self.best_round = stop, rnd
        if self.anchor - self.best >= GAIN:
            self.anchor, self.waiting = self.best, 0
        else:
            self.waiting += 1
        return self.waiting >= PATIENCE


# ------------------------------------------------------------------ models
def xgb_select(xgb, Xf, yf, Xs, ys):
    params = dict(XGB_PARAMS, device=DEVICE)
    dfit = xgb.QuantileDMatrix(Xf, yf, max_bin=params['max_bin'])
    dstop = xgb.QuantileDMatrix(Xs, ys, ref=dfit)
    booster, plateau, t0 = xgb.Booster(params, [dfit, dstop]), Plateau(), time.time()
    for i in range(LIMIT):
        booster.update(dfit, i)
        text = booster.eval_set([(dfit, 'fit'), (dstop, 'stop')], i + 1)
        v = {p.split(':')[0].replace('-logloss', ''): float(p.split(':')[1]) for p in text.split()[1:]}
        done = plateau.track(i + 1, v['fit'], v['stop'])
        if (i + 1) % 100 == 0 or done:
            print(f'  [xgboost select] round {i + 1}; fit={v["fit"]:.5f} stop={v["stop"]:.5f} '
                  f'best={plateau.best:.5f}@{plateau.best_round}; {(time.time() - t0) / 60:.1f} min', flush=True)
        if done:
            break
    booster.set_param({'device': DEVICE})
    margin = booster.inplace_predict(Xs, iteration_range=(0, plateau.best_round), predict_type='margin')
    return booster, plateau, np.asarray(margin, np.float64)


def xgb_final(xgb, X, y, rounds):
    params = dict(XGB_PARAMS, device=DEVICE)
    d = xgb.QuantileDMatrix(X, y, max_bin=params['max_bin'])
    return xgb.train(params, d, num_boost_round=rounds)


def lgb_select(lgb, Xf, yf, Xs, ys):
    params = dict(LGB_PARAMS, num_threads=os.cpu_count() or 2)
    dfit = lgb.Dataset(Xf, yf, params=params, free_raw_data=False)
    dstop = lgb.Dataset(Xs, ys, params=params, reference=dfit, free_raw_data=False)
    plateau, t0 = Plateau(), time.time()

    def callback(env):
        v = {r[0]: float(r[2]) for r in env.evaluation_result_list}
        n = env.iteration + 1
        done = plateau.track(n, v['fit'], v['stop'])
        if n % 100 == 0 or done:
            print(f'  [lightgbm select] round {n}; fit={v["fit"]:.5f} stop={v["stop"]:.5f} '
                  f'best={plateau.best:.5f}@{plateau.best_round}; {(time.time() - t0) / 60:.1f} min', flush=True)
        if done:
            raise lgb.callback.EarlyStopException(n - 1, env.evaluation_result_list)
    callback.order = 30
    model = lgb.train(params, dfit, num_boost_round=LIMIT, valid_sets=[dfit, dstop], valid_names=['fit', 'stop'],
                      callbacks=[callback], keep_training_booster=True)
    margin = model.predict(Xs, num_iteration=plateau.best_round, raw_score=True, num_threads=params['num_threads'])
    return model, plateau, np.asarray(margin, np.float64)


def lgb_final(lgb, X, y, rounds):
    params = dict(LGB_PARAMS, num_threads=os.cpu_count() or 2)
    return lgb.train(params, lgb.Dataset(X, y, params=params), num_boost_round=rounds)


def svm_prepare(X, mean=None, inv=None, rows=None):
    Z = np.sign(X) * np.log1p(np.abs(X))
    Z[~np.isfinite(Z)] = 0
    if mean is None:
        R = Z[rows].astype(np.float64)
        mean = R.mean(0)
        std = np.sqrt(((R - mean) ** 2).mean(0))
        inv = np.where(std > 1e-6, 1 / np.where(std > 1e-6, std, 1), 0.0)
        mean, inv = mean.astype(np.float32), inv.astype(np.float32)
    Z -= mean; Z *= inv
    np.clip(Z, -CLIP, CLIP, out=Z)
    return Z.astype(np.float32), mean, inv


def svm_epoch(model, Z, y, rows, seed):
    perm = np.random.default_rng(seed).permutation(rows)
    for i in range(0, len(perm), BATCH):
        idx = perm[i:i + BATCH]
        model.partial_fit(Z[idx].astype(np.float64), y[idx].astype(np.int64), classes=np.array([0, 1]))


def svm_select(Z, y, fit_rows, stop_rows):
    from sklearn.linear_model import SGDClassifier
    from sklearn.metrics import average_precision_score
    new = lambda a: SGDClassifier(loss='hinge', penalty='l2', alpha=a, learning_rate='optimal', fit_intercept=True,
                                  shuffle=False, average=True, random_state=SEED)
    best = dict(ap=-1.0)
    settings = []
    for a in ALPHAS:
        model, top, anchor, waiting, top_epoch, coef = new(a), -1.0, -1.0, 0, 0, None
        for epoch in range(1, SVM_EPOCHS + 1):
            svm_epoch(model, Z, y, fit_rows, SEED + epoch)
            c, b = model.coef_.ravel().copy(), float(model.intercept_[0])
            if not np.isfinite(c).all():
                break
            ap = float(average_precision_score(y[stop_rows], Z[stop_rows] @ c.astype(np.float32) + b))
            if ap > top:
                top, top_epoch, coef = ap, epoch, (c, b)
            if top - anchor >= SVM_GAIN:
                anchor, waiting = top, 0
            else:
                waiting += 1
            if waiting >= SVM_PATIENCE:
                break
        settings.append(dict(alpha=a, best_epoch=top_epoch, best_stop_ap=top))
        print(f'  [svm select] alpha={a:g}: best AP {top:.5f} at epoch {top_epoch}', flush=True)
        if coef is not None and top > best['ap']:
            best = dict(ap=top, alpha=a, epochs=top_epoch, coef=coef)
    return best, settings


def svm_final(Z, y, alpha, epochs):
    from sklearn.linear_model import SGDClassifier
    model = SGDClassifier(loss='hinge', penalty='l2', alpha=alpha, learning_rate='optimal', fit_intercept=True,
                          shuffle=False, average=True, random_state=SEED)
    rows = np.arange(len(y))
    for epoch in range(1, epochs + 1):
        svm_epoch(model, Z, y, rows, SEED + 1000 + epoch)
    return model.coef_.ravel().copy(), float(model.intercept_[0])


# ------------------------------------------------------------------ main
def main():
    import lightgbm as lgb, xgboost as xgb, sklearn, psutil
    if lgb.__version__ != '4.7.0' or xgb.__version__ != '3.4.1':
        raise RuntimeError('Install lightgbm==4.7.0 and xgboost==3.4.1')
    old_report = read(OLD / 'report.json')
    if old_report['status'] != f'{TAG}_FOUR_WAY_COMPLETE':
        raise ValueError('Run the four-way comparison (weeks 0-39 models) first; it is the baseline here.')
    manifest = read(DATA / 'manifest.json')
    if manifest['status'] != f'{TAG}_EXPORT_READY':
        raise ValueError('Unexpected export status')
    counts = manifest['counts']
    need = (counts['train_rows'] + counts['dev_rows']) * FEATURES * 4 * 5 + 3 * 1024**3
    if psutil.virtual_memory().total < need:
        raise RuntimeError(f'Needs about {need / 1024**3:.0f} GB of RAM: switch on High-RAM')
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    protocol = dict(version=f'{FMT}-retrain-0-51-v1', script_sha256=sha(__file__),
        manifest_sha256=sha(DATA / 'manifest.json'), baseline_report_sha256=sha(OLD / 'report.json'),
        select=f'fit weeks 0-{FIT_LAST}, judge weeks {STOP_FIRST}-{STOP_LAST}', final='weeks 0-51',
        roles='Platt + <=1% FPR thresholds + ranking on weeks 48-51 scores of the weeks 0-47 models',
        xgboost=XGB_PARAMS, lightgbm=LGB_PARAMS, tree_rule=dict(limit=LIMIT, patience=PATIENCE, gain=GAIN),
        svm=dict(alphas=list(ALPHAS), epochs=SVM_EPOCHS, patience=SVM_PATIENCE, gain=SVM_GAIN, batch=BATCH, clip=CLIP),
        versions=dict(xgboost=xgb.__version__, lightgbm=lgb.__version__, sklearn=sklearn.__version__,
                      numpy=np.__version__), xgboost_device=DEVICE,
        test_policy='weeks 52-63 scored once after roles.json is frozen; second look at this test (benchmark)')
    if (OUT / 'protocol.json').exists() and read(OUT / 'protocol.json') != protocol:
        raise ValueError('Frozen protocol changed (script edited after starting). Use a new OUT folder.')
    write(OUT / 'protocol.json', protocol)
    if (OUT / 'report.json').exists():
        print('Already finished:\n' + (OUT / 'report.json').read_text())
        return

    print('Copying and verifying training + development data ...', flush=True)
    files = sorted(str(copy_checked(DATA / n, WORK / 'data' / n, f['sha256']))
                   for n, f in manifest['files'].items() if n.startswith(('train/', 'dev/')))
    d = load(files)
    X, y, week = d['X'], d['y'].astype(int), d['week']
    if len(y) != counts['train_rows'] + counts['dev_rows'] or week.min() != 0 or week.max() != 51:
        raise ValueError('Unexpected weeks 0-51 data')
    fit_rows, stop_rows = np.flatnonzero(week <= FIT_LAST), np.flatnonzero(week >= STOP_FIRST)
    ys = y[stop_rows]
    print(f'  weeks 0-{FIT_LAST}: {len(fit_rows):,} files; weeks {STOP_FIRST}-{STOP_LAST}: {len(stop_rows):,} files; '
          f'all weeks 0-51: {len(y):,} files; XGBoost device: {DEVICE}', flush=True)

    # ---- 1. selection on weeks 48-51 ----
    if not (OUT / 'selection.json').exists():
        print('Stage 1: choosing settings on weeks 48-51 ...', flush=True)
        xb, xp, xm = xgb_select(xgb, X[fit_rows], y[fit_rows].astype(np.float32), X[stop_rows], ys.astype(np.float32))
        del xb; gc.collect()
        lb, lp, lm = lgb_select(lgb, X[fit_rows], y[fit_rows].astype(np.float32), X[stop_rows], ys.astype(np.float32))
        del lb; gc.collect()
        Z, mean, inv = svm_prepare(X, rows=fit_rows)
        best, settings = svm_select(Z, y, fit_rows, stop_rows)
        sm = Z[stop_rows] @ best['coef'][0].astype(np.float32) + best['coef'][1]
        del Z; gc.collect()
        np.savez(WORK / 'selector_scores.npz', xgb=xm, lgbm=lm, svm=sm.astype(np.float64), y=ys,
                 sha256=d['sha256'][stop_rows])
        np.savez(WORK / 'svm_scaler.npz', mean=mean, inverse_std=inv)
        selection = dict(xgboost_rounds=xp.best_round, xgboost_stop_logloss=xp.best,
                         lightgbm_rounds=lp.best_round, lightgbm_stop_logloss=lp.best,
                         svm_alpha=best['alpha'], svm_epochs=best['epochs'], svm_stop_ap=best['ap'], svm_settings=settings,
                         selector_scores_sha256=save(WORK / 'selector_scores.npz', 'selector_scores.npz'),
                         svm_scaler_sha256=save(WORK / 'svm_scaler.npz', 'svm_scaler.npz'),
                         xgboost_history=xp.history, lightgbm_history=lp.history)
        write(OUT / 'selection.json', selection)
    sel = read(OUT / 'selection.json')
    print(f'Selected: XGBoost {sel["xgboost_rounds"]} rounds, LightGBM {sel["lightgbm_rounds"]} rounds, '
          f'SVM alpha={sel["svm_alpha"]:g} x {sel["svm_epochs"]} epochs', flush=True)

    # ---- 2. final models on weeks 0-51 ----
    names = dict(xgb=f'XGB_{TAG}_0-51.ubj', lgbm=f'LGBM_{TAG}_0-51.txt', svm=f'SVM_{TAG}_0-51.npz')
    if not (OUT / 'final_models.json').exists():
        print('Stage 2: training the final models on all weeks 0-51 ...', flush=True)
        xgb_final(xgb, X, y.astype(np.float32), sel['xgboost_rounds']).save_model(WORK / names['xgb'])
        lgb_final(lgb, X, y.astype(np.float32), sel['lightgbm_rounds']).save_model(str(WORK / names['lgbm']))
        with np.load(OUT / 'svm_scaler.npz') as s:
            mean, inv = s['mean'], s['inverse_std']
        Z, _, _ = svm_prepare(X, mean, inv)
        coef, b = svm_final(Z, y, sel['svm_alpha'], sel['svm_epochs'])
        del Z; gc.collect()
        np.savez(WORK / names['svm'], coefficient=coef, intercept=np.array([b]), mean=mean, inverse_std=inv,
                 clip=np.array([CLIP]), transform=np.array(['signed_log1p']), alpha=np.array([sel['svm_alpha']]),
                 epochs=np.array([sel['svm_epochs']]), training_rows=np.array([len(y)]))
        write(OUT / 'final_models.json', {k: dict(file=n, sha256=save(WORK / n, n)) for k, n in names.items()})
    final = read(OUT / 'final_models.json')
    for k, v in final.items():
        if sha(OUT / v['file']) != v['sha256']:
            raise ValueError(f'Final model checksum failed: {v["file"]}')
    del X, d; gc.collect()

    # ---- 3. roles from the out-of-time weeks 48-51 scores ----
    if not (OUT / 'roles.json').exists():
        from sklearn.metrics import average_precision_score
        with np.load(OUT / 'selector_scores.npz') as s:
            sc, yy = {k: s[k] for k in ('xgb', 'lgbm', 'svm')}, s['y'].astype(int)
        cal = {m: calibrate(sc[m], yy) for m in sc}
        prob = {m: expit(cal[m]['slope'] * sc[m] + cal[m]['intercept']) for m in sc}
        blend = lambda w: sum(v * prob[k] for k, v in w.items())
        cuts = {k: threshold(blend(w), yy) for k, w in MIX.items()}
        ranking = sorted((dict(key=k, candidate=NAMES[k], recall=float(np.mean(blend(MIX[k])[yy == 1] >= cuts[k]['threshold'])),
                               false_alarm_rate=float(np.mean(blend(MIX[k])[yy == 0] >= cuts[k]['threshold'])),
                               ap=float(average_precision_score(yy, blend(MIX[k])))) for k in 'ABCD'),
                         key=lambda r: (r['recall'], r['ap']), reverse=True)
        primary, challenger = ranking[0]['key'], ranking[1]['key']
        weights = {}
        for k in (primary, challenger):
            for m, v in MIX[k].items():
                weights[m] = weights.get(m, 0) + 0.5 * v
        cuts['ENS'] = threshold(blend(weights), yy)
        write(OUT / 'roles.json', dict(primary=primary, challenger=challenger, primary_name=NAMES[primary],
              challenger_name=NAMES[challenger], ensemble_effective_weights=weights, calibration=cal,
              thresholds=cuts, ranking=ranking, rows=int(len(yy)), benign_rows=int((yy == 0).sum()),
              rule='Chosen on weeks 48-51 scores of the weeks 0-47 models, before the test is scored'))
    roles = read(OUT / 'roles.json')
    print('Roles frozen:', json.dumps({k: roles[k] for k in ('primary_name', 'challenger_name',
                                                              'ensemble_effective_weights')}), flush=True)

    # ---- 4. test (second look), new pipeline vs the frozen weeks 0-39 pipeline ----
    print('Scoring the test weeks 52-63 ...', flush=True)
    tfiles = sorted(str(copy_checked(DATA / n, WORK / 'data' / n, f['sha256']))
                    for n, f in manifest['files'].items() if n.startswith('test/'))
    t = load(tfiles)
    ty = t['y'].astype(int)
    xgbm = xgb.Booster(model_file=str(OUT / final['xgb']['file']))
    xgbm.set_param({'device': DEVICE})
    lgbm = lgb.Booster(model_file=str(OUT / final['lgbm']['file']))
    with np.load(OUT / final['svm']['file']) as s:
        Z, _, _ = svm_prepare(t['X'], s['mean'], s['inverse_std'])
        m_svm = Z @ s['coefficient'].astype(np.float32) + float(s['intercept'][0])
    margins = dict(xgb=np.asarray(xgbm.inplace_predict(t['X'], predict_type='margin'), np.float64),
                   lgbm=lgbm.predict(t['X'], raw_score=True, num_threads=os.cpu_count() or 2).astype(np.float64),
                   svm=m_svm.astype(np.float64))
    cal, cuts = roles['calibration'], roles['thresholds']
    prob = {m: expit(cal[m]['slope'] * margins[m] + cal[m]['intercept']) for m in margins}
    mixes = dict(MIX, ENS=roles['ensemble_effective_weights'])
    with np.load(OLD / 'test_predictions.npz') as o:
        if not np.array_equal(o['sha256'], t['sha256']):
            raise ValueError('Test file order differs from the baseline run')
        old_prob = {k: o[f'{k}_probability'] for k in ('A', 'B', 'C', 'D', 'ENS')}
    old_roles = read(OLD / 'roles.json')
    rows, preds = [], {}
    for k in ('A', 'B', 'C', 'D', 'ENS'):
        p = sum(v * prob[m] for m, v in mixes[k].items())
        r, preds[k] = metrics(f'new 0-51 {NAMES.get(k, "Final ensemble")}', ty, p, cuts[k]['threshold'])
        rows.append(dict(r, key=k, pipeline='weeks 0-51'))
        r, preds['old_' + k] = metrics(f'old 0-39 {NAMES.get(k, "Final ensemble")}', ty, old_prob[k],
                                       old_roles['thresholds'][k]['threshold'])
        rows.append(dict(r, key='old_' + k, pipeline='weeks 0-39'))
    weekly = {}
    for wk in sorted(np.unique(t['week']).tolist()):
        m = t['week'] == wk
        weekly[int(wk)] = {k: dict(recall=float(np.mean(preds[k][m & (ty == 1)])),
                                   false_alarm_rate=float(np.mean(preds[k][m & (ty == 0)]))) for k in ('ENS', 'old_ENS')}
    wrong_new, wrong_old = preds['ENS'] != ty, preds['old_ENS'] != ty
    paired = dict(new_fixes=int((wrong_old & ~wrong_new).sum()), new_adds=int((~wrong_old & wrong_new).sum()),
                  both_wrong=int((wrong_old & wrong_new).sum()))
    with open(OUT / 'test_comparison.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    np.savez_compressed(WORK / 'test_predictions.npz', sha256=t['sha256'], week=t['week'], y=t['y'],
                        **{f'{k}_probability': sum(v * prob[m] for m, v in mixes[k].items()) for k in mixes})
    save(WORK / 'test_predictions.npz', 'test_predictions.npz')

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    wk = sorted(weekly)
    fig, ax = plt.subplots(1, 3, figsize=(20, 5.5), constrained_layout=True)
    for k, label, color in (('old_ENS', 'Old ensemble (weeks 0-39)', '#9aa0a6'), ('ENS', 'New ensemble (weeks 0-51)', '#d93025')):
        ax[0].plot(wk, [100 * weekly[w][k]['recall'] for w in wk], marker='o', label=label, color=color)
        ax[1].plot(wk, [100 * weekly[w][k]['false_alarm_rate'] for w in wk], marker='o', label=label, color=color)
    ax[1].axhline(100 * FPR, color='gray', ls=':', lw=1)
    ax[0].set(xlabel='Test week', ylabel='Malware caught (%)', title='Recall week by week')
    ax[1].set(xlabel='Test week', ylabel='False alarms (%)', title='False alarms week by week (target 1%)')
    keys = ['old_A', 'A', 'old_B', 'B', 'old_ENS', 'ENS']
    byk = {r['key']: r for r in rows}
    x = np.arange(len(keys))
    b1 = ax[2].bar(x - .2, [byk[k]['fn'] for k in keys], .4, label='Missed malware', color='#d93025')
    b2 = ax[2].bar(x + .2, [byk[k]['fp'] for k in keys], .4, label='False alarms', color='#9aa0a6')
    ax[2].bar_label(b1, fontsize=7); ax[2].bar_label(b2, fontsize=7)
    ax[2].set_xticks(x, ['old XGB', 'new XGB', 'old LGBM', 'new LGBM', 'old ENS', 'new ENS'], fontsize=8)
    ax[2].set(title='Test errors: old (0-39) vs new (0-51)')
    for a in ax:
        a.grid(alpha=.2); a.legend(fontsize=8)
    fig.suptitle(f'{TAG}: retrained on weeks 0-51 vs the weeks 0-39 pipeline, on {len(ty):,} test files (weeks 52-63)')
    for ext in ('png', 'pdf'):
        fig.savefig(OUT / f'{FMT}_retrain_0_51.{ext}', dpi=170)
    plt.close(fig)

    brief = lambda r: {k: r[k] for k in ('model', 'recall', 'false_alarm_rate', 'fp', 'fn', 'average_precision',
                                         'log_loss')}
    report = dict(status=f'{TAG}_RETRAIN_0_51_COMPLETE', primary=roles['primary_name'],
        challenger=roles['challenger_name'], ensemble_effective_weights=roles['ensemble_effective_weights'],
        selection={k: sel[k] for k in ('xgboost_rounds', 'lightgbm_rounds', 'svm_alpha', 'svm_epochs')},
        ranking_on_weeks_48_51=roles['ranking'], threshold_benign_rows=roles['benign_rows'],
        test=[brief(r) for r in rows],
        weekly_recall_range=dict(new=[min(weekly[w]['ENS']['recall'] for w in wk), max(weekly[w]['ENS']['recall'] for w in wk)],
                                 old=[min(weekly[w]['old_ENS']['recall'] for w in wk), max(weekly[w]['old_ENS']['recall'] for w in wk)]),
        new_vs_old_ensemble=paired, final_models=final,
        scope='Second look at the test (first: four-way-v1). All settings fixed in advance; thresholds rest on '
              f'{roles["benign_rows"]:,} benign files of weeks 48-51, so they are noisier than the 12-week ones.')
    write(OUT / 'report.json', report)
    print(json.dumps({k: report[k] for k in ('status', 'primary', 'challenger', 'selection', 'test',
                                              'weekly_recall_range', 'new_vs_old_ensemble')}, indent=2))


if __name__ == '__main__':
    main()
