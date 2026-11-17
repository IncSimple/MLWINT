"""PDF real-world retrain, step R3 (Google Colab; T4 or CPU, High-RAM not needed): train the PDF detector on EMBER
PDFs + real-world clean PDFs from SafeDocs, set its verdict thresholds, and test it once.

Everything below is fixed before running (nothing is chosen by looking at the test or the holdout):
  data     EMBER weeks 0-47 + SafeDocs fit  -> select       judged on EMBER weeks 48-51 + SafeDocs judge
           EMBER weeks 0-51 + SafeDocs fit + judge -> final models (same number of rounds as selected)
  weights  malware and clean count equally in total; inside the clean side EMBER clean and SafeDocs count equally
           (so 66k web PDFs do not drown out the 26k EMBER clean files)
  models   XGBoost + LightGBM, the same parameters as every earlier MLWINT model; rounds by early stopping on the
           judge set (100 rounds without a 1e-5 drop of the weighted log loss); ensemble 50/50 (SVM blends were
           rejected for every format before)
  verdicts Platt calibration and thresholds from the SELECT models' scores on the judge set (the final models have
           seen it). A threshold must hold on BOTH clean sources: MALICIOUS = at most 0.5 % of EMBER clean AND at
           most 0.5 % of SafeDocs clean flagged; SUSPICIOUS the same with 3 %; the 1 % cut the same with 1 %.
  test     ONCE, after the card is frozen: EMBER weeks 52-63 (viewed before -> benchmark) and SafeDocs holdout
           (never scored by a trained-here model). Acceptance rule, agreed before this run:
             A1 malware recall at the 1 % cut >= 94.97 % on EMBER weeks 52-63 (the shipped detector's result)
             A2 false alarms at the 1 % cut <= 1 % on SafeDocs holdout
             A3 false alarms at the 1 % cut <= 1 % on EMBER clean weeks 52-63
           The shipped 1.0.0 detector is scored on the same files for comparison. PDFs with active content are
           unlabelled: their verdicts are shown, not counted.
Output: experiments/pdf-realworld-v1/retrain-v1/  protocol.json, select.json, card_pdf.json, models/, report.json
Status PDF_RW_RETRAIN_COMPLETE. Re-running resumes after the last finished stage.
"""
import hashlib, json, os, shutil, sys, time
from pathlib import Path

import numpy as np

ROOT = Path(os.environ.get('MLWINT_COLAB_ROOT', '/content/drive/MyDrive/MLWINT-colab'))
EM = ROOT / 'inputs/pdf-v1'
SD = ROOT / 'inputs/pdf-rw-v1'
AUDIT = ROOT / 'experiments/pdf-realworld-v1/audit-v1/report.json'
SHIPPED = ROOT / 'experiments/phase1-closeout-v1/verdict_policy_pdf.json'
OUT = ROOT / 'experiments/pdf-realworld-v1/retrain-v1'
FEATURES, SEED = 2568, 42
FIT_LAST, JUDGE_FIRST, JUDGE_LAST = 47, 48, 51
LIMIT, PATIENCE, GAIN = 10000, 100, 1e-5
MAL_FPR, SUS_FPR, CUT_FPR = 0.005, 0.03, 0.01
ACCEPT = dict(recall_min=0.9497, safedocs_fpr_max=0.01, ember_fpr_max=0.01)
XGB_PARAMS = dict(objective='binary:logistic', eval_metric='logloss', tree_method='hist', grow_policy='depthwise',
                  eta=0.05, max_depth=6, min_child_weight=1, reg_lambda=1.0, reg_alpha=0.0, gamma=0.0,
                  colsample_bytree=0.8, subsample=1.0, max_bin=256, max_cached_hist_node=64, seed=42,
                  validate_parameters=True, verbosity=1)
LGB_PARAMS = dict(objective='binary', metric='binary_logloss', learning_rate=0.05, num_leaves=31, max_depth=-1,
                  min_data_in_leaf=20, lambda_l1=0.0, lambda_l2=0.0, feature_fraction=0.8, bagging_fraction=1.0,
                  bagging_freq=0, max_bin=255, bin_construct_sample_cnt=200000, histogram_pool_size=512, seed=42,
                  force_col_wise=True, verbosity=-1)
DEVICE = 'cuda' if shutil.which('nvidia-smi') else 'cpu'


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


def log(msg):
    print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)


# ---------------------------------------------------------------------------------------------- data
def load_ember():
    manifest = read(EM / 'manifest.json')
    parts = []
    for name, info in sorted(manifest['files'].items()):
        if name.endswith('.npz'):
            if sha(EM / name) != info['sha256']:
                raise ValueError(f'Checksum failed: {EM / name}')
            with np.load(EM / name) as z:
                parts.append({k: z[k] for k in ('X', 'y', 'week', 'sha256')})
    d = {k: np.concatenate([p[k] for p in parts]) for k in parts[0]}
    d['X'], d['y'] = d['X'].astype(np.float32), d['y'].astype(int)
    return d


def load_safedocs():
    manifest = read(SD / 'manifest.json')
    if manifest.get('status') != 'PDF_RW_DATA_READY':
        raise SystemExit('Run step R2 (safedocs_audit.py) first')
    out = {}
    for name, info in manifest['files'].items():
        if sha(SD / name) != info['sha256']:
            raise ValueError(f'Checksum failed: {SD / name}')
        with np.load(SD / name) as z:
            out[name.replace('safedocs_', '').replace('.npz', '')] = {k: z[k] for k in z.files}
    return out


def assemble(em, em_mask, sd_parts):
    """Rows, labels, weights and a source tag (0 EMBER clean, 1 EMBER malware, 2 SafeDocs clean)."""
    sdX = np.vstack([p['X'] for p in sd_parts]).astype(np.float32)
    X = np.vstack([em['X'][em_mask], sdX])
    y = np.r_[em['y'][em_mask], np.zeros(len(sdX), int)]
    src = np.r_[em['y'][em_mask], np.full(len(sdX), 2)]
    n = {s: int((src == s).sum()) for s in (0, 1, 2)}
    total = float(len(y))
    # malware half of the total weight, each clean source a quarter
    w = np.select([src == 0, src == 1, src == 2], [total / 4 / n[0], total / 2 / n[1], total / 4 / n[2]])
    return X, y, w.astype(np.float32), src, n


# ---------------------------------------------------------------------------------------------- models
def train_xgb(X, y, w, rounds=None, Xj=None, yj=None, wj=None):
    import xgboost as xgb
    params = dict(XGB_PARAMS, device=DEVICE)
    dtrain = xgb.QuantileDMatrix(X, y, weight=w, max_bin=params['max_bin'])
    if rounds is not None:
        return xgb.train(params, dtrain, rounds, verbose_eval=False), rounds
    djudge = xgb.QuantileDMatrix(Xj, yj, weight=wj, ref=dtrain)
    stop = xgb.callback.EarlyStopping(rounds=PATIENCE, min_delta=GAIN, save_best=True, data_name='judge',
                                      metric_name='logloss')
    model = xgb.train(params, dtrain, LIMIT, evals=[(djudge, 'judge')], callbacks=[stop], verbose_eval=100)
    return model, model.best_iteration + 1


def train_lgbm(X, y, w, rounds=None, Xj=None, yj=None, wj=None):
    import lightgbm as lgb
    params = dict(LGB_PARAMS, num_threads=os.cpu_count())
    dtrain = lgb.Dataset(X, y, weight=w, free_raw_data=False)
    if rounds is not None:
        return lgb.train(params, dtrain, rounds), rounds
    djudge = lgb.Dataset(Xj, yj, weight=wj, reference=dtrain)
    model = lgb.train(params, dtrain, LIMIT, valid_sets=[djudge], valid_names=['judge'],
                      callbacks=[lgb.early_stopping(PATIENCE, min_delta=GAIN, verbose=True), lgb.log_evaluation(100)])
    return model, model.best_iteration


def margin(kind, model, X):
    if kind == 'xgb':
        model.set_param({'device': 'cpu'})
        return np.asarray(model.inplace_predict(X, predict_type='margin'), np.float64)
    return model.predict(X, raw_score=True).astype(np.float64)


def calibrate(m, y):
    from sklearn.linear_model import LogisticRegression
    mean, scale = float(m.mean()), float(m.std())
    fit = LogisticRegression(C=1e6, solver='lbfgs', max_iter=2000, tol=1e-10)
    fit.fit(((m - mean) / scale)[:, None], y)
    if fit.n_iter_[0] >= 2000 or fit.coef_[0, 0] <= 0:
        raise ValueError('Calibration did not converge with increasing scores')
    slope = float(fit.coef_[0, 0] / scale)
    return dict(slope=slope, intercept=float(fit.intercept_[0] - slope * mean))


def ensemble(margins, cal):
    from scipy.special import expit
    return sum(0.5 * expit(cal[k]['slope'] * margins[k] + cal[k]['intercept']) for k in ('xgb', 'lgbm'))


def cut(clean_scores, fpr):
    s = np.sort(clean_scores)[::-1]
    return float(np.nextafter(s[int(np.floor(fpr * len(s)))], np.inf))


def both_sources_cut(prob, src, fpr):
    per = {name: cut(prob[src == s], fpr) for name, s in (('ember_clean', 0), ('safedocs_clean', 2))}
    return max(per.values()), per


def tiers(prob, mal, sus):
    return np.where(prob >= mal, 2, np.where(prob >= sus, 1, 0))


def summary(prob, y, mal, sus, one):
    t = tiers(prob, mal, sus)
    out = {}
    for label, name in ((1, 'malware'), (0, 'clean')):
        m = y == label
        if m.any():
            out[name] = dict(files=int(m.sum()), malicious=float(np.mean(t[m] == 2)),
                             suspicious=float(np.mean(t[m] == 1)), clean=float(np.mean(t[m] == 0)))
            if one is not None:
                out[name]['at_1pct_cut'] = float(np.mean(prob[m] >= one))
    return out


def shipped_probability(X):
    import lightgbm as lgb, xgboost as xgb
    from scipy.special import expit
    card = read(SHIPPED)
    prob = np.zeros(len(X))
    for m, w in card['ensemble']['weights'].items():
        path = ROOT / card['models'][m]['file']
        if sha(path) != card['models'][m]['sha256']:
            raise ValueError(f'Model checksum failed: {path}')
        raw = (xgb.Booster(model_file=str(path)).inplace_predict(X, predict_type='margin') if m == 'xgb'
               else lgb.Booster(model_file=str(path)).predict(X, raw_score=True))
        c = card['ensemble']['calibration'][m]
        prob += w * expit(c['slope'] * np.asarray(raw, np.float64) + c['intercept'])
    v = card['verdicts']
    return prob, float(v['malicious']['threshold']), float(v['suspicious']['threshold'])


# ---------------------------------------------------------------------------------------------- main
def main():
    import lightgbm as lgb, xgboost as xgb, sklearn
    if lgb.__version__ != '4.7.0' or xgb.__version__ != '3.4.1':
        raise RuntimeError('Install lightgbm==4.7.0 and xgboost==3.4.1 (the versions the app uses)')
    audit = read(AUDIT)
    if audit.get('status') != 'PDF_RW_AUDIT_DONE':
        raise SystemExit('Run step R2 first')
    drop = audit['audit']['source_only_indices']
    if drop:
        raise SystemExit(f'R2 found {len(drop)} source-only features: this script expects none (ask before going on)')
    protocol = dict(version='pdf-realworld-retrain-v1', script_sha256=sha(__file__),
                    data_manifest_sha256=sha(SD / 'manifest.json'), ember_manifest_sha256=sha(EM / 'manifest.json'),
                    audit_report_sha256=sha(AUDIT), shipped_card_sha256=sha(SHIPPED),
                    select=f'EMBER weeks 0-{FIT_LAST} + SafeDocs fit; judge EMBER weeks {JUDGE_FIRST}-{JUDGE_LAST} + SafeDocs judge',
                    final='EMBER weeks 0-51 + SafeDocs fit + judge, selected rounds',
                    weights='malware 1/2, EMBER clean 1/4, SafeDocs clean 1/4 of the total weight',
                    thresholds=dict(malicious=MAL_FPR, suspicious=SUS_FPR, one_percent=CUT_FPR,
                                    rule='must hold on EMBER clean and on SafeDocs clean of the judge set'),
                    acceptance=ACCEPT, xgboost=XGB_PARAMS, lightgbm=LGB_PARAMS, xgboost_device=DEVICE,
                    early_stopping=dict(limit=LIMIT, patience=PATIENCE, min_delta=GAIN),
                    versions=dict(xgboost=xgb.__version__, lightgbm=lgb.__version__, sklearn=sklearn.__version__,
                                  numpy=np.__version__))
    if (OUT / 'protocol.json').exists() and read(OUT / 'protocol.json') != protocol:
        raise SystemExit('The frozen protocol changed (script edited after starting). Use a new OUT folder.')
    write(OUT / 'protocol.json', protocol)
    if (OUT / 'report.json').exists():
        print('Already finished:\n' + (OUT / 'report.json').read_text())
        return

    log(f'Loading data (XGBoost device: {DEVICE}) ...')
    em, sd = load_ember(), load_safedocs()
    week = em['week']
    models_dir = OUT / 'models'
    models_dir.mkdir(parents=True, exist_ok=True)

    # ---- select ----
    Xj, yj, wj, sj, nj = assemble(em, (week >= JUDGE_FIRST) & (week <= JUDGE_LAST), [sd['judge']])
    if not (OUT / 'select.json').exists():
        Xf, yf, wf, _, nf = assemble(em, week <= FIT_LAST, [sd['fit']])
        log(f'Select: fit {nf}, judge {nj} (0 EMBER clean, 1 EMBER malware, 2 SafeDocs)')
        log('XGBoost (select) ...')
        mx, rx = train_xgb(Xf, yf, wf, None, Xj, yj, wj)
        mx = mx[:rx]
        log(f'XGBoost: {rx} rounds')
        log('LightGBM (select) ...')
        ml, rl = train_lgbm(Xf, yf, wf, None, Xj, yj, wj)
        log(f'LightGBM: {rl} rounds')
        del Xf
        margins = dict(xgb=margin('xgb', mx, Xj), lgbm=margin('lgbm', ml, Xj))
        cal = {k: calibrate(v, yj) for k, v in margins.items()}
        prob = ensemble(margins, cal)
        mal, mal_per = both_sources_cut(prob, sj, MAL_FPR)
        sus, sus_per = both_sources_cut(prob, sj, SUS_FPR)
        one, one_per = both_sources_cut(prob, sj, CUT_FPR)
        sus = min(sus, mal)
        mx.save_model(str(models_dir / 'XGB_PDF_select.ubj'))
        ml.save_model(str(models_dir / 'LGBM_PDF_select.txt'))
        write(OUT / 'select.json', dict(
            rounds=dict(xgb=rx, lgbm=rl), calibration=cal,
            thresholds=dict(malicious=mal, suspicious=sus, one_percent=one,
                            per_source=dict(malicious=mal_per, suspicious=sus_per, one_percent=one_per)),
            judge_rows=nj,
            judge_check=dict(ember=summary(prob[sj != 2], yj[sj != 2], mal, sus, one),
                             safedocs=summary(prob[sj == 2], yj[sj == 2], mal, sus, one))))
        del mx, ml
    sel = read(OUT / 'select.json')
    rx, rl = sel['rounds']['xgb'], sel['rounds']['lgbm']
    log(f'Selected: XGBoost {rx} rounds, LightGBM {rl} rounds; thresholds {sel["thresholds"]}')

    # ---- final ----
    fx, fl = models_dir / 'XGB_PDF_rw.ubj', models_dir / 'LGBM_PDF_rw.txt'
    if not (fx.exists() and fl.exists() and (OUT / 'card_pdf.json').exists()):
        Xa, ya, wa, _, na = assemble(em, week <= 51, [sd['fit'], sd['judge']])
        log(f'Final models on {na} ...')
        train_xgb(Xa, ya, wa, rx)[0].save_model(str(fx))
        train_lgbm(Xa, ya, wa, rl)[0].save_model(str(fl))
        del Xa
        t = sel['thresholds']
        write(OUT / 'card_pdf.json', dict(
            format='PDF', key='pdf', version='2026.12.1-candidate',
            verdicts=dict(
                malicious=dict(rule='ensemble probability >= threshold', threshold=t['malicious'],
                               calibration_false_alarm_target=MAL_FPR),
                suspicious=dict(rule='threshold <= ensemble probability < malicious threshold',
                                threshold=t['suspicious'], calibration_false_alarm_target=SUS_FPR),
                clean=dict(rule='below the suspicious threshold')),
            one_percent_cut=t['one_percent'],
            ensemble=dict(weights=dict(xgb=0.5, lgbm=0.5), calibration=sel['calibration'],
                          formula='sum over models of weight * sigmoid(slope * raw_margin + intercept)',
                          raw_margin=dict(xgb="XGBoost inplace_predict(predict_type='margin')",
                                          lgbm='LightGBM predict(raw_score=True)')),
            models=dict(xgb=dict(file='models/XGB_PDF_rw.ubj', sha256=sha(fx)),
                        lgbm=dict(file='models/LGBM_PDF_rw.txt', sha256=sha(fl))),
            features='EMBER2024 thrember PEFeatureExtractor, 2,568 values',
            calibration_set='select models on EMBER weeks 48-51 + SafeDocs judge; thresholds hold on both clean sources',
            training='EMBER PDF weeks 0-51 + SafeDocs clean (fit + judge zips)'))
    card = read(OUT / 'card_pdf.json')
    for m in ('xgb', 'lgbm'):
        if sha(OUT / card['models'][m]['file']) != card['models'][m]['sha256']:
            raise ValueError('Final model checksum failed')
    log('Card frozen. Opening the test (EMBER weeks 52-63) and the SafeDocs holdout ONCE ...')

    # ---- test, once ----
    import lightgbm as lgb, xgboost as xgb
    bx, bl = xgb.Booster(model_file=str(fx)), lgb.Booster(model_file=str(fl))
    mal, sus, one = card['verdicts']['malicious']['threshold'], card['verdicts']['suspicious']['threshold'], card['one_percent_cut']
    test = week >= 52
    sets = dict(ember_test=(em['X'][test], em['y'][test]),
                safedocs_holdout=(sd['holdout']['X'].astype(np.float32), np.zeros(len(sd['holdout']['X']), int)),
                safedocs_active_unlabelled=(sd['active']['X'].astype(np.float32), None))
    results, scores = {}, {}
    for name, (X, y) in sets.items():
        p = ensemble(dict(xgb=margin('xgb', bx, X), lgbm=margin('lgbm', bl, X)), card['ensemble']['calibration'])
        old, omal, osus = shipped_probability(X)
        scores[name] = p
        if y is None:
            t, o = tiers(p, mal, sus), tiers(old, omal, osus)
            results[name] = dict(files=int(len(p)),
                                 new=dict(malicious=float(np.mean(t == 2)), suspicious=float(np.mean(t == 1))),
                                 shipped=dict(malicious=float(np.mean(o == 2)), suspicious=float(np.mean(o == 1))))
        else:
            results[name] = dict(new=summary(p, y, mal, sus, one), shipped=summary(old, y, omal, osus, None))
    e, h = results['ember_test']['new'], results['safedocs_holdout']['new']
    checks = dict(A1_recall=dict(value=e['malware']['at_1pct_cut'], need=f'>= {100 * ACCEPT["recall_min"]:.2f}%',
                                 passed=e['malware']['at_1pct_cut'] >= ACCEPT['recall_min']),
                  A2_safedocs_false_alarms=dict(value=h['clean']['at_1pct_cut'], need=f'<= {100 * ACCEPT["safedocs_fpr_max"]:.2f}%',
                                                passed=h['clean']['at_1pct_cut'] <= ACCEPT['safedocs_fpr_max']),
                  A3_ember_false_alarms=dict(value=e['clean']['at_1pct_cut'], need=f'<= {100 * ACCEPT["ember_fpr_max"]:.2f}%',
                                             passed=e['clean']['at_1pct_cut'] <= ACCEPT['ember_fpr_max']))
    weekly = {}
    for wk in np.unique(week[test]):
        m = week[test] == wk
        yy, pp = em['y'][test][m], scores['ember_test'][m]
        weekly[int(wk)] = dict(recall_1pct=float(np.mean(pp[yy == 1] >= one)),
                               clean_false_alarms_1pct=float(np.mean(pp[yy == 0] >= one)))
    np.savez_compressed(OUT / 'test_scores.npz', ember_sha256=em['sha256'][test], ember_y=em['y'][test],
                        ember_week=week[test], ember_p=scores['ember_test'], holdout_sha256=sd['holdout']['sha256'],
                        holdout_p=scores['safedocs_holdout'], active_sha256=sd['active']['sha256'],
                        active_p=scores['safedocs_active_unlabelled'])
    report = dict(status='PDF_RW_RETRAIN_COMPLETE', accepted=all(c['passed'] for c in checks.values()),
                  acceptance=checks, card_sha256=sha(OUT / 'card_pdf.json'), rounds=sel['rounds'],
                  thresholds=dict(malicious=mal, suspicious=sus, one_percent=one), results=results, weekly=weekly,
                  note='EMBER weeks 52-63 had been viewed before (benchmark); SafeDocs holdout is fresh. '
                       'Shipped = MLWINT 1.0.0 detector with its own thresholds.')
    write(OUT / 'report.json', report)

    # ---- summary ----
    pct = lambda v: f'{100 * v:.2f}%'
    s = results['ember_test']['shipped']
    so = results['safedocs_holdout']['shipped']
    a = results['safedocs_active_unlabelled']
    print('\n=== Step R3 summary ===')
    print(f'Rounds: XGBoost {rx}, LightGBM {rl}')
    print('                                   new          shipped 1.0.0')
    print(f'EMBER test malware   MALICIOUS     {pct(e["malware"]["malicious"]):>8}     {pct(s["malware"]["malicious"]):>8}')
    print(f'                     flagged       {pct(1 - e["malware"]["clean"]):>8}     {pct(1 - s["malware"]["clean"]):>8}')
    print(f'EMBER test clean     MALICIOUS     {pct(e["clean"]["malicious"]):>8}     {pct(s["clean"]["malicious"]):>8}')
    print(f'                     flagged       {pct(1 - e["clean"]["clean"]):>8}     {pct(1 - s["clean"]["clean"]):>8}')
    print(f'SafeDocs holdout     MALICIOUS     {pct(h["clean"]["malicious"]):>8}     {pct(so["clean"]["malicious"]):>8}')
    print(f'  (clean, real web)  flagged       {pct(1 - h["clean"]["clean"]):>8}     {pct(1 - so["clean"]["clean"]):>8}')
    print(f'Active-content PDFs  MALICIOUS     {pct(a["new"]["malicious"]):>8}     {pct(a["shipped"]["malicious"]):>8}   (unlabelled)')
    print('Acceptance (1 % cut):')
    for k, c in checks.items():
        print(f'  {k:<26} {pct(c["value"]):>8}  need {c["need"]:<8}  {"PASS" if c["passed"] else "FAIL"}')
    print(f'\nPDF_RW_RETRAIN_COMPLETE  accepted={report["accepted"]}  report: {OUT / "report.json"}')


if __name__ == '__main__':
    main()
