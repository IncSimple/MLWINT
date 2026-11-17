"""PDF real-world retrain, step R3 diagnosis (Colab CPU, no training, ~5 min). Two questions:

A. Fair comparison. The shipped 1.0.0 detector's 94.97 % came from a 1 % cut set on EMBER clean only; on real web
   PDFs that cut flags far more than 1 %. Here BOTH detectors get a cut set by the same rule on the same judge data
   (at most X % of EMBER clean weeks 48-51 AND at most X % of SafeDocs judge flagged), and are compared on the EMBER
   test weeks 52-63 and the SafeDocs holdout. Note: the shipped models were trained on weeks 48-51, so their EMBER
   cut there is optimistic; the SafeDocs side decides the cut in practice. Second look at the test/holdout: the
   numbers are a benchmark, informational only - the R3 acceptance result stays "not accepted".
B. Which clean web PDFs score high? Judge split only (the holdout is not used here): the top 1 % of SafeDocs
   judge PDFs by the new select models vs the rest - size, pages, PDF indicators.
Writes experiments/pdf-realworld-v1/retrain-v1/diagnosis.json
"""
import json, os
from pathlib import Path

import numpy as np

ROOT = Path(os.environ.get('MLWINT_COLAB_ROOT', '/content/drive/MyDrive/MLWINT-colab'))
R3 = ROOT / 'experiments/pdf-realworld-v1/retrain-v1'
SD = ROOT / 'inputs/pdf-rw-v1'
SHARDS = ROOT / 'inputs/safedocs-v1/shards'
import importlib.util
spec = importlib.util.spec_from_file_location('r3', ROOT / 'code/retrain_pdf_realworld.py')
r3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r3)


def main():
    import lightgbm as lgb, xgboost as xgb
    if r3.read(R3 / 'report.json').get('status') != 'PDF_RW_RETRAIN_COMPLETE':
        raise SystemExit('Run step R3 first')
    sel, card = r3.read(R3 / 'select.json'), r3.read(R3 / 'card_pdf.json')
    em, sd = r3.load_ember(), r3.load_safedocs()
    week, y = em['week'], em['y']
    judge_em, test = (week >= 48) & (week <= 51), week >= 52

    def new_select(X):
        mx = xgb.Booster(model_file=str(R3 / 'models/XGB_PDF_select.ubj'))
        ml = lgb.Booster(model_file=str(R3 / 'models/LGBM_PDF_select.txt'))
        return r3.ensemble(dict(xgb=r3.margin('xgb', mx, X), lgbm=r3.margin('lgbm', ml, X)), sel['calibration'])

    def new_final(X):
        bx = xgb.Booster(model_file=str(R3 / 'models/XGB_PDF_rw.ubj'))
        bl = lgb.Booster(model_file=str(R3 / 'models/LGBM_PDF_rw.txt'))
        return r3.ensemble(dict(xgb=r3.margin('xgb', bx, X), lgbm=r3.margin('lgbm', bl, X)),
                           card['ensemble']['calibration'])

    shipped = lambda X: r3.shipped_probability(X)[0]
    Xjc = em['X'][judge_em & (y == 0)]
    Xsj = sd['judge']['X'].astype(np.float32)
    Xt, yt = em['X'][test], y[test]
    Xh = sd['holdout']['X'].astype(np.float32)

    # ---- A. same rule, same judge data, both detectors ----
    detectors = dict(new=(new_select, new_final), shipped=(shipped, shipped))
    fair = {}
    for name, (judge_fn, test_fn) in detectors.items():
        pj_em, pj_sd = judge_fn(Xjc), judge_fn(Xsj)
        pt, ph = test_fn(Xt), test_fn(Xh)
        rows = {}
        for fpr in (0.005, 0.01, 0.02, 0.03):
            c = max(r3.cut(pj_em, fpr), r3.cut(pj_sd, fpr))
            rows[f'{100 * fpr:g}%'] = dict(threshold=c, ember_test_recall=float(np.mean(pt[yt == 1] >= c)),
                                           ember_test_false_alarms=float(np.mean(pt[yt == 0] >= c)),
                                           safedocs_holdout_false_alarms=float(np.mean(ph >= c)))
        from sklearn.metrics import roc_auc_score
        both_clean = np.r_[pt[yt == 0], ph]
        rows['auc_ember_malware_vs_all_clean'] = float(roc_auc_score(
            np.r_[np.ones(int((yt == 1).sum())), np.zeros(len(both_clean))], np.r_[pt[yt == 1], both_clean]))
        fair[name] = rows

    # ---- B. high-scoring clean web PDFs (judge split only) ----
    p = new_select(Xsj)
    top = p >= np.quantile(p, 0.99)
    want = set(sd['judge']['sha256'].tolist())
    ind, cols = {}, None
    for f in sorted(SHARDS.glob('*.npz')):
        with np.load(f) as z:
            cols = [str(c) for c in z['indicator_columns']]
            for s, row in zip(z['sha256'], z['indicators']):
                if s in want:
                    ind[str(s)] = row
    I = np.array([ind[str(s)] for s in sd['judge']['sha256']])
    def profile(m):
        out = dict(files=int(m.sum()), median_kb=float(np.median(sd['judge']['bytes'][m]) / 1024))
        for j, c in enumerate(cols):
            out[c if c in ('pages', 'eof_markers') else f'has {c}'] = (
                float(np.median(I[m, j])) if c in ('pages', 'eof_markers') else float(np.mean(I[m, j] > 0)))
        return out
    zips = {}
    for z in sd['judge']['zip_id'][top]:
        zips[str(z)] = zips.get(str(z), 0) + 1
    high = dict(top_1pct=profile(top), rest=profile(~top), top_by_zip=zips,
                top_examples=[dict(name=str(sd['judge']['name'][i]), zip=str(sd['judge']['zip_id'][i]),
                                   sha256=str(sd['judge']['sha256'][i]), score=round(float(p[i]), 4))
                              for i in np.argsort(-p)[:15]])
    r3.write(R3 / 'diagnosis.json', dict(fair_comparison=fair, high_scoring_clean_web_pdfs=high,
                                         note='benchmark / diagnosis only; R3 acceptance result unchanged'))

    pct = lambda v: f'{100 * v:6.2f}%'
    print('\n=== A. Same rule for both (cut holds on EMBER clean AND web PDFs of the judge set) ===')
    print('false-alarm   detector   malware caught   EMBER clean flagged   web PDFs flagged (holdout)')
    for fpr in ('0.5%', '1%', '2%', '3%'):
        for name in ('new', 'shipped'):
            r = fair[name][fpr]
            print(f'{fpr:>8}      {name:<8}   {pct(r["ember_test_recall"])}          {pct(r["ember_test_false_alarms"])}'
                  f'              {pct(r["safedocs_holdout_false_alarms"])}')
    print(f'AUC malware vs all clean:  new {fair["new"]["auc_ember_malware_vs_all_clean"]:.4f}   '
          f'shipped {fair["shipped"]["auc_ember_malware_vs_all_clean"]:.4f}')
    print('\n=== B. Top 1 % scoring clean web PDFs (judge split) vs the rest ===')
    t, r = high['top_1pct'], high['rest']
    for k in t:
        print(f'  {k:<22} {t[k]:>10.3f}   {r[k]:>10.3f}')
    print(f'  spread over zips: {len(zips)} of {len(set(sd["judge"]["zip_id"].tolist()))}, most in one zip: {max(zips.values())}')
    print('\nDIAGNOSIS_DONE')


if __name__ == '__main__':
    main()
