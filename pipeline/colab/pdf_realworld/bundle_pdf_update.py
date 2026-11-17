"""PDF real-world retrain, ship step (Colab CPU, ~2 min): pack the new PDF detector for the PC.

Makes experiments/pdf-realworld-v1/retrain-v1/MLWINT_pdf_2026.12.1.zip with the same layout as the Phase 1 bundle:
  cards/pdf.json                 detector card (thresholds, calibration, model files + checksums, test results)
  models/pdf/XGB_PDF_rw.ubj      final XGBoost
  models/pdf/LGBM_PDF_rw.txt     final LightGBM
  parity/pdf.npz                 300 vectors (100 EMBER test, 100 SafeDocs holdout, 100 active-content PDFs) with the
                                 probability computed here, so the PC can prove it scores exactly the same
  update.json                    what this is, checksums of every file
"""
import hashlib, json, os, zipfile
from pathlib import Path

import numpy as np

ROOT = Path(os.environ.get('MLWINT_COLAB_ROOT', '/content/drive/MyDrive/MLWINT-colab'))
R3 = ROOT / 'experiments/pdf-realworld-v1/retrain-v1'
VERSION = '2026.12.1'
import importlib.util
spec = importlib.util.spec_from_file_location('r3', ROOT / 'code/retrain_pdf_realworld.py')
r3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r3)


def hexsha(a):
    a = np.asarray(a)
    return np.array([bytes(r).hex() for r in a]) if a.ndim == 2 else a.astype('U64')


def main():
    import lightgbm as lgb, xgboost as xgb
    report = r3.read(R3 / 'report.json')
    if report.get('status') != 'PDF_RW_RETRAIN_COMPLETE':
        raise SystemExit('Run step R3 first')
    card = r3.read(R3 / 'card_pdf.json')
    names = dict(xgb='XGB_PDF_rw.ubj', lgbm='LGBM_PDF_rw.txt')
    for m, n in names.items():
        if r3.sha(R3 / 'models' / n) != card['models'][m]['sha256']:
            raise ValueError(f'Checksum failed: {n}')
    diag = r3.read(R3 / 'diagnosis.json') if (R3 / 'diagnosis.json').exists() else {}
    app_card = dict(card, version=VERSION,
                    models={m: dict(file=f'models/pdf/{n}', sha256=card['models'][m]['sha256'],
                                    source=f'experiments/pdf-realworld-v1/retrain-v1/models/{n}')
                            for m, n in names.items()},
                    test_check=dict(acceptance=report['acceptance'], accepted_by_rule=report['accepted'],
                                    results=report['results'], weekly=report['weekly'],
                                    fair_comparison=diag.get('fair_comparison'), safedocs_in_ember=None,
                                    decision='Adopted 2026-11-17 by the owner although the pre-set rule failed (A1, A2): '
                                             'with the same both-sources cut it catches more malware than 1.0.0 at '
                                             'every false-alarm level (1 %: 89.8 % vs 74.3 %).'))

    # parity vectors
    em, sd = r3.load_ember(), r3.load_safedocs()
    em['sha256'] = hexsha(em['sha256'])
    # R2's "also in EMBER" check compared hex text with raw bytes, so it could not match: redo it properly here
    em_set = set(em['sha256'].tolist())
    overlap = {k: int(sum(s in em_set for s in sd[k]['sha256'].tolist())) for k in ('fit', 'judge', 'holdout', 'active')}
    print(f'SafeDocs files that are also in EMBER (by SHA-256): {overlap}')
    app_card['test_check']['safedocs_in_ember'] = overlap
    rng = np.random.default_rng(7)
    test = np.where(em['week'] >= 52)[0]
    pick = lambda n, k: rng.choice(n, size=min(k, n), replace=False)
    ti, hi, ai = test[pick(len(test), 100)], pick(len(sd['holdout']['X']), 100), pick(len(sd['active']['X']), 100)
    X = np.vstack([em['X'][ti], sd['holdout']['X'][hi], sd['active']['X'][ai]]).astype(np.float32)
    shas = np.r_[em['sha256'][ti], sd['holdout']['sha256'][hi], sd['active']['sha256'][ai]]
    y = np.r_[em['y'][ti], np.zeros(len(hi)), np.full(len(ai), -1)].astype(np.int8)
    bx = xgb.Booster(model_file=str(R3 / 'models' / names['xgb']))
    bl = lgb.Booster(model_file=str(R3 / 'models' / names['lgbm']))
    p = r3.ensemble(dict(xgb=r3.margin('xgb', bx, X), lgbm=r3.margin('lgbm', bl, X)), card['ensemble']['calibration'])

    work = Path(os.environ.get('MLWINT_WORK', '/content/pdf-update'))
    (work / 'cards').mkdir(parents=True, exist_ok=True)
    (work / 'models/pdf').mkdir(parents=True, exist_ok=True)
    (work / 'parity').mkdir(parents=True, exist_ok=True)
    (work / 'cards/pdf.json').write_text(json.dumps(app_card, indent=2, allow_nan=False))
    for n in names.values():
        (work / 'models/pdf' / n).write_bytes((R3 / 'models' / n).read_bytes())
    np.savez_compressed(work / 'parity/pdf.npz', X=X,
                        sha256=np.array([bytes.fromhex(s) for s in shas], dtype='S32').view(np.uint8).reshape(-1, 32),
                        ensemble_probability=p, y=y)
    files = {str(f.relative_to(work)).replace('\\', '/'): dict(sha256=r3.sha(f))
             for f in sorted(work.rglob('*')) if f.is_file() and f.name != 'update.json'}
    (work / 'update.json').write_text(json.dumps(dict(
        status='MLWINT_MODEL_UPDATE', format='pdf', models_version=VERSION, replaces='2026.11.1 PDF detector',
        files=files), indent=2))
    out = R3 / f'MLWINT_pdf_{VERSION}.zip'
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for f in sorted(work.rglob('*')):
            if f.is_file():
                z.write(f, str(f.relative_to(work)).replace('\\', '/'))
    print(json.dumps(dict(files=files), indent=1))
    print(f'\nPDF_UPDATE_BUNDLED  {out}  ({out.stat().st_size / 1e6:.1f} MB)  sha256 {r3.sha(out)}')


if __name__ == '__main__':
    main()
