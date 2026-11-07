"""Phase 1 close-out: a MALICIOUS / SUSPICIOUS / CLEAN verdict policy for each Windows format.
Usage (any Colab runtime, CPU is enough; nothing is trained):  !python closeout_verdicts.py

Policy, fixed before running and identical for every format:
  MALICIOUS   ensemble score at or above the cut that flags <= 0.5% of clean files on the calibration set
              (stricter than the 1% used so far, leaving room for drift)
  SUSPICIOUS  between that and the cut that flags <= 3% of clean files ("needs a second opinion")
  CLEAN       below
Calibration sets (never the test):
  Win32, Win64, .NET : development weeks 40-51 scores already saved by the four-way runs
  PDF                : weeks 48-51 scores of the weeks 0-47 models (the shipped models are the weeks 0-51 ones)
Then each policy is checked once on the saved test predictions (weeks 52-63). A table of other cut-offs is
added for information only; it is not used to choose anything.
Writes experiments/phase1-closeout-v1/: one verdict_policy_<format>.json per format (the deployable detector
card: model files + checksums, calibration, ensemble weights, thresholds), the report, a CSV and a graph.
"""
import csv, hashlib, json
from pathlib import Path

import numpy as np

ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
OUT = ROOT / 'experiments/phase1-closeout-v1'
MALICIOUS_FPR, SUSPICIOUS_FPR = 0.005, 0.03
INFO_FPRS = (0.001, 0.0025, 0.005, 0.01, 0.02, 0.03, 0.05)
FORMATS = {
    'win32': dict(title='Win32', exp='experiments/win32-fourway-v1', run='four-way-full-dev-v1', calibration='dev',
                  jobs=dict(xgb='xgboost-extended-v1', lgbm='lightgbm-extended-v1', svm='svm-raw-v2')),
    'win64': dict(title='Win64', exp='experiments/win64-fourway-v1', run='four-way-v1', calibration='dev',
                  jobs=dict(xgb='xgboost-v1', lgbm='lightgbm-v1', svm='svm-raw-v1')),
    'dotnet': dict(title='.NET', exp='experiments/dotnet-fourway-v1', run='four-way-v1', calibration='dev',
                   jobs=dict(xgb='xgboost-v1', lgbm='lightgbm-v1', svm='svm-raw-v1')),
    'pdf': dict(title='PDF', exp='experiments/pdf-fourway-v1', run='retrain-0-51-v1', calibration='selector',
                jobs=None),
}


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


def expit(x):
    from scipy.special import expit as f
    return f(x)


def cut(score, y, fpr):
    benign = np.sort(score[y == 0])[::-1]
    allowed = int(np.floor(fpr * len(benign)))
    return float(np.nextafter(benign[allowed], np.inf)), allowed, len(benign)


def tiers(prob, mal, sus):
    return np.where(prob >= mal, 2, np.where(prob >= sus, 1, 0))       # 2 malicious, 1 suspicious, 0 clean


def one_format(key, cfg):
    run = ROOT / cfg['exp'] / cfg['run']
    roles = read(run / 'roles.json')
    weights = roles['ensemble_effective_weights']
    cal = {m: roles['calibration'][m] for m in weights}
    ens = lambda margins: sum(w * expit(cal[m]['slope'] * margins[m] + cal[m]['intercept']) for m, w in weights.items())

    # ---- calibration set (never the test) ----
    if cfg['calibration'] == 'dev':
        files = sorted((run / 'scores/dev').glob('*.npz'))
        parts = [dict(np.load(f)) for f in files]
        data = {k: np.concatenate([p[k] for p in parts]) for k in ['y', *weights]}
        source = f'development weeks 40-51 ({len(files)} saved score files)'
    else:
        with np.load(run / 'selector_scores.npz') as z:
            data = {k: z[k] for k in ['y', *weights]}
        source = 'weeks 48-51 scores of the weeks 0-47 models'
    cy, cp = data['y'].astype(int), ens(data)
    # Rebuilding the old 1% cut must give exactly the frozen one: proves the scores and weights are right.
    old_cut = roles['thresholds']['ENS']['threshold']
    rebuilt, _, _ = cut(cp, cy, 0.01)
    if not np.isclose(rebuilt, old_cut, rtol=0, atol=1e-12):
        raise ValueError(f'{key}: rebuilt 1% threshold {rebuilt} differs from the frozen {old_cut}')
    mal, mal_allowed, n_benign = cut(cp, cy, MALICIOUS_FPR)
    sus, sus_allowed, _ = cut(cp, cy, SUSPICIOUS_FPR)
    ct = tiers(cp, mal, sus)

    # ---- model files of the shipped ensemble ----
    if cfg['jobs']:
        models = {}
        for m in weights:
            job = ROOT / cfg['exp'] / cfg['jobs'][m]
            r = read(job / 'report.json')
            models[m] = dict(file=f'{cfg["exp"]}/{cfg["jobs"][m]}/{r["model_file"]}', sha256=r['model_sha256'])
    else:
        final = read(run / 'final_models.json')
        models = {m: dict(file=f'{cfg["exp"]}/{cfg["run"]}/{final[m]["file"]}', sha256=final[m]['sha256'])
                  for m in weights}
    for m, v in models.items():
        if sha(ROOT / v['file']) != v['sha256']:
            raise ValueError(f'{key}: model checksum failed: {v["file"]}')

    # ---- one check on the saved test predictions ----
    with np.load(run / 'test_predictions.npz') as z:
        ty, tp, week = z['y'].astype(int), z['ENS_probability'], z['week']
    tt = tiers(tp, mal, sus)
    share = lambda t, y, cls, tier: float(np.mean(t[y == cls] == tier))
    result = dict(
        format=cfg['title'], test_files=int(len(ty)),
        malware=dict(malicious=share(tt, ty, 1, 2), suspicious=share(tt, ty, 1, 1), clean_missed=share(tt, ty, 1, 0),
                     missed_files=int(((tt == 0) & (ty == 1)).sum())),
        clean_files=dict(malicious_false_alarm=share(tt, ty, 0, 2), suspicious=share(tt, ty, 0, 1),
                         clean=share(tt, ty, 0, 0), false_alarm_files=int(((tt == 2) & (ty == 0)).sum()),
                         suspicious_files=int(((tt == 1) & (ty == 0)).sum())),
        flagged_malware=float(np.mean(tt[ty == 1] >= 1)),
        old_1pct_rule=dict(recall=float(np.mean(tp[ty == 1] >= old_cut)), false_alarm_rate=float(np.mean(tp[ty == 0] >= old_cut))),
        calibration_check=dict(malware_malicious=share(ct, cy, 1, 2), malware_flagged=float(np.mean(ct[cy == 1] >= 1)),
                               clean_malicious=share(ct, cy, 0, 2), clean_suspicious=share(ct, cy, 0, 1)),
        weekly_missed_malware={int(w): float(np.mean(tt[(week == w) & (ty == 1)] == 0)) for w in np.unique(week)},
        weekly_malicious_false_alarms={int(w): float(np.mean(tt[(week == w) & (ty == 0)] == 2)) for w in np.unique(week)})
    info = []
    for f in INFO_FPRS:
        c, _, _ = cut(cp, cy, f)
        info.append(dict(format=cfg['title'], calibration_false_alarm_target=f, threshold=c,
                         test_recall=float(np.mean(tp[ty == 1] >= c)), test_false_alarm_rate=float(np.mean(tp[ty == 0] >= c))))

    card = dict(format=cfg['title'], key=key, verdicts=dict(
                    malicious=dict(rule='ensemble probability >= threshold', threshold=mal,
                                   calibration_false_alarm_target=MALICIOUS_FPR, allowed_clean_files=mal_allowed),
                    suspicious=dict(rule='threshold <= ensemble probability < malicious threshold', threshold=sus,
                                    calibration_false_alarm_target=SUSPICIOUS_FPR, allowed_clean_files=sus_allowed),
                    clean=dict(rule='below the suspicious threshold')),
                ensemble=dict(weights=weights, calibration=cal,
                              formula='sum over models of weight * sigmoid(slope * raw_margin + intercept)',
                              raw_margin=dict(xgb="XGBoost inplace_predict(predict_type='margin')",
                                              lgbm='LightGBM predict(raw_score=True)')),
                models=models, features='EMBER2024 thrember PEFeatureExtractor, 2,568 values',
                calibration_set=dict(source=source, files=int(len(cy)), clean_files=n_benign),
                test_check=result, roles_file=f'{cfg["exp"]}/{cfg["run"]}/roles.json')
    write(OUT / f'verdict_policy_{key}.json', card)
    return card, info


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cards, info = {}, []
    for key, cfg in FORMATS.items():
        print(f'{cfg["title"]} ...', flush=True)
        cards[key], rows = one_format(key, cfg)
        info += rows
    rows = []
    for key, c in cards.items():
        t = c['test_check']
        rows.append(dict(format=c['format'], test_files=t['test_files'],
                         malware_malicious=t['malware']['malicious'], malware_suspicious=t['malware']['suspicious'],
                         malware_missed=t['malware']['clean_missed'], malware_missed_files=t['malware']['missed_files'],
                         clean_false_alarm=t['clean_files']['malicious_false_alarm'],
                         clean_false_alarm_files=t['clean_files']['false_alarm_files'],
                         clean_suspicious=t['clean_files']['suspicious'],
                         clean_suspicious_files=t['clean_files']['suspicious_files'],
                         old_rule_recall=t['old_1pct_rule']['recall'],
                         old_rule_false_alarms=t['old_1pct_rule']['false_alarm_rate']))
    with open(OUT / 'closeout_table.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    with open(OUT / 'cutoff_table_information_only.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(info[0])); w.writeheader(); w.writerows(info)

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(13, 6.5), constrained_layout=True)
    labels, y = [], 0
    colors = {'MALICIOUS': '#d93025', 'SUSPICIOUS': '#f29900', 'CLEAN': '#1e8e3e'}
    for r in rows:
        for who, parts in ((f'{r["format"]}  malware', (r['malware_malicious'], r['malware_suspicious'], r['malware_missed'])),
                           (f'{r["format"]}  clean files', (r['clean_false_alarm'], r['clean_suspicious'],
                                                            1 - r['clean_false_alarm'] - r['clean_suspicious']))):
            left = 0
            for (name, color), v in zip(colors.items(), parts):
                ax.barh(y, 100 * v, left=100 * left, color=color, label=name if y == 0 else None)
                if v >= 0.004:
                    ax.text(100 * (left + v / 2), y, f'{100 * v:.1f}%', ha='center', va='center', fontsize=7,
                            color='white' if name != 'SUSPICIOUS' else 'black')
                left += v
            labels.append(who); y += 1
        y += 0.6
    ticks, pos = [], 0
    for r in rows:
        ticks += [pos, pos + 1]; pos += 2.6
    ax.set_yticks(ticks, labels, fontsize=9)
    ax.invert_yaxis()
    ax.set(xlim=(0, 100), xlabel='Share of test files (%)',
           title='Phase 1 verdicts on the test weeks 52-63 (thresholds set on calibration data only)\n'
                 f'MALICIOUS: <= {100 * MALICIOUS_FPR:g}% clean files flagged on calibration;  '
                 f'SUSPICIOUS: down to <= {100 * SUSPICIOUS_FPR:g}%')
    ax.legend(loc='upper left', bbox_to_anchor=(1.005, 1.0), fontsize=8)
    for ext in ('png', 'pdf'):
        fig.savefig(OUT / f'phase1_verdicts.{ext}', dpi=170)
    plt.close(fig)

    report = dict(status='PHASE1_CLOSEOUT_COMPLETE',
                  policy=dict(malicious_calibration_false_alarm_target=MALICIOUS_FPR,
                              suspicious_calibration_false_alarm_target=SUSPICIOUS_FPR),
                  formats=rows,
                  detector_cards={k: dict(file=f'experiments/phase1-closeout-v1/verdict_policy_{k}.json',
                                          sha256=sha(OUT / f'verdict_policy_{k}.json')) for k in cards},
                  note='Thresholds come from calibration data only. Win32 and PDF tests had been viewed before '
                       '(benchmarks); Win64 and .NET tests are fresh. The cut-off table is information only.')
    write(OUT / 'closeout_report.json', report)
    print(json.dumps({k: report[k] for k in ('status', 'policy', 'formats')}, indent=2))


if __name__ == '__main__':
    main()
