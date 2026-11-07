"""T4 runtime. Win32 XGBoost: train past the old 2,000-round limit.

Stage 1 select : continue the round selector (fitted on inner_fit only, 2,000 rounds)
                 on inner_fit, measuring loss on inner_fit AND inner_stop every round.
                 Stop after 100 rounds without a meaningful (>=1e-5) drop in inner_stop
                 loss, or at 8,000 rounds. The round with the lowest inner_stop loss = N.
Stage 2 refit  : continue the final model (all 1,199,974 rows, 2,000 rounds) to N rounds.
Then           : old vs new on the development files (ranking metrics only) + learning
                 curves (overfitting check). The test files are not touched here.
Same parameters as the original run except device='cuda'. Old models are not changed.
Checkpoints every 50 rounds on Drive; re-running resumes.
"""
import gc, hashlib, json, os, shutil, threading, time
from pathlib import Path

import numpy as np
import psutil

ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
DATA = ROOT / 'inputs/win32-fourway-v1'
AUDIT = ROOT / 'experiments/win32-fourway-v1/leakage-audit-v1/report.json'
JOB = ROOT / 'experiments/win32-fourway-v1/xgboost-extended-v1'
WORK = Path('/content/MLWINT-work/win32-xgb-extended')
START, LIMIT, PATIENCE, GAIN, EVERY = 2000, 8000, 100, 1e-5, 50
DEVICE = 'cuda'
PARAMS = dict(objective='binary:logistic', eval_metric='logloss', tree_method='hist',
              grow_policy='depthwise', eta=0.05, max_depth=6, min_child_weight=1, reg_lambda=1.0,
              reg_alpha=0.0, gamma=0.0, colsample_bytree=0.8, subsample=1.0, max_bin=256,
              max_cached_hist_node=64, seed=42, validate_parameters=True, verbosity=1)


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


def make_iter(xgb, files, parts):
    """Feeds the shards to XGBoost one at a time (only rows whose part is in `parts`).
    On the GPU each shard is handed over as a CuPy array, so the binned training matrix
    is built directly in GPU memory (fast, and it keeps the 12.7 GB system RAM free)."""
    to_device = (lambda a: a)
    if DEVICE == 'cuda':
        import cupy
        to_device = cupy.asarray

    class Shards(xgb.DataIter):
        def __init__(self):
            self.i = 0
            super().__init__(cache_prefix=None)

        def next(self, input_data):
            while self.i < len(files):
                with np.load(files[self.i]) as z:
                    keep = np.isin(z['part'], parts)
                    X, y = z['X'][keep], z['y'][keep].astype(np.float32)
                self.i += 1
                if len(y):
                    input_data(data=to_device(X), label=to_device(y))
                    return True
            return False

        def reset(self):
            self.i = 0
    return Shards()


def evaluate(booster, evals, rnd):
    text = booster.eval_set(evals, rnd)
    return {p.split(':')[0].replace('-logloss', ''): float(p.split(':')[1]) for p in text.split()[1:]}


def run(xgb, stage, start_file, dtrain, evals, target, params):
    """Continue start_file to `target` rounds. With evals: plateau stopping on 'stop'.
    Checkpoint (model + state) to Drive every EVERY rounds; resume from it if present."""
    marker = JOB / f'{stage}-checkpoint.json'
    cache = [dtrain] + [m for m, _ in evals]
    if marker.exists():
        saved = read(marker)
        if sha(JOB / saved['file']) != saved['sha256']:
            raise ValueError(f'{stage} checkpoint checksum failed')
        state, model_file = saved['state'], JOB / saved['file']
    else:
        state, model_file = dict(done=START, history=[], best_loss=1e308, best_round=START,
                                 anchor_loss=1e308, waiting=0, finished=False), start_file
    booster = xgb.Booster(params, cache, model_file=str(model_file))
    if booster.num_boosted_rounds() != state['done']:
        raise ValueError('Checkpoint round count differs from its state')
    print(f'[{stage}] resuming at {state["done"]} rounds', flush=True)

    def track(rnd):
        v = evaluate(booster, evals, rnd)
        state['history'].append(dict(round=rnd, fit_logloss=v['fit'], stop_logloss=v['stop']))
        if v['stop'] < state['best_loss']:
            state['best_loss'], state['best_round'] = v['stop'], rnd
        if state['anchor_loss'] - state['best_loss'] >= GAIN:
            state['anchor_loss'], state['waiting'] = state['best_loss'], 0
        else:
            state['waiting'] += 1
        return state['waiting'] >= PATIENCE

    def save():
        local = WORK / f'{stage}-{state["done"]}.ubj'
        booster.save_model(local)
        checksum = sha(local)
        copy_checked(local, JOB / local.name, checksum)
        old = read(marker)['file'] if marker.exists() else None
        write(marker, dict(file=local.name, sha256=checksum, state=state))
        if old and old != local.name:
            (JOB / old).unlink(missing_ok=True)
        local.unlink()

    if evals and not state['history']:          # measure the 2,000-round starting point
        track(START)
        state['waiting'] = 0
    started = time.time()
    while not state['finished'] and state['done'] < target:
        booster.update(dtrain, state['done'])
        state['done'] += 1
        halted = track(state['done']) if evals else False
        state['finished'] = halted or state['done'] >= target
        if state['done'] % EVERY == 0 or state['finished']:
            save()
            msg = f'[{stage}] round {state["done"]}/{target}; {(time.time() - started) / 60:.1f} min'
            if evals:
                h = state['history'][-1]
                msg += (f'; fit={h["fit_logloss"]:.6f} stop={h["stop_logloss"]:.6f} '
                        f'best={state["best_loss"]:.6f}@{state["best_round"]} patience={state["waiting"]}/{PATIENCE}')
            print(msg, flush=True)
    return booster, state


def main():
    import xgboost as xgb
    from sklearn.metrics import average_precision_score, log_loss, roc_auc_score
    if xgb.__version__ != '3.4.1':
        raise RuntimeError('Install xgboost==3.4.1 (same version as the original training)')
    if read(AUDIT)['status'] != 'WIN32_SEPARATION_PASSED':
        raise ValueError('Leakage audit has not passed')
    manifest = read(DATA / 'manifest.json')
    JOB.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    protocol = dict(version='win32-xgb-extended-v1', script_sha256=sha(__file__),
        manifest_sha256=sha(DATA / 'manifest.json'), audit_sha256=sha(AUDIT),
        start_models={k: manifest['models'][k] for k in ('xgboost.ubj', 'xgboost_round_selector.ubj')},
        parameters=PARAMS, device=DEVICE, start_rounds=START, maximum_rounds=LIMIT,
        patience=PATIENCE, minimum_gain=GAIN, xgboost=xgb.__version__,
        selection='Round chosen on inner_stop (weeks 36-39) only; development/test unused for choosing')
    # The protocol is frozen once training has produced anything; before that a corrected
    # script may replace it (nothing trained yet, so nothing can be mixed).
    started = any((JOB / n).exists() for n in ('select-checkpoint.json', 'selection.json',
                                               'refit-checkpoint.json', 'report.json'))
    (frozen if started else write)(JOB / 'protocol.json', protocol)
    if (JOB / 'report.json').exists():
        print('Already finished:\n' + (JOB / 'report.json').read_text())
        return

    stop_ram = threading.Event()
    def guard():
        while not stop_ram.wait(2):
            if psutil.virtual_memory().available < 1024**3:
                print('Stopped: system RAM below 1 GiB. Drive checkpoint kept; re-run to resume.', flush=True)
                os._exit(75)
    threading.Thread(target=guard, daemon=True).start()

    print('Copying and verifying the Win32 data on local disk ...', flush=True)
    files = {n: copy_checked(DATA / n, WORK / 'data' / n, f['sha256'])
             for n, f in manifest['files'].items() if n.endswith('.npz')}
    train_files = sorted(str(p) for n, p in files.items() if n.startswith('train/'))
    for name in ('xgboost.ubj', 'xgboost_round_selector.ubj'):
        if sha(DATA / 'models' / name) != manifest['models'][name]:
            raise ValueError(f'Start model checksum failed: {name}')
    params = dict(PARAMS, device=DEVICE)

    # ---- stage 1: choose N on inner_stop ----
    if not (JOB / 'selection.json').exists():
        print('Building GPU matrices (inner_fit, inner_stop) ...', flush=True)
        dfit = xgb.QuantileDMatrix(make_iter(xgb, train_files, [1]), max_bin=PARAMS['max_bin'])
        dstop = xgb.QuantileDMatrix(make_iter(xgb, train_files, [2]), ref=dfit)
        if (dfit.num_row(), dstop.num_row()) != (manifest['counts']['inner_fit'], manifest['counts']['inner_stop']):
            raise ValueError('Unexpected inner_fit / inner_stop row counts')
        start = DATA / 'models/xgboost_round_selector.ubj'
        if xgb.Booster(model_file=str(start)).num_boosted_rounds() != START:
            raise ValueError('Selector is not the 2,000-round model')
        booster, state = run(xgb, 'select', start, dfit, [(dfit, 'fit'), (dstop, 'stop')], LIMIT, params)
        write(JOB / 'selection.json', dict(selected_rounds=state['best_round'], best_stop_logloss=state['best_loss'],
            start_stop_logloss=state['history'][0]['stop_logloss'], evaluated_rounds=state['done'],
            stopped_by='patience' if state['waiting'] >= PATIENCE else 'round limit', history=state['history']))
        del dfit, dstop, booster; gc.collect()
    selection = read(JOB / 'selection.json')
    N = selection['selected_rounds']
    print(f'Selected {N} rounds (inner_stop loss {selection["start_stop_logloss"]:.6f} at {START} -> '
          f'{selection["best_stop_logloss"]:.6f})', flush=True)

    # ---- stage 2: extend the final all-rows model to N ----
    final_name = 'XGB_WIN32_extended.ubj'
    if N <= START:
        print(f'No gain beyond {START} rounds: the original model is kept unchanged.', flush=True)
        shutil.copyfile(DATA / 'models/xgboost.ubj', WORK / final_name)
    else:
        print('Building GPU matrix (all 1,199,974 training rows) ...', flush=True)
        dall = xgb.QuantileDMatrix(make_iter(xgb, train_files, [1, 2]), max_bin=PARAMS['max_bin'])
        if dall.num_row() != manifest['counts']['train_rows']:
            raise ValueError('Unexpected training row count')
        booster, _ = run(xgb, 'refit', DATA / 'models/xgboost.ubj', dall, [], N, params)
        booster.save_model(WORK / final_name)
        del dall, booster; gc.collect()
    copy_checked(WORK / final_name, JOB / final_name, sha(WORK / final_name))
    new = xgb.Booster(model_file=str(JOB / final_name))
    if new.num_boosted_rounds() != max(N, START):
        raise ValueError('Final model has the wrong number of rounds')

    # ---- old vs new on development files (ranking quality only; thresholds come later) ----
    with np.load(files['dev/dev.npz']) as z:
        Xd, yd = z['X'], z['y'].astype(int)
    dd = xgb.DMatrix(Xd)
    old = xgb.Booster(model_file=str(DATA / 'models/xgboost.ubj'))
    dev = {}
    for name, m in ((f'old_{START}', old), (f'new_{max(N, START)}', new)):
        m.set_param({'device': DEVICE})
        p = m.predict(dd)
        dev[name] = dict(log_loss=float(log_loss(yd, p)), average_precision=float(average_precision_score(yd, p)),
                         roc_auc=float(roc_auc_score(yd, p)))

    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    h = selection['history']
    r = [x['round'] for x in h]
    gap = [x['stop_logloss'] - x['fit_logloss'] for x in h]
    fig, ax = plt.subplots(1, 2, figsize=(14, 5), constrained_layout=True)
    ax[0].plot(r, [x['fit_logloss'] for x in h], label='Training rows (inner_fit, weeks 0-35)')
    ax[0].plot(r, [x['stop_logloss'] for x in h], label='Unseen stopping rows (weeks 36-39)')
    ax[0].axvline(N, color='gray', ls='--', label=f'Selected {N}')
    ax[0].set(xlabel='Boosting round', ylabel='Log loss', title=f'Win32 XGBoost beyond {START} rounds')
    ax[1].plot(r, gap, color='#d93025')
    ax[1].axvline(N, color='gray', ls='--')
    ax[1].set(xlabel='Boosting round', ylabel='Stopping loss - training loss',
              title='Overfitting gap (rising = memorising training files)')
    for a in ax:
        a.grid(alpha=.2)
    ax[0].legend()
    for ext in ('png', 'pdf'):
        fig.savefig(JOB / f'learning_curve.{ext}', dpi=180)
    plt.close(fig)
    with open(JOB / 'learning_curve.csv', 'w') as f:
        f.write('round,fit_logloss,stop_logloss,gap\n')
        for x, g in zip(h, gap):
            f.write(f'{x["round"]},{x["fit_logloss"]!r},{x["stop_logloss"]!r},{g!r}\n')

    at = {x['round']: x for x in h}
    report = dict(status='WIN32_XGB_EXTENDED', model_file=final_name, model_sha256=sha(JOB / final_name),
        selected_rounds=N, evaluated_rounds=selection['evaluated_rounds'], stopped_by=selection['stopped_by'],
        inner_stop_logloss=dict(at_2000=selection['start_stop_logloss'], best=selection['best_stop_logloss']),
        overfitting_gap=dict(at_2000=gap[0], at_selected=at[N]['stop_logloss'] - at[N]['fit_logloss']),
        development_old_vs_new=dev, test_used=False,
        note='Development numbers are a sanity check; thresholds, calibration and test come in the 4-way step.')
    write(JOB / 'report.json', report)
    print(json.dumps(report, indent=2))
    stop_ram.set()


if __name__ == '__main__':
    main()
