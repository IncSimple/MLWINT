"""CPU High-RAM runtime. Win32 LightGBM: train past the old 2,000-round limit.

Same method as the XGBoost extension:
Stage 1 select : continue the round selector (inner_fit only, 2,000 rounds) on inner_fit,
                 measuring loss on inner_fit and on unseen inner_stop (weeks 36-39) every
                 round; stop after 100 rounds without a >=1e-5 drop, or at 8,000. Best = N.
Stage 2 refit  : continue the final model (all 1,199,974 rows, 2,000 rounds) to N rounds.
Then           : old vs new on development files + learning curve / overfitting gap.
Same parameters as the original LightGBM v2 run, on the CPU like the original (LightGBM's
GPU mode would change the numbers). Predictions use the exact feature values, so there is
no binning mismatch. Old models are not changed; test files are not touched.
Checkpoints every 50 rounds on Drive; re-running resumes.
"""
import gc, hashlib, json, os, shutil, threading, time
from pathlib import Path

import numpy as np
import psutil

ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
DATA = ROOT / 'inputs/win32-fourway-v1'
AUDIT = ROOT / 'experiments/win32-fourway-v1/leakage-audit-v1/report.json'
JOB = ROOT / 'experiments/win32-fourway-v1/lightgbm-extended-v1'
WORK = Path('/content/MLWINT-work/win32-lgbm-extended')
START, LIMIT, PATIENCE, GAIN, EVERY = 2000, 8000, 100, 1e-5, 50
FEATURES = 2568
PARAMS = dict(objective='binary', metric='binary_logloss', learning_rate=0.05, num_leaves=31,
              max_depth=-1, min_data_in_leaf=20, lambda_l1=0.0, lambda_l2=0.0, feature_fraction=0.8,
              bagging_fraction=1.0, bagging_freq=0, max_bin=255, bin_construct_sample_cnt=200000,
              histogram_pool_size=512, seed=42, force_col_wise=True, verbosity=-1)


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


def load(files, parts, rows):
    """Rows whose part is in `parts`, into one preallocated float32 matrix (no double copy)."""
    X = np.empty((rows, FEATURES), dtype=np.float32)
    y = np.empty(rows, dtype=np.float32)
    at = 0
    for f in files:
        with np.load(f) as z:
            keep = np.isin(z['part'], parts)
            n = int(keep.sum())
            X[at:at + n], y[at:at + n] = z['X'][keep], z['y'][keep]
        at += n
    if at != rows:
        raise ValueError(f'Expected {rows} rows, read {at}')
    return X, y


def logloss(y, margin):
    return float(np.mean(np.logaddexp(0.0, margin) - y * margin))


def run(lgb, stage, start_file, train_set, valid, target, params):
    """Continue start_file to `target` rounds; with `valid`, plateau stopping on 'stop'."""
    marker = JOB / f'{stage}-checkpoint.json'
    if marker.exists():
        saved = read(marker)
        if sha(JOB / saved['file']) != saved['sha256']:
            raise ValueError(f'{stage} checkpoint checksum failed')
        state, model_file = saved['state'], JOB / saved['file']
    else:
        state, model_file = dict(done=START, history=[], best_loss=1e308, best_round=START,
                                 anchor_loss=1e308, waiting=0, finished=False), start_file
    print(f'[{stage}] resuming at {state["done"]} rounds', flush=True)
    if state['finished'] or state['done'] >= target:
        return lgb.Booster(model_file=str(model_file)), state
    started = time.time()

    def save(model):
        local = WORK / f'{stage}-{state["done"]}.txt'
        model.save_model(str(local), num_iteration=-1)
        checksum = sha(local)
        copy_checked(local, JOB / local.name, checksum)
        old = read(marker)['file'] if marker.exists() else None
        write(marker, dict(file=local.name, sha256=checksum, state=state))
        if old and old != local.name:
            (JOB / old).unlink(missing_ok=True)
        local.unlink()

    def track(rnd, fit_loss, stop_loss):
        state['history'].append(dict(round=rnd, fit_logloss=fit_loss, stop_logloss=stop_loss))
        if stop_loss < state['best_loss']:
            state['best_loss'], state['best_round'] = stop_loss, rnd
        if state['anchor_loss'] - state['best_loss'] >= GAIN:
            state['anchor_loss'], state['waiting'] = state['best_loss'], 0
        else:
            state['waiting'] += 1
        return state['waiting'] >= PATIENCE

    def callback(env):
        number = env.model.current_iteration()
        if number != state['done'] + 1:
            raise RuntimeError(f'Unexpected round {number} after {state["done"]}')
        if valid and not state['history']:         # the 2,000-round starting point, from init scores
            track(START, logloss(train_set.get_label(), train_set.get_init_score()),
                  logloss(valid.get_label(), valid.get_init_score()))
            state['waiting'] = 0
        state['done'] = number
        halted = False
        if valid:
            v = {r[0]: float(r[2]) for r in env.evaluation_result_list}
            halted = track(number, v['fit'], v['stop'])
        state['finished'] = halted or number >= target
        if number % EVERY == 0 or state['finished']:
            save(env.model)
            msg = f'[{stage}] round {number}/{target}; {(time.time() - started) / 60:.1f} min'
            if valid:
                h = state['history'][-1]
                msg += (f'; fit={h["fit_logloss"]:.6f} stop={h["stop_logloss"]:.6f} '
                        f'best={state["best_loss"]:.6f}@{state["best_round"]} patience={state["waiting"]}/{PATIENCE}')
            print(msg, flush=True)
        if halted:
            raise lgb.callback.EarlyStopException(number - 1, env.evaluation_result_list)
    callback.order, callback.before_iteration = 30, False

    sets, names = ([train_set, valid], ['fit', 'stop']) if valid else ([], [])
    model = lgb.train(params, train_set, num_boost_round=target - state['done'], valid_sets=sets,
                      valid_names=names, init_model=str(model_file), callbacks=[callback],
                      keep_training_booster=True)
    state['finished'] = True
    save(model)
    return model, state


def main():
    import lightgbm as lgb
    from sklearn.metrics import average_precision_score, log_loss, roc_auc_score
    if lgb.__version__ != '4.7.0':
        raise RuntimeError('Install lightgbm==4.7.0 (same version as the original training)')
    if read(AUDIT)['status'] != 'WIN32_SEPARATION_PASSED':
        raise ValueError('Leakage audit has not passed')
    if psutil.virtual_memory().total < 40 * 1024**3:
        raise RuntimeError('Use a CPU runtime with High-RAM (needs about 30 GB)')
    manifest = read(DATA / 'manifest.json')
    counts = manifest['counts']
    JOB.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    params = dict(PARAMS, num_threads=os.cpu_count() or 2)
    protocol = dict(version='win32-lgbm-extended-v1', script_sha256=sha(__file__),
        manifest_sha256=sha(DATA / 'manifest.json'), audit_sha256=sha(AUDIT),
        start_models={k: manifest['models'][k] for k in ('lightgbm.txt', 'lightgbm_round_selector.txt')},
        parameters=PARAMS, start_rounds=START, maximum_rounds=LIMIT, patience=PATIENCE,
        minimum_gain=GAIN, lightgbm=lgb.__version__,
        selection='Round chosen on inner_stop (weeks 36-39) only; development/test unused for choosing')
    started = any((JOB / n).exists() for n in ('select-checkpoint.json', 'selection.json',
                                               'refit-checkpoint.json', 'report.json'))
    (frozen if started else write)(JOB / 'protocol.json', protocol)
    if (JOB / 'report.json').exists():
        print('Already finished:\n' + (JOB / 'report.json').read_text())
        return

    stop_ram = threading.Event()
    def guard():
        while not stop_ram.wait(2):
            if psutil.virtual_memory().available < 2 * 1024**3:
                print('Stopped: system RAM below 2 GiB. Drive checkpoint kept; re-run to resume.', flush=True)
                os._exit(75)
    threading.Thread(target=guard, daemon=True).start()

    print('Copying and verifying the Win32 data on local disk ...', flush=True)
    files = {n: copy_checked(DATA / n, WORK / 'data' / n, f['sha256'])
             for n, f in manifest['files'].items() if n.endswith('.npz')}
    train_files = sorted(str(p) for n, p in files.items() if n.startswith('train/'))
    for name in ('lightgbm.txt', 'lightgbm_round_selector.txt'):
        if sha(DATA / 'models' / name) != manifest['models'][name]:
            raise ValueError(f'Start model checksum failed: {name}')

    # ---- stage 1: choose N on inner_stop ----
    if not (JOB / 'selection.json').exists():
        print('Loading inner_fit and inner_stop rows ...', flush=True)
        Xf, yf = load(train_files, [1], counts['inner_fit'])
        Xs, ys = load(train_files, [2], counts['inner_stop'])
        start = DATA / 'models/lightgbm_round_selector.txt'
        if lgb.Booster(model_file=str(start)).current_iteration() != START:
            raise ValueError('Selector is not the 2,000-round model')
        dfit = lgb.Dataset(Xf, yf, params=params, free_raw_data=False)
        dstop = lgb.Dataset(Xs, ys, params=params, reference=dfit, free_raw_data=False)
        model, state = run(lgb, 'select', start, dfit, dstop, LIMIT, params)
        write(JOB / 'selection.json', dict(selected_rounds=state['best_round'], best_stop_logloss=state['best_loss'],
            start_stop_logloss=state['history'][0]['stop_logloss'], evaluated_rounds=state['done'],
            stopped_by='patience' if state['waiting'] >= PATIENCE else 'round limit', history=state['history']))
        del Xf, yf, Xs, ys, dfit, dstop, model; gc.collect()
    selection = read(JOB / 'selection.json')
    N = selection['selected_rounds']
    print(f'Selected {N} rounds (inner_stop loss {selection["start_stop_logloss"]:.6f} at {START} -> '
          f'{selection["best_stop_logloss"]:.6f})', flush=True)

    # ---- stage 2: extend the final all-rows model to N ----
    final_name = 'LGBM_WIN32_extended.txt'
    if N <= START:
        print(f'No gain beyond {START} rounds: the original model is kept unchanged.', flush=True)
        shutil.copyfile(DATA / 'models/lightgbm.txt', WORK / final_name)
    else:
        print('Loading all 1,199,974 training rows ...', flush=True)
        Xa, ya = load(train_files, [1, 2], counts['train_rows'])
        dall = lgb.Dataset(Xa, ya, params=params, free_raw_data=False)
        model, _ = run(lgb, 'refit', DATA / 'models/lightgbm.txt', dall, None, N, params)
        model.save_model(str(WORK / final_name), num_iteration=-1)
        del Xa, ya, dall, model; gc.collect()
    copy_checked(WORK / final_name, JOB / final_name, sha(WORK / final_name))
    new = lgb.Booster(model_file=str(JOB / final_name))
    if new.current_iteration() != max(N, START):
        raise ValueError('Final model has the wrong number of rounds')

    # ---- old vs new on development files ----
    with np.load(files['dev/dev.npz']) as z:
        Xd, yd = z['X'], z['y'].astype(int)
    old = lgb.Booster(model_file=str(DATA / 'models/lightgbm.txt'))
    dev = {}
    for name, m in ((f'old_{START}', old), (f'new_{max(N, START)}', new)):
        p = m.predict(Xd, num_threads=params['num_threads'])
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
    ax[0].set(xlabel='Boosting round', ylabel='Log loss', title=f'Win32 LightGBM beyond {START} rounds')
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
    report = dict(status='WIN32_LGBM_EXTENDED', model_file=final_name, model_sha256=sha(JOB / final_name),
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
