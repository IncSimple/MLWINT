"""Win64 tree models, trained from scratch.  Usage (Colab):
    !python train_win64_trees.py xgboost     -> T4 GPU runtime
    !python train_win64_trees.py lightgbm    -> CPU High-RAM runtime

Same parameters and the same method as the Win32 extended models:
Stage 1 select : train on inner_fit (weeks 0-35), measuring loss on inner_fit AND on the unseen
                 inner_stop weeks (36-39) every round. Stop after 100 rounds without a >=1e-5
                 drop in inner_stop loss, or at 10,000 rounds. Round with the lowest inner_stop
                 loss = N.
Stage 2 refit  : train a new model on all training rows (weeks 0-39) for exactly N rounds.
Then           : development sanity numbers (weeks 40-51), training-vs-unseen gaps and learning
                 curves (overfitting check). The sealed test files are never opened here.
Checkpoints every 50 rounds on Drive; re-running the same command resumes.
"""
import gc, hashlib, json, os, shutil, sys, threading, time
from pathlib import Path

import numpy as np
import sys as _sys
FMT = _sys.argv[1].lower() if len(_sys.argv) > 1 else ''
if FMT not in ('pdf', 'elf', 'dotnet', 'win64'):
    raise SystemExit('First argument must be the format: pdf | elf | dotnet')
TAG = FMT.upper()
import psutil

ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
DATA = ROOT / f'inputs/{FMT}-v1'
AUDIT = ROOT / f'experiments/{FMT}-fourway-v1/leakage-audit-v1/report.json'
EXP = ROOT / f'experiments/{FMT}-fourway-v1'
LIMIT, PATIENCE, GAIN, EVERY = 10000, 100, 1e-5, 50
FEATURES, GAP_SAMPLE, SEED = 2568, 40000, 42
MODELS = {
    'xgboost': dict(job='xgboost-v1', work=f'{FMT}-xgb', final=f'XGB_{TAG}.ubj', status=f'{TAG}_XGB_TRAINED',
                    version='3.4.1', title=f'{TAG} XGBoost',
                    params=dict(objective='binary:logistic', eval_metric='logloss', tree_method='hist',
                                grow_policy='depthwise', eta=0.05, max_depth=6, min_child_weight=1,
                                reg_lambda=1.0, reg_alpha=0.0, gamma=0.0, colsample_bytree=0.8, subsample=1.0,
                                max_bin=256, max_cached_hist_node=64, seed=42, validate_parameters=True,
                                verbosity=1)),
    'lightgbm': dict(job='lightgbm-v1', work=f'{FMT}-lgbm', final=f'LGBM_{TAG}.txt', status=f'{TAG}_LGBM_TRAINED',
                     version='4.7.0', title=f'{TAG} LightGBM',
                     params=dict(objective='binary', metric='binary_logloss', learning_rate=0.05, num_leaves=31,
                                 max_depth=-1, min_data_in_leaf=20, lambda_l1=0.0, lambda_l2=0.0,
                                 feature_fraction=0.8, bagging_fraction=1.0, bagging_freq=0, max_bin=255,
                                 bin_construct_sample_cnt=200000, histogram_pool_size=512, seed=42,
                                 force_col_wise=True, verbosity=-1)),
}
DEVICE = 'cuda' if shutil.which('nvidia-smi') else 'cpu'   # XGBoost only: GPU when the runtime has one


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


def load(files, parts, rows=None):
    """Rows whose part is in `parts`, in one preallocated float32 matrix."""
    if rows is None:
        rows = 0
        for f in files:
            with np.load(f) as z:
                rows += int(np.isin(z['part'], parts).sum())
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


class Plateau:
    """Training state + the stopping rule, saved with every checkpoint."""
    def __init__(self, state=None):
        self.s = state or dict(done=0, history=[], best_loss=1e308, best_round=0, anchor_loss=1e308,
                               waiting=0, finished=False)

    def track(self, rnd, fit_loss, stop_loss):
        s = self.s
        s['history'].append(dict(round=rnd, fit_logloss=fit_loss, stop_logloss=stop_loss))
        if stop_loss < s['best_loss']:
            s['best_loss'], s['best_round'] = stop_loss, rnd
        if s['anchor_loss'] - s['best_loss'] >= GAIN:
            s['anchor_loss'], s['waiting'] = s['best_loss'], 0
        else:
            s['waiting'] += 1
        return s['waiting'] >= PATIENCE

    def message(self, stage, target, started):
        s = self.s
        msg = f'[{stage}] round {s["done"]}/{target}; {(time.time() - started) / 60:.1f} min'
        if s['history']:
            h = s['history'][-1]
            msg += (f'; fit={h["fit_logloss"]:.6f} stop={h["stop_logloss"]:.6f} '
                    f'best={s["best_loss"]:.6f}@{s["best_round"]} patience={s["waiting"]}/{PATIENCE}')
        return msg


def checkpoint(job, work, stage, state, save_model, ext):
    marker = job / f'{stage}-checkpoint.json'
    local = work / f'{stage}-{state["done"]}.{ext}'
    save_model(local)
    checksum = sha(local)
    copy_checked(local, job / local.name, checksum)
    old = read(marker)['file'] if marker.exists() else None
    write(marker, dict(file=local.name, sha256=checksum, state=state))
    if old and old != local.name:
        (job / old).unlink(missing_ok=True)
    local.unlink()


def resume(job, stage):
    marker = job / f'{stage}-checkpoint.json'
    if not marker.exists():
        return Plateau(), None
    saved = read(marker)
    if sha(job / saved['file']) != saved['sha256']:
        raise ValueError(f'{stage} checkpoint checksum failed')
    return Plateau(saved['state']), job / saved['file']


# ---------------------------------------------------------------- XGBoost
def xgb_iter(xgb, files, parts):
    """Shards fed one at a time; on the GPU as CuPy arrays (binned matrix built in GPU memory)."""
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


def xgb_run(xgb, job, work, stage, dtrain, evals, target, params):
    plateau, model_file = resume(job, stage)
    s = plateau.s
    cache = [dtrain] + [m for m, _ in evals]
    booster = xgb.Booster(params, cache, model_file=str(model_file) if model_file else None)
    if booster.num_boosted_rounds() != s['done']:
        raise ValueError('Checkpoint round count differs from its state')
    print(f'[{stage}] starting at round {s["done"]}', flush=True)
    started = time.time()
    while not s['finished'] and s['done'] < target:
        booster.update(dtrain, s['done'])
        s['done'] += 1
        halted = False
        if evals:
            text = booster.eval_set(evals, s['done'])
            v = {p.split(':')[0].replace('-logloss', ''): float(p.split(':')[1]) for p in text.split()[1:]}
            halted = plateau.track(s['done'], v['fit'], v['stop'])
        s['finished'] = halted or s['done'] >= target
        if s['done'] % EVERY == 0 or s['finished']:
            checkpoint(job, work, stage, s, lambda p: booster.save_model(p), 'ubj')
            print(plateau.message(stage, target, started), flush=True)
    return booster, s


def train_xgboost(cfg, job, work, files, counts):
    import xgboost as xgb
    params = dict(cfg['params'], device=DEVICE)
    train_files = sorted(str(p) for n, p in files.items() if n.startswith('train/'))
    if not (job / 'selection.json').exists():
        print('Building matrices (inner_fit, inner_stop) ...', flush=True)
        dfit = xgb.QuantileDMatrix(xgb_iter(xgb, train_files, [1]), max_bin=params['max_bin'])
        dstop = xgb.QuantileDMatrix(xgb_iter(xgb, train_files, [2]), ref=dfit)
        if (dfit.num_row(), dstop.num_row()) != (counts['inner_fit'], counts['inner_stop']):
            raise ValueError('Unexpected inner_fit / inner_stop row counts')
        _, s = xgb_run(xgb, job, work, 'select', dfit, [(dfit, 'fit'), (dstop, 'stop')], LIMIT, params)
        save_selection(job, s)
        del dfit, dstop; gc.collect()
    N = read(job / 'selection.json')['selected_rounds']
    final = work / cfg['final']
    if not (job / cfg['final']).exists():
        print(f'Building matrix (all {counts["train_rows"]:,} training rows) ...', flush=True)
        dall = xgb.QuantileDMatrix(xgb_iter(xgb, train_files, [1, 2]), max_bin=params['max_bin'])
        if dall.num_row() != counts['train_rows']:
            raise ValueError('Unexpected training row count')
        booster, _ = xgb_run(xgb, job, work, 'refit', dall, [], N, params)
        booster.save_model(final)
        copy_checked(final, job / cfg['final'], sha(final))
        del dall, booster; gc.collect()
    model = xgb.Booster(model_file=str(job / cfg['final']))
    if model.num_boosted_rounds() != N:
        raise ValueError('Final model has the wrong number of rounds')
    model.set_param({'device': DEVICE})
    return N, lambda X: model.inplace_predict(X, predict_type='margin').astype(np.float64)


# ---------------------------------------------------------------- LightGBM
def lgb_run(lgb, job, work, stage, train_set, valid, target, params):
    plateau, model_file = resume(job, stage)
    s = plateau.s
    print(f'[{stage}] starting at round {s["done"]}', flush=True)
    if s['finished'] or s['done'] >= target:
        return lgb.Booster(model_file=str(model_file)), s
    started = time.time()

    def callback(env):
        number = env.model.current_iteration()
        if number != s['done'] + 1:
            raise RuntimeError(f'Unexpected round {number} after {s["done"]}')
        s['done'] = number
        halted = False
        if valid is not None:
            v = {r[0]: float(r[2]) for r in env.evaluation_result_list}
            halted = plateau.track(number, v['fit'], v['stop'])
        s['finished'] = halted or number >= target
        if number % EVERY == 0 or s['finished']:
            checkpoint(job, work, stage, s, lambda p: env.model.save_model(str(p), num_iteration=-1), 'txt')
            print(plateau.message(stage, target, started), flush=True)
        if halted:
            raise lgb.callback.EarlyStopException(number - 1, env.evaluation_result_list)
    callback.order, callback.before_iteration = 30, False

    sets, names = ([train_set, valid], ['fit', 'stop']) if valid is not None else ([], [])
    model = lgb.train(params, train_set, num_boost_round=target - s['done'], valid_sets=sets, valid_names=names,
                      init_model=str(model_file) if model_file else None, callbacks=[callback],
                      keep_training_booster=True)
    if not s['finished']:
        s['finished'] = True
        checkpoint(job, work, stage, s, lambda p: model.save_model(str(p), num_iteration=-1), 'txt')
    return model, s


def train_lightgbm(cfg, job, work, files, counts):
    import lightgbm as lgb
    threads = os.cpu_count() or 2
    params = dict(cfg['params'], num_threads=threads)
    train_files = sorted(str(p) for n, p in files.items() if n.startswith('train/'))
    if not (job / 'selection.json').exists():
        print('Loading inner_fit and inner_stop rows ...', flush=True)
        Xf, yf = load(train_files, [1], counts['inner_fit'])
        Xs, ys = load(train_files, [2], counts['inner_stop'])
        dfit = lgb.Dataset(Xf, yf, params=params, free_raw_data=False)
        dstop = lgb.Dataset(Xs, ys, params=params, reference=dfit, free_raw_data=False)
        _, s = lgb_run(lgb, job, work, 'select', dfit, dstop, LIMIT, params)
        save_selection(job, s)
        del Xf, yf, Xs, ys, dfit, dstop; gc.collect()
    N = read(job / 'selection.json')['selected_rounds']
    final = work / cfg['final']
    if not (job / cfg['final']).exists():
        print(f'Loading all {counts["train_rows"]:,} training rows ...', flush=True)
        Xa, ya = load(train_files, [1, 2], counts['train_rows'])
        dall = lgb.Dataset(Xa, ya, params=params, free_raw_data=False)
        model, _ = lgb_run(lgb, job, work, 'refit', dall, None, N, params)
        model.save_model(str(final), num_iteration=-1)
        copy_checked(final, job / cfg['final'], sha(final))
        del Xa, ya, dall, model; gc.collect()
    model = lgb.Booster(model_file=str(job / cfg['final']))
    if model.current_iteration() != N:
        raise ValueError('Final model has the wrong number of rounds')
    return N, lambda X: model.predict(X, raw_score=True, num_threads=threads).astype(np.float64)


# ---------------------------------------------------------------- shared
def save_selection(job, s):
    write(job / 'selection.json', dict(selected_rounds=s['best_round'], best_stop_logloss=s['best_loss'],
        evaluated_rounds=s['done'], stopped_by='patience' if s['waiting'] >= PATIENCE else 'round limit',
        history=s['history']))


def metrics(y, margin):
    from sklearn.metrics import average_precision_score, roc_auc_score
    y = y.astype(int)
    loss = float(np.mean(np.logaddexp(0.0, margin) - y * margin))
    return dict(rows=int(len(y)), log_loss=loss, average_precision=float(average_precision_score(y, margin)),
                roc_auc=float(roc_auc_score(y, margin)), error_rate_at_0_5=float(np.mean((margin > 0) != (y == 1))))


def main(model_name):
    cfg = MODELS[model_name]
    job, work = EXP / cfg['job'], Path('/content/MLWINT-work') / cfg['work']
    if model_name == 'xgboost':
        import xgboost as lib
        if DEVICE == 'cuda':
            import cupy  # noqa: F401  (fails early if this is not a GPU runtime)
    else:
        import lightgbm as lib
    if lib.__version__ != cfg['version']:
        raise RuntimeError(f'Install {model_name}=={cfg["version"]} (same version as Win32)')
    if read(AUDIT)['status'] != f'{TAG}_SEPARATION_PASSED':
        raise ValueError('Leakage audit has not passed')
    manifest = read(DATA / 'manifest.json')
    if manifest['status'] != f'{TAG}_EXPORT_READY':
        raise ValueError('Unexpected export status')
    counts = manifest['counts']
    need = counts['train_rows'] * FEATURES * 4 * 4 + 3 * 1024**3
    if psutil.virtual_memory().total < need:
        raise RuntimeError(f'Needs about {need / 1024**3:.0f} GB of RAM: switch on High-RAM')
    job.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    protocol = dict(version=f'{FMT}-{model_name}-v1', script_sha256=sha(__file__),
        manifest_sha256=sha(DATA / 'manifest.json'), audit_sha256=sha(AUDIT), parameters=cfg['params'],
        device=DEVICE if model_name == 'xgboost' else 'cpu', maximum_rounds=LIMIT, patience=PATIENCE,
        minimum_gain=GAIN, library_version=lib.__version__,
        selection='Rounds chosen on inner_stop (weeks 36-39) only; development and test unused for choosing')
    started = any((job / n).exists() for n in ('select-checkpoint.json', 'selection.json', 'refit-checkpoint.json',
                                                cfg['final'], 'report.json'))
    (frozen if started else write)(job / 'protocol.json', protocol)
    if (job / 'report.json').exists():
        print('Already finished:\n' + (job / 'report.json').read_text())
        return

    stop_ram = threading.Event()
    def guard():
        while not stop_ram.wait(2):
            if psutil.virtual_memory().available < 1024**3:
                print('Stopped: system RAM below 1 GiB. Drive checkpoint kept; re-run to resume.', flush=True)
                os._exit(75)
    threading.Thread(target=guard, daemon=True).start()

    print('Copying and verifying training + development data on local disk (test files are not copied) ...',
          flush=True)
    files = {n: copy_checked(DATA / n, work / 'data' / n, f['sha256'])
             for n, f in manifest['files'].items() if n.startswith(('train/', 'dev/'))}
    train = train_xgboost if model_name == 'xgboost' else train_lightgbm
    N, margin = train(cfg, job, work, files, counts)
    selection = read(job / 'selection.json')
    print(f'Selected {N} rounds (best inner_stop loss {selection["best_stop_logloss"]:.6f}); final model ready.',
          flush=True)

    # ---- final model: seen training rows vs unseen development rows ----
    train_files = sorted(str(p) for n, p in files.items() if n.startswith('train/'))
    dev_files = sorted(str(p) for n, p in files.items() if n.startswith('dev/'))
    Xt, yt = load(train_files, [1, 2], counts['train_rows'])
    pick = np.sort(np.random.default_rng(SEED).choice(len(yt), min(GAP_SAMPLE, len(yt)), replace=False))
    Xt, yt = Xt[pick], yt[pick]
    gc.collect()
    Xd, yd = load(dev_files, [3], counts['dev_rows'])
    seen, unseen = metrics(yt, margin(Xt)), metrics(yd, margin(Xd))
    del Xt, Xd; gc.collect()

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
    ax[0].set(xlabel='Boosting round', ylabel='Log loss', yscale='log', title=f'{cfg["title"]}: learning curve')
    ax[1].plot(r, gap, color='#d93025')
    ax[1].axvline(N, color='gray', ls='--')
    ax[1].set(xlabel='Boosting round', ylabel='Stopping loss - training loss',
              title='Overfitting gap (rising = memorising training files)')
    for a in ax:
        a.grid(alpha=.2)
    ax[0].legend()
    for ext in ('png', 'pdf'):
        fig.savefig(job / f'learning_curve.{ext}', dpi=180)
    plt.close(fig)
    with open(job / 'learning_curve.csv', 'w') as f:
        f.write('round,fit_logloss,stop_logloss,gap\n')
        for x, g in zip(h, gap):
            f.write(f'{x["round"]},{x["fit_logloss"]!r},{x["stop_logloss"]!r},{g!r}\n')

    at = {x['round']: x for x in h}
    report = dict(status=cfg['status'], model_file=cfg['final'], model_sha256=sha(job / cfg['final']),
        selected_rounds=N, evaluated_rounds=selection['evaluated_rounds'], stopped_by=selection['stopped_by'],
        selector=dict(inner_fit_logloss=at[N]['fit_logloss'], inner_stop_logloss=at[N]['stop_logloss'],
                      gap=at[N]['stop_logloss'] - at[N]['fit_logloss']),
        final_model=dict(training_sample=seen, development=unseen,
                         log_loss_gap=unseen['log_loss'] - seen['log_loss'],
                         average_precision_gap=seen['average_precision'] - unseen['average_precision']),
        test_used=False,
        note='Development numbers are a sanity check; calibration, thresholds and the sealed test come in the '
             '4-way step. Training-sample numbers are on files the final model was trained on.')
    write(job / 'report.json', report)
    print(json.dumps({k: v for k, v in report.items() if k != 'note'}, indent=2))
    stop_ram.set()


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[2] not in MODELS:
        raise SystemExit('Usage: python train_format_trees.py pdf|elf|dotnet xgboost|lightgbm')
    main(sys.argv[2])
