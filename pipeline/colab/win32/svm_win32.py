"""CPU High-RAM runtime. Win32 candidate SVM: linear SVM on the raw 2,568 EMBER2024 features.

Preprocessing (learned from inner_fit rows only, then frozen inside the model file):
  signed log   x -> sign(x) * log(1 + |x|)    (tames byte counts and file sizes)
  standardise  with inner_fit mean / std; constant features -> 0; clip to +-10
Stage 1 select : SGD hinge-loss SVMs with 4 alphas trained side by side on inner_fit
                 (weeks 0-35). After every epoch: average precision on unseen inner_stop
                 (weeks 36-39). A setting stops after 3 epochs without +1e-4 AP.
                 Setting and epoch are chosen on inner_stop only.
Stage 2 refit  : same setting and number of epochs on all 1,199,974 training rows
                 (same as the XGBoost / LightGBM final models).
Overfitting    : every epoch, AP and hinge loss on a fixed 119,986-row sample of inner_fit
                 versus inner_stop (the gap), plus development AP of the inner_fit-only
                 model versus the refit model.
Development    : sanity AP / ROC AUC only; thresholds and calibration come in the 4-way step.
Test rows are never loaded. Checkpoints after every epoch on Drive; re-running resumes.
"""
import csv, gc, hashlib, json, os, pickle, shutil, threading, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import psutil

ROOT = Path('/content/drive/MyDrive/MLWINT-colab')
DATA = ROOT / 'inputs/win32-fourway-v1'
AUDIT = ROOT / 'experiments/win32-fourway-v1/leakage-audit-v1/report.json'
JOB = ROOT / 'experiments/win32-fourway-v1/svm-raw-v1'
WORK = Path('/content/MLWINT-work/win32-svm')
FEATURES, CLIP, BATCH = 2568, 10.0, 50000
ALPHAS = (1e-7, 1e-6, 1e-5, 1e-4)
MAX_EPOCHS, PATIENCE, MIN_GAIN, SEED = 15, 3, 1e-4, 42
MIN_RAM_GIB = 40


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


def load_train(files, rows):
    """inner_fit (1) and inner_stop (2) rows into one preallocated float32 matrix."""
    X = np.empty((rows, FEATURES), dtype=np.float32)
    y, part = np.empty(rows, dtype=np.int8), np.empty(rows, dtype=np.int8)
    at = 0
    for number, f in enumerate(files, 1):
        with np.load(f) as z:
            keep = np.isin(z['part'], [1, 2])
            n = int(keep.sum())
            X[at:at + n], y[at:at + n], part[at:at + n] = z['X'][keep], z['y'][keep], z['part'][keep]
        at += n
        if number % 10 == 0 or number == len(files):
            print(f'  loaded shard {number}/{len(files)}', flush=True)
    if at != rows:
        raise ValueError(f'Expected {rows} rows, read {at}')
    return X, y, part


def signed_log_(X, step=20000):
    """In place, in chunks. Returns how many non-finite values were set to 0."""
    bad = 0
    for i in range(0, len(X), step):
        b = X[i:i + step]
        np.copyto(b, np.sign(b) * np.log1p(np.abs(b)))
        mask = ~np.isfinite(b)
        bad += int(mask.sum())
        b[mask] = 0
    return bad


def fit_scaler(X, rows, step=20000):
    """Two passes (mean, then squared deviations) so constant features come out exactly 0."""
    total, squares = np.zeros(FEATURES), np.zeros(FEATURES)
    for i in range(0, len(rows), step):
        total += X[rows[i:i + step]].sum(0, dtype=np.float64)
    mean = total / len(rows)
    for i in range(0, len(rows), step):
        squares += ((X[rows[i:i + step]].astype(np.float64) - mean) ** 2).sum(0)
    std = np.sqrt(squares / len(rows))
    inv = np.where(std > 1e-6, 1 / np.where(std > 1e-6, std, 1), 0.0)
    return mean.astype(np.float32), inv.astype(np.float32)


def standardise_(X, mean, inv, step=20000):
    for i in range(0, len(X), step):
        b = X[i:i + step]
        b -= mean; b *= inv
        np.clip(b, -CLIP, CLIP, out=b)


def margin(X, rows, coef, intercept, step=50000):
    c = coef.astype(np.float32)
    return np.concatenate([X[rows[i:i + step]] @ c for i in range(0, len(rows), step)]) + intercept


def scores(y, m):
    from sklearn.metrics import average_precision_score
    s = 2 * y.astype(np.float64) - 1
    benign = np.sort(m[y == 0])[::-1]
    cut = np.nextafter(benign[int(np.floor(0.01 * len(benign)))], np.inf)
    return dict(ap=float(average_precision_score(y, m)), hinge=float(np.mean(np.maximum(0, 1 - s * m))),
                recall_at_1pct_fpr=float(np.mean(m[y == 1] >= cut)))


def new_model(alpha):
    from sklearn.linear_model import SGDClassifier
    return SGDClassifier(loss='hinge', penalty='l2', alpha=alpha, learning_rate='optimal',
                         fit_intercept=True, shuffle=False, average=True, random_state=SEED)


def one_epoch(X, y, rows, models, epoch, threads, label):
    """One shuffled pass over `rows`, every model sees the same batches."""
    perm = np.random.default_rng(SEED + epoch).permutation(rows)
    batches = range(0, len(perm), BATCH)
    for number, i in enumerate(batches, 1):
        idx = perm[i:i + BATCH]
        Xb, yb = X[idx].astype(np.float64), y[idx].astype(np.int64)
        with ThreadPoolExecutor(threads) as pool:
            list(pool.map(lambda m: m.partial_fit(Xb, yb, classes=np.array([0, 1])), models))
        if number % 5 == 0 or number == len(batches):
            print(f'  [{label}] epoch {epoch}: batch {number}/{len(batches)}', flush=True)


class Checkpoint:
    """Pickled state on Drive; keeps the current and the previous file."""
    def __init__(self, name):
        self.marker, self.previous, self.name = JOB / f'{name}-checkpoint.json', \
            JOB / f'{name}-checkpoint.previous.json', name

    def load(self):
        for m in (self.marker, self.previous):
            if m.exists():
                saved = read(m)
                if (JOB / saved['file']).exists() and sha(JOB / saved['file']) == saved['sha256']:
                    with open(JOB / saved['file'], 'rb') as f:
                        return pickle.load(f)
        if self.marker.exists():
            raise ValueError(f'No valid {self.name} checkpoint survived checksum verification')
        return None

    def save(self, state):
        local = WORK / f'{self.name}-{state["epoch"]}.pkl'
        with open(local, 'wb') as f:
            pickle.dump(state, f)
        checksum = sha(local)
        copy_checked(local, JOB / local.name, checksum)
        if self.marker.exists():
            write(self.previous, read(self.marker))
        write(self.marker, dict(file=local.name, sha256=checksum, epoch=state['epoch']))
        keep = {read(m)['file'] for m in (self.marker, self.previous) if m.exists()}
        for p in JOB.glob(f'{self.name}-*.pkl'):
            if p.name not in keep:
                p.unlink()
        local.unlink()


def save_model(path, coef, intercept, mean, inv, alpha, epochs, rows):
    np.savez(path, coefficient=np.asarray(coef, np.float64), intercept=np.array([intercept]),
             mean=mean, inverse_std=inv, clip=np.array([CLIP]), transform=np.array(['signed_log1p']),
             alpha=np.array([alpha]), epochs=np.array([epochs]), training_rows=np.array([rows]))


# ------------------------------------------------------------------ main
def main():
    import sklearn
    from sklearn.metrics import average_precision_score, roc_auc_score
    if read(AUDIT)['status'] != 'WIN32_SEPARATION_PASSED':
        raise ValueError('Leakage audit has not passed')
    if psutil.virtual_memory().total < MIN_RAM_GIB * 1024**3:
        raise RuntimeError('Use a CPU runtime with High-RAM (needs about 20 GB)')
    manifest = read(DATA / 'manifest.json')
    counts = manifest['counts']
    JOB.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    protocol = dict(version='win32-svm-raw-v1', script_sha256=sha(__file__),
        manifest_sha256=sha(DATA / 'manifest.json'), audit_sha256=sha(AUDIT), features=FEATURES,
        preprocessing='signed log1p, standardise with inner_fit mean/std (constant -> 0), clip +-10',
        model='sklearn SGDClassifier(loss=hinge, penalty=l2, learning_rate=optimal, average=True), partial_fit, '
              f'batches of {BATCH}', alphas=list(ALPHAS), max_epochs=MAX_EPOCHS, patience=PATIENCE,
        minimum_ap_gain=MIN_GAIN, seed=SEED, sklearn=sklearn.__version__, numpy=np.__version__,
        selection='Alpha and epoch chosen by inner_stop (weeks 36-39) AP; development/test unused for choosing',
        final='Refit with the chosen alpha and epochs on all training rows (inner_fit + inner_stop)')
    started = any((JOB / n).exists() for n in ('select-checkpoint.json', 'selection.json',
                                               'refit-checkpoint.json', 'report.json'))
    (frozen if started else write)(JOB / 'protocol.json', protocol)
    if (JOB / 'report.json').exists():
        report = read(JOB / 'report.json')
        if sha(JOB / report['model_file']) != report['model_sha256']:
            raise ValueError('Saved SVM checksum failed')
        print('Already finished:\n' + json.dumps(report, indent=2))
        return

    stop_ram = threading.Event()
    def guard():
        while not stop_ram.wait(2):
            if psutil.virtual_memory().available < 2 * 1024**3:
                print('Stopped: system RAM below 2 GiB. Drive checkpoint kept; re-run to resume.', flush=True)
                os._exit(75)
    threading.Thread(target=guard, daemon=True).start()
    threads = max(1, min(len(ALPHAS), os.cpu_count() or 1))

    print('Copying and verifying the Win32 training + development data on local disk ...', flush=True)
    files = {n: copy_checked(DATA / n, WORK / 'data' / n, f['sha256'])
             for n, f in manifest['files'].items()
             if n.endswith('.npz') and (n.startswith('train/') or n.startswith('dev/'))}
    train_files = sorted(str(p) for n, p in files.items() if n.startswith('train/'))
    print('Loading training rows ...', flush=True)
    X, y, part = load_train(train_files, counts['train_rows'])
    fit_rows, stop_rows = np.flatnonzero(part == 1), np.flatnonzero(part == 2)
    if (len(fit_rows), len(stop_rows)) != (counts['inner_fit'], counts['inner_stop']):
        raise ValueError('Unexpected inner_fit / inner_stop sizes')
    print('Preprocessing (signed log, inner_fit-only standardisation) ...', flush=True)
    nonfinite = signed_log_(X)
    mean, inv = fit_scaler(X, fit_rows)
    standardise_(X, mean, inv)
    fit_sample = np.sort(np.random.default_rng(SEED).choice(fit_rows, len(stop_rows), replace=False))
    yfs, ys = y[fit_sample].astype(int), y[stop_rows].astype(int)

    # ---- stage 1: choose alpha and epoch on inner_stop ----
    if not (JOB / 'selection.json').exists():
        ck = Checkpoint('select')
        state = ck.load() or dict(epoch=0, configs=[dict(
            alpha=a, stopped=False, waiting=0, best_ap=-1.0, anchor_ap=-1.0, best_epoch=0,
            best_coef=None, best_intercept=None, history=[], note='', model=new_model(a)) for a in ALPHAS])
        print(f'[select] resuming after epoch {state["epoch"]}', flush=True)
        while state['epoch'] < MAX_EPOCHS and not all(c['stopped'] for c in state['configs']):
            epoch, t0 = state['epoch'] + 1, time.time()
            active = [c for c in state['configs'] if not c['stopped']]
            one_epoch(X, y, fit_rows, [c['model'] for c in active], epoch, threads, 'select')
            for c in active:
                coef, b = c['model'].coef_.ravel(), float(c['model'].intercept_[0])
                if not (np.isfinite(coef).all() and np.isfinite(b)):
                    c['stopped'], c['note'] = True, 'diverged'
                    continue
                f, s = scores(yfs, margin(X, fit_sample, coef, b)), scores(ys, margin(X, stop_rows, coef, b))
                c['history'].append(dict(epoch=epoch, fit_ap=f['ap'], stop_ap=s['ap'], fit_hinge=f['hinge'],
                                         stop_hinge=s['hinge'], stop_recall_at_1pct_fpr=s['recall_at_1pct_fpr']))
                if s['ap'] > c['best_ap']:
                    c['best_ap'], c['best_epoch'], c['best_coef'], c['best_intercept'] = s['ap'], epoch, coef.copy(), b
                if c['best_ap'] - c['anchor_ap'] >= MIN_GAIN:
                    c['anchor_ap'], c['waiting'] = c['best_ap'], 0
                else:
                    c['waiting'] += 1
                c['stopped'] = c['waiting'] >= PATIENCE
            state['epoch'] = epoch
            ck.save(state)
            print(f'[select] epoch {epoch}/{MAX_EPOCHS} done in {(time.time() - t0) / 60:.1f} min', flush=True)
            for c in state['configs']:
                h = c['history'][-1] if c['history'] else {}
                print(f'    alpha={c["alpha"]:g}  stop AP={h.get("stop_ap", float("nan")):.5f}  '
                      f'fit AP={h.get("fit_ap", float("nan")):.5f}  '
                      f'recall@1%={h.get("stop_recall_at_1pct_fpr", float("nan")):.4f}  '
                      f'best={c["best_ap"]:.5f}@{c["best_epoch"]}  patience={c["waiting"]}/{PATIENCE}'
                      f'{"  STOPPED" if c["stopped"] else ""}{"  " + c["note"] if c["note"] else ""}', flush=True)
        usable = [c for c in state['configs'] if c['best_coef'] is not None]
        if not usable:
            raise ValueError('Every SVM setting diverged')
        best = max(usable, key=lambda c: c['best_ap'])
        save_model(WORK / 'SVM_WIN32_selector.npz', best['best_coef'], best['best_intercept'], mean, inv,
                   best['alpha'], best['best_epoch'], len(fit_rows))
        copy_checked(WORK / 'SVM_WIN32_selector.npz', JOB / 'SVM_WIN32_selector.npz',
                     sha(WORK / 'SVM_WIN32_selector.npz'))
        write(JOB / 'selection.json', dict(alpha=best['alpha'], epochs=best['best_epoch'], stop_ap=best['best_ap'],
            selector_file='SVM_WIN32_selector.npz', selector_sha256=sha(JOB / 'SVM_WIN32_selector.npz'),
            settings=[dict(alpha=c['alpha'], best_epoch=c['best_epoch'], best_stop_ap=c['best_ap'],
                           epochs_run=len(c['history']), note=c['note'], history=c['history'])
                      for c in state['configs']]))
    selection = read(JOB / 'selection.json')
    alpha, epochs = selection['alpha'], selection['epochs']
    print(f'Selected alpha={alpha:g}, {epochs} epochs (inner_stop AP {selection["stop_ap"]:.5f})', flush=True)

    # ---- stage 2: refit on all training rows ----
    all_rows = np.arange(len(y))
    ck = Checkpoint('refit')
    state = ck.load() or dict(epoch=0, model=new_model(alpha))
    print(f'[refit] resuming after epoch {state["epoch"]}', flush=True)
    while state['epoch'] < epochs:
        epoch = state['epoch'] + 1
        one_epoch(X, y, all_rows, [state['model']], 1000 + epoch, 1, 'refit')
        state['epoch'] = epoch
        ck.save(state)
    coef, b = state['model'].coef_.ravel(), float(state['model'].intercept_[0])
    if not (np.isfinite(coef).all() and np.isfinite(b)):
        raise ValueError('Refit diverged')
    final = 'SVM_WIN32.npz'
    save_model(WORK / final, coef, b, mean, inv, alpha, epochs, len(all_rows))
    copy_checked(WORK / final, JOB / final, sha(WORK / final))
    train_scores = scores(y.astype(int), margin(X, all_rows, coef, b))
    del X; gc.collect()

    # ---- development sanity check (same frozen preprocessing) ----
    with np.load(files['dev/dev.npz']) as z:
        Xd, yd = z['X'].astype(np.float32), z['y'].astype(int)
    signed_log_(Xd); standardise_(Xd, mean, inv)
    drows = np.arange(len(yd))
    with np.load(JOB / selection['selector_file']) as z:
        sel_coef, sel_b = z['coefficient'], float(z['intercept'][0])
    dev = {}
    for name, (c_, b_) in (('selector_inner_fit_only', (sel_coef, sel_b)), ('final_all_training_rows', (coef, b))):
        m = margin(Xd, drows, c_, b_)
        dev[name] = dict(average_precision=float(average_precision_score(yd, m)), roc_auc=float(roc_auc_score(yd, m)))

    # ---- curves ----
    rows = [dict(alpha=s['alpha'], **h) for s in selection['settings'] for h in s['history']]
    with open(JOB / 'tuning_history.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 3, figsize=(18, 5), constrained_layout=True)
    for s in selection['settings']:
        e = [h['epoch'] for h in s['history']]
        ax[0].plot(e, [h['stop_ap'] for h in s['history']], marker='o', label=f'alpha={s["alpha"]:g}')
    chosen = next(s for s in selection['settings'] if s['alpha'] == alpha)['history']
    e = [h['epoch'] for h in chosen]
    ax[1].plot(e, [h['fit_ap'] for h in chosen], marker='o', label='Training rows (inner_fit sample)')
    ax[1].plot(e, [h['stop_ap'] for h in chosen], marker='o', label='Unseen stopping rows (weeks 36-39)')
    ax[2].plot(e, [h['fit_hinge'] for h in chosen], marker='o', label='Training rows (inner_fit sample)')
    ax[2].plot(e, [h['stop_hinge'] for h in chosen], marker='o', label='Unseen stopping rows (weeks 36-39)')
    for a in ax[1:]:
        a.axvline(epochs, color='gray', ls='--', label=f'Selected epoch {epochs}')
    ax[0].set(xlabel='Epoch', ylabel='Average precision', title='inner_stop AP by setting')
    ax[1].set(xlabel='Epoch', ylabel='Average precision', title=f'Overfitting check (AP), alpha={alpha:g}')
    ax[2].set(xlabel='Epoch', ylabel='Mean hinge loss', title='Overfitting check (hinge loss)')
    for a in ax:
        a.grid(alpha=.2); a.legend(fontsize=8)
    fig.suptitle('Win32 linear SVM on raw EMBER2024 features (chosen on inner_stop only)')
    for ext in ('png', 'pdf'):
        fig.savefig(JOB / f'tuning_curve.{ext}', dpi=180)
    plt.close(fig)

    at = next(h for h in chosen if h['epoch'] == epochs)
    report = dict(status='WIN32_SVM_TRAINED', model_file=final, model_sha256=sha(JOB / final),
        selector_file=selection['selector_file'], selector_sha256=selection['selector_sha256'],
        selected=dict(alpha=alpha, epochs=epochs, inner_stop_ap=selection['stop_ap'],
                      inner_stop_recall_at_1pct_fpr=at['stop_recall_at_1pct_fpr']),
        settings=[{k: s[k] for k in ('alpha', 'best_epoch', 'best_stop_ap', 'epochs_run', 'note')}
                  for s in selection['settings']],
        overfitting=dict(fit_sample_ap=at['fit_ap'], stop_ap=at['stop_ap'], ap_gap=at['fit_ap'] - at['stop_ap'],
                         fit_hinge=at['fit_hinge'], stop_hinge=at['stop_hinge'],
                         hinge_gap=at['stop_hinge'] - at['fit_hinge'],
                         final_model_training_ap=train_scores['ap']),
        development=dev, preprocessing=dict(nonfinite_values_set_to_zero=nonfinite,
                                            constant_features=int((inv == 0).sum())),
        rows=dict(inner_fit=len(fit_rows), inner_stop=len(stop_rows), final_training=len(all_rows),
                  development=len(yd)),
        test_used=False,
        note='Development numbers are a sanity check; calibration, thresholds and test come in the 4-way step.')
    write(JOB / 'report.json', report)
    print(json.dumps(report, indent=2))
    stop_ram.set()


if __name__ == '__main__':
    main()
