"""Install a detector update made on Colab (e.g. MLWINT_pdf_2026.12.1.zip) into models/phase1, safely.

  python scripts/install_model_update.py <update.zip> [--compare-folder DIR] [--dry-run]

1. checks every file of the update against its checksum
2. builds the updated bundle in a temporary folder and proves PARITY: the 300 saved vectors must score exactly as on
   Colab (difference < 1e-5, same verdict for all)
3. scores the PDFs in --compare-folder (default: your Downloads, read-only, nothing is uploaded) with the OLD and the
   NEW detector and prints before / after
4. only if all checks pass (and not --dry-run): backs up the old files to backups/models-<old version>-<format>/,
   installs the new ones, rewrites models/phase1/manifest.json and version.json ("models" + "models_fingerprint").
   Scan memory notices the change by itself and re-checks files.
To undo: copy the backup folder's contents back over models/phase1 and restore its version.json.
Status MODEL_UPDATE_INSTALLED (or MODEL_UPDATE_CHECKED for --dry-run).
"""
import argparse, hashlib, json, shutil, sys, tempfile, time, zipfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.detection.phase1_detectors import Phase1Detectors   # noqa: E402

BUNDLE = ROOT / 'models/phase1'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def models_fingerprint():
    h = hashlib.sha256()
    for m in sorted((ROOT / 'models').glob('phase*/manifest.json')):
        h.update(m.read_bytes())
    return h.hexdigest()[:12]


def unpack(zip_path, dest):
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())) or info.filename.startswith('/'):
                raise ValueError(f'Unsafe path in the update: {info.filename}')
        z.extractall(dest)
    upd = json.loads((dest / 'update.json').read_text())
    if upd.get('status') != 'MLWINT_MODEL_UPDATE':
        raise SystemExit('This zip is not an MLWINT model update')
    for name, info in upd['files'].items():
        if sha(dest / name) != info['sha256']:
            raise SystemExit(f'Checksum failed in the update: {name}')
    return upd


def build(old_dir, new_dir, upd, staged):
    """Copy the current bundle, swap in the update's files for its format, rewrite the manifest."""
    fmt = upd['format']
    shutil.copytree(old_dir, new_dir)
    manifest = json.loads((new_dir / 'manifest.json').read_text())
    if fmt not in manifest['formats']:
        raise SystemExit(f'Format {fmt} is not in this bundle')
    old_card = json.loads((old_dir / f'cards/{fmt}.json').read_text())
    old_files = {f'cards/{fmt}.json', f'parity/{fmt}.npz'} | {v['file'] for v in old_card['models'].values()}
    for name in old_files:
        (new_dir / name).unlink(missing_ok=True)
        manifest['files'].pop(name, None)
    for name in upd['files']:
        (new_dir / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged / name, new_dir / name)
        manifest['files'][name] = dict(sha256=upd['files'][name]['sha256'])
    manifest.setdefault('updates', []).append(dict(format=fmt, models_version=upd['models_version'],
                                                   installed=time.strftime('%Y-%m-%d %H:%M')))
    (new_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    return sorted(old_files)


def parity(det, fmt):
    with np.load(det.dir / f'parity/{fmt}.npz') as z:
        X, expected = z['X'], z['ensemble_probability']
    got = det.probability(fmt, X)
    diff = float(np.max(np.abs(got - expected)))
    same = int(sum(det.verdict(fmt, g) == det.verdict(fmt, e) for g, e in zip(got, expected)))
    return dict(vectors=len(X), max_abs_difference=diff, same_verdict=same, ok=bool(diff < 1e-5 and same == len(X)))


def compare(old, new, folder, fmt, limit=1000):
    if fmt != 'pdf' or not folder.is_dir():
        return None
    files = sorted(p for p in folder.rglob('*') if p.is_file() and p.suffix.lower() == '.pdf')[:limit]
    rows, ext = [], new.extractor()
    for p in files:
        try:
            data = p.read_bytes()
            if b'%PDF' not in data[:1024]:
                continue
            X = np.asarray(ext.feature_vector(data), np.float32).reshape(1, -1)
        except Exception:
            continue
        po, pn = float(old.probability(fmt, X)[0]), float(new.probability(fmt, X)[0])
        rows.append(dict(file=str(p.relative_to(folder)), old=old.verdict(fmt, po), new=new.verdict(fmt, pn),
                         old_p=round(po, 4), new_p=round(pn, 4)))
    count = lambda k: {v: sum(r[k] == v for r in rows) for v in ('CLEAN', 'SUSPICIOUS', 'MALICIOUS')}
    return dict(folder=str(folder), pdfs=len(rows), old=count('old'), new=count('new'),
                changed=[r for r in rows if r['old'] != r['new']])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('zip')
    ap.add_argument('--compare-folder', default=str(Path.home() / 'Downloads'))
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()
    version = json.loads((ROOT / 'version.json').read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        print('1. Checking the update ...', flush=True)
        upd = unpack(Path(a.zip), tmp / 'update')
        fmt = upd['format']
        print(f'   OK: {fmt} detector, models {upd["models_version"]}, {len(upd["files"])} files', flush=True)

        print('2. Building the updated bundle and checking parity with Colab ...', flush=True)
        old_det = Phase1Detectors(BUNDLE)
        replaced = build(BUNDLE, tmp / 'bundle', upd, tmp / 'update')
        new_det = Phase1Detectors(tmp / 'bundle')
        par = parity(new_det, fmt)
        print(f'   max difference {par["max_abs_difference"]:.2e}; same verdict {par["same_verdict"]}/{par["vectors"]} '
              f'{"OK" if par["ok"] else "MISMATCH"}', flush=True)
        others = {k: parity(new_det, k)['ok'] for k in new_det.cards if k != fmt}
        print(f'   other formats unchanged: {others}', flush=True)
        if not par['ok'] or not all(others.values()):
            raise SystemExit('PARITY FAILED - nothing installed')

        print(f'3. Old vs new on the PDFs in {a.compare_folder} (read-only) ...', flush=True)
        cmp = compare(old_det, new_det, Path(a.compare_folder), fmt)
        if cmp:
            print(f'   {cmp["pdfs"]} PDFs   before {cmp["old"]}   after {cmp["new"]}', flush=True)
            for r in cmp['changed']:
                print(f'   {r["old"]:>10} -> {r["new"]:<10} {r["old_p"]:.3f} -> {r["new_p"]:.3f}  {r["file"]}', flush=True)

        report = dict(update=upd['models_version'], format=fmt, parity=par, other_formats=others, compare=cmp,
                      old_models_version=version['models'])
        if a.dry_run:
            report['status'] = 'MODEL_UPDATE_CHECKED'
        else:
            print('4. Installing ...', flush=True)
            backup = ROOT / f'backups/models-{version["models"]}-{fmt}'
            if backup.exists():
                raise SystemExit(f'{backup} already exists - move it away first')
            for name in replaced + ['manifest.json']:
                if (BUNDLE / name).exists():
                    (backup / name).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(BUNDLE / name, backup / name)
            shutil.copy2(ROOT / 'version.json', backup / 'version.json')
            for name in replaced:
                (BUNDLE / name).unlink(missing_ok=True)
            for name in upd['files']:
                (BUNDLE / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp / 'bundle' / name, BUNDLE / name)
            shutil.copy2(tmp / 'bundle/manifest.json', BUNDLE / 'manifest.json')
            Phase1Detectors(BUNDLE)                                 # verifies every checksum again
            version['models'] = upd['models_version']
            version['models_fingerprint'] = models_fingerprint()
            (ROOT / 'version.json').write_text(json.dumps(version, indent=1), encoding='utf-8')
            report.update(status='MODEL_UPDATE_INSTALLED', backup=str(backup))
            print(f'   installed; old files kept in {backup}', flush=True)
    out = ROOT / f'reports/model-updates/{fmt}-{upd["models_version"]}.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f'\n{report["status"]}  report: {out}')


if __name__ == '__main__':
    main()
