"""PDF real-world retrain, step R1 (Google Colab, CPU): features of real-world clean PDFs from SafeDocs.

SafeDocs CC-MAIN-2021-31-PDF-UNTRUNCATED (Digital Corpora) holds ~7.9 million PDFs from the public web, packed in
7,933 zip files of ~1,000 PDFs (1-2.8 GB each). This script takes a spread of zips across the whole corpus, and for
every PDF stores ONLY:
  - the 2,568 EMBER2024 features (thrember PEFeatureExtractor.feature_vector, exactly what MLWINT's detector reads),
  - its SHA-256, size and file name inside the zip,
  - MLWINT's PDF indicator counts (/JS, /JavaScript, /Launch, /EmbeddedFile, ... incl. #xx-escaped names), so PDFs
    with active content can be screened out of the "clean" side later.
The PDFs themselves are never kept: each zip is downloaded to the runtime's disk, read, and deleted.

One shard per zip: <OUT>/shards/<zip>.npz (resumable: a zip whose shard exists is skipped).
Status file: <OUT>/status.json (status SAFEDOCS_FEATURES_DONE when all chosen zips are done).

Usage (Colab):
  python safedocs_features.py --dry-run            one zip, first 150 PDFs: speed + size estimate (writes nothing
                                                   to the shards folder)
  python safedocs_features.py --zips 60            the real run: 60 zips spread over the corpus (~60,000 PDFs)
  python safedocs_features.py --zip-file x.zip     test on a local zip (no download)
"""
import argparse, hashlib, json, os, re, shutil, sys, time, zipfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import numpy as np

BASE = 'https://digitalcorpora.s3.amazonaws.com/corpora/files/CC-MAIN-2021-31-PDF-UNTRUNCATED/zipfiles'
N_ZIPS = 7933                                   # 0000.zip .. 7932.zip
OUT = Path(os.environ.get('MLWINT_SAFEDOCS_OUT', '/content/drive/MyDrive/MLWINT-colab/inputs/safedocs-v1'))
TMP = Path(os.environ.get('MLWINT_SAFEDOCS_TMP', '/content/safedocs_tmp'))
MAX_BYTES = 64 << 20                            # larger PDFs are skipped (recorded), like very large files in MLWINT
N_FEATURES = 2568

# MLWINT's PDF indicators (src/detection/phase2_evidence.py), counted the same way
INDICATORS = ['/JavaScript', '/JS', '/Launch', '/OpenAction', '/AA', '/EmbeddedFile', '/RichMedia', '/XFA', '/URI',
              '/SubmitForm', '/GoToR', '/ObjStm', '/Encrypt']
ACTIVE = {'/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/RichMedia', '/XFA'}   # MLWINT's PDF_ACTIVE
NAME = re.compile(rb'/[A-Za-z0-9#]+')
HEX = re.compile(rb'#([0-9A-Fa-f]{2})')
COLUMNS = INDICATORS + ['escaped_names', 'eof_markers', 'pages']


def indicator_row(data):
    counts, hidden = Counter(), 0
    for raw in NAME.findall(data):
        name = HEX.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
        text = name.decode('latin-1')
        if text in INDICATORS:
            counts[text] += 1
            hidden += raw != name
    pages = len(re.findall(rb'/Type\s*/Page\b', data))
    return [counts[i] for i in INDICATORS] + [hidden, data.count(b'%%EOF'), pages]


# ---------------------------------------------------------------------------------------------- workers
_EXTRACTOR = None


def _init():
    global _EXTRACTOR
    import warnings
    warnings.filterwarnings('ignore')
    from thrember.features import PEFeatureExtractor
    _EXTRACTOR = PEFeatureExtractor()


def work(item):
    name, data = item
    sha = hashlib.sha256(data).hexdigest()
    t = time.time()
    try:
        if b'%PDF' not in data[:1024]:
            return name, sha, len(data), None, None, 'no %PDF header in the first 1 KB (MLWINT would not route it as PDF)', 0.0
        vec = np.asarray(_EXTRACTOR.feature_vector(data), dtype=np.float32)
        if vec.shape != (N_FEATURES,):
            return name, sha, len(data), None, None, f'feature vector has shape {vec.shape}', 0.0
        return name, sha, len(data), vec, indicator_row(data), '', time.time() - t
    except Exception as e:                                         # a broken PDF must not stop the run
        return name, sha, len(data), None, None, f'{type(e).__name__}: {str(e)[:200]}', time.time() - t


# ---------------------------------------------------------------------------------------------- zips
def zip_url(i):
    lo = i // 1000 * 1000
    return f'{BASE}/{lo:04d}-{lo + 999:04d}/{i:04d}.zip'


def chosen_zips(n):
    """A fixed spread over the whole corpus (the same every time, so runs can resume and splits can use it)."""
    return sorted({int(round(x)) for x in np.linspace(0, N_ZIPS - 1, n)})


def download(i):
    import requests
    TMP.mkdir(parents=True, exist_ok=True)
    path, part = TMP / f'{i:04d}.zip', TMP / f'{i:04d}.zip.part'
    for attempt in range(5):
        try:
            with requests.get(zip_url(i), stream=True, timeout=60) as r:
                r.raise_for_status()
                total = int(r.headers.get('content-length', 0))
                with open(part, 'wb') as f:
                    for chunk in r.iter_content(8 << 20):
                        f.write(chunk)
            if total and part.stat().st_size != total:
                raise IOError(f'incomplete download ({part.stat().st_size} of {total} bytes)')
            part.replace(path)
            return path
        except Exception as e:
            print(f'  download {i:04d} failed ({e}); retry {attempt + 1}/5', flush=True)
            time.sleep(10 * (attempt + 1))
    raise SystemExit(f'could not download {zip_url(i)}')


def members(path, limit=None):
    with zipfile.ZipFile(path) as z:
        names = sorted(n for n in z.namelist() if n.lower().endswith('.pdf'))[:limit]
        for n in names:
            info = z.getinfo(n)
            if info.file_size > MAX_BYTES:
                yield n, None, info.file_size
            else:
                yield n, z.read(n), info.file_size


def process_zip(path, pool, limit=None):
    rows, skipped = [], []
    big = []

    def items():
        for n, data, size in members(path, limit):
            if data is None:
                big.append(dict(name=n, bytes=size, reason=f'larger than {MAX_BYTES >> 20} MB'))
                continue
            yield n, data

    for name, sha, size, vec, ind, err, secs in pool.map(work, items(), chunksize=4):
        if vec is None:
            skipped.append(dict(name=name, sha256=sha, bytes=size, reason=err))
        else:
            rows.append((name, sha, size, vec, ind, secs))
    return rows, skipped + big


def save_shard(dest, zip_id, rows, skipped):
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.stem + '.part.npz')
    np.savez_compressed(
        tmp,
        X=np.stack([r[3] for r in rows]) if rows else np.zeros((0, N_FEATURES), np.float32),
        sha256=np.array([r[1] for r in rows], dtype='U64'),
        name=np.array([r[0] for r in rows], dtype='U32'),
        bytes=np.array([r[2] for r in rows], dtype=np.int64),
        indicators=np.array([r[4] for r in rows], dtype=np.int32).reshape(-1, len(COLUMNS)),
        indicator_columns=np.array(COLUMNS),
        zip_id=np.array(zip_id),
        skipped=np.array(json.dumps(skipped)))
    tmp.replace(dest)


def summary(rows):
    if not rows:
        return {}
    ind = np.array([r[4] for r in rows])
    active = np.any(ind[:, [INDICATORS.index(a) for a in ACTIVE]] > 0, axis=1) | (ind[:, COLUMNS.index('escaped_names')] > 0)
    secs = np.array([r[5] for r in rows])
    return dict(pdfs=len(rows), with_active_content=int(active.sum()),
                seconds_per_pdf=round(float(secs.mean()), 3), mb_per_pdf=round(float(np.mean([r[2] for r in rows])) / 2 ** 20, 2))


# ---------------------------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--zips', type=int, default=60, help='how many zips to spread over the corpus (~1,000 PDFs each)')
    ap.add_argument('--dry-run', action='store_true', help='one zip, first 150 PDFs, estimate only')
    ap.add_argument('--zip-file', help='test on a local zip instead of downloading')
    ap.add_argument('--workers', type=int, default=os.cpu_count() or 2)
    a = ap.parse_args()
    import thrember
    print(f'thrember {getattr(thrember, "__version__", "?")} from {thrember.__file__}; {a.workers} workers', flush=True)

    with ProcessPoolExecutor(a.workers, initializer=_init) as pool:
        if a.zip_file or a.dry_run:
            t = time.time()
            path = Path(a.zip_file) if a.zip_file else download(chosen_zips(a.zips)[0])
            dl = time.time() - t
            t = time.time()
            rows, skipped = process_zip(path, pool, limit=None if a.zip_file else 150)
            took = time.time() - t
            s = summary(rows)
            per = took / max(1, len(rows) + len(skipped))
            print(json.dumps(dict(s, skipped=len(skipped), download_seconds=round(dl),
                                  wall_seconds_per_pdf=round(per, 3)), indent=1))
            if rows:
                dest = OUT / 'dryrun' / f'{path.stem}.npz'
                save_shard(dest, path.stem, rows, skipped)
                print(f'test shard: {dest} ({dest.stat().st_size // 1024} KB for {len(rows)} PDFs)')
            est_h = (per * 1000 + dl) * a.zips / 3600
            print(f'ESTIMATE for --zips {a.zips}: ~{est_h:.1f} h on this runtime, '
                  f'~{a.zips * 1000:,} PDFs, shards ~{a.zips * 1000 * 4 // 1024} MB on Drive')
            if not a.zip_file:
                path.unlink(missing_ok=True)
            print('SAFEDOCS_DRYRUN_DONE')
            return

        todo = chosen_zips(a.zips)
        done = {p.stem for p in (OUT / 'shards').glob('*.npz')} if (OUT / 'shards').exists() else set()
        print(f'{len(todo)} zips chosen; {len(done & {f"{i:04d}" for i in todo})} already done', flush=True)
        status = dict(source='SafeDocs CC-MAIN-2021-31-PDF-UNTRUNCATED', zips=todo, features='thrember PEFeatureExtractor',
                      indicator_columns=COLUMNS, max_bytes=MAX_BYTES)
        t_all = time.time()
        pending = [i for i in todo if not (OUT / 'shards' / f'{i:04d}.npz').exists()]
        # the next zip downloads while the current one is processed, so downloads cost no extra time
        with ThreadPoolExecutor(1) as fetcher:
            nxt = fetcher.submit(download, pending[0]) if pending else None
            for k, i in enumerate(pending):
                t = time.time()
                path = nxt.result()
                nxt = fetcher.submit(download, pending[k + 1]) if k + 1 < len(pending) else None
                rows, skipped = process_zip(path, pool)
                save_shard(OUT / 'shards' / f'{i:04d}.npz', f'{i:04d}', rows, skipped)
                path.unlink(missing_ok=True)
                s = summary(rows)
                left = (time.time() - t_all) / (k + 1) * (len(pending) - k - 1) / 3600
                print(f'[{len(todo) - len(pending) + k + 1}/{len(todo)}] {i:04d}.zip: {s.get("pdfs", 0)} PDFs, '
                      f'{len(skipped)} skipped, {s.get("with_active_content", 0)} with active content, '
                      f'{time.time() - t:.0f} s (about {left:.1f} h left)', flush=True)
        # only this run's zips (a different --zips picks different zips: keep the same number when resuming)
        shards = [OUT / 'shards' / f'{i:04d}.npz' for i in todo if (OUT / 'shards' / f'{i:04d}.npz').exists()]
        total = sum(int(np.load(p)['X'].shape[0]) for p in shards)
        status.update(shards=len(shards), pdfs=total, hours=round((time.time() - t_all) / 3600, 2),
                      status='SAFEDOCS_FEATURES_DONE' if len(shards) >= len(todo) else 'SAFEDOCS_FEATURES_PARTIAL')
        (OUT / 'status.json').write_text(json.dumps(status, indent=1))
        shutil.rmtree(TMP, ignore_errors=True)
        print(status['status'], f'{total:,} PDFs in {len(shards)} shards')


if __name__ == '__main__':
    main()
