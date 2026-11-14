"""MLWINT Phase 1 detectors on the PC (read-only). Save as MLWINT/src/detection/phase1_detectors.py

Loads the bundle exported from Colab (MLWINT_phase1_detectors.zip, unpacked to MLWINT/models/phase1) and turns
any file into a verdict:
  1. format   : PDF if '%PDF' is in the first 1 KB; PE files are routed like EMBER2024 labels them:
                .NET if the CLR runtime header is present, Win64 if the CPU type is x64 / Itanium, else Win32
  2. features : thrember PEFeatureExtractor (the same 2,568 features the models were trained on)
  3. score    : 50/50 ensemble of the calibrated XGBoost and LightGBM probabilities (from the detector card)
  4. verdict  : MALICIOUS / SUSPICIOUS / CLEAN using the card's two thresholds
Files are only read, never changed, moved or uploaded.
"""
import hashlib, json
from pathlib import Path

import numpy as np

FORMAT_NAMES = {'win32': 'Win32', 'win64': 'Win64', 'dotnet': '.NET', 'pdf': 'PDF'}
MAX_BYTES = 256 * 1024**2
X64_MACHINES = {0x8664, 0x200}                       # IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_IA64


def _sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def detect_format(data):
    """Return 'pdf', 'win32', 'win64', 'dotnet' or None (unsupported), plus a short reason."""
    if b'%PDF' in data[:1024]:
        return 'pdf', 'PDF header found'
    if data[:2] != b'MZ':
        return None, 'not a PE or PDF file'
    import pefile
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as e:
        return None, f'invalid PE file: {e}'
    try:
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        clr = len(dirs) > 14 and dirs[14].VirtualAddress > 0 and dirs[14].Size > 0
        machine = pe.FILE_HEADER.Machine
    finally:
        pe.close()
    if clr:
        return 'dotnet', '.NET runtime header found'
    if machine in X64_MACHINES:
        return 'win64', f'64-bit PE (machine 0x{machine:04x})'
    return 'win32', f'PE (machine 0x{machine:04x})'


class Phase1Detectors:
    def __init__(self, bundle_dir=None, verify=True):
        root = Path(__file__).resolve().parents[2]
        self.dir = Path(bundle_dir) if bundle_dir else root / 'models/phase1'
        self.manifest = json.loads((self.dir / 'manifest.json').read_text())
        if self.manifest.get('status') != 'MLWINT_PHASE1_BUNDLE':
            raise ValueError(f'{self.dir} is not an MLWINT Phase 1 bundle')
        if verify:
            self.verify()
        self.cards = {k: json.loads((self.dir / f'cards/{k}.json').read_text()) for k in self.manifest['formats']}
        self._models, self._extractor = {}, None

    def verify(self):
        for name, info in self.manifest['files'].items():
            if _sha(self.dir / name) != info['sha256']:
                raise ValueError(f'Checksum failed: {name}. Unpack the bundle again.')

    def extractor(self):
        if self._extractor is None:
            from thrember.features import PEFeatureExtractor
            self._extractor = PEFeatureExtractor()
        return self._extractor

    def models(self, key):
        if key not in self._models:
            import lightgbm as lgb, xgboost as xgb
            loaded = {}
            for m, info in self.cards[key]['models'].items():
                path = str(self.dir / info['file'])
                if m == 'xgb':
                    b = xgb.Booster(model_file=path)
                    b.set_param({'device': 'cpu', 'nthread': 4})
                    loaded[m] = b
                elif m == 'lgbm':
                    loaded[m] = lgb.Booster(model_file=path)
                elif m == 'svm':
                    with np.load(path) as z:
                        loaded[m] = {k: z[k] for k in ('coefficient', 'intercept', 'mean', 'inverse_std', 'clip')}
                else:
                    raise ValueError(f'Unsupported model type in card: {m}')
            self._models[key] = loaded
        return self._models[key]

    def probability(self, key, X):
        """Ensemble probability for feature rows X (n x 2568), exactly as computed on Colab."""
        from scipy.special import expit
        X = np.ascontiguousarray(X, dtype=np.float32).reshape(-1, 2568)
        ens = self.cards[key]['ensemble']
        margins = {}
        for m, model in self.models(key).items():
            if m == 'xgb':
                margins[m] = np.asarray(model.inplace_predict(X, predict_type='margin'), np.float64)
            elif m == 'svm':
                Z = np.sign(X) * np.log1p(np.abs(X))
                Z[~np.isfinite(Z)] = 0
                Z = (Z - model['mean']) * model['inverse_std']
                np.clip(Z, -float(model['clip'][0]), float(model['clip'][0]), out=Z)
                margins[m] = (Z @ model['coefficient'].astype(np.float32) + float(model['intercept'][0])).astype(np.float64)
            else:
                margins[m] = model.predict(X, raw_score=True, num_threads=4).astype(np.float64)
        return sum(w * expit(ens['calibration'][m]['slope'] * margins[m] + ens['calibration'][m]['intercept'])
                   for m, w in ens['weights'].items())

    def verdict(self, key, p):
        v = self.cards[key]['verdicts']
        return 'MALICIOUS' if p >= v['malicious']['threshold'] else 'SUSPICIOUS' if p >= v['suspicious']['threshold'] \
            else 'CLEAN'

    def scan_bytes(self, data):
        key, reason = detect_format(data)
        if key is None or key not in self.cards:
            return dict(status='unsupported', reason=reason)
        X = np.asarray(self.extractor().feature_vector(data), dtype=np.float32)
        if X.shape != (2568,) or not np.isfinite(X).all():
            return dict(status='failed', format=FORMAT_NAMES[key], reason='feature extraction gave an invalid vector')
        p = float(self.probability(key, X)[0])
        card = self.cards[key]['verdicts']
        return dict(status='scanned', format=FORMAT_NAMES[key], format_reason=reason, probability=p,
                    verdict=self.verdict(key, p), thresholds=dict(malicious=card['malicious']['threshold'],
                                                                  suspicious=card['suspicious']['threshold']))

    def scan_file(self, path):
        path = Path(path)
        try:
            size = path.stat().st_size
            if size > MAX_BYTES:
                return dict(path=str(path), status='skipped', reason=f'larger than {MAX_BYTES // 1024**2} MB')
            with open(path, 'rb') as f:                      # read-only
                data = f.read()
        except OSError as e:
            return dict(path=str(path), status='skipped', reason=f'cannot read: {e.strerror or e}')
        try:
            result = self.scan_bytes(data)
        except Exception as e:                               # one bad file must not stop a scan
            result = dict(status='failed', reason=f'{type(e).__name__}: {e}')
        return dict(path=str(path), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), **result)