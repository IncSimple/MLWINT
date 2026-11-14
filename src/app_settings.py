"""MLWINT settings (G4). Save as MLWINT/src/app_settings.py
Stored in MLWINT/config/mlwint_settings.json, next to your keys file (config/intel_keys.json). Used by the window AND
the command line:
  memory_days        re-check a remembered file after this many days (default 30)
  models_dir         a different folder holding phase1/ and phase2/ ('' = MLWINT/models)
  remember_options   the window keeps your scan choices and folder list between sessions
  scan_options       those choices (written by the window)
  animations         moving effects in the window (switch off on slow PCs)
Kept outside src/detection on purpose: the scan memory resets when files in src/detection change, and settings
should never cause that.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETTINGS_FILE = ROOT / 'config/mlwint_settings.json'
DEFAULTS = dict(memory_days=30, models_dir='', remember_options=True, scan_options={}, animations=True)
MEMORY_DAYS_RANGE = (1, 365)


def load_settings(path=None):
    path = Path(path) if path else SETTINGS_FILE
    out = dict(DEFAULTS, scan_options={})
    try:
        saved = json.loads(path.read_text(encoding='utf-8'))
        out.update({k: v for k, v in saved.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    lo, hi = MEMORY_DAYS_RANGE
    try:
        out['memory_days'] = max(lo, min(hi, int(out['memory_days'])))
    except (TypeError, ValueError):
        out['memory_days'] = DEFAULTS['memory_days']
    return out


def save_settings(settings, path=None):
    path = Path(path) if path else SETTINGS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    keep = {k: settings.get(k, v) for k, v in DEFAULTS.items()}
    tmp = path.with_name(path.name + '.pending')
    tmp.write_text(json.dumps(keep, indent=1), encoding='utf-8')
    tmp.replace(path)


def models_problem(folder):
    """'' when the folder holds MLWINT models (phase1/ and phase2/ with their manifests), else what is missing."""
    if not folder:
        return ''
    p = Path(folder)
    missing = [f'{part}/manifest.json' for part in ('phase1', 'phase2') if not (p / part / 'manifest.json').is_file()]
    return ('missing ' + ', '.join(missing)) if missing else ''


def models_dir(settings=None):
    """The models folder to use: the one from the settings if it is valid, else None (= MLWINT/models)."""
    s = settings or load_settings()
    folder = s.get('models_dir') or ''
    return Path(folder) if folder and not models_problem(folder) else None