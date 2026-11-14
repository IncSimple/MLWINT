"""MLWINT large-file check (files over 256 MB, e.g. big installers). Save as MLWINT/src/detection/large_files.py

The normal check skips files over 256 MB: the detector reads the whole file (about 5 minutes and 2 GB of memory per
GB) and capa / emulation are not practical. The large-file check runs separately, only when you ask for it:
  1. digital signature (who published it) - the most telling sign for big installers
  2. Microsoft Defender scan of just this file, in report-only mode (-DisableRemediation): Defender does NOT
     quarantine, delete or change anything; MLWINT only reads its answer
  3. MLWINT's detector on the whole file, counted at half weight (less reliable on very large installers, which
     are mostly packed data) and without its usual minimum score
  4. hash lookup and PC context, like every other file (added later by mlwint_analyse)
"""
import os, re, subprocess
from pathlib import Path

from . import phase2_meter as pm
from .phase1_detectors import MAX_BYTES

LARGE_LIMIT = 4 * 1024**3                 # files up to 4 GB
DEFENDER_TIMEOUT = 1800


def mpcmdrun():
    """Path of Microsoft Defender's command-line scanner (newest platform version first)."""
    platform = Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'Microsoft/Windows Defender/Platform'
    found = sorted(platform.glob('*/MpCmdRun.exe'), key=lambda p: p.parent.name, reverse=True) \
        if platform.is_dir() else []
    classic = Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Windows Defender/MpCmdRun.exe'
    return next((p for p in found + [classic] if p.is_file()), None)


def defender_scan(path, timeout=DEFENDER_TIMEOUT):
    """Report-only Defender scan of one file -> dict(status='clean'|'detected'|'failed', threats=[...], reason)."""
    exe = mpcmdrun()
    if exe is None:
        return dict(status='failed', threats=[], reason='Microsoft Defender command-line scanner not found')
    try:
        out = subprocess.run([str(exe), '-Scan', '-ScanType', '3', '-File', str(path), '-DisableRemediation'],
                             capture_output=True, text=True, timeout=timeout,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired:
        return dict(status='failed', threats=[], reason=f'no answer within {timeout // 60} minutes')
    except OSError as e:
        return dict(status='failed', threats=[], reason=str(e))
    text = (out.stdout or '') + (out.stderr or '')
    threats = sorted(set(re.findall(r'Threat\s*:\s*(\S.*?)\s*$', text, flags=re.M)))
    if threats or out.returncode == 2:
        return dict(status='detected', threats=threats or ['(name not shown)'], reason='')
    if 'found no threats' in text or out.returncode == 0:
        return dict(status='clean', threats=[], reason='')
    last = [l.strip() for l in text.splitlines() if l.strip()][-1:] or [f'exit code {out.returncode}']
    return dict(status='failed', threats=[], reason=last[0][:200])


def is_large(path):
    try:
        return Path(path).stat().st_size > MAX_BYTES
    except OSError:
        return False


def large_check(meter, path):
    """ThreatMeter-style result for one large file (see the module text). Read-only."""
    path = Path(path)
    size = path.stat().st_size
    if size > LARGE_LIMIT:
        return dict(path=str(path), status='skipped',
                    reason=f'larger than {LARGE_LIMIT // 1024**3} GB - too large even for the large-file check')
    old = pm.MAX_BYTES
    pm.MAX_BYTES = LARGE_LIMIT
    try:
        r = meter.assess(path)
    finally:
        pm.MAX_BYTES = old
    if r.get('status') != 'assessed':
        return r
    parts = []
    for p in r['parts']:
        if p['part'] == 'detector':
            p = dict(p, points=round(p['points'] / 2, 1),
                     reason=p['reason'] + ' (half weight: the detector is less reliable on very large installers)')
        elif p['part'] == 'evidence':
            p = dict(p, points=0.0, reason='capability check not run on large files (too slow)')
        parts.append(p)
    scan = defender_scan(path)
    if scan['status'] == 'detected':
        parts.append(dict(part='defender scan', points=30.0,
                          reason='Microsoft Defender detects it: ' + ', '.join(scan['threats'])
                                 + ' (report-only scan: Defender changed nothing)'))
        floor = 60
    elif scan['status'] == 'clean':
        parts.append(dict(part='defender scan', points=0.0,
                          reason='Microsoft Defender found no threat (report-only scan: nothing was changed)'))
        floor = 0
    else:
        parts.append(dict(part='defender scan', points=0.0, reason=f'Defender scan not available: {scan["reason"]}'))
        floor = 0
    score = int(round(max(floor, min(r.get('cap', 100.0), 100.0, sum(p['points'] for p in parts)))))
    return dict(r, parts=parts, floor=floor, score=score, level=pm.level(score), large_file=True,
                defender_scan=scan, deep_check_reason='not run on large files (too slow)')