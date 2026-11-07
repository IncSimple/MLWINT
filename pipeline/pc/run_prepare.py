"""Runs prepare_format.py unchanged, but retries a file swap that Windows briefly blocks
(antivirus / search indexer holding the file for a moment). Same arguments as prepare_format.py."""
import os, runpy, sys, time
from pathlib import Path

_replace = os.replace


def patient_replace(src, dst, *args, **kwargs):
    for attempt in range(1, 121):                     # up to about 60 seconds
        try:
            return _replace(src, dst, *args, **kwargs)
        except PermissionError:
            if attempt == 120:
                raise
            if attempt in (1, 20, 60):
                print(f'  (file busy, retrying: {Path(dst).name})', flush=True)
            time.sleep(0.5)


os.replace = patient_replace
script = str(Path(__file__).with_name('prepare_format.py'))
sys.argv = [script] + sys.argv[1:]
runpy.run_path(script, run_name='__main__')