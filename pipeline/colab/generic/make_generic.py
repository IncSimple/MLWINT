"""Turns the four tested Win64 Colab scripts into format-generic ones (pdf | elf | dotnet | win64).
Every replacement must match exactly the expected number of times, otherwise nothing is written."""
import sys
from pathlib import Path

CODE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('/content/drive/MyDrive/MLWINT-colab/code')
HEAD = ("import sys as _sys\n"
        "FMT = _sys.argv[1].lower() if len(_sys.argv) > 1 else ''\n"
        "if FMT not in ('pdf', 'elf', 'dotnet', 'win64'):\n"
        "    raise SystemExit('First argument must be the format: pdf | elf | dotnet')\n"
        "TAG = FMT.upper()\n")
NEED = ("    need = counts['train_rows'] * FEATURES * 4 * {k} + 3 * 1024**3\n"
        "    if psutil.virtual_memory().total < need:\n"
        "        raise RuntimeError(f'Needs about {{need / 1024**3:.0f}} GB of RAM: switch on High-RAM')\n")
COMMON = [("import numpy as np\n", "import numpy as np\n" + HEAD, 1),
          ("'inputs/win64-v1'", "f'inputs/{FMT}-v1'", 1),
          ("'WIN64_SEPARATION_PASSED'", "f'{TAG}_SEPARATION_PASSED'", 1)]
JOBS = {
 ('audit_win64_leakage.py', 'audit_format.py'): [COMMON[0], COMMON[2],
    ("Path('/content/drive/MyDrive/MLWINT-colab/inputs/win64-v1')",
     "Path(f'/content/drive/MyDrive/MLWINT-colab/inputs/{FMT}-v1')", 1),
    ("Path('/content/drive/MyDrive/MLWINT-colab/experiments/win64-fourway-v1/leakage-audit-v1')",
     "Path(f'/content/drive/MyDrive/MLWINT-colab/experiments/{FMT}-fourway-v1/leakage-audit-v1')", 1),
    ("'WIN64_EXPORT_READY'", "f'{TAG}_EXPORT_READY'", 1)],
 ('train_win64_trees.py', 'train_format_trees.py'): COMMON + [
    ("'experiments/win64-fourway-v1", "f'experiments/{FMT}-fourway-v1", 2),
    ("work='win64-xgb', final='XGB_WIN64.ubj', status='WIN64_XGB_TRAINED'",
     "work=f'{FMT}-xgb', final=f'XGB_{TAG}.ubj', status=f'{TAG}_XGB_TRAINED'", 1),
    ("title='Win64 XGBoost'", "title=f'{TAG} XGBoost'", 1),
    ("work='win64-lgbm', final='LGBM_WIN64.txt', status='WIN64_LGBM_TRAINED'",
     "work=f'{FMT}-lgbm', final=f'LGBM_{TAG}.txt', status=f'{TAG}_LGBM_TRAINED'", 1),
    ("title='Win64 LightGBM'", "title=f'{TAG} LightGBM'", 1),
    ("DEVICE = 'cuda'          # XGBoost only",
     "DEVICE = 'cuda' if shutil.which('nvidia-smi') else 'cpu'   # XGBoost only: GPU when the runtime has one", 1),
    ("        if psutil.virtual_memory().total < 40 * 1024**3:\n"
     "            raise RuntimeError('Use a CPU runtime with High-RAM (8 CPU cores; needs about 15 GB)')\n", "", 1),
    ("    if manifest['status'] != 'WIN64_EXPORT_READY':", "    if manifest['status'] != f'{TAG}_EXPORT_READY':", 1),
    ("    counts = manifest['counts']\n", "    counts = manifest['counts']\n" + NEED.format(k=4), 1),
    ("version=f'win64-{model_name}-v1'", "version=f'{FMT}-{model_name}-v1'", 1),
    ("    if len(sys.argv) != 2 or sys.argv[1] not in MODELS:\n"
     "        raise SystemExit('Usage: python train_win64_trees.py xgboost|lightgbm')\n"
     "    main(sys.argv[1])",
     "    if len(sys.argv) != 3 or sys.argv[2] not in MODELS:\n"
     "        raise SystemExit('Usage: python train_format_trees.py pdf|elf|dotnet xgboost|lightgbm')\n"
     "    main(sys.argv[2])", 1)],
 ('svm_win64.py', 'svm_format.py'): COMMON + [
    ("'experiments/win64-fourway-v1/leakage-audit-v1/report.json'",
     "f'experiments/{FMT}-fourway-v1/leakage-audit-v1/report.json'", 1),
    ("'experiments/win64-fourway-v1/svm-raw-v1'", "f'experiments/{FMT}-fourway-v1/svm-raw-v1'", 1),
    ("'/content/MLWINT-work/win64-svm'", "f'/content/MLWINT-work/{FMT}-svm'", 1),
    ("'SVM_WIN64", "f'SVM_{TAG}", 7),
    ("fig.suptitle('Win64 linear SVM", "fig.suptitle(f'{TAG} linear SVM", 1),
    ("status='WIN64_SVM_TRAINED'", "status=f'{TAG}_SVM_TRAINED'", 1),
    ("version='win64-svm-raw-v1'", "version=f'{FMT}-svm-raw-v1'", 1),
    ("the Win64 training + development", "the training + development", 1),
    ("    if psutil.virtual_memory().total < MIN_RAM_GIB * 1024**3:\n"
     "        raise RuntimeError('Use a CPU runtime with High-RAM (needs about 20 GB)')\n", "", 1),
    ("    counts = manifest['counts']\n", "    counts = manifest['counts']\n" + NEED.format(k=2), 1)],
 ('fourway_win64.py', 'fourway_format.py'): COMMON + [
    ("'experiments/win64-fourway-v1'", "f'experiments/{FMT}-fourway-v1'", 1),
    ("'/content/MLWINT-work/win64-fourway'", "f'/content/MLWINT-work/{FMT}-fourway'", 1),
    ("'WIN64_XGB_TRAINED'", "f'{TAG}_XGB_TRAINED'", 1),
    ("'WIN64_LGBM_TRAINED'", "f'{TAG}_LGBM_TRAINED'", 1),
    ("'WIN64_SVM_TRAINED'", "f'{TAG}_SVM_TRAINED'", 1),
    ("    if manifest['status'] != 'WIN64_EXPORT_READY':", "    if manifest['status'] != f'{TAG}_EXPORT_READY':", 1),
    ("version='win64-four-way-v1'", "version=f'{FMT}-four-way-v1'", 1),
    ("fig.suptitle('Win64 overfitting check", "fig.suptitle(f'{TAG} overfitting check", 1),
    ("'win64_", "f'{FMT}_", 6),
    ("f'Win64 specialist", "f'{TAG} specialist", 1),
    ("status='WIN64_FOUR_WAY_COMPLETE'", "status=f'{TAG}_FOUR_WAY_COMPLETE'", 1),
    ("the Win64 test files were sealed", "the test files were sealed", 1)],
}
out = {}
for (src, dst), reps in JOBS.items():
    s = (CODE / src).read_text()
    for old, new, n in reps:
        if s.count(old) != n:
            raise SystemExit(f'{src}: expected {n}x {old[:60]!r}, found {s.count(old)} - nothing written')
        s = s.replace(old, new)
    left = [l.strip() for l in s.splitlines()
            if ('win64' in l.lower()) and not l.lstrip().startswith(('#', '"""')) and "'win64'" not in l]
    compile(s, dst, 'exec')
    out[dst] = (s, left)
for dst, (s, left) in out.items():
    (CODE / dst).write_text(s)
    print(f'wrote {dst}' + (f'   (lines still naming Win64, text only: {len(left)})' if left else ''))
