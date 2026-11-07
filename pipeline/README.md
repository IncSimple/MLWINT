# Pipeline

Two environments are used:
- **PC** (`pipeline/pc/`): downloads EMBER2024, turns the records into feature vectors, applies the
  leakage rules and packs shards for Google Drive. Needs the EMBER2024 Python environment with `thrember`.
- **Google Colab** (`pipeline/colab/`): leakage audit, training, comparison and close-out. Data and
  results live under `MyDrive/MLWINT-colab/` (`inputs/<type>-v1`, `experiments/<type>-fourway-v1`).

Every script checks the checksums of its inputs, freezes its own settings, and resumes after a stop.

## Win64, .NET and PDF (current pipeline)

**On the PC:** put the `pipeline/pc/*.py` files in a `scripts/` folder inside your data project (they
import each other and treat the folder above `scripts/` as the project root, with the archives in
`data/raw/ember2024/archives/`). Then, from the project folder (`<TYPE>` = `Dot_Net` or `PDF`;
Win64 uses `prepare_win64.py` the same way):
```bash
python scripts/run_prepare.py <TYPE> download
python scripts/run_prepare.py <TYPE> prepare
python scripts/run_prepare.py <TYPE> export
```
`run_prepare.py` runs `prepare_format.py` unchanged but retries a file save that Windows briefly blocks.
Upload `exports/colab/<type>-v1` to `MyDrive/MLWINT-colab/inputs/`.

**On Colab** (T4 GPU runtime; switch on High-RAM for the larger types):
```python
F = 'dotnet'   # or 'pdf'
C = '/content/drive/MyDrive/MLWINT-colab/code'
!python {C}/audit_format.py {F}                 # leakage audit
!python {C}/train_format_trees.py {F} xgboost   # XGBoost
!python {C}/train_format_trees.py {F} lightgbm  # LightGBM
!python {C}/svm_format.py {F}                   # linear SVM
!python {C}/fourway_format.py {F}               # four-way comparison, then the sealed test
```
The `*_format.py` scripts are generated once from the tested Win64 scripts by `generic/make_generic.py`.
`generic/retrain_format.py` retrains a type on weeks 0–51 (used for PDF).

## Win32 (first file type, built step by step)
PC: `sample_ember2024_pilot` → `vectorize_ember2024_pilot` → `prepare_full_ember2024_win32` →
`train_full_ember2024_xgboost` / `train_full_ember2024_lightgbm` → `reselect_full_ember2024_lightgbm` →
`freeze_and_download_ember2024_test` (with `prepare_ember2024_test_week`, `repair_ember2024_test_dates`,
`evaluate_frozen_ember2024_test`) → `export_win32_fourway_colab` → `prepare_full_development_win32`.

Colab: `audit_win32_leakage` → `extend_win32_xgboost` (T4) → `extend_win32_lightgbm` (CPU High-RAM) →
`svm_win32` → `svm_win32_v2` (wider grid) → `fourway_win32`.

## Close-out
```python
!python /content/drive/MyDrive/MLWINT-colab/code/closeout_verdicts.py
```
Builds the malicious / suspicious / clean thresholds and one detector card per file type.
