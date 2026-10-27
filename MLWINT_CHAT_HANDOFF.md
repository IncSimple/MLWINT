# MLWINT — Chat Handoff for Codex

**Purpose:** Historical technical context; verify against current source and reports.

**Handoff prepared:** 2026-10-27
**Project location:** repository root (machine-specific path omitted).

> This document is a project-context handoff, not a replacement for the repository. Verify current files and results before making changes. Some validation/test data has already been used during model selection, so do not describe the existing results as a pristine final benchmark.

---

## 1. Project overview

MLWINT is a machine-learning malware detection project built around the EMBER 2018 dataset and its 2,381-dimensional feature representation. The current model candidates are LightGBM, XGBoost, and a 50/50 probability ensemble.

Current intended roles:
- **LightGBM baseline:** primary production candidate.
- **XGBoost baseline:** fast-inference challenger.
- **50/50 LightGBM + XGBoost probability ensemble:** research candidate; it has shown the strongest validation metrics so far, but is slower than a single model.

The system currently includes a feature-array predictor, command-line inference, and a FastAPI service.

## 2. Environment and data

Reported environment:
- Windows PowerShell
- Python `3.13.3`
- LightGBM `4.7.0`
- XGBoost `3.4.1`
- NumPy `2.5.4`
- Project virtual environment: `.venv`

Raw EMBER data directory: `data/raw/ember2018/`
- `train_features_0.jsonl` through `train_features_5.jsonl`
- `test_features.jsonl`
- `ember_model_2018.txt`

Processed chunk directory: `data/processed/ember/train_full_chunks/`
- 600,000 labeled records were vectorized.
- 200,000 unlabeled records were skipped.
- 1,203 chunks (`X_*.npy`, `y_*.npy`); the manifest reportedly records all six training files as completed.

Sample model data:
- `data/processed/ember/model_data/X_sample.npy`: `(100000, 2381)`, `float32`
- `data/processed/ember/model_data/y_sample.npy`: `(100000,)`
- Sample is balanced: 50,000 benign and 50,000 malicious.
- `src/models/prepare_dataset.py` uses `np.random.default_rng(42)`, samples 50,000 records per class without replacement, concatenates them, shuffles, and saves X/y. It does **not** save a source-row/hash mapping.

Feature representation:
- EMBER feature version 2
- 2,381 features
- Feature groups:
  - histogram: indices `0–255`
  - byteentropy: `256–511`
  - strings: `512–615`
  - general: `616–625`
  - header: `626–687`
  - section: `688–942`
  - imports: `943–2222`
  - exports: `2223–2350`
  - datadirectories: `2351–2380`

Important: some hashed section features can be negative because of signed FeatureHasher behavior. **Do not clip negative values.**

Raw JSONL records include fields such as `sha256`, `md5`, `appeared`, `label`, `avclass`, and feature fields. `process_raw_features(record)` was verified to reproduce vectors exactly. A `raw_features(record)` path failed with the installed LIEF version when given precomputed feature structures.

## 3. Train/validation/test split

Split file: `reports/ember/model_comparison/split_indices.npz`

The saved split contains:
- Train: 70,000
- Validation: 15,000
- Test/reserved test: 15,000
- Stratified split, created with `random_state=42`
- Index sets were checked for disjointness and full coverage of the 100,000 sample rows.

`src/models/compare_models.py` created the split and trains several candidates. `src/models/train_xgboost.py` loads the same saved split. A later regularization runner reportedly loads the existing split rather than recreating it. Preserve this split for comparisons unless there is a clearly documented reason to create a new experiment split.

### Evaluation caution

The validation partition has been used repeatedly for model comparison and threshold/regularization tuning. Test metrics have also been explored previously. Therefore, neither partition should be presented as a completely untouched final benchmark. For a defensible final estimate, establish a new untouched evaluation set or use an appropriately designed split/protocol, and document it before examining its results.

A provenance audit reconstructed the sample-row mapping by replaying the deterministic sampling process and matched all 100,000 sample rows to chunk/label provenance. It found examples of identical feature vectors associated with different SHA-256 hashes across partitions. This demonstrates that distinct files can have identical feature vectors; it does **not**, by itself, establish malware-family leakage or prove train/test contamination. Investigate duplicates and provenance carefully before making claims.

## 4. Model artifacts and current candidate roles

Main candidate artifacts:
- `src/models/candidates/lightgbm_baseline.txt`
- `src/models/candidates/lightgbm_regularized.txt`
- `src/models/candidates/extra_trees.joblib`
- `src/models/candidates/random_forest.joblib`
- `src/models/candidates/xgboost_ember.json`

Other, older LightGBM artifacts:
- `src/models/lightgbm_ember.txt`
- `src/models/lightgbm_ember_v2.txt`

The unified regularization experiment writes additional artifacts to:
- `src/models/candidates/regularization_experiment/lightgbm_regularized.txt`
- `src/models/candidates/regularization_experiment/xgboost_regularized.json`

Do not overwrite the baseline candidate artifacts during further experiments. Keep each experimental artifact and its configuration/report separate.

## 5. Model training provenance

### LightGBM baseline

In `src/models/compare_models.py`, the baseline configuration was reported as:
- `n_estimators=1000`
- `learning_rate=0.05`
- `num_leaves=31`
- `colsample_bytree=0.8`
- early stopping patience: 50, monitoring validation binary log loss

Saved as `src/models/candidates/lightgbm_baseline.txt`. The recorded best iteration reached 1000, so the run reached the configured estimator limit rather than stopping early.

### Regularized LightGBM candidate

Configuration in the comparison script was reported as:
- `n_estimators=1200`
- `learning_rate=0.03`
- `num_leaves=15`
- `max_depth=7`
- `min_child_samples=100`
- `reg_alpha=1`
- `reg_lambda=5`
- `colsample_bytree=0.8`
- early stopping patience: 50

Saved as `src/models/candidates/lightgbm_regularized.txt`.

### XGBoost baseline

`src/models/train_xgboost.py` reportedly uses:
- `n_estimators=1500`
- `learning_rate=0.05`
- `max_depth=8`
- `min_child_weight=5`
- `subsample=0.8`
- `colsample_bytree=0.8`
- `reg_alpha=0.1`
- `reg_lambda=5`
- early stopping patience: 50
- evaluation metric: `aucpr`

Saved as `src/models/candidates/xgboost_ember.json`; recorded best iteration: 1284.

### Older scripts are not the same candidates

- `train_model.py` trains an older model saved to `src/models/lightgbm_ember.txt`; its reported 80/20 evaluation arrangement should not be conflated with the saved candidate split.
- `train_model_v2.py` trains an older model saved to `src/models/lightgbm_ember_v2.txt`.
- Do not assume those old artifacts are the models used in the current predictor.

## 6. Recorded baseline validation results

These results were measured on the repeatedly used 15,000-row validation partition. They are useful for reproducing the current comparison, not for claiming final unbiased performance.

| Candidate | ROC-AUC | PR-AUC | Log loss | F1 at threshold 0.5 |
|---|---:|---:|---:|---:|
| LightGBM baseline | 0.995208 | 0.995536 | 0.08716 | 0.96779 |
| XGBoost baseline | 0.995579 | 0.995812 | 0.08421 | 0.96708 |
| 50/50 baseline ensemble | 0.995611 | 0.995875 | 0.08320 | 0.96776 |

Additional recorded results:
- LightGBM baseline best iteration: 1000.
- XGBoost baseline best iteration: 1284.
- The baseline ensemble had the strongest validation ROC-AUC, PR-AUC, and log loss in the recorded comparison.
- The ensemble's gain over XGBoost is small and inference is slower than a single model.

### Train/validation fit audit for baseline LightGBM

Reported training metrics:
- ROC-AUC: `0.999997702`
- PR-AUC: `0.999997708`
- log loss: `0.023520669`
- accuracy: `0.999471429`
- precision: `0.999428620`
- recall: `0.999514286`
- F1: `0.999471451`

Reported validation metrics:
- ROC-AUC: `0.995208409`
- PR-AUC: `0.995536084`
- log loss: `0.087162253`
- accuracy: `0.967933333`
- precision: `0.969875485`
- recall: `0.965866667`
- F1: `0.967866925`

Gaps reported:
- ROC-AUC train minus validation: `0.004789293`
- F1 train minus validation: `0.031604526`
- validation minus training log loss: `0.063641584`

Interpretation: the model fits the training partition extremely well, with a meaningful train/validation gap. Continue checking generalization, calibration, and performance on genuinely independent data.

### Stronger-regularization sweep (corrected evaluation)

A bug in the first evaluation pass was corrected: calling `LGBMClassifier.predict()` returned hard labels rather than probabilities. The corrected evaluator uses `predict_proba()` for `LGBMClassifier` and probability predictions for the LightGBM Booster. Treat the following as the corrected reported results:

| Configuration | ROC-AUC | PR-AUC | Log loss | F1 at threshold 0.5 |
|---|---:|---:|---:|---:|
| Baseline LightGBM | 0.995208 | 0.995536 | 0.08716 | 0.96779 |
| Baseline XGBoost | 0.995579 | 0.995812 | 0.08421 | 0.96708 |
| Baseline ensemble | 0.995611 | 0.995875 | 0.08320 | 0.96776 |
| Stronger-regularized LightGBM | 0.993891 | 0.994140 | 0.10216 | 0.96098 |
| Stronger-regularized XGBoost | 0.994790 | 0.995016 | 0.09218 | 0.96407 |
| Ensemble with regularized LightGBM + baseline XGBoost | 0.994958 | 0.995179 | 0.09021 | 0.96496 |
| Ensemble with baseline LightGBM + regularized XGBoost | 0.995257 | 0.995515 | 0.08792 | 0.96611 |
| Ensemble with both regularized candidates | 0.994497 | 0.994724 | 0.09623 | 0.96290 |

Interpretation: the stronger regularization tested here reduced validation performance. This does not prove regularization is generally unhelpful; the chosen settings may be too strong or not well matched to the data. Do not replace the baseline models based on this sweep.

A first result table from the experiment runner was invalid for the newly trained LightGBM models because it called `LGBMClassifier.predict()` and treated hard labels as probabilities. That table's LightGBM probability metrics (including an ROC-AUC around `0.961133`) must be disregarded. The corrected reevaluation script is `src/models/reevaluate_regularization.py`; its report is `reports/ember/model_comparison/regularization_experiment_corrected.json`.

## 7. Current experiment state and recommended next steps

The last planned step was a **mild regularization sweep** for LightGBM and XGBoost. It has not been confirmed as completed.

Suggested workflow:
1. Inspect the current repository, `git status`, README, and experiment scripts before changing anything.
2. Read `src/models/run_regularization_experiment.py` and `src/models/reevaluate_regularization.py`; verify current configs and saved outputs.
3. Keep baseline artifacts unchanged.
4. Run a controlled, mild regularization sweep with a small number of configurations. Change only a few parameters at a time and save every candidate/configuration separately.
5. Compare validation ROC-AUC, PR-AUC, log loss, calibration, F1, precision, recall, and confusion matrices. For operational use, evaluate at a threshold chosen to meet an explicit false-positive-rate or false-negative-rate requirement, not only at 0.5.
6. Measure inference latency and memory on a representative batch and hardware.
7. Do not select a winner solely on this reused validation partition. Define a clean final evaluation protocol before reporting final benchmark numbers.
8. Investigate data provenance and exact feature-vector duplicates; distinguish identical vectors from same-file duplicates and from family-level leakage.
9. Add/verify reproducibility metadata: package versions, random seeds, feature schema/version, dataset source and checksums, model configuration, training split IDs, and artifact hashes.

A previous `learning_curve_analysis.py` evaluates one already-trained model on subsets of its original training rows and reuses the same validation predictions; it is **not** a conventional learning curve and cannot establish whether retraining on more data would help.

## 8. Predictor, CLI, and API

### Predictor

File: `src/detection/predictor.py`

Reported behavior:
- `MalwarePredictor(model_name: Literal["lightgbm", "xgboost", "ensemble"] = "lightgbm")`
- Project root resolved using `Path(__file__).resolve().parents[2]`
- Candidate model directory: `src/models/candidates`
- Expected feature count: `2381`
- Loads `lightgbm_baseline.txt` for LightGBM and ensemble.
- Loads `xgboost_ember.json` for XGBoost and ensemble.
- Converts inputs to `float32`, supports one- or two-dimensional arrays, validates 2,381 columns and finite values.
- `predict_proba()` returns probabilities.
- `predict(features, threshold=0.5)` validates threshold in `[0, 1]` and returns `int8` labels.
- Ensemble prediction is the 50/50 mean of LightGBM and XGBoost probabilities.

### CLI

File: `src/detection/cli.py`

Reported interface:
- `--model` accepts `lightgbm`, `xgboost`, or `ensemble`.
- Requires `.npy` feature input.
- Optional CSV output.
- Threshold defaults to `0.5`.
- Uses memory mapping and `allow_pickle=False`.

The CLI was run against the 100,000-row sample. Recorded counts:
- LightGBM: 49,929 malicious; 50,071 benign
- XGBoost: 49,894 malicious; 50,106 benign
- Ensemble: 49,899 malicious; 50,101 benign

These are prediction counts only; they are not accuracy figures.

### FastAPI

File: `src/detection/api.py`

Reported launch command from the project root:
```powershell
python -m uvicorn src.detection.api:app --host 127.0.0.1 --port 8000
```

Endpoints:
- `GET /health`
- `GET /models`
- `POST /predict`

The API was started successfully. A test using one feature vector from `X_sample.npy` returned HTTP 200:
- LightGBM: `97.1886%` malicious probability
- XGBoost: `99.7050%` malicious probability
- Ensemble: `98.4468%` malicious probability

These are model outputs for one sample, not proof of malware status or model accuracy.

## 9. Tests and key files

Reported tests:
- `tests/test_predictor.py`: 6 tests passed.

Important files to inspect first:
```text
src/detection/predictor.py
src/detection/cli.py
src/detection/api.py
src/models/compare_models.py
src/models/train_xgboost.py
src/models/diagnose_model_fit.py
src/models/evaluate_regularized_fit.py
src/models/run_regularization_experiment.py
src/models/reevaluate_regularization.py
reports/ember/model_comparison/split_indices.npz
reports/ember/model_comparison/comparison_results.json
reports/ember/model_comparison/regularization_experiment_corrected.json
```

Existence of these files and results was reported in the previous chat; verify in the current checkout rather than assuming every file is present.



Repository preparation note: historical metrics and claims above are context, not newly run checks.
