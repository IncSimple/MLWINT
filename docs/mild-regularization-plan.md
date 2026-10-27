# Mild regularization experiment plan

Continuation checkpoint: 2026-10-27. Status: runner implemented and tested;
the EMBER sweep has not been trained.

This sweep tests small regularization changes against the saved baseline models
using the existing development split. Probability extraction uses the corrected
LightGBM helper. Historical stronger-regularization reports remain separate.

## Verified starting point

- Existing environment: Python 3.13.3, NumPy 2.5.4, LightGBM 4.7.0,
  XGBoost 3.4.1. No dependencies were installed or upgraded.
- EMBER 2018/v2 sample: `(100000, 2381)` float32 features and 100,000 labels,
  with 50,000 samples in each class.
- Saved split: 70,000 training, 15,000 validation, 15,000 test indices;
  disjoint with full sample coverage. The test partition is already exploratory
  from prior work and will not be evaluated by this sweep.
- Baseline model and split hashes match `configs/artifacts.json`.
- Verification: 53 tests without saved model dependencies passed in 3.04 seconds,
  including probability extraction and synthetic sweep tests. The six
  artifact-dependent integration cases were deselected. The completed suite
  used normal Windows runtime access with the existing Python environment.
- The source export is the GitHub working copy. Data, trained models and the
  existing environment remain in the separate original research folder.

## Proposed configurations

Train seven candidates sequentially. Each changes one regularization parameter
from its respective baseline; use seed 42, the saved training/validation rows,
and the original early-stopping metric and patience of 50 rounds.

| Candidate | Only change from baseline |
|---|---|
| lightgbm_min_child_40 | `min_child_samples=40` (baseline default: 20) |
| lightgbm_leaves_23 | `num_leaves=23` (baseline: 31) |
| lightgbm_alpha_01 | `reg_alpha=0.1` (baseline default: 0.0) |
| lightgbm_lambda_1 | `reg_lambda=1.0` (baseline default: 0.0) |
| xgboost_depth_7 | `max_depth=7` (baseline: 8) |
| xgboost_min_child_7 | `min_child_weight=7` (baseline: 5) |
| xgboost_lambda_7 | `reg_lambda=7.0` (baseline: 5.0) |

Common LightGBM configuration: binary objective, 1,000 estimators,
learning rate 0.05, 31 leaves, column sampling 0.8; remaining parameters at
baseline defaults, with defaults and effective parameters recorded at run time.
Monitor validation binary log loss. Use a bounded thread count of 6; record it
as an execution difference from the original baseline's `n_jobs=-1`.

Common XGBoost configuration: binary logistic objective, validation `aucpr`,
1,500 estimators, learning rate 0.05, depth 8, child weight 5, row/column sampling
0.8, alpha 0.1, lambda 5.0, histogram trees, CPU, 6 threads. Apply only the named
candidate override.

## Outputs and evaluation

The new `src/models/run_mild_regularization.py` reads
`configs/mild_regularization.json`; the historical runner still trains its
original stronger configurations. The new runner defaults to a dry run that
validates inputs and shows resolved configurations and outputs. `--run` enables
training; existing run output directories are refused.

Run from the source export with the existing research environment active:

```powershell
# Replace the placeholder with the original project folder containing the data/models.
python -m src.models.run_mild_regularization --research-root "PATH_TO_RESEARCH_CHECKOUT" --run-id mild-v1
# Same resolved plan, explicitly enabling training:
python -m src.models.run_mild_regularization --research-root "PATH_TO_RESEARCH_CHECKOUT" --run-id mild-v1 --run
```

`--output-root` defaults to the runner's repository root. `--jobs` defaults to 6.
Each run checks the existing split, binary labels and 2,381-column float32 schema;
training also checks finite training/validation feature values. It never
generates test predictions. A completed run verifies baseline/split hashes have
not changed. Failed runs retain their checkpoint and require a fresh run ID.

For each unique run ID, write configuration, environment versions, input and
artifact SHA-256 hashes, split counts, best iteration, training time and metrics
under `reports/ember/model_comparison/mild_regularization/<run_id>/`.
Keep trained model files in the corresponding local ignored directory under
`src/models/candidates/mild_regularization/<run_id>/`. Push source,
configurations and aggregate reports to GitHub; keep datasets, environments,
trained models and per-row predictions local.

Evaluate the existing baselines and each new candidate on training and reused
validation rows. Report ROC-AUC, average precision, log loss, Brier score and a
fixed 10-bin reliability table. At threshold 0.5, record precision, recall, F1,
false-positive/negative rates and confusion counts, plus train/validation gaps.
Compare all 20 cross-algorithm pairs at fixed equal weights, including the
baseline ensemble and each new candidate paired with the opposite baseline.
There are nine single-model evaluations and 20 ensembles, ranked together in
`by_pr_auc.csv` (descending PR-AUC, then ascending log loss) and `by_log_loss.csv`
(ascending log loss, then descending PR-AUC), alongside ROC-AUC, Brier score and
F1. `report.json` contains full train/validation results and is checkpointed after
each assessment. Hard class labels are never used for ranking/calibration metrics;
signed input features are not clipped.

Measure warmed prediction latency over the first 1,024 saved validation indices
with three measured repetitions after one warm-up call. Record thread count,
CPU and cumulative process peak memory, including data and previously loaded
models. This memory figure is not an isolated per-model measurement. Ensemble
timings execute both constituent models. Batch size/repetitions can be changed
with `--latency-batch-size` and `--latency-repeats`.

No operational threshold target has been set. Report threshold-0.5 comparisons
without presenting them as an operational recommendation. A later deployment
decision needs an explicit false-positive/negative target. All results from
these reused partitions remain exploratory; define and document an independent
evaluation protocol before making final benchmark claims.

## Runner verification

The original EMBER inputs passed the dry run with the existing environment and
70,000/15,000/15,000 saved indices. A separate tiny synthetic run trained both
algorithms, saved both candidates, evaluated four singles and four ensembles,
wrote JSON/CSV reports, preserved every input hash and refused a repeated run ID.
Synthetic test-partition features contained NaNs to verify they were not used
in training/validation prediction. These smoke-test scores are not project
performance results. No synthetic models or test reports are published.
The completed suite passed 53 tests without saved-model dependencies; the six
artifact-dependent integration cases were deselected. LightGBM emitted an
`eval_set` deprecation warning in the synthetic fit; execution completed.

## GitHub workflow

The user requested incremental pushes to `IncSimple/MLWINT`. For each completed
checkpoint, review the exact changed files, run relevant tests, commit and push
the source export. Verify the remote commit before reporting a successful push.
Preserve the original research history, baseline artifacts and saved split.
