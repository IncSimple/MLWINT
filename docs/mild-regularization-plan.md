# Mild regularization experiment plan

Continuation checkpoint: 2026-10-27. Status: proposed, not trained.

The handoff identifies a mild regularization sweep as the next research task.
Inspection confirmed the existing stronger-regularization scripts and corrected
report; no mild-sweep runner or results were found. The original runner still
used hard classifier labels as probabilities; this checkpoint fixes that path
and shares the corrected extraction with the reevaluator. Old report files
remain historical records rather than results of the corrected runner.

## Verified starting point

- Existing environment: Python 3.13.3, NumPy 2.5.4, LightGBM 4.7.0,
  XGBoost 3.4.1. No dependencies were installed or upgraded.
- EMBER 2018/v2 sample: `(100000, 2381)` float32 features and 100,000 labels,
  with 50,000 samples in each class.
- Saved split: 70,000 training, 15,000 validation, 15,000 test indices;
  disjoint with full sample coverage. The test partition is already exploratory
  from prior work and will not be evaluated by this sweep.
- Baseline model and split hashes match `configs/artifacts.json`.
- Verification: 41 tests without saved model dependencies passed in 2.16 seconds,
  including the new classifier/saved-Booster probability regression test. The
  six artifact-dependent integration cases were deselected. The restricted
  Windows runtime stalled in existing asyncio tests; the completed suite used
  normal runtime access with the same existing Python environment.
- The source export is the GitHub working copy. Data, trained models and the
  existing environment remain in the separate original research folder.

## Proposed configurations

Train four candidates sequentially. Each changes one regularization parameter
from its respective baseline; use seed 42, the saved training/validation rows,
and the original early-stopping metric and patience of 50 rounds.

| Candidate | Only change from baseline |
|---|---|
| lightgbm_min_child_40 | `min_child_samples=40` (baseline default: 20) |
| lightgbm_lambda_1 | `reg_lambda=1.0` (baseline default: 0.0) |
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

Implement a new guarded runner with explicit research-data and artifact paths;
the historical runner still trains its original stronger configurations.
Default to a dry run that shows resolved configurations and outputs. Require
an explicit training option and refuse existing output directories.

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
Compare each candidate's equal-weight probability ensemble with the other
unchanged baseline. Do not use hard class labels for ranking/calibration metrics
or clip signed input features.

Measure warmed prediction latency over the same fixed validation batch and
record thread count, CPU, repetitions and process peak memory with its platform
and scope. Latency and process memory remain workload-dependent observations.

No operational threshold target has been set. Report threshold-0.5 comparisons
without presenting them as an operational recommendation. A later deployment
decision needs an explicit false-positive/negative target. All results from
these reused partitions remain exploratory; define and document an independent
evaluation protocol before making final benchmark claims.

## GitHub workflow

The user requested incremental pushes to `IncSimple/MLWINT`. For each completed
checkpoint, review the exact changed files, run relevant tests, commit and push
the source export. Verify the remote commit before reporting a successful push.
Preserve the original research history, baseline artifacts and saved split.
