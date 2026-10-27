# Evaluation protocol and recorded results
The repository preserves `reports/ember/model_comparison/split_indices.npz`:
train_idx 70,000; val_idx 15,000; test_idx 15,000, seed 42. Repository preparation
checks disjointness and full coverage but does not rerun dataset-wide evaluation.

The README table comes from `ensemble_validation_comparison.json`, with threshold
0.5. PR-AUC is the scripts' `average_precision_score` convention. Additional
log-loss results are in `regularization_experiment_corrected.json`.
Use `python -m src.models.evaluate_ensemble` for the baseline comparison or
`python -m src.models.reevaluate_regularization` for the corrected experiment;
both require local arrays/models and overwrite their reports.

Validation is reused for tuning, early stopping and selection; test metrics were
also explored. These are exploratory results, not untouched final benchmarks.
Threshold 0.5 results differ from the selected FPR-limited threshold results.
Choose operational thresholds under explicit FPR/FNR requirements using a
documented protocol before examining a new final evaluation set.
