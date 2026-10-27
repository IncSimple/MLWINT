# Experiment interpretation
Existing reports and scripts are retained, including historical failures. No new
training or mild regularization sweep is performed for repository organization.

`regularization_experiment.json` and its CSV contain an invalid evaluation path
for newly trained LightGBM classifiers: hard-label `predict()` outputs were treated
as probabilities. Use `regularization_experiment_corrected.json` for probability
metrics. `reevaluate_regularization.py` uses Booster.predict or classifier
predict_proba appropriately. The corrected report records stronger regularization
performing worse on reused validation data. This does not establish that all
regularization is harmful.

`learning_curve_analysis.py` evaluates one fixed fitted model on subsets; it is
not a learning curve from retraining at different sample sizes. Its existing plots
do not establish the benefit of adding training data. `batch_evaluation(Failed).py`
is retained as historical work and is not a supported workflow. Prediction CSVs
are generated local outputs and excluded. Latency reports reflect their recorded
hardware/workload, not a portable deployment guarantee.
