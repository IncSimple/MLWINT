# Model training
Run documented training commands only in a separate experiment copy. They are
existing research scripts with fixed output paths, some executing at import time.
Do not import them in tests or application startup.

| Entry point (`python -m ...`) | Inputs | Writes |
|---|---|---|
| `src.models.prepare_dataset` | full X/y chunks | X_sample.npy, y_sample.npy |
| `src.models.compare_models` | sample arrays | split_indices.npz, LightGBM/forest candidates, comparison_results.json |
| `src.models.train_xgboost` | sample and saved split | xgboost_ember.json, xgboost_validation.json |
| `src.models.run_regularization_experiment` | sample and saved split | separate regularization_experiment models and reports |

`compare_models` recreates the stratified split with random_state 42. Preserve the
saved split and exact sample order for existing comparisons. Baseline LightGBM
uses 1,000 estimators, learning_rate 0.05, 31 leaves and colsample_bytree 0.8;
validation log-loss early stopping patience is 50. XGBoost uses 1,500 estimators,
learning_rate 0.05, depth 8, min_child_weight 5, subsample/colsample 0.8,
reg_alpha 0.1, reg_lambda 5 and aucpr early stopping patience 50.
Older `train_model.py` and `train_model_v2.py` save different LightGBM artifacts;
the predictor uses neither. Scripts and observed versions are the authoritative
configuration; there is no external YAML config loader.
