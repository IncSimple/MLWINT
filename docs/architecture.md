# Architecture
The existing namespace-package layout is preserved. `src/ingestion` converts raw
EMBER structures with `PEFeatureExtractor(feature_version=2).process_raw_features`.
`src/models/prepare_dataset.py` samples 50,000 rows per class with NumPy seed 42.
`compare_models.py` saves stratified 70,000/15,000/15,000 indices with seed 42.
Training scripts save local artifacts; `src/detection/predictor.py` resolves the
repository root using `Path(__file__).resolve().parents[2]`.
The predictor loads baseline candidates lazily when constructed. The API caches
predictors per model name. Ensemble scores are the mean of two probabilities.
CLI input supports batches; API requests contain one feature vector.
No database, web dashboard, raw-file upload pipeline or dynamic sandbox is implemented.
