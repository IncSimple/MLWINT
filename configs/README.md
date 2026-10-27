# Configuration
Runtime paths resolve relative to the repository root. Supported model names:
lightgbm, xgboost, ensemble; default lightgbm. Features: EMBER v2 / 2381 / float32.
Default threshold: 0.5. Sampling and split seed: 42.
Training parameters remain in the existing scripts, documented in
docs/model-training.md. No YAML/JSON config loader or environment override is implemented.
`artifacts.json` is a provenance manifest, not a runtime configuration file.
