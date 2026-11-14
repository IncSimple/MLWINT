# Trained models

Models are not stored in the repository; they are attached to GitHub Releases.

- **For the app (`v1.0.0` and later):** `MLWINT-models-<version>.zip` holds `models/phase1` (detector bundle: cards, models, parity vectors, manifest) and `models/phase2` (family and behaviour classifiers). Unzip it into the repository root. The Windows installer already contains them.
- **Phase 1 research release (`v1.0-phase1`):** the individual detector files below, with `SHA256SUMS.txt`.

| File type | XGBoost | LightGBM | Detector card |
|---|---|---|---|
| Win32 | `XGB_WIN32_extended.ubj` | `LGBM_WIN32_extended.txt` | `results/phase1/verdict_policy_win32.json` |
| Win64 | `XGB_WIN64.ubj` | `LGBM_WIN64.txt` | `results/phase1/verdict_policy_win64.json` |
| .NET | `XGB_DOTNET.ubj` | `LGBM_DOTNET.txt` | `results/phase1/verdict_policy_dotnet.json` |
| PDF | `XGB_PDF_0-51.ubj` | `LGBM_PDF_0-51.txt` | `results/phase1/verdict_policy_pdf.json` |

`SHA256SUMS.txt` in the release lists every file's checksum; the same checksums are in each detector card.

## Giving a verdict
1. Extract the 2,568 features with the EMBER2024 `thrember` `PEFeatureExtractor`.
2. Raw scores: XGBoost `inplace_predict(X, predict_type='margin')`, LightGBM `predict(X, raw_score=True)`
   (xgboost 3.4.1, lightgbm 4.7.0).
3. For each model, `p = sigmoid(slope * score + intercept)` with the card's `ensemble.calibration`.
4. Ensemble probability = the card's `ensemble.weights` applied to those probabilities (50/50).
5. Verdict: at or above `verdicts.malicious.threshold` → MALICIOUS; at or above
   `verdicts.suspicious.threshold` → SUSPICIOUS; otherwise CLEAN.
