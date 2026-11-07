# Methodology

## Dataset and features
- **EMBER2024** (`joyce8/EMBER2024` on Hugging Face, pinned to revision `3d23efef`), weekly files from
  late September 2023 to mid-December 2024: 52 training weeks plus 12 official test weeks.
- Features: the `thrember` `PEFeatureExtractor`, 2,568 numbers per file (byte histogram, byte entropy,
  strings, general file information, and PE header / section / import / export details). EMBER2024 stores
  every file type in this same layout; for PDFs the PE-specific parts are simply empty.
- Labels come from the dataset (aggregated antivirus results). Files are never executed.

## Time-ordered splits
| Part | Weeks | Purpose |
|---|---|---|
| inner_fit | 0–35 | model fitting |
| inner_stop | 36–39 | choosing boosting rounds and SVM settings |
| development | 40–51 | calibration, thresholds, choosing primary / challenger |
| test | 52–63 | scored once, after everything else was frozen |

Final models are retrained on weeks 0–39 with the chosen settings. (PDF's shipped models use weeks 0–51:
settings chosen on weeks 48–51, thresholds from the weeks 0–47 models' scores on weeks 48–51.)

## Leakage controls
Applied while preparing each file type, then re-checked by an independent audit before training:
- one row per unique SHA-256; repeated records must agree on label, vector and date;
- feature vectors shared by a clean and a malicious file are removed; one row per identical vector;
- a later period drops any file (SHA-256) or identical vector already seen in an earlier period;
- every file's first-submission date must fall inside its period; periods are strictly ordered in time;
- a "too good" check: no single feature may separate the classes almost perfectly (AUC ≥ 0.99);
- test labels are sealed: not counted or printed until the roles are frozen.

Not covered: near-duplicates, repacked variants of the same malware, and family overlap across periods.

## Models and selection
- **XGBoost** (depth 6, eta 0.05, 80% columns per tree, 256 bins) and **LightGBM** (31 leaves,
  learning rate 0.05, 80% features). The same parameters for every file type.
- **Linear SVM**: hinge loss with averaged SGD on signed-log, standardised features (scaler learned on
  inner_fit only); the alpha grid and number of epochs chosen on inner_stop.
- **Calibration:** Platt scaling per model on development data.
- **Thresholds:** the score at which at most 1% of clean development files are flagged.
- **Ranking:** development recall at that threshold, then development average precision.
  Best = primary, second = challenger; the shipped detector averages their calibrated probabilities 50/50.

## Overfitting checks
- Learning curves on inner_fit vs inner_stop for every tree model (patience-based stopping, never the
  round limit).
- Training-sample vs development vs test log loss and average precision for every candidate.
- Week-by-week recall and false-alarm rate on the test.

## Reproducibility
Every script freezes a protocol (including its own checksum), verifies every input file by SHA-256,
writes checkpoints to Google Drive and resumes after interruptions.
