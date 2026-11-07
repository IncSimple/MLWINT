# Phase 1 results: detection

All numbers are on EMBER2024 with the time-ordered split described in [methodology.md](methodology.md).
"Malware caught" is recall; "false alarms" is the share of clean files flagged. Unless stated otherwise,
thresholds were set for **1% false alarms on development data** and then applied unchanged to the test.

## Data per file type

| File type | Training (weeks 0–35) | Round selection (36–39) | Development (40–51) | Test (52–63) |
|---|---|---|---|---|
| Win32 | 1,079,988 | 119,986 | 359,990 | 359,991 |
| Win64 | 359,993 | 39,997 | 120,000 | 119,990 |
| .NET | 180,000 | 20,000 | 60,000 | 59,953 |
| PDF | 36,000 | 4,000 | 12,000 | 12,000 |

Every set is balanced between malware and clean files. Exact duplicates, cross-period overlaps and
conflicting labels were removed before training (counts are in each format's preparation report).

## Trained models

| File type | XGBoost rounds | LightGBM rounds | Dev AP (XGB / LGBM) | Linear SVM (alpha, epochs, dev AP) |
|---|---|---|---|---|
| Win32 | 5,529 | 6,011 | 0.99825 / 0.99818 | 1e-3, 14, 0.98804 |
| Win64 | 2,028 | 2,143 | 0.99883 / 0.99885 | 1e-3, 14, 0.99481 |
| .NET | 713 | 745 | 0.99743 / 0.99728 | 1e-7, 4, 0.98681 |
| PDF (weeks 0–39) | 213 | 167 | 0.99832 / 0.99842 | 1e-2, 6, 0.99262 |
| PDF (weeks 0–51, shipped) | 289 | 253 | – | 1e-2, 3 |

Rounds were chosen on weeks 36–39 only (stop after 100 rounds without improvement), then the model was
retrained on all training weeks for exactly that many rounds. Win32 continued earlier 2,000-round models.

## Four-way comparison (test weeks 52–63)

Roles were chosen on development data and frozen before the test was opened.

### Win32 (test seen once before: benchmark)
| Model | Caught | False alarms | Missed | AP |
|---|---|---|---|---|
| **Ensemble (LightGBM + XGBoost)** | **96.48%** | 0.99% | 6,331 | 0.99806 |
| B LightGBM (primary) | 96.47% | 1.02% | 6,359 | |
| A XGBoost (challenger) | 96.44% | 0.96% | 6,403 | |
| D LightGBM + SVM | 94.12% | | 10,576 | |
| C XGBoost + SVM | 94.05% | | 10,717 | |
| SVM alone | 84.14% | | 28,556 | |
| Earlier 2,000-round XGBoost | 95.67% | | 7,798 | |

Training longer cut missed malware by about 18% versus the earlier 2,000-round models.
Weekly ensemble recall: 94.95–97.53%.

### Win64 (fresh test)
| Model | Caught | False alarms | Missed | AP |
|---|---|---|---|---|
| **Ensemble (LightGBM + XGBoost)** | **97.71%** | 1.08% | 1,372 | 0.99859 |
| B LightGBM (primary) | 97.69% | 1.10% | 1,387 | 0.99857 |
| A XGBoost (challenger) | 97.64% | 1.07% | 1,417 | 0.99854 |
| C XGBoost + SVM | 96.59% | 1.03% | 2,047 | 0.99788 |
| D LightGBM + SVM | 96.54% | 1.01% | 2,074 | 0.99790 |
| SVM alone | 93.10% | 0.96% | 4,141 | 0.99462 |

Development recall 97.98% → test 97.71%. Weekly ensemble recall: 97.3–98.2%.

### .NET (fresh test)
| Model | Caught | False alarms | Missed | AP |
|---|---|---|---|---|
| **Ensemble (XGBoost + LightGBM)** | **94.36%** | 0.89% | 1,692 | 0.99771 |
| A XGBoost (primary) | 94.14% | 0.87% | 1,759 | 0.99766 |
| B LightGBM (challenger) | 94.21% | 0.89% | 1,736 | 0.99764 |
| C XGBoost + SVM | 91.13% | 0.75% | 2,660 | 0.99655 |
| D LightGBM + SVM | 90.84% | 0.74% | 2,749 | 0.99656 |
| SVM alone | 79.01% | 0.65% | 6,298 | 0.99084 |

No drift: development ≈ 94.5% → test 94.4%. Weekly ensemble recall: 93.8–95.2%.

### PDF
First run (models trained on weeks 0–39, fresh test):

| Model | Caught | False alarms | Missed |
|---|---|---|---|
| Ensemble (LightGBM + XGBoost) | 93.22% | 2.13% | 407 |
| C XGBoost + SVM | 94.07% | 2.05% | 356 |
| D LightGBM + SVM | 94.15% | 2.15% | 351 |
| SVM alone | 89.65% | 1.82% | 621 |

Strong drift: development recall 98.0% fell to 93.2% on the test, and false alarms doubled.
The models were therefore retrained on all weeks 0–51 with a procedure fixed in advance
(second look at the same test, so this is a benchmark):

| | Weeks 0–39 ensemble | **Weeks 0–51 ensemble (shipped)** |
|---|---|---|
| Malware caught | 93.22% | **94.97%** |
| Missed | 407 | **302** |
| False alarms | 2.13% | 2.67% |
| AP / log loss | 0.99196 / 0.123 | **0.99328 / 0.106** |
| Worst week | 88.4% | **92.0%** |

The newer models rank files better; the higher false-alarm rate comes from thresholds set on only four
weeks of clean PDFs. This is handled by the verdict policy below.

## The linear SVM question
Pairing each tree model with a linear SVM (50/50) was tested on every file type. The SVM alone does catch
some files both trees miss (for example 418 of 1,763 on Win64), but averaging it in breaks roughly three
correct files for every one it fixes. It lost on development data every time and is not used.

## Phase 1 close-out: the verdict policy
Thresholds: 🔴 MALICIOUS where ≤ 0.5% of clean calibration files score higher; 🟠 SUSPICIOUS down to ≤ 3%;
🟢 CLEAN below. Calibration data: development weeks 40–51 (PDF: weeks 48–51).

| File type | Malware 🔴 | Malware 🟠 | Malware missed | Clean wrongly 🔴 | Clean 🟠 |
|---|---|---|---|---|---|
| Win32 | 95.2% | 2.8% | 2.0% (3,602) | 0.55% (996) | 2.3% |
| Win64 | 96.0% | 3.1% | 0.9% (514) | 0.47% (282) | 2.9% |
| .NET | 91.3% | 6.6% | 2.1% (632) | 0.48% (143) | 2.0% |
| PDF | 93.5% | 4.3% | 2.2% (132) | 1.67% (100) | 4.9% |

Against the single 1% threshold, malware missed outright fell from 6,331 / 1,372 / 1,692 / 302 to
3,602 / 514 / 632 / 132 (Win32 / Win64 / .NET / PDF), while false "malicious" verdicts roughly halved.
The 0.5% target held on later weeks for Win32, Win64 and .NET (0.47–0.55%); PDF still drifts (1.67%).

Each file type has a **detector card** (`results/phase1/verdict_policy_<type>.json`) with the model files,
their checksums, the calibration, the ensemble weights and both thresholds.

## Side result: Android (not part of MLWINT)
APK models trained earlier on the MH-1M dataset (XGBoost + LightGBM ensemble: 93.49% malware caught at
0.97% false alarms) are kept aside for a separate Android app.
