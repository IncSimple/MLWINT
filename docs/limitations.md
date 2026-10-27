# Limitations and future work
- Historical static PE features are not evidence of current-threat generalization.
- The 100,000-row balanced sample does not reflect deployment class prevalence.
- Reused validation/test results require a new independent evaluation protocol.
- Identical feature vectors can correspond to distinct hashes; investigate
  same-file, vector and family-level overlap separately before making leakage claims.
- Sample preparation saves no source-row/hash mapping; improve provenance in a
  new experiment while preserving existing sample and split artifacts.
- Calibration, drift, adversarial robustness and operational thresholds need study.
- Raw binary extraction compatibility is not validated with current LIEF.
- Authentication, rate limits, artifact readiness and operational monitoring are future work.
- Fresh dependency installation, hosted CI and non-Windows support are not yet verified.
