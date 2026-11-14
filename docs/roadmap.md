# Roadmap

## Phase 1: Detection ✅
Per-file-type detectors for Win32, Win64, .NET and PDF, each an XGBoost + LightGBM ensemble, with a
three-level verdict (malicious / suspicious / clean). See [phase1-results.md](phase1-results.md).

## Phase 2: Analysis ✅
- Family and behaviour classifiers from EMBER2024 tags, shown only at tested precision tiers.
- Evidence: capa capabilities mapped to MITRE ATT&CK; PDF active-content indicators.
- Safe simulation with Speakeasy emulation for suspicious and risky files.
- The transparent 0-100 threat meter (every point explained).

## Phase 3: Intelligence ✅
- PC context (origin, ran before, running, autostart, Defender history), offline ATT&CK explanations and
  mitigations, opt-in hash-only reputation, prioritised plain-language advice.
- Desktop app (Flutter, Material 3), scan memory, whole-PC and large-file checks, easy-to-read PDF reports,
  history with comparisons, Windows installer with in-place updates (v1.0.0).

## Next
- **PDF detector retrain on real-world clean PDFs** (the EMBER2024 PDF model over-flags ordinary documents;
  currently handled by the PDF cap).
- An outside reality check on recent files from a different source.
- Periodic retraining on newer weeks; drift monitoring.
- Code-signed installer; optional in-app update check.
