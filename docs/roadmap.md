# Roadmap

## Phase 1: Detection ✅
Per-file-type detectors for Win32, Win64, .NET and PDF, each an XGBoost + LightGBM ensemble, with a
three-level verdict (malicious / suspicious / clean). See [phase1-results.md](phase1-results.md).

## Phase 2: Analysis (next)
Goal: for every file Phase 1 marks malicious or suspicious, describe **what it is and what it can do**.
- **Family, behaviour and technique prediction.** EMBER2024 includes, for many malicious files, a family
  label, behaviour tags (for example *dropper*), capa capabilities (for example *create process
  suspended*) and MITRE ATT&CK techniques (for example *Obfuscated Files or Information, T1027*). Models
  trained on these tags can predict them for new files from the same features.
- **Threat meter:** one easy-to-read risk level combining the detection score with the capabilities found.
- **Resolving "suspicious" files:** a suspicious verdict triggers deeper checks (capability analysis, and
  later an isolated Windows virtual machine) so uncertain files are confirmed or cleared, not guessed.
- **Drift monitoring:** especially for PDF, where malware changes quickly.

## Phase 3: Intelligence
Goal: turn the evidence into **plain-language explanations and advice**.
- What the file is, what it can do, how risky it is, and what the user can do about it.
- A desktop application (PySide6): model details one click away, real progress reporting.
- MLWINT stays **read-only**: it never deletes, quarantines or changes files.

## Open items
- An outside reality check: score the detectors on recent files from a different source.
- Periodic retraining on newer weeks (PDF first).
