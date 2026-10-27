# Repository preparation — 2026-10-27

## Outcome
This source-and-reports export preserves the existing MLWINT implementation and
relative paths. The original research checkout remains on disk with its existing
history, raw dataset, generated arrays and trained models. A separate clean Git
repository was initialized on main for this export. No remote, stage, commit or
push was created automatically.

## Original inspection
- Branch main; one commit, 0737654 (Initial commit); no configured remotes.
- 2,502 tracked files totaling 18,630,713,835 bytes in the working checkout.
- The commit includes raw JSONL files, downloaded archive, generated arrays and models.
- Existing untracked detection code, tests, audit scripts and experiment reports
  were included in this export where lightweight; nothing was discarded from the original.
- Existing MIT license and copyright were preserved.
- No credential filenames or common GitHub/AWS/private-key patterns matched the
  original commit scan. Text-content scope: Python, Markdown, TOML, YAML and JSON;
  raw JSONL, binary datasets and model binaries were not scanned for arbitrary secrets.
  This pattern scan is not a guarantee that all sensitive content has been identified.

## Created or improved
- README: verified commands, architecture Mermaid diagram, setup, inference,
  saved comparison metrics, dataset attribution, limitations and license notes.
- docs/: architecture, installation, dataset, features, training, evaluation,
  experiments, API, artifacts, limitations and GitHub Desktop publication guides.
- .gitignore and .gitattributes; pyproject metadata and pytest settings.
- Pinned runtime, development and optional research requirements from the existing environment.
- configs/artifacts.json: paths, sizes and SHA-256 hashes for nine trained artifacts
  and the preserved split; accompanying configuration guide.
- Contribution/security documents, GitHub issue/PR templates and lightweight CI.
- Original six predictor tests retained with integration scope and missing-artifact skips.
- Forty additional synthetic predictor, CLI and API tests.
- Technical handoff retained with local account-transfer instructions removed.
- data/, scripts/, deployment/ and tests/ usage guides.

## Verification actually performed
- Original tests/test_predictor.py before edits: 6 passed in 12.24 seconds.
- New tests/test_interfaces.py in export: 40 passed in 2.14 seconds.
- Final original-project suite after documentation/config updates: 46 passed in 3.12 seconds.
- Final export suite: 40 passed, 6 expected artifact-dependent skips in 2.10 seconds.
- Split integrity: 70,000/15,000/15,000 indices, disjoint and full 100,000-row coverage.
- Split SHA-256: 21a0b569e98c2726a4ee791a27daa1824080716d76751d909b1e3bab895a99c7.
- Candidate hashes recorded; no models were trained or overwritten.
- Existing source whitespace is preserved for byte-for-byte source fidelity;
  whitespace checks are scoped to the newly authored documentation/configuration/tests.
- Tests use Python 3.13.3 from the existing environment. Restricted Windows
  asyncio execution stalled; the successful synthetic run used normal runtime access.

## Intentional exclusions
- Original .git history (contains approximately 18.6 GB of tracked material).
- .venv, Python/test caches, generated temporary files and local editor settings.
- data/raw, data/processed, downloads: large reproducible/local dataset artifacts.
- Trained LightGBM/XGBoost/forest artifacts: local restore strategy, no unapproved
  redistribution or automatic Git LFS setup. See docs/artifacts.md.
- cli_predictions.csv: reproducible per-row inference output.
- Empty placeholder directories from the original project were not copied.
- Lightweight JSON/CSV/PNG reports and split_indices.npz remain included, including
  historical reports whose limitations are explained in docs/experiments.md.

## Environment and remaining checks
Observed direct versions: NumPy 2.5.4, LightGBM 4.7.0, XGBoost 3.4.1,
scikit-learn 1.9.1, SciPy 1.18.1, joblib 1.6.0, FastAPI 0.162.0,
Pydantic 2.14.1, Starlette 1.10.0, Uvicorn 0.54.0, pytest 9.1.1.
Optional pandas 3.1.0, Matplotlib 3.11.2, LIEF 1.0.0; EMBER 0.1.0 at the
commit recorded in requirements-research.txt. httpx is absent and not required.
Fresh dependency installation, hosted CI and non-Windows compatibility have not
been verified. Current requirements pin direct versions rather than a full lock.
The original research environment was not modified. Model/data redistribution,
combined upstream AGPL obligations and public visibility still need owner review.
The new export intentionally has no models; inference needs local restoration.
The clean export was added and selected in GitHub Desktop for offline review.
The application displays 103 proposed new files. No commit or Publish action was taken.
