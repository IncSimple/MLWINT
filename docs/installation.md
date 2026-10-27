# Installation and environment
The inspected environment is Windows, CPython 3.13.3 (64-bit). Use the README's
explicit `.venv` executable commands to avoid a different system Python.
`requirements.txt` pins direct runtime/training dependencies to observed versions;
`requirements-dev.txt` adds pytest. These are not a complete transitive lockfile.
No packages were upgraded during repository preparation. A clean install on another
machine and Linux/macOS compatibility remain unverified.

Optional ingestion/research dependencies are in `requirements-research.txt`.
The installed EMBER distribution reports 0.1.0 and upstream commit
`d97a0b523de02f3fe5ea6089d080abacab6ee931`. Its code is AGPLv3; review those terms
when distributing a combined application. The pinned source requires Git/network
access on a new machine. Offline use needs a separately prepared wheel cache.
LIEF 1.0.0 was observed locally; this does not validate raw-PE feature extraction
against EMBER's historical extractor versions. Precomputed JSONL vectorization is
the existing workflow. Do not assume raw-byte extraction has matching semantics.

No `.env` file is required or read by the current implementation. Run research
commands from the repository root. `pyproject.toml` provides metadata and pytest
settings; installing from the requirements files is the supported setup workflow.
