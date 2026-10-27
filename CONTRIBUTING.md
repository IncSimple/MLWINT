# Contributing
Read README.md and the evaluation limitations. Preserve baseline artifacts,
source paths and split indices. Develop experiments with distinct output paths.
Install requirements-dev.txt and run `python -m pytest -m "not integration"`.
Run artifact-backed tests separately if relevant. Do not import training scripts
into the service or test suite, commit data/models/secrets, or claim exploratory
metrics as independent benchmarks. Describe the change and checks in each PR.
