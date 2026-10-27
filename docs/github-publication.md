# Offline GitHub Desktop publication
Two locations have different purposes:

1. The original MLWINT directory remains the working research project. Its initial
   commit includes approximately 18.6 GB of data/models. Added ignore rules do not
   remove those files from its history. Do not publish that history as this export.
2. This folder is a source-and-reports export of the same implementation, with an
   initialized Git repository and no inherited history. Original source paths,
   small reports and split indices are preserved. Large local artifacts stay in
   the original directory. The export is not an inference installation until
   trusted models are restored as described in artifacts.md.

No files are staged or committed automatically. Review `docs/proposed-staging.txt`
and `docs/repository-preparation.md`. From this export folder:

```powershell
git status --short
git add --pathspec-from-file=docs/proposed-staging.txt
git diff --cached --stat
git diff --cached --check
# After reviewing the staged content:
git commit -m "Prepare MLWINT source, documentation and inference tests"
```

GitHub Desktop: **File > Add local repository**, choose this folder, then
**Add repository**. Review and commit changes offline if preferred. When online
and signed into the intended account, first check that account for an existing
`MLWINT` repository. If absent, use **Publish repository**, name it `MLWINT`, and
keep **Keep this code private** checked. If it already exists, inspect it and
use its clone/remote instead of creating a duplicate or force pushing.

Description: Machine-learning-based malware intelligence and detection using
EMBER features, LightGBM, XGBoost, and a FastAPI inference service.

Suggested topics: cybersecurity, malware-detection, machine-learning, ember,
lightgbm, xgboost, fastapi, python, threat-detection.

No GitHub remote has been configured or pushed by repository preparation.
Review third-party licensing, exclusions and repository contents before public
release. Private publication is the default; changing visibility is a separate decision.
Official guide: https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-a-repository-from-your-local-computer-to-github-desktop
