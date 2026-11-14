# Releasing MLWINT (G5)

## Build a release
From the MLWINT folder, with the EMBER2024 environment:

```
experiments/ember2024/.venv/Scripts/python.exe packaging/build_release.py
```

This:
1. builds the window (Flutter) with the version from `version.json`,
2. assembles a self-contained copy in `dist/MLWINT` (program, one Python 3.13 runtime, the three trimmed Python
   environments, models, ATT&CK data, capa rules),
3. checks that copy (starts its engine and runs the health check),
4. builds `dist/MLWINT-Setup-<version>.exe` with Inno Setup 6, if installed.

It never copies `config/` (your API keys), `reports/`, the scan memory, `.git` or training data.

## What users get
`MLWINT-Setup-<version>.exe` installs for the current user (no admin rights) into
`%LOCALAPPDATA%\Programs\MLWINT`, with Start-menu (and optionally desktop) shortcuts. Nothing else is needed on their
PC: no Python, no Flutter.

## Shipping an update
1. Make the change:
   - program changes (window, engine, `src/`): raise `"app"` in `version.json` (1.0.0 -> 1.0.1 for fixes, 1.1.0 for
     features);
   - retrained models: put them in `models/phase1` / `models/phase2` (same manifest format) and raise `"models"`
     (e.g. 2026.12.1). Raise `"app"` too, because the installer is versioned by `"app"`.
2. Run `build_release.py`.
3. Give people the new `MLWINT-Setup-<version>.exe`. Running it over the old version updates in place:
   - program, runtime and models are replaced (old files are removed first, so nothing stale is left),
   - the user's reports, settings, keys and scan memory stay,
   - the scan memory notices new models or detection code by itself and re-checks files on the next scan.
4. Never change the `AppId` in `packaging/mlwint.iss`: it is how Windows knows the new setup updates the old one.

## Notes
- `packaging/make_icon.py` redraws the app icon (`packaging/mlwint.ico`, also copied into the Flutter runner).
- The setup is not code-signed, so Windows SmartScreen shows "Windows protected your PC" the first time
  (More info -> Run anyway). A code-signing certificate removes that warning.
- Speakeasy's 32-bit decoy program is left out of the bundle (Microsoft Defender flags it; MLWINT never uses it).
