# Building MLWINT from source

Everything below runs on Windows 10/11 x64 from the repository folder. Paths are relative to it.

## 1. Python environments (Python 3.13)
Install Python 3.13 from python.org, then:

```bash
python -m venv experiments/ember2024/.venv
experiments/ember2024/.venv/Scripts/python -m pip install -r environments/ember2024.txt

python -m venv experiments/capa/.venv
experiments/capa/.venv/Scripts/python -m pip install -r environments/capa.txt

python -m venv experiments/speakeasy/.venv
experiments/speakeasy/.venv/Scripts/python -m pip install -r environments/speakeasy.txt
```

All three must be made from the **same** Python 3.13 (the release builder checks this).

> Microsoft Defender may quarantine Speakeasy's `winenv/decoys/x86/default_exe.exe` as a trojan (a false
> positive). Leave it quarantined: MLWINT points 32-bit decoys at an empty folder and does not need it.

## 2. Models, capa rules and ATT&CK data
| What | Where it goes | Source |
|---|---|---|
| Detectors + classifiers | `models/phase1/`, `models/phase2/` | `MLWINT-models-<version>.zip` from [Releases](https://github.com/IncSimple/MLWINT/releases) |
| capa rules + signatures | `tools/capa-source-v9.4.0/rules`, `tools/capa-source-v9.4.0/sigs` | the capa v9.4.0 source release on [github.com/mandiant/capa](https://github.com/mandiant/capa/releases) (rules and sigs folders) |
| MITRE ATT&CK Enterprise | `data/attack/enterprise-attack.json` | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) (`enterprise-attack/enterprise-attack.json`) |

Check everything is in place (nothing is run, only files are checked):

```bash
experiments/ember2024/.venv/Scripts/python.exe scripts/phase1_check.py
experiments/ember2024/.venv/Scripts/python.exe scripts/settings_check.py
```

## 3. Command line
```bash
experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_analyse.py "C:\Users\you\Downloads" --recursive
experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_analyse.py setup.exe --evidence all --deep all
```
Reports go to `reports/analyse/` (JSON, TXT and the easy-to-read PDF).

## 4. The window (Flutter)
Install Flutter (stable) with the Visual Studio "Desktop development with C++" tools, then:

```bash
cd mlwint_app
flutter pub get
flutter run -d windows                                  # development
flutter build windows --release                         # build/windows/x64/runner/Release/MLWINT.exe
flutter run -d windows --dart-define=MLWINT_DEMO=true   # the sample data instead of real scans
```

The app finds the MLWINT folder by walking up from its own location (or `MLWINT_ROOT`), and the engine's Python at
`experiments/ember2024/.venv/Scripts/pythonw.exe` (or `MLWINT_PYTHON`). No Flutter plugins are used, so Windows
Developer Mode is not required.

## 5. Web demo
```bash
experiments/ember2024/.venv/Scripts/python.exe packaging/make_demo_data.py   # sample data + sample PDF
cd mlwint_app
flutter build web --release --base-href /MLWINT/
```
`build/web` is what GitHub Pages serves (branch `gh-pages`).

## 6. Installer
Install [Inno Setup 6](https://jrsoftware.org/isinfo.php), then:

```bash
experiments/ember2024/.venv/Scripts/python.exe packaging/build_release.py
```

This builds the window, assembles `dist/MLWINT` (program, one shared Python runtime, the three trimmed
environments, models, ATT&CK data, capa rules; never `config/` or `reports/`), checks it by starting its engine,
and compiles `dist/MLWINT-Setup-<version>.exe`. See [packaging/README.md](../packaging/README.md).

## 7. Self-checks
| Script | Checks |
|---|---|
| `phase1_check.py` | detector bundle, parity, ~600 clean Windows files |
| `phase2_evidence_check.py`, `phase2_meter_check.py`, `phase2_deepcheck_check.py` | capa / PDF evidence, meter, emulation |
| `phase3_context_check.py`, `phase3_attack_check.py`, `phase3_reputation_check.py`, `phase3_advice_check.py` | PC facts, ATT&CK, hash lookup (offline mocks), advice |
| `memory_check.py`, `gui_check.py`, `history_check.py`, `settings_check.py` | memory, PySide6 window, history, settings |
