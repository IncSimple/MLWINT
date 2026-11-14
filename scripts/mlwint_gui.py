"""MLWINT desktop window (GUI step G1). Save as MLWINT/scripts/mlwint_gui.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/pythonw.exe scripts/mlwint_gui.py            (no console window)
    experiments/ember2024/.venv/Scripts/python.exe  scripts/mlwint_gui.py "C:\\Users\\you\\Downloads"
Read-only, like mlwint_analyse.py: nothing is deleted, moved, quarantined, run or uploaded.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.gui.app import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())