"""Make the easy-to-read PDF for an existing MLWINT report. Save as MLWINT/scripts/mlwint_report.py
Run from the MLWINT folder with the EMBER2024 environment:
    experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_report.py                  (newest report)
    experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_report.py reports/analyse/analysis-20261112-230400.json
    experiments/ember2024/.venv/Scripts/python.exe scripts/mlwint_report.py --all            (every report without a PDF)
New scans make the PDF by themselves; this is for older reports. It only reads the .json and writes the .pdf
next to it.
"""
import argparse, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.report.plain_report import write_pdf  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('reports', nargs='*', type=Path, help='analysis-*.json files (default: the newest one)')
    ap.add_argument('--all', action='store_true', help='every report in reports/analyse that has no PDF yet')
    ap.add_argument('--open', action='store_true', help='open the PDF when it is ready')
    a = ap.parse_args()
    folder = ROOT / 'reports/analyse'
    every = sorted(folder.glob('analysis-*.json'))
    if a.all:
        todo = [j for j in every if not j.with_suffix('.pdf').is_file()]
    elif a.reports:
        todo = a.reports
    else:
        todo = every[-1:]
    if not todo:
        print('Nothing to do: no report found (or every report already has its PDF).')
        return
    for js in todo:
        pdf = write_pdf(js)
        print(f'{pdf}  ({pdf.stat().st_size // 1024} KB)')
    if a.open and len(todo) == 1:
        os.startfile(pdf)


if __name__ == '__main__':
    main()