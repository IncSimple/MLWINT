
import json
from collections import Counter
from pathlib import Path

DATA_DIR = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "raw"
    / "ember2018"
)

VALID_LABELS = {-1, 0, 1}


def main():
    total_records = 0
    total_labels = Counter()
    total_malformed = 0

    for path in sorted(DATA_DIR.glob("train_features_*.jsonl")):
        file_records = 0
        file_labels = Counter()
        malformed = 0

        print(f"\nChecking {path.name}...")

        with path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                    label = record.get("label")

                    if label not in VALID_LABELS:
                        malformed += 1
                        continue

                    file_records += 1
                    file_labels[label] += 1

                except (json.JSONDecodeError, AttributeError):
                    malformed += 1

        print(f"  Valid records: {file_records:,}")
        print(f"  Label counts: {dict(sorted(file_labels.items()))}")
        print(f"  Invalid records: {malformed:,}")

        total_records += file_records
        total_labels.update(file_labels)
        total_malformed += malformed

    print("\n===== DATASET SUMMARY =====")
    print(f"Total valid records: {total_records:,}")
    print(f"Combined label counts: {dict(sorted(total_labels.items()))}")
    print(f"Invalid records: {total_malformed:,}")
    print(f"Labeled records (0 and 1): {total_labels[0] + total_labels[1]:,}")
    print(f"Unlabeled records (-1): {total_labels[-1]:,}")


if __name__ == "__main__":
    main()
