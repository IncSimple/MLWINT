
import json
from pathlib import Path
from collections import Counter

DATA_DIR = (
    Path(__file__).resolve().parents[2]
    / "data" / "raw" / "ember2018"
)

SAMPLES_PER_FILE = 3


def inspect_file(path):
    total = 0
    labels = Counter()
    first_labels = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            record = json.loads(line)
            label = record.get("label")
            labels[str(label)] += 1

            if len(first_labels) < SAMPLES_PER_FILE:
                first_labels.append(label)

            total += 1

    return total, labels, first_labels


def main():
    for path in sorted(DATA_DIR.glob("train_features_*.jsonl")):
        total, labels, first_labels = inspect_file(path)

        print(f"\n{path.name}")
        print(f"Records: {total:,}")
        print(f"Labels: {dict(labels)}")
        print(f"First labels: {first_labels}")


if __name__ == "__main__":
    main()

