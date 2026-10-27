
import json
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_FILE = PROJECT_ROOT / "data" / "raw" / "ember2018" / "train_features_0.jsonl"
RECORD_LIMIT = 1000


def main():
    labels = Counter()
    field_types = {}
    records_read = 0

    with DATA_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if records_read >= RECORD_LIMIT:
                break

            if not line.strip():
                continue

            record = json.loads(line)
            records_read += 1
            labels[str(record.get("label"))] += 1

            for key, value in record.items():
                field_types.setdefault(key, type(value).__name__)

    print(f"File: {DATA_FILE.name}")
    print(f"Records inspected: {records_read}")

    print("\nField types:")
    for field, value_type in sorted(field_types.items()):
        print(f"  {field}: {value_type}")

    print("\nLabel distribution:")
    for label, count in sorted(labels.items()):
        print(f"  label={label}: {count}")

    print("\nTotal distinct labels:", len(labels))


if __name__ == "__main__":
    main()
