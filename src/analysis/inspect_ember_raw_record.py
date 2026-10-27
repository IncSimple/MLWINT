
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW_FILE = ROOT / "data" / "raw" / "ember2018" / "train_features_0.jsonl"
TARGET_LINE = 487

with RAW_FILE.open("r", encoding="utf-8") as f:
    for line_number, line in enumerate(f, start=1):
        if line_number == TARGET_LINE:
            record = json.loads(line)
            break
    else:
        raise RuntimeError("Target record not found")

print("Label:", record.get("label"))

section = record.get("section")
print("\nSection field type:", type(section).__name__)
print("Section content:")
print(json.dumps(section, indent=2)[:12000])

print("\nTop-level section-related fields:")
for key in ("general", "header", "section", "datadirectories"):
    value = record.get(key)
    print(f"{key}: type={type(value).__name__}")
    if isinstance(value, dict):
        print("  keys:", list(value.keys()))
    elif isinstance(value, list):
        print("  length:", len(value))
        if value:
            print("  first element:", repr(value[0]))

