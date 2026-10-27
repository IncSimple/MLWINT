
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ember.features import PEFeatureExtractor

extractor = PEFeatureExtractor(feature_version=2)

print("Total dimensions:", extractor.dim)

offset = 0
feature_ranges = []

for feature in extractor.features:
    size = feature.dim
    start = offset
    end = offset + size - 1

    feature_ranges.append((feature.name, start, end, size))

    print(
        f"{feature.name:20s} "
        f"indices {start:4d}-{end:4d} "
        f"(dimensions={size})"
    )

    offset += size

print("\n--- TARGET FEATURE MAPPING ---")

for target in (0, 2351):
    matches = [
        (name, start, end)
        for name, start, end, _ in feature_ranges
        if start <= target <= end
    ]

    if matches:
        name, start, end = matches[0]
        print(f"Feature {target}: {name} (range {start}-{end})")
    else:
        print(f"Feature {target}: no matching feature group found")

print("\nFeature mapping complete.")
