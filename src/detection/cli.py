
"""Command-line inference for MLWINT's trained EMBER models."""

import argparse
import csv
from pathlib import Path

import numpy as np

from src.detection.predictor import MalwarePredictor


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run MLWINT malware predictions on an EMBER feature matrix."
    )
    parser.add_argument(
        "--model",
        choices=["lightgbm", "xgboost", "ensemble"],
        default="lightgbm",
        help="Model to use (default: lightgbm).",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to a .npy file containing 2,381 features per row.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path for a CSV containing prediction results.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Malicious-class threshold from 0 to 1 (default: 0.5).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.input.is_file():
        raise SystemExit(f"Input file not found: {args.input}")

    if args.input.suffix.lower() != ".npy":
        raise SystemExit("Input must be a .npy feature matrix.")

    if not 0.0 <= args.threshold <= 1.0:
        raise SystemExit("--threshold must be between 0 and 1.")

    try:
        features = np.load(args.input, mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Could not load input array: {exc}") from exc

    if features.ndim == 1:
        features = features.reshape(1, -1)

    if features.ndim != 2:
        raise SystemExit(
            f"Expected a 1D or 2D feature array; got shape {features.shape}."
        )

    if features.shape[0] == 0:
        raise SystemExit("Input contains no samples.")

    predictor = MalwarePredictor(args.model)
    probabilities = predictor.predict_proba(features)
    predictions = (probabilities >= args.threshold).astype(np.int8)

    labels = np.where(predictions == 1, "malicious", "benign")

    print(f"Model: {args.model}")
    print(f"Input: {args.input}")
    print(f"Samples processed: {len(predictions):,}")
    print(f"Threshold: {args.threshold:.4f}")
    print(f"Predicted malicious: {int(predictions.sum()):,}")
    print(f"Predicted benign: {int((predictions == 0).sum()):,}")

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(
                ["sample_index", "malicious_probability", "prediction", "threshold"]
            )
            for i, (probability, label) in enumerate(zip(probabilities, labels)):
                writer.writerow([i, f"{probability:.8f}", label, args.threshold])

        print(f"CSV results saved to: {args.output}")

    else:
        print("\nFirst predictions:")
        print("index | malicious_probability | prediction")
        for i, (probability, label) in enumerate(
            zip(probabilities[:20], labels[:20])
        ):
            print(f"{i:5d} | {probability:22.6f} | {label}")

        if len(predictions) > 20:
            print(f"... {len(predictions) - 20:,} additional results not displayed.")


if __name__ == "__main__":
    main()
