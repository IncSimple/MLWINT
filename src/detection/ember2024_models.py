"""MLWINT's EMBER2024 model roles and inference interface."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

import numpy as np


Role = Literal["primary", "challenger", "research"]
FEATURE_COUNT = 2568

ARTIFACTS = {
    "primary": {
        "name": "EMBER2024 XGBoost",
        "file": (
            "src/models/candidates/ember2024/"
            "challenger-full-temporal-v1/xgboost_challenger_full.ubj"
        ),
        "sha256": (
            "d067841d7fbdabeb51c05b59ab1e49fbb"
            "cdc67c1888cb8c8facd7c7515a859be"
        ),
    },
    "challenger": {
        "name": "Improved EMBER2024 LightGBM",
        "file": (
            "src/models/candidates/ember2024/"
            "lightgbm-full-temporal-v2/lightgbm_primary_full.txt"
        ),
        "sha256": (
            "ef94d30817a401ecd5e09d97d5b5d5201"
            "a0b510f283de9dbb72bfed1d9a3e60c"
        ),
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


class Ember2024Models:
    """Default to XGBoost; load the challenger only when requested."""

    def __init__(self, project_root=None):
        self.root = (
            Path(project_root).resolve()
            if project_root is not None
            else Path(__file__).resolve().parents[2]
        )
        self._models = {}

    def describe(self) -> dict:
        roles = {
            role: {
                **info,
                "path": str(self.root / info["file"]),
            }
            for role, info in ARTIFACTS.items()
        }

        roles["research"] = {
            "name": "50/50 probability average",
            "formula": "0.5 * primary_score + 0.5 * challenger_score",
            "separate_model_file": False,
        }

        return {
            "dataset": "EMBER2024 Win32",
            "feature_count": FEATURE_COUNT,
            "default_role": "primary",
            "roles": roles,
        }

    def _load(self, role):
        if role in self._models:
            return self._models[role]

        info = ARTIFACTS[role]
        path = self.root / info["file"]

        if not path.is_file():
            raise FileNotFoundError(f"Missing {role} model: {path}")

        if sha256(path) != info["sha256"]:
            raise ValueError(f"Unexpected {role} model contents: {path}")

        if role == "primary":
            import xgboost as xgb

            model = xgb.Booster()
            model.load_model(str(path))
            model.set_param({"nthread": 6, "device": "cpu"})
            count = model.num_features()

        else:
            import lightgbm as lgb

            model = lgb.Booster(model_file=str(path))
            count = model.num_feature()

        if count != FEATURE_COUNT:
            raise ValueError(
                f"{role} model has {count} features; "
                f"expected {FEATURE_COUNT}."
            )

        self._models[role] = model
        return model

    def verify(self) -> dict:
        for role in ARTIFACTS:
            self._load(role)

        return {"status": "verified", **self.describe()}

    @staticmethod
    def _features(features):
        X = np.asarray(features, dtype=np.float32)

        if X.ndim == 1:
            X = X.reshape(1, -1)

        if (
            X.ndim != 2
            or X.shape[1] != FEATURE_COUNT
            or X.shape[0] == 0
        ):
            raise ValueError(
                f"Expected a nonempty array with {FEATURE_COUNT} columns."
            )

        if not np.isfinite(X).all():
            raise ValueError("Features contain NaN or infinity.")

        return np.ascontiguousarray(X)

    def predict_proba(
        self,
        features,
        role: Role = "primary",
    ) -> np.ndarray:
        """
        Return malicious-class scores.

        Inputs must use the same EMBER2024 feature schema and order
        used during training. Matching the column count alone is
        insufficient.
        """
        if role not in ("primary", "challenger", "research"):
            raise ValueError(f"Unknown model role: {role}")

        X = self._features(features)

        if role == "research":
            scores = (
                self.predict_proba(X, "primary")
                + self.predict_proba(X, "challenger")
            ) / 2.0

        elif role == "primary":
            scores = self._load(role).inplace_predict(X)

        else:
            scores = self._load(role).predict(X, num_threads=6)

        scores = np.asarray(scores, dtype=np.float64)

        if scores.shape != (len(X),) or not np.isfinite(scores).all():
            raise ValueError("The model returned invalid scores.")

        if np.any((scores < 0) | (scores > 1)):
            raise ValueError("Model scores must be between zero and one.")

        return scores

    def predict(
        self,
        features,
        role: Role = "primary",
        threshold=0.5,
    ) -> np.ndarray:
        """Return 0 (predicted benign) or 1 (predicted malicious)."""
        if not np.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError(
                "Threshold must be finite and between zero and one."
            )

        scores = self.predict_proba(features, role)
        return (scores >= threshold).astype(np.int8)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    models = Ember2024Models(args.project_root)
    result = models.verify() if args.verify else models.describe()

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()