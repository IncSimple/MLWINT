"""Probability extraction shared by the binary LightGBM experiments."""

import lightgbm as lgb
import numpy as np


def lightgbm_probability(model, features):
    """Return malicious-class scores for a Booster or fitted classifier.

    LGBMClassifier.predict returns class labels, whereas Booster.predict
    returns probabilities for the binary models used by this project.
    """
    if isinstance(model, lgb.Booster):
        return np.asarray(model.predict(features), dtype=np.float64)
    return np.asarray(model.predict_proba(features)[:, 1], dtype=np.float64)
