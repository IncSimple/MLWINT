import numpy as np
import pytest

from src.detection.predictor import MalwarePredictor, MODEL_DIR

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not all((MODEL_DIR / name).is_file() for name in
                ("lightgbm_baseline.txt", "xgboost_ember.json")),
        reason="Trusted local candidate artifacts are required",
    ),
]


@pytest.mark.parametrize("model_name", [
    "lightgbm",
    "xgboost",
    "ensemble",
])
def test_prediction_output(model_name):
    predictor = MalwarePredictor(model_name)
    X = np.zeros((3, 2381), dtype=np.float32)

    probabilities = predictor.predict_proba(X)
    predictions = predictor.predict(X)

    assert probabilities.shape == (3,)
    assert np.isfinite(probabilities).all()
    assert np.all((probabilities >= 0) & (probabilities <= 1))
    assert set(np.unique(predictions)).issubset({0, 1})


def test_rejects_wrong_feature_count():
    predictor = MalwarePredictor("lightgbm")

    with pytest.raises(ValueError, match="Expected 2381 features"):
        predictor.predict_proba(np.zeros((1, 100)))


def test_rejects_nonfinite_features():
    predictor = MalwarePredictor("lightgbm")
    X = np.zeros((1, 2381), dtype=np.float32)
    X[0, 0] = np.nan

    with pytest.raises(ValueError, match="NaN or infinite"):
        predictor.predict_proba(X)


def test_rejects_invalid_threshold():
    predictor = MalwarePredictor("lightgbm")

    with pytest.raises(ValueError, match="Threshold"):
        predictor.predict(np.zeros((1, 2381)), threshold=1.5)
