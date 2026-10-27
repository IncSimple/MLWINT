"""Guard against treating LightGBM class labels as probability scores."""

import lightgbm as lgb
import numpy as np

from src.models.probabilities import lightgbm_probability


def test_classifier_and_saved_booster_return_matching_soft_probabilities(tmp_path):
    rng = np.random.default_rng(42)
    features = rng.normal(size=(80, 4)).astype(np.float32)
    labels = (features[:, 0] + features[:, 1] > 0).astype(np.int8)
    classifier = lgb.LGBMClassifier(
        n_estimators=5, num_leaves=4, min_child_samples=3,
        random_state=42, n_jobs=1, verbosity=-1,
    ).fit(features, labels)
    path = tmp_path / "binary_model.txt"
    classifier.booster_.save_model(str(path))
    restored = lgb.Booster(model_file=str(path))

    classifier_scores = lightgbm_probability(classifier, features)
    restored_scores = lightgbm_probability(restored, features)

    assert classifier_scores.shape == (len(features),)
    assert classifier_scores.dtype == np.float64
    assert np.all((classifier_scores > 0) & (classifier_scores < 1))
    assert not np.array_equal(classifier_scores, classifier.predict(features))
    np.testing.assert_allclose(classifier_scores, restored_scores, rtol=1e-12)
