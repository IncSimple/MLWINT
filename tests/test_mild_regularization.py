"""Small real-model checks for the sweep's data and artifact boundaries."""

import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pytest
import xgboost as xgb

from src.models import run_mild_regularization as sweep


@pytest.fixture
def research(tmp_path):
    root = tmp_path / "research"
    for relative in sweep.INPUTS.values():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(42)
    features = rng.normal(size=(60, sweep.FEATURES)).astype(np.float32)
    labels = np.tile([0, 1], 30).astype(np.int8)
    features[:, 0] += 2 * labels
    # Nonfinite test rows prove training/validation evaluation does not use them.
    features[48:] = np.nan
    np.save(root / sweep.INPUTS["features"], features)
    np.save(root / sweep.INPUTS["labels"], labels)
    np.savez(root / sweep.INPUTS["split"], train_idx=np.arange(36),
             val_idx=np.arange(36, 48), test_idx=np.arange(48, 60))
    lgb_model = lgb.LGBMClassifier(n_estimators=3, num_leaves=4,
                                  min_child_samples=3, n_jobs=1, verbosity=-1)
    lgb_model.fit(features[:36], labels[:36])
    lgb_model.booster_.save_model(str(root / sweep.BASELINES["lightgbm_baseline"]))
    xgb_model = xgb.XGBClassifier(n_estimators=3, max_depth=2, n_jobs=1)
    xgb_model.fit(features[:36], labels[:36])
    xgb_model.save_model(str(root / sweep.BASELINES["xgboost_baseline"]))
    config = json.loads((sweep.ROOT / "configs/mild_regularization.json").read_text())
    config["early_stopping_rounds"] = 2
    config["lightgbm"].update(n_estimators=3, num_leaves=4, min_child_samples=3)
    config["xgboost"].update(n_estimators=3, max_depth=2, min_child_weight=1)
    config["candidates"] = [
        {"name": "small_lgb", "algorithm": "lightgbm", "changes": {"min_child_samples": 4}},
        {"name": "small_xgb", "algorithm": "xgboost", "changes": {"min_child_weight": 2}},
    ]
    config_path = tmp_path / "small_config.json"
    config_path.write_text(json.dumps(config))
    output = tmp_path / "outputs"
    argv = ["--research-root", str(root), "--output-root", str(output),
            "--config", str(config_path), "--run-id", "synthetic",
            "--jobs", "1", "--latency-repeats", "1", "--latency-batch-size", "4"]
    return root, output, argv


def test_dry_run_does_not_create_outputs(research):
    _, output, argv = research
    plan = sweep.main(argv)
    assert plan["mode"] == "dry_run"
    assert not output.exists()
    assert len(plan["candidates"]) == 2


def test_real_small_sweep_preserves_inputs_and_refuses_overwrite(research):
    root, _, argv = research
    before = {key: sweep.sha256(root / path) for key, path in sweep.INPUTS.items()}
    report = sweep.main([*argv, "--run"])
    assert report["status"] == "complete"
    assert report["protected_inputs_unchanged"] is True
    assert len(report["artifacts"]) == 2
    assert len(report["results"]) == 8  # four singles and four cross-algorithm ensembles
    assert {key: sweep.sha256(root / path) for key, path in sweep.INPUTS.items()} == before
    for result in report["results"].values():
        assert result["train"]["records"] == 36
        assert result["validation"]["records"] == 12
        assert "test" not in result
        assert result["latency"]["process_peak_bytes"] > 0
        if "weights" in result:
            assert result["weights"] == [0.5, 0.5]
    first = report["rankings"]["by_pr_auc"]
    second = report["rankings"]["by_log_loss"]
    assert [row["pr_auc"] for row in first] == sorted(
        [row["pr_auc"] for row in first], reverse=True)
    assert [row["log_loss"] for row in second] == sorted(row["log_loss"] for row in second)
    report_paths = list(Path(argv[3]).rglob("report.json"))
    assert len(report_paths) == 1
    assert json.loads(report_paths[0].read_text())["status"] == "complete"
    assert len(list(Path(argv[3]).rglob("by_*.csv"))) == 2
    with pytest.raises(FileExistsError):
        sweep.main([*argv, "--run"])


@pytest.mark.parametrize("indices", [np.arange(1, 37), np.arange(36, dtype=float),
                                     np.array([-1, *range(1, 36)])])
def test_invalid_splits_are_rejected(research, indices):
    root, _, _ = research
    np.savez(root / sweep.INPUTS["split"], train_idx=indices,
             val_idx=np.arange(36, 48), test_idx=np.arange(48, 60))
    with pytest.raises(ValueError):
        sweep.read_inputs(root)


def test_metrics_handle_probability_endpoints_and_empty_bins():
    result = sweep.metrics(np.array([0, 1, 0, 1]), np.array([0, 1, 0.5, 0.5]), 0.5)
    assert result["confusion"] == {"tn": 1, "fp": 1, "fn": 0, "tp": 2}
    bins = result["reliability_10_bins"]
    assert sum(row["count"] for row in bins) == 4
    assert bins[9]["count"] == 1
    assert bins[1]["mean_probability"] is None
    with pytest.raises(ValueError):
        sweep.metrics(np.array([0, 1]), np.array([0.1, np.nan]), 0.5)


def test_default_candidates_change_one_parameter_each():
    config = json.loads((sweep.ROOT / "configs/mild_regularization.json").read_text())
    candidates = sweep.resolve_candidates(config, jobs=6)
    assert len(candidates) == 7
    for candidate in candidates:
        baseline = config[candidate["algorithm"]]
        changed = {key for key in baseline if baseline[key] != candidate["parameters"][key]}
        assert changed == set(candidate["changes"])


@pytest.mark.parametrize("name", ["../outside", "CON", "bad.name", "", "x" * 81])
def test_invalid_output_names(name):
    with pytest.raises(ValueError):
        sweep.safe_name(name)
