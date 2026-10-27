"""Lightweight inference contracts, with no dataset or trained model files."""
import asyncio
import json
import sys
from types import SimpleNamespace

import numpy as np
import pytest

from src.detection import api, cli, predictor


@pytest.fixture
def fake_models(monkeypatch, tmp_path):
    for name in ("lightgbm_baseline.txt", "xgboost_ember.json"):
        (tmp_path / name).touch()
    monkeypatch.setattr(predictor, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(
        predictor.lgb, "Booster",
        lambda **kwargs: SimpleNamespace(predict=lambda x: np.full(len(x), 0.2)),
    )
    monkeypatch.setattr(
        predictor.xgb, "XGBClassifier",
        lambda: SimpleNamespace(
            load_model=lambda path: None,
            predict_proba=lambda x: np.tile([0.4, 0.6], (len(x), 1)),
        ),
    )


@pytest.mark.parametrize("name,expected", [("lightgbm", 0.2), ("xgboost", 0.6), ("ensemble", 0.4)])
def test_probabilities_and_labels(fake_models, name, expected):
    model = predictor.MalwarePredictor(name)
    x = np.zeros((3, 2381))
    p = model.predict_proba(x)
    assert p.shape == (3,)
    assert np.allclose(p, expected)
    assert np.all((0 <= p) & (p <= 1))
    assert np.array_equal(model.predict(x), [int(expected >= 0.5)] * 3)
    assert model.predict(x).dtype == np.int8
    assert model.predict_proba(x[0]).shape == (1,)


@pytest.mark.parametrize("x", [np.zeros(2380), np.zeros((2, 100)), np.zeros((1, 1, 2381)), np.array(1)])
def test_invalid_dimensions(x):
    with pytest.raises(ValueError):
        predictor.MalwarePredictor._validate_features(x)


@pytest.mark.parametrize("value", [np.nan, np.inf, -np.inf])
def test_nonfinite_features(value):
    x = np.zeros(2381)
    x[0] = value
    with pytest.raises(ValueError, match="NaN or infinite"):
        predictor.MalwarePredictor._validate_features(x)


def test_signed_hash_values_preserved():
    x = np.zeros(2381)
    x[700] = -2.5
    checked = predictor.MalwarePredictor._validate_features(x)
    assert checked.dtype == np.float32
    assert checked[0, 700] == -2.5


@pytest.mark.parametrize("threshold", [-0.1, 1.1, np.nan, np.inf])
def test_invalid_threshold(fake_models, threshold):
    with pytest.raises(ValueError, match="Threshold"):
        predictor.MalwarePredictor().predict(np.zeros(2381), threshold)


@pytest.mark.parametrize("threshold,label", [(0, 1), (0.2, 1), (1, 0)])
def test_boundary_threshold(fake_models, threshold, label):
    assert predictor.MalwarePredictor().predict(np.zeros(2381), threshold)[0] == label


def test_unsupported_model():
    with pytest.raises(ValueError, match="Unsupported model"):
        predictor.MalwarePredictor("invalid")


def test_missing_artifact(monkeypatch, tmp_path):
    monkeypatch.setattr(predictor, "MODEL_DIR", tmp_path)
    with pytest.raises(FileNotFoundError):
        predictor.MalwarePredictor()


@pytest.mark.parametrize("args", [[], ["--input", "x.npy", "--model", "invalid"]])
def test_cli_argument_validation(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["mlwint", *args])
    with pytest.raises(SystemExit) as err:
        cli.parse_args()
    assert err.value.code == 2


@pytest.mark.parametrize("case", ["missing", "suffix", "threshold", "empty", "rank"])
def test_cli_input_validation(monkeypatch, tmp_path, case):
    path = tmp_path / ("input.txt" if case == "suffix" else "input.npy")
    if case != "missing":
        with path.open("wb") as f:
            np.save(f, np.zeros((0, 2381) if case == "empty" else
                                (1, 1, 2381) if case == "rank" else (1, 2381)))
    argv = ["mlwint", "--input", str(path)]
    if case == "threshold":
        argv += ["--threshold", "nan"]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit):
        cli.main()


def test_cli_csv(fake_models, monkeypatch, tmp_path):
    path, out = tmp_path / "x.npy", tmp_path / "out.csv"
    np.save(path, np.zeros((2, 2381)))
    monkeypatch.setattr(sys, "argv", ["mlwint", "--input", str(path), "--output", str(out)])
    cli.main()
    lines = out.read_text().splitlines()
    assert lines[0] == "sample_index,malicious_probability,prediction,threshold"
    assert len(lines) == 3
    assert "0.20000000,benign,0.5" in lines[1]


def request(method, path, body=None):
    """Exercise the ASGI application without adding an HTTP client dependency."""
    async def run():
        messages = []
        received = False

        async def receive():
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": json.dumps(body).encode() if body is not None else b"",
                    "more_body": False}

        async def send(message):
            messages.append(message)

        await api.app({"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                       "method": method, "scheme": "http", "path": path,
                       "raw_path": path.encode(), "query_string": b"",
                       "headers": [(b"content-type", b"application/json")],
                       "client": ("127.0.0.1", 123), "server": ("test", 80),
                       "root_path": ""}, receive, send)
        status = next(m["status"] for m in messages if m["type"] == "http.response.start")
        payload = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
        return status, json.loads(payload)

    return asyncio.run(run())


def test_health_and_models():
    assert request("GET", "/health") == (200, {"status": "ok", "service": "MLWINT"})
    status, body = request("GET", "/models")
    assert status == 200
    assert body == {"default": "lightgbm", "available": ["lightgbm", "xgboost", "ensemble"]}


@pytest.mark.parametrize("patch", [
    {"features": [0.0] * 2380}, {"features": [0.0] * 2382},
    {"features": ["invalid"] * 2381}, {"model": "invalid"},
    {"threshold": -0.1}, {"threshold": 1.1},
])
def test_api_request_validation(patch):
    body = {"features": [0.0] * 2381, **patch}
    assert request("POST", "/predict", body)[0] == 422


@pytest.mark.parametrize("model", ["lightgbm", "xgboost", "ensemble"])
def test_api_prediction(fake_models, monkeypatch, model):
    monkeypatch.setattr(api, "_predictors", {})
    status, body = request("POST", "/predict", {"features": [0.0] * 2381, "model": model})
    assert status == 200
    assert body["model"] == model
    assert 0 <= body["malicious_probability"] <= 1
    assert body["threshold"] == 0.5


def test_api_nonfinite_route():
    # Direct route call avoids JSON's lack of a standard NaN representation.
    with pytest.raises(api.HTTPException) as err:
        api.predict(api.PredictRequest(features=[np.nan] + [0.0] * 2380))
    assert err.value.status_code == 422


def test_api_missing_artifact(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "_predictors", {})
    monkeypatch.setattr(predictor, "MODEL_DIR", tmp_path)
    assert request("POST", "/predict", {"features": [0.0] * 2381})[0] == 503
