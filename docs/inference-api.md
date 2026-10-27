# Inference API
Start `python -m uvicorn src.detection.api:app --host 127.0.0.1 --port 8000`.
`GET /health` returns `{"status":"ok","service":"MLWINT"}` without loading models.
`GET /models` returns default `lightgbm` and supported names lightgbm/xgboost/ensemble.
These routes do not assert trained-artifact readiness.

`POST /predict` accepts JSON with `model` (default lightgbm), `features` (exactly
2,381 finite numbers), and `threshold` (default 0.5, inclusive range [0,1]).
It returns model, malicious_probability, prediction (`benign`/`malicious`), threshold.
The API supports one vector per request; CLI supports batches. Labels use >= threshold.
Malformed bodies, wrong model names and invalid values yield 422. Missing artifacts
yield 503. The current service has no authentication, rate limiting or batch limits
beyond the one-vector schema; use loopback for local experiments. Model load errors
may include local paths in responses, so review error handling before external use.
