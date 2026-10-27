# Local deployment
Restore trusted candidate artifacts, install requirements, and run:
`python -m uvicorn src.detection.api:app --host 127.0.0.1 --port 8000`.
Health/model-listing routes describe the running process and supported names,
not artifact readiness. The service is a local research interface. External
deployment needs authentication, TLS, rate limits, error sanitization and
operational evaluation. No hosted deployment or container image is claimed.
