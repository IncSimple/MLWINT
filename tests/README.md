# Tests
`python -m pytest -m "not integration"` runs synthetic tests with mocked model
loaders and direct ASGI requests. It needs neither data, models nor httpx.
`python -m pytest -m integration` runs the original six model-backed cases;
both trusted baseline artifacts must be present or these cases skip.
Test collection is restricted to tests/ because src/ingestion/test_*.py are
existing data-driven research scripts with work at import time.
CI targets Windows/Python 3.13; hosted execution is not yet verified.
