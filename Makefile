# Local CI gate — mirrors .github/workflows/ci.yml step-for-step so a green
# `make ci` is a green CI run (CI additionally runs the same steps on a
# 3.11/3.12 matrix). Run before every push.
.PHONY: ci venv lint test

ci: venv lint test

venv:
	uv venv --clear
	uv pip install -e ".[dev]"

lint:
	.venv/bin/ruff check src tests
	.venv/bin/ruff format --check src tests

test:
	.venv/bin/pytest -v

# Deep property exploration (reviewer rec): 200x200 Hypothesis state machine
# against a soaked DB. Run nightly by auspexai-property-nightly.timer on rage;
# -o timeout=0 lifts the global 60s per-test cap (this single test runs for
# tens of minutes by design).
property-nightly:
	AUSPEXAI_PROPERTY_PROFILE=nightly AUSPEXAI_PROPERTY_SOAK=1 \
	.venv/bin/pytest tests/test_integrity_properties.py -q -o timeout=0
