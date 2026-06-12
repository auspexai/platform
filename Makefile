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
