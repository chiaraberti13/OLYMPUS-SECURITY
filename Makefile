.PHONY: install lint format-check type test test-portable test-posix check demo clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev]"

# --------------------------------------------------------------------------- #
# Local mirrors of the blocking first-party quality gates. CI also enforces
# package smoke tests, pip-audit and gitleaks on every pull request.
# --------------------------------------------------------------------------- #
lint:
	$(PYTHON) -m ruff check .

format-check:
	$(PYTHON) -m ruff format --check .

type:
	$(PYTHON) -m mypy --strict src/olympus

test:
	$(PYTHON) -m pytest

test-portable:
	$(PYTHON) -m pytest -m "not posix_only"

test-posix:
	$(PYTHON) -m pytest -m posix_only

check:
	$(MAKE) lint
	$(MAKE) format-check
	$(MAKE) type
	$(MAKE) test

demo:
	olympus core export-schemas ./examples/output

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
