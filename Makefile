.PHONY: install lint format-check type test test-portable test-posix test-coverage check demo clean

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

test-coverage:
	$(PYTHON) -m pytest -m "not root_only" --cov=olympus --cov-branch \
		--cov-report=term-missing --cov-report=json:.coverage-report.json
	$(PYTHON) scripts/check_branch_coverage.py .coverage-report.json

check:
	$(MAKE) lint
	$(MAKE) format-check
	$(MAKE) type
	$(MAKE) test-coverage

demo:
	olympus core export-schemas ./examples/output

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
