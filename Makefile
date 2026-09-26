.PHONY: install lint format-check type test test-unit test-contract test-integration test-container test-live-lab test-portable test-posix test-coverage check demo clean

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

test-unit:
	$(PYTHON) -m pytest -m "unit and not posix_only"

test-contract:
	$(PYTHON) -m pytest -m "contract and not posix_only"

test-integration:
	$(PYTHON) -m pytest -m "integration and not posix_only"

# These suites are deliberately opt-in and fail if no matching tests exist.
test-container:
	OLYMPUS_RUN_CONTAINER_TESTS=1 $(PYTHON) -m pytest -m container

test-live-lab:
	@test "$(OLYMPUS_LIVE_LAB_AUTHORIZATION)" = "I_HAVE_AUTHORIZATION" || \
		{ echo "Set OLYMPUS_LIVE_LAB_AUTHORIZATION=I_HAVE_AUTHORIZATION only after validating the lab scope."; exit 2; }
	OLYMPUS_RUN_LIVE_LAB_TESTS=1 $(PYTHON) -m pytest -m live_lab

test-portable:
	$(PYTHON) -m pytest -m "not posix_only"

test-posix:
	$(PYTHON) -m pytest -m posix_only

test-coverage:
	$(PYTHON) -m pytest -m "(unit or contract or integration or posix_only) and not root_only" \
		--cov=olympus --cov-branch \
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
