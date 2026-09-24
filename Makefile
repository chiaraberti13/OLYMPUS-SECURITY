.PHONY: install lint type test check demo clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev]"

# --------------------------------------------------------------------------- #
# Local quality helpers. Locally they never block you; CI is what enforces
# ruff and pytest (plus build, pip-audit and gitleaks) on every pull request.
# mypy stays optional until ROADMAP.md DEV-C wires it into CI. See
# CONTRIBUTING.md, "What CI enforces today".
# --------------------------------------------------------------------------- #
lint:
	$(PYTHON) -m ruff check .

type:
	$(PYTHON) -m mypy .

test:
	$(PYTHON) -m pytest

# `check` runs the optional helpers for convenience and never fails the build
# (leading '-' tells make to ignore their exit status).
check:
	-$(MAKE) lint
	-$(MAKE) type
	-$(MAKE) test

demo:
	olympus core export-schemas ./examples/output

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
