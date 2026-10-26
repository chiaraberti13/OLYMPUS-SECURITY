.PHONY: install lint format-check type test test-unit test-contract test-integration test-container test-live-lab test-portable test-posix test-coverage test-mutation benchmark benchmark-standard schemas schemas-check contract-goldens check demo clean

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
	$(PYTHON) -m pytest -m "not container and not live_lab"

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
	$(PYTHON) -m pytest -m "not posix_only and not container and not live_lab"

test-posix:
	$(PYTHON) -m pytest -m posix_only

test-coverage:
	$(PYTHON) -m pytest -m "(unit or contract or integration or posix_only) and not root_only" \
		--cov=olympus --cov-branch \
		--cov-report=term-missing --cov-report=json:.coverage-report.json
	$(PYTHON) scripts/check_branch_coverage.py .coverage-report.json

# POSIX-only, bounded mutation gate for critical scope/redaction/parser/status/job rules.
test-mutation:
	$(PYTHON) -m mutmut run --max-children 4 \
		"olympus.athena.scope.x__reject_out_of_scope*" \
		"olympus.athena.scope.x_ensure_target_allowed*" \
		"olympus.core.execution.x__sensitive_key*" \
		"olympus.core.execution.x_redact_url*" \
		"olympus.core.execution.x_redact_text*" \
		"olympus.core.execution.x_safe_terminal_text*" \
		"olympus.core.execution.x_redact_mapping*" \
		"olympus.engagements.manifest.xǁEngagementManifestǁauthorizes*" \
		"olympus.engagements.manifest.xǁSignedEngagementManifestǁauthorize*" \
		"olympus.themis.adapters.nmap.xǁNmapAdapterǁparse*" \
		"olympus.themis.api.xǁApiSettingsǁvalidate*" \
		"olympus.themis.concurrency.xǁRequestConcurrencyGateǁtry_acquire*" \
		"olympus.themis.legacy_vap.x__decision*" \
		"olympus.themis.legacy_vap.x_verify_legacy_vap_snapshot*" \
		"olympus.themis.legacy_vap.x_create_legacy_vap_conversion_plan*" \
		"olympus.themis.legacy_vap.x_approve_legacy_vap_import*" \
		"olympus.themis.legacy_vap.x_import_legacy_vap_history*" \
		"olympus.themis.jobs.xǁThemisJobStoreǁclaim_next*" \
		"olympus.themis.identity.x__validate_lifetime*" \
		"olympus.themis.identity.x_rotate_identity*" \
		"olympus.themis.oidc.xǁOidcVerifierǁverify*" \
		"olympus.minerva.provenance.x__validate_command_template*" \
		"olympus.minerva.provenance.x__validate_reason_status*" \
		"olympus.minerva.vault.x_load_evidence_encryption_key*" \
		"olympus.minerva.vault.x__unpack*" \
		"olympus.minerva.vault.x_load_protected_evidence*" \
		"olympus.themis.sandbox.xǁScannerIsolationStatusǁmissing*" \
		"olympus.themis.sandbox.x_inspect_scanner_isolation*" \
		"olympus.themis.sandbox.x__trusted_root_file*" \
		"olympus.themis.scope.x_resolve_and_validate*" \
		"olympus.core.coverage.xǁCoverageǁstatus*" \
		"olympus.athena.cli.x__exit_code_for*" \
		"olympus.athena.domain.assessment.x_advance_job*" \
		"olympus.athena.domain.assessment.x_derive_terminal_state*"
	$(PYTHON) scripts/check_mutation_gate.py

# Deterministic offline performance baselines; add --enforce to apply budgets.
benchmark:
	$(PYTHON) scripts/benchmark_hot_paths.py --profile quick

benchmark-standard:
	$(PYTHON) scripts/benchmark_hot_paths.py --profile standard

schemas:
	$(PYTHON) scripts/export_schema_catalog.py

schemas-check:
	$(PYTHON) scripts/export_schema_catalog.py --check

contract-goldens:
	$(PYTHON) scripts/update_contract_goldens.py

check:
	$(MAKE) lint
	$(MAKE) format-check
	$(MAKE) type
	$(MAKE) schemas-check
	$(MAKE) test-coverage
	$(MAKE) test-mutation

demo:
	olympus core export-schemas ./examples/output

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
