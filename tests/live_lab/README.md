# Authorized live-lab tests

`test_nuclei_live.py` is the Nuclei pilot. The ordinary CI suite excludes live
tests. The dedicated workflow checks its temporary JUnit report for collected,
non-skipped cases. The workflow currently does not publish that report or a
signed run manifest.

For QA-3, distinguish the [historical execution records](../../docs/themis-execution-evidence.md)
from evidence for a particular commit. The pilot's closure criteria are in the
[roadmap](../../ROADMAP.md#14-quality-assurance-e-test). They require a successful
run, the tested commit, engine and data versions and a verifiable signed record.
The offline signature tests use synthetic data to exercise verification failures.
