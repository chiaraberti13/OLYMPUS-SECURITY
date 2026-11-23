"""Multi-agent orchestration contract (AI-1 / ADR-012 DEC-14).

Verified offline (authority + approvals are injectable ports): off by default, every
gated action goes through the execution authority (never bypassed), destructive needs
human approval, a refused step blocks its dependents, and the graph is validated.
"""

from __future__ import annotations

import pytest

from olympus.ai.orchestrator import (
    ActionClass,
    AgentAction,
    GateDecision,
    Orchestrator,
    OrchestratorDisabledError,
    TaskGraphError,
    gate_for,
)

pytestmark = pytest.mark.unit

ON = {"OLYMPUS_AI_ENABLED": "true"}


class _Authority:
    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.authorized: list[str] = []
        self.executed: list[str] = []

    def authorize(self, action: AgentAction) -> bool:
        self.authorized.append(action.name)
        return self.allow

    def execute(self, action: AgentAction) -> str:
        self.executed.append(action.name)
        return f"ran {action.name}"


class _Approvals:
    def __init__(self, approved: set[str] | None = None) -> None:
        self.approved = approved or set()

    def is_approved(self, action: AgentAction) -> bool:
        return action.name in self.approved


def _orch(authority: _Authority, approvals: _Approvals | None = None) -> Orchestrator:
    return Orchestrator(authority=authority, approvals=approvals or _Approvals(), env=ON)


def test_gate_matrix() -> None:
    assert gate_for(ActionClass.OBSERVE) is GateDecision.AUTONOMOUS
    assert gate_for(ActionClass.ANALYZE) is GateDecision.AUTONOMOUS
    assert gate_for(ActionClass.ACTIVE) is GateDecision.REQUIRES_AUTHORIZATION
    assert gate_for(ActionClass.DESTRUCTIVE) is GateDecision.REQUIRES_HUMAN_APPROVAL


def test_disabled_by_default() -> None:
    orch = Orchestrator(authority=_Authority(), approvals=_Approvals(), env={})
    with pytest.raises(OrchestratorDisabledError):
        orch.run([AgentAction("look", ActionClass.OBSERVE)])


def test_autonomous_actions_run_without_authorization() -> None:
    auth = _Authority(allow=False)  # would deny if asked
    out = _orch(auth).run(
        [AgentAction("read", ActionClass.OBSERVE), AgentAction("corr", ActionClass.ANALYZE)]
    )
    assert [o.status for o in out] == ["ran", "ran"]
    assert auth.authorized == []  # autonomous never consults authorization
    assert auth.executed == ["read", "corr"]


def test_active_requires_authority() -> None:
    denied = _orch(_Authority(allow=False)).run([AgentAction("scan", ActionClass.ACTIVE)])
    assert denied[0].status == "refused"
    allowed_auth = _Authority(allow=True)
    allowed = _orch(allowed_auth).run([AgentAction("scan", ActionClass.ACTIVE)])
    assert allowed[0].status == "ran" and allowed_auth.executed == ["scan"]


def test_destructive_requires_human_approval_and_authority() -> None:
    # No approval -> refused even if the authority would allow.
    auth = _Authority(allow=True)
    out = _orch(auth).run([AgentAction("exploit", ActionClass.DESTRUCTIVE)])
    assert out[0].status == "refused" and auth.executed == []
    # Approval + authority -> runs.
    auth2 = _Authority(allow=True)
    orch = Orchestrator(authority=auth2, approvals=_Approvals({"exploit"}), env=ON)
    out2 = orch.run([AgentAction("exploit", ActionClass.DESTRUCTIVE)])
    assert out2[0].status == "ran" and auth2.executed == ["exploit"]


def test_refused_step_blocks_dependents() -> None:
    auth = _Authority(allow=False)
    out = _orch(auth).run(
        [
            AgentAction("scan", ActionClass.ACTIVE),
            AgentAction("report", ActionClass.ANALYZE, depends_on=("scan",)),
        ]
    )
    status = {o.action: o.status for o in out}
    assert status["scan"] == "refused" and status["report"] == "skipped"
    assert "report" not in auth.executed


def test_graph_validation() -> None:
    auth = _Authority()
    with pytest.raises(TaskGraphError):
        _orch(auth).run([AgentAction("a", ActionClass.OBSERVE, depends_on=("missing",))])
    with pytest.raises(TaskGraphError):
        _orch(auth).run(
            [
                AgentAction("a", ActionClass.OBSERVE, depends_on=("b",)),
                AgentAction("b", ActionClass.OBSERVE, depends_on=("a",)),
            ]
        )


def test_provenance_trail_records_every_step() -> None:
    orch = _orch(_Authority())
    orch.run([AgentAction("read", ActionClass.OBSERVE)])
    assert len(orch.trail) == 1 and orch.trail[0].action == "read"
