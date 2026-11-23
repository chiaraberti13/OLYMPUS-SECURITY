"""Multi-agent orchestration core (AI-1, gated by ADR-012 / DEC-14).

The orchestrator schedules a task graph of agent actions; it is **not** an execution
engine. Every action that would touch a target or run an engine is delegated to an
injected **execution authority** port (Themis in production) — the orchestrator
never executes directly, so Themis stays the single authority for scope, isolation
and authorization (ADR-011).

Each action carries an :class:`ActionClass`; the DEC-14 gating matrix decides whether
it may run autonomously, needs the signed-manifest authorization, or needs explicit
human approval. The orchestrator is fail-closed: an action the authority denies, or a
destructive action without approval, is refused and its dependents are skipped, and
every step is recorded with provenance. With the AI feature flag off the orchestrator
is inert (:class:`OrchestratorDisabledError`).

No network or process I/O here: the authority and approvals are injectable ports, so
the whole module is unit-tested offline.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from olympus.ai import ai_enabled


class ActionClass(StrEnum):
    """How much authority an agent action needs (DEC-14)."""

    OBSERVE = "observe"  # read-only: read findings, inspect graph
    ANALYZE = "analyze"  # simulate/correlate/replay, no live target
    ACTIVE = "active"  # a live scan / engine run against a target
    DESTRUCTIVE = "destructive"  # exploitation, external writes, remediation apply


class GateDecision(StrEnum):
    AUTONOMOUS = "autonomous"
    REQUIRES_AUTHORIZATION = "requires-authorization"
    REQUIRES_HUMAN_APPROVAL = "requires-human-approval"


#: The DEC-14 gating matrix. Read/analyze run autonomously; a live action needs the
#: authority's in-scope authorization; a destructive action always needs human
#: approval (in addition to the authority).
GATE_MATRIX: dict[ActionClass, GateDecision] = {
    ActionClass.OBSERVE: GateDecision.AUTONOMOUS,
    ActionClass.ANALYZE: GateDecision.AUTONOMOUS,
    ActionClass.ACTIVE: GateDecision.REQUIRES_AUTHORIZATION,
    ActionClass.DESTRUCTIVE: GateDecision.REQUIRES_HUMAN_APPROVAL,
}


def gate_for(action_class: ActionClass) -> GateDecision:
    return GATE_MATRIX[action_class]


class OrchestratorError(RuntimeError):
    """Base class for orchestration refusals."""


class OrchestratorDisabledError(OrchestratorError):
    """The AI layer is disabled."""


class TaskGraphError(OrchestratorError):
    """The task graph is malformed (unknown dependency or a cycle)."""


@dataclass(frozen=True)
class AgentAction:
    """One unit of agent work, classified for gating."""

    name: str
    action_class: ActionClass
    #: Names of actions that must complete successfully before this one.
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True)
class StepOutcome:
    action: str
    action_class: ActionClass
    decision: GateDecision
    status: str  # "ran" | "refused" | "skipped"
    detail: str = ""


@runtime_checkable
class ExecutionAuthority(Protocol):
    """Port for the execution authority (Themis). The orchestrator never bypasses it."""

    def authorize(self, action: AgentAction) -> bool:
        """Whether this action is in scope and authorized to run."""

    def execute(self, action: AgentAction) -> str:
        """Run the action under the authority's isolation; return a short detail."""


@runtime_checkable
class ApprovalGate(Protocol):
    """Port for human approval of destructive actions."""

    def is_approved(self, action: AgentAction) -> bool:
        """Whether a human has approved this specific destructive action."""


def _order(actions: Sequence[AgentAction]) -> list[AgentAction]:
    by_name = {a.name: a for a in actions}
    if len(by_name) != len(actions):
        raise TaskGraphError("duplicate action name in task graph")
    ordered: list[AgentAction] = []
    seen: set[str] = set()
    temp: set[str] = set()

    def visit(name: str) -> None:
        if name in seen:
            return
        if name in temp:
            raise TaskGraphError(f"dependency cycle at {name!r}")
        if name not in by_name:
            raise TaskGraphError(f"unknown dependency {name!r}")
        temp.add(name)
        for dep in by_name[name].depends_on:
            visit(dep)
        temp.discard(name)
        seen.add(name)
        ordered.append(by_name[name])

    for action in actions:
        visit(action.name)
    return ordered


@dataclass
class Orchestrator:
    """Schedule a task graph, gating every step and delegating execution to Themis."""

    authority: ExecutionAuthority
    approvals: ApprovalGate
    env: Mapping[str, str] | None = None
    trail: list[StepOutcome] = field(default_factory=list)

    def run(self, actions: Sequence[AgentAction]) -> list[StepOutcome]:
        """Run the graph in dependency order. Fail-closed and fully recorded.

        A step whose gate is not satisfied is **refused** and every step that
        (transitively) depends on it is **skipped** — an agent can never run work
        that hangs off a denied action.
        """
        if not ai_enabled(self.env):
            raise OrchestratorDisabledError("the AI layer is disabled (set OLYMPUS_AI_ENABLED)")

        outcomes: list[StepOutcome] = []
        blocked: set[str] = set()
        for action in _order(actions):
            decision = gate_for(action.action_class)
            if any(dep in blocked for dep in action.depends_on):
                outcome = StepOutcome(
                    action.name,
                    action.action_class,
                    decision,
                    "skipped",
                    "depends on a refused step",
                )
                blocked.add(action.name)
                outcomes.append(outcome)
                continue

            refusal = self._refusal(action, decision)
            if refusal is not None:
                blocked.add(action.name)
                outcomes.append(
                    StepOutcome(action.name, action.action_class, decision, "refused", refusal)
                )
                continue

            detail = self.authority.execute(action)
            outcomes.append(StepOutcome(action.name, action.action_class, decision, "ran", detail))

        self.trail.extend(outcomes)
        return outcomes

    def _refusal(self, action: AgentAction, decision: GateDecision) -> str | None:
        """Return a refusal reason if the gate is not satisfied, else None."""
        if decision is GateDecision.REQUIRES_HUMAN_APPROVAL and not self.approvals.is_approved(
            action
        ):
            return "destructive action without human approval"
        if decision in (
            GateDecision.REQUIRES_AUTHORIZATION,
            GateDecision.REQUIRES_HUMAN_APPROVAL,
        ) and not self.authority.authorize(action):
            return "refused by the execution authority (out of scope / unauthorized)"
        return None
