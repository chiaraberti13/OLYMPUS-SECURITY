"""Finding lifecycle persistence: the append-only transition audit trail (WEB-C).

The :class:`olympus.core.models.Finding` contract carries only a finding's
*current* status. This package persists the immutable trail of how it got there
(:class:`olympus.core.models.FindingTransition`), so CLI, TUI, API and Web share
one audit log rather than a private per-interface history.
"""
