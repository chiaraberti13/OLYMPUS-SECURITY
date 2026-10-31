"""Engagement: the top-level, scope-owning container (ROADMAP WEB-B).

One shared model (:class:`olympus.core.models.Engagement`) and one store, so
CLI, TUI, API and Web reference the same engagements and the same database
rather than a private per-interface notion of scope.
"""
