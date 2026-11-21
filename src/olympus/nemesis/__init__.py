"""Nemesis — offline auditor of weak, default and reused credentials (RED-3).

Nemesis never attacks a service and never touches the network: it audits a set of
credentials the operator is authorized to review (a password policy check and a
comparison against a local list of known-weak/default passwords), and reports what
is weak, default or reused. Secrets are masked in every output and never logged.
"""

from __future__ import annotations
