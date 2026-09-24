#!/usr/bin/env python3
"""Create or update the repository labels managed by Olympus.

The synchronizer is deliberately conservative: it never deletes labels and it
does not touch labels absent from ``.github/labels.json``.  The GitHub token is
used only in the Authorization header and is never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

API_ROOT = "https://api.github.com"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COLOR_PATTERN = re.compile(r"^[0-9A-Fa-f]{6}$")
MAX_DESCRIPTION_LENGTH = 100


class LabelSyncError(RuntimeError):
    """Raised when the manifest or GitHub response cannot be trusted."""


@dataclass(frozen=True)
class Label:
    """One normalized GitHub label declaration."""

    name: str
    color: str
    description: str

    def payload(self) -> dict[str, str]:
        return {
            "name": self.name,
            "color": self.color,
            "description": self.description,
        }


@dataclass(frozen=True)
class ChangePlan:
    """Managed labels that need creation or an in-place update."""

    create: tuple[Label, ...]
    update: tuple[Label, ...]


def load_manifest(path: Path) -> tuple[Label, ...]:
    """Load and strictly validate the managed label manifest."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabelSyncError(f"cannot read label manifest {path}: {exc}") from exc
    if not isinstance(raw, list) or not raw:
        raise LabelSyncError("label manifest must be a non-empty JSON array")

    labels: list[Label] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != {"name", "color", "description"}:
            raise LabelSyncError(
                f"label #{index + 1} must contain exactly name, color and description"
            )
        name = item["name"]
        color = item["color"]
        description = item["description"]
        if not isinstance(name, str) or not name.strip() or len(name) > 50:
            raise LabelSyncError(f"label #{index + 1} has an invalid name")
        if not isinstance(color, str) or COLOR_PATTERN.fullmatch(color) is None:
            raise LabelSyncError(f"label {name!r} must use a six-digit hexadecimal color")
        if not isinstance(description, str) or len(description) > MAX_DESCRIPTION_LENGTH:
            raise LabelSyncError(
                f"label {name!r} description exceeds {MAX_DESCRIPTION_LENGTH} characters"
            )
        key = name.casefold()
        if key in seen:
            raise LabelSyncError(f"duplicate managed label {name!r}")
        seen.add(key)
        labels.append(Label(name=name, color=color.upper(), description=description))
    return tuple(labels)


def plan_changes(desired: tuple[Label, ...], existing: tuple[Label, ...]) -> ChangePlan:
    """Return the minimal create/update plan without deleting unmanaged labels."""
    current = {label.name.casefold(): label for label in existing}
    create: list[Label] = []
    update: list[Label] = []
    for label in desired:
        found = current.get(label.name.casefold())
        if found is None:
            create.append(label)
            continue
        if found.color.upper() != label.color or found.description != label.description:
            update.append(label)
    return ChangePlan(create=tuple(create), update=tuple(update))


def _request(
    method: str,
    endpoint: str,
    token: str,
    payload: dict[str, str] | None = None,
) -> tuple[Any, dict[str, str]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(  # noqa: S310 - URL is built from the fixed HTTPS API root
        f"{API_ROOT}{endpoint}",
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "olympus-label-sync",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed HTTPS API root
            body = response.read()
            headers = {key.lower(): value for key, value in response.headers.items()}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise LabelSyncError(f"GitHub API returned {exc.code} for {endpoint}: {detail}") from exc
    except URLError as exc:
        raise LabelSyncError(f"GitHub API request failed for {endpoint}: {exc.reason}") from exc
    if not body:
        return None, headers
    try:
        return json.loads(body), headers
    except json.JSONDecodeError as exc:
        raise LabelSyncError(f"GitHub API returned invalid JSON for {endpoint}") from exc


def fetch_existing(repository: str, token: str) -> tuple[Label, ...]:
    """Fetch all current labels using bounded pagination."""
    labels: list[Label] = []
    for page in range(1, 101):
        payload, _headers = _request(
            "GET", f"/repos/{repository}/labels?per_page=100&page={page}", token
        )
        if not isinstance(payload, list):
            raise LabelSyncError("GitHub labels endpoint did not return a list")
        for item in payload:
            if not isinstance(item, dict):
                raise LabelSyncError("GitHub labels endpoint returned an invalid entry")
            labels.append(
                Label(
                    name=str(item.get("name", "")),
                    color=str(item.get("color", "")),
                    description=str(item.get("description") or ""),
                )
            )
        if len(payload) < 100:
            return tuple(labels)
    raise LabelSyncError("GitHub label pagination exceeded 100 pages")


def synchronize(repository: str, token: str, desired: tuple[Label, ...]) -> ChangePlan:
    """Apply the minimal non-destructive change plan to one repository."""
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise LabelSyncError("repository must use the owner/name form")
    if not token.strip():
        raise LabelSyncError("a non-empty GitHub token is required")
    plan = plan_changes(desired, fetch_existing(repository, token))
    for label in plan.create:
        _request("POST", f"/repos/{repository}/labels", token, label.payload())
    for label in plan.update:
        encoded_name = quote(label.name, safe="")
        _request(
            "PATCH",
            f"/repos/{repository}/labels/{encoded_name}",
            token,
            label.payload(),
        )
    return plan


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the manifest without contacting GitHub",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        desired = load_manifest(args.manifest)
        if args.check:
            print(f"validated {len(desired)} managed labels")
            return 0
        plan = synchronize(args.repository, args.token, desired)
    except LabelSyncError as exc:
        print(f"label sync failed: {exc}", file=sys.stderr)
        return 1
    print(f"labels synchronized: created={len(plan.create)} updated={len(plan.update)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
