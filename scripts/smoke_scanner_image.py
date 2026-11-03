"""Acceptance smoke test for the built scanner image (run by the docker-build CI job).

    python scripts/smoke_scanner_image.py olympus-scanners:ci

For every engine the image is declared to ship (``in_scanner_image`` in the scanner
registry) it runs the manifest's ``presence_probe`` inside the image and requires a
clean exit; for git-installed engines it also requires ``git rev-parse HEAD`` to equal
the pinned commit. It is the precursor of ``olympus engines doctor --strict``: it
proves the image really contains what the manifests say, instead of trusting the
Dockerfile text.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable

from olympus.engines.loader import load_all, load_all_data
from olympus.integrations.scanners import by_name

Runner = Callable[[list[str]], tuple[int, str]]


def _docker(argv: list[str]) -> tuple[int, str]:
    """Run ``docker`` with a fixed argument vector (never a shell, never user input)."""
    completed = subprocess.run(  # noqa: S603
        ["docker", *argv],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def smoke(image: str, runner: Runner = _docker) -> list[str]:
    """Return every way the image differs from the manifests; empty means it passes."""
    problems: list[str] = []
    code, output = runner(["run", "--rm", "--entrypoint", "test", image, "-f", "/NOTICE"])
    if code != 0:
        problems.append(f"/NOTICE is missing from the image ({output})")
    for name, manifest in sorted(load_all().items()):
        spec = by_name(name)
        if spec is None or not spec.in_scanner_image or manifest.engine.distribution == "api":
            continue
        probe = manifest.engine.presence_probe
        code, output = runner(["run", "--rm", "--entrypoint", probe[0], image, *probe[1:]])
        if code != 0:
            problems.append(f"{name}: presence probe {probe} exited {code}: {output[:200]}")
        source = manifest.engine.source
        if manifest.engine.distribution == "git":
            code, head = runner(
                [
                    "run",
                    "--rm",
                    "--entrypoint",
                    "git",
                    image,
                    "-C",
                    str(source.checkout_path),
                    "rev-parse",
                    "HEAD",
                ]
            )
            if code != 0 or head.strip() != source.commit:
                problems.append(f"{name}: checkout is at {head.strip()!r}, pinned {source.commit}")
    for data_name, data in sorted(load_all_data().items()):
        source = data.data.source
        code, head = runner(
            [
                "run",
                "--rm",
                "--entrypoint",
                "git",
                image,
                "-C",
                str(source.checkout_path),
                "rev-parse",
                "HEAD",
            ]
        )
        if code != 0 or head.strip() != source.commit:
            problems.append(f"{data_name}: checkout is at {head.strip()!r}, pinned {source.commit}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: smoke_scanner_image.py IMAGE", file=sys.stderr)
        return 2
    problems = smoke(argv[0])
    for problem in problems:
        print(f"FAIL {problem}")
    if not problems:
        print("scanner image matches the engine manifests")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
