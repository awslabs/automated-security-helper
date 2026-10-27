# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check that every image pulled during a Docs CI Runners job is one it may pull.

WHY THIS EXISTS
---------------
The runners the Docs CI Runners workflow uses pull images: install_tools.py pulls the
pinned ones, and the runners and the pipelines they run can pull more. The job records
the Docker daemon's image pull events from before the installs until after the runs,

    docker events --filter type=image --filter event=pull --format '{{json .}}'

and this script then checks the recording. A pull passes only when its reference is
an image ``ref`` runners.toml pins by digest, or an image the job built itself
(--built). Anything else, a tag, an unlisted digest or an unlisted image, fails the
step. So does a recording that cannot be trusted to be complete: a missing events
file, a line that is not JSON, a missing pull log, or a reference install_tools.py
pulled (its --pull-log) with no pull event, which means the recording did not cover
the installs.

Docker Hub references compare in their short and full forms: ``cimg/python@...`` is
``docker.io/cimg/python@...``, and ``python`` is ``docker.io/library/python``.

Usage::

    python3 -I tests/integration/docs/ci_runners/image_allowlist.py \\
        --events <docker events file> --pulls <install_tools.py pull log> \\
        --manifest tests/integration/docs/ci_runners/runners.toml [--built <image>]...

Exit codes: 0 when every pull is allowed and the recording covers the installs; 1 with
each problem printed; 2 for a usage error.

It runs as ``python3 -I`` on Python 3.10 and later and imports nothing from the files
beside it. On Python 3.11 and later it uses the standard library only, reading TOML
with tomllib; 3.10 has no tomllib, so there it imports tomli, which must be installed
for that Python.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

DOCKER_HUB = "docker.io"
_DOCKER_HUB_NAMES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})


def full_reference(ref: str) -> str:
    """A reference with its registry spelled out, Docker Hub's included.

    The first component is a registry when a / follows it and it has a dot or a colon
    or is localhost, as Docker reads it; otherwise the image is on Docker Hub, where a
    one-component name is under library/.
    """
    first, slash, rest = ref.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = DOCKER_HUB, ref
    if host in _DOCKER_HUB_NAMES:
        host = DOCKER_HUB
        if "/" not in path:
            path = f"library/{path}"
    return f"{host}/{path}"


def _manifest_refs(manifest: Path, problems: list[str]) -> set[str]:
    try:
        document = tomllib.loads(Path(manifest).read_text(encoding="utf-8"))
    except FileNotFoundError:
        problems.append(f"{manifest}: no such file")
        return set()
    except tomllib.TOMLDecodeError as error:
        problems.append(f"{manifest}: not TOML ({error})")
        return set()
    images = document.get("images", {})
    refs = set()
    if isinstance(images, dict):
        for entry in images.values():
            ref = entry.get("ref") if isinstance(entry, dict) else None
            if isinstance(ref, str):
                refs.add(full_reference(ref))
    return refs


def _pulled(events: Path, problems: list[str]) -> list[tuple[int, str]] | None:
    """(line number, reference) of every image pull event, or None without a file."""
    if not events.is_file():
        problems.append(
            f"{events}: no such file; the docker events recording must start before"
            " the installs and write this file"
        )
        return None
    pulled = []
    lines = events.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            problems.append(f"{events}: line {number} is not JSON ({error.msg})")
            continue
        if not isinstance(record, dict):
            problems.append(f"{events}: line {number} is not a JSON object")
            continue
        if record.get("Type", "image") != "image":
            continue
        if (record.get("Action") or record.get("status")) != "pull":
            continue
        actor = record.get("Actor")
        ref = actor.get("ID") if isinstance(actor, dict) else None
        if not ref:
            ref = record.get("id")
        if not (isinstance(ref, str) and ref):
            problems.append(
                f"{events}: line {number} is a pull with no image reference"
            )
            continue
        pulled.append((number, ref))
    return pulled


def image_allowlist_problems(
    events: Path, pulls: Path, manifest: Path, built: Iterable[str] = ()
) -> list[str]:
    """Every problem with the job's image pulls; [] when there is none.

    ``events`` is the ``docker events --format '{{json .}}'`` recording, ``pulls``
    install_tools.py's pull log, ``manifest`` runners.toml, and ``built`` the images
    the job built itself.
    """
    events, pulls = Path(events), Path(pulls)
    problems: list[str] = []
    allowed = _manifest_refs(manifest, problems)
    # An image the job built is accepted on a pull event too: a runner can ask the
    # daemon to pull an image name before it uses the copy the job built under that
    # name. The caller chooses built names that no registry serves an image under.
    allowed |= {full_reference(ref) for ref in built}
    pulled = _pulled(events, problems)
    for number, ref in pulled or ():
        if full_reference(ref) not in allowed:
            problems.append(
                f"{events}: line {number}: pulled {ref}, which is neither an image"
                " runners.toml pins by digest nor one this job built"
            )
    if not pulls.is_file():
        problems.append(
            f"{pulls}: no such file; install_tools.py --pull-log writes it, and without"
            " it the check that the recording covered the installs cannot run"
        )
    elif pulled is not None:
        recorded = {full_reference(ref) for _number, ref in pulled}
        lines = pulls.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            ref = line.strip()
            if ref and full_reference(ref) not in recorded:
                problems.append(
                    f"{pulls}: line {number}: install_tools.py pulled {ref}, and {events}"
                    " has no pull event for it, so the recording did not cover the"
                    " installs"
                )
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="image_allowlist.py",
        description=(
            "Check a job's recorded image pulls against runners.toml and the images"
            " the job built."
        ),
    )
    parser.add_argument(
        "--events", required=True, type=Path, help="the docker events recording"
    )
    parser.add_argument(
        "--pulls", required=True, type=Path, help="install_tools.py's --pull-log file"
    )
    parser.add_argument("--manifest", required=True, type=Path, help="runners.toml")
    parser.add_argument(
        "--built",
        action="append",
        default=[],
        metavar="IMAGE",
        help="an image the job built itself; repeat for each",
    )
    args = parser.parse_args(argv)
    problems = image_allowlist_problems(
        args.events, args.pulls, args.manifest, built=args.built
    )
    for problem in problems:
        print(problem)
    if problems:
        print(f"image allowlist: {len(problems)} problem(s)")
        return 1
    print("image allowlist: every pull is a pinned digest or a built image")
    return 0


if __name__ == "__main__":
    sys.exit(main())
