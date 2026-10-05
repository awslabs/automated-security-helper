#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fails when a container image the repository runs is named by a mutable tag.

The sibling of assert-actions-pinned.mjs. That gate covers `uses:`; this one covers the
images, which have the same defect: `gradle:jdk21` resolves to whatever the tag points at
on the day the job runs, so an upstream push changes what executes inside a job holding
this repository's tokens, with no diff here to review. A digest removes the indirection.

WHAT IS CHECKED

1. Workflows (.github/workflows/*.yml) and composite or Docker actions
   (.github/actions/**/action.yml), parsed as YAML: every job `container:` (the string
   form and the `image:` key), every `services.<name>.image`, and `runs.image` for a
   `docker://` action. A value that is a `${{ matrix.<key> }}` expression is resolved
   against the job's strategy.matrix, `include` entries too, and every value it can take
   is checked. Any other expression cannot be resolved offline and fails.
2. Every tracked Dockerfile (Dockerfile*, *.Dockerfile, Containerfile*): each FROM must
   name an earlier stage, carry `@sha256:<64 hex>`, or come from an ARG. An ARG with no
   default is supplied by whoever builds the file and is outside what this check can
   see. An ARG with a default must default to a digest-pinned reference or be paired with
   an `ARG <NAME>_DIGEST=sha256:...` that the build verifies, which is the root
   Dockerfile's arrangement (see BASE_IMAGE_DIGEST there and .github/actions/prepull-base-image).
3. A FROM that names an image this repository builds locally in the same job, and so has
   no stable digest, is accepted only under a comment on the line directly above it:
   `# assert-images-pinned: built-locally <reason>`. The reason is required.
4. Every tracked file that creates a kind cluster must name a digest-pinned kindest/node
   image. kind's default node image is fixed per kind release, but it is an implicit
   pull of a tag that nothing in this tree records.

WHAT IT CANNOT SEE

Images named inside `run:` scripts (`docker run fedora:41 ...`) and in documentation are
not parsed. A digest is checked for form, not for existence; resolving one needs the
registry.

NO VACUOUS PASSES

Zero workflow files, zero Dockerfiles, or zero image references in total each fail: they
mean the census broke, not that the tree is clean. --self-test plants one violation per
rule and requires each to be reported, and plants the accepted forms and requires
silence.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
MATRIX_EXPR = re.compile(r"^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$")
LOCAL_MARKER = re.compile(r"^\s*#\s*assert-images-pinned:\s*built-locally\s+\S")
KIND_CREATE = re.compile(r"""kind['"]?\s*,?\s*['"]?create['"]?\s*,?\s*['"]?cluster""")
KIND_NODE_PINNED = re.compile(r"kindest/node:[^\s\"'@]+@sha256:[0-9a-f]{64}")
KIND_NODE_ANY = re.compile(r"kindest/node(:[^\s\"'@]+)?(@sha256:[0-9a-f]*)?")

Problem = Tuple[str, str]  # (location, message)


def _pinned(ref: str) -> bool:
    return bool(DIGEST.search(ref.strip().strip('"').strip("'")))


# --------------------------------------------------------------------------
# Workflows and actions
# --------------------------------------------------------------------------


def _matrix_values(job: Dict[str, Any], key: str) -> Optional[List[Any]]:
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return None
    values: List[Any] = []
    direct = matrix.get(key)
    if isinstance(direct, list):
        values.extend(direct)
    elif direct is not None:
        values.append(direct)
    for entry in matrix.get("include") or []:
        if isinstance(entry, dict) and key in entry:
            values.append(entry[key])
    return values or None


def _check_ref(
    location: str, ref: Any, job: Dict[str, Any], problems: List[Problem]
) -> int:
    """Checks one image reference; returns how many concrete references it examined."""
    if not isinstance(ref, str) or not ref.strip():
        problems.append((location, f"image reference is not a string: {ref!r}"))
        return 0
    ref = ref.strip()
    if "${{" in ref:
        match = MATRIX_EXPR.match(ref)
        values = _matrix_values(job, match.group(1)) if match else None
        if not values:
            problems.append(
                (
                    location,
                    f"{ref} cannot be resolved offline, so its pin cannot be checked",
                )
            )
            return 0
        count = 0
        for value in values:
            count += _check_ref(f"{location} ({ref})", value, job, problems)
        return count
    if not _pinned(ref):
        problems.append(
            (
                location,
                f"{ref} is not pinned by digest (expected <image>@sha256:<64 hex>)",
            )
        )
    return 1


def check_workflow(path: Path, text: str, problems: List[Problem]) -> int:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        problems.append((str(path), f"not parseable as YAML: {exc}"))
        return 0
    if not isinstance(document, dict):
        return 0
    count = 0
    runs = document.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("image"), str):
        image = runs["image"]
        if image.startswith("docker://"):
            count += _check_ref(
                f"{path}: runs.image", image[len("docker://") :], {}, problems
            )
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return count
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        container = job.get("container")
        if isinstance(container, str):
            count += _check_ref(
                f"{path}: jobs.{job_id}.container", container, job, problems
            )
        elif isinstance(container, dict) and "image" in container:
            count += _check_ref(
                f"{path}: jobs.{job_id}.container.image",
                container["image"],
                job,
                problems,
            )
        services = job.get("services")
        if isinstance(services, dict):
            for service_id, service in services.items():
                image = service.get("image") if isinstance(service, dict) else service
                count += _check_ref(
                    f"{path}: jobs.{job_id}.services.{service_id}.image",
                    image,
                    job,
                    problems,
                )
    return count


# --------------------------------------------------------------------------
# Dockerfiles
# --------------------------------------------------------------------------

ARG_LINE = re.compile(
    r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?\s*$", re.IGNORECASE
)
FROM_LINE = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE
)
VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def check_dockerfile(path: Path, text: str, problems: List[Problem]) -> int:
    args: Dict[str, Optional[str]] = {}
    stages: Set[str] = set()
    lines = text.splitlines()
    count = 0
    for number, line in enumerate(lines, start=1):
        arg = ARG_LINE.match(line)
        if arg:
            default = arg.group(2)
            args[arg.group(1)] = (
                default.strip().strip('"').strip("'") if default is not None else None
            )
            continue
        match = FROM_LINE.match(line)
        if not match:
            continue
        count += 1
        ref, alias = match.group(1), match.group(2)
        location = f"{path}:{number}"
        if alias:
            stages.add(alias.lower())
        if ref.lower() in stages and ref.lower() != (alias or "").lower():
            continue
        if ref.lower() == "scratch" or _pinned(ref):
            continue
        previous = lines[number - 2] if number >= 2 else ""
        if LOCAL_MARKER.match(previous):
            continue
        variables = VAR_REF.findall(ref)
        if variables and VAR_REF.sub("", ref) == "":
            name = variables[0]
            default = args.get(name)
            digest = args.get(f"{name}_DIGEST") or ""
            if name not in args:
                problems.append(
                    (location, f"FROM {ref} uses ${name}, which no ARG declares")
                )
            elif default is None:
                pass  # supplied by the builder; outside this check
            elif _pinned(default) or digest.startswith("sha256:"):
                pass
            else:
                problems.append(
                    (
                        location,
                        (
                            f"FROM {ref} defaults to {args[name]}, which is not pinned by digest "
                            f"and has no ARG {name}_DIGEST=sha256:... beside it"
                        ),
                    )
                )
            continue
        problems.append((location, f"FROM {ref} is not pinned by digest"))
    return count


# --------------------------------------------------------------------------
# kind
# --------------------------------------------------------------------------


def check_kind(path: Path, text: str, problems: List[Problem]) -> int:
    if not KIND_CREATE.search(text):
        return 0
    unpinned = [
        m.group(0)
        for m in KIND_NODE_ANY.finditer(text)
        if not KIND_NODE_PINNED.match(m.group(0))
    ]
    if not KIND_NODE_PINNED.search(text):
        problems.append(
            (
                str(path),
                "creates a kind cluster without a digest-pinned kindest/node image (--image)",
            )
        )
    for ref in unpinned:
        problems.append((str(path), f"{ref} is not pinned by digest"))
    return 1


# --------------------------------------------------------------------------
# Census
# --------------------------------------------------------------------------


def _is_dockerfile(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name.startswith(("Dockerfile", "Containerfile")) or name.endswith(
        (".Dockerfile", ".dockerfile")
    )


def _is_workflow(path: str) -> bool:
    return (
        path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
    ) or (
        path.startswith(".github/actions/")
        and path.rsplit("/", 1)[-1] in ("action.yml", "action.yaml")
    )


KIND_SUFFIXES = (".py", ".sh", ".yml", ".yaml", ".mjs", ".js", ".ts", ".ps1")


def scan(root: Path, files: Iterable[str]) -> Tuple[List[Problem], Dict[str, int]]:
    problems: List[Problem] = []
    totals = {"workflows": 0, "dockerfiles": 0, "references": 0, "kind": 0}
    for rel in sorted(files):
        path = root / rel
        if not path.is_file():
            continue
        if rel.startswith(".github/scripts/assert-images-pinned"):
            continue  # this file names the patterns it looks for
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _is_workflow(rel):
            totals["workflows"] += 1
            totals["references"] += check_workflow(Path(rel), text, problems)
        if _is_dockerfile(rel):
            totals["dockerfiles"] += 1
            totals["references"] += check_dockerfile(Path(rel), text, problems)
        if rel.endswith(KIND_SUFFIXES):
            totals["kind"] += check_kind(Path(rel), text, problems)
    return problems, totals


def tracked_files(root: Path) -> List[str]:
    result = subprocess.run(  # noqa: S603, S607
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True
    )
    return [p for p in result.stdout.decode("utf-8").split("\0") if p]


def report(problems: List[Problem], totals: Dict[str, int]) -> int:
    for location, message in problems:
        print(f"::error::{location}: {message}")
    census = (
        f"{totals['workflows']} workflow/action files, {totals['dockerfiles']} Dockerfiles, "
        f"{totals['references']} image references, {totals['kind']} kind cluster definitions"
    )
    if (
        totals["workflows"] == 0
        or totals["dockerfiles"] == 0
        or totals["references"] == 0
    ):
        print(
            f"::error::census found nothing to check ({census}); the file listing or a matcher is broken"
        )
        return 1
    if problems:
        print(f"FAIL: {len(problems)} unpinned image reference(s) across {census}")
        return 1
    print(f"OK: every image is pinned by digest across {census}")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

D = "sha256:" + "a" * 64

SELF_TEST_FILES = {
    ".github/workflows/good.yml": f"""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    container: debian@{D}
    services:
      db: {{image: "postgres:16@{D}"}}
    steps: [{{run: echo}}]
  b:
    runs-on: ubuntu-latest
    container: {{image: "${{{{ matrix.image }}}}"}}
    strategy:
      matrix:
        include:
          - {{image: "ubuntu@{D}"}}
    steps: [{{run: echo}}]
""",
    "ok/Dockerfile": f"""ARG BASE=python:3.12-slim@{D}
ARG TAGGED=python:3.12-slim
ARG TAGGED_DIGEST={D}
ARG SUPPLIED
FROM ${{BASE}} AS one
FROM ${{TAGGED}} AS two
FROM ${{SUPPLIED}}
FROM one
FROM scratch
# assert-images-pinned: built-locally the e2e builds this image two steps earlier
FROM ash-e2e:local
""",
    "ok/kind_ok.py": f'run(["kind", "create", "cluster", "--image", "kindest/node:v1.34.0@{D}"])\n',
}

SELF_TEST_BAD = {
    ".github/workflows/bad-string.yml": (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: gradle:jdk21\n    steps: [{run: echo}]\n",
        "gradle:jdk21 is not pinned",
    ),
    ".github/workflows/bad-image-key.yml": (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container:\n      image: gradle:jdk21\n    steps: [{run: echo}]\n",
        "container.image: gradle:jdk21",
    ),
    ".github/workflows/bad-service.yml": (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    services:\n      db:\n        image: postgres:16\n    steps: [{run: echo}]\n",
        "services.db.image: postgres:16",
    ),
    ".github/workflows/bad-matrix.yml": (
        (
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: ${{ matrix.image }}\n"
            "    strategy:\n      matrix:\n        image: [debian:12]\n    steps: [{run: echo}]\n"
        ),
        "debian:12 is not pinned",
    ),
    ".github/workflows/bad-expr.yml": (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: ${{ inputs.image }}\n    steps: [{run: echo}]\n",
        "cannot be resolved offline",
    ),
    ".github/actions/bad/action.yml": (
        "runs:\n  using: docker\n  image: docker://alpine:3\n",
        "alpine:3 is not pinned",
    ),
    "bad/Dockerfile": (
        "FROM python:3.12-slim\n",
        "FROM python:3.12-slim is not pinned",
    ),
    "bad/arg.Dockerfile": (
        "ARG BASE=python:3.12-slim\nFROM ${BASE}\n",
        "has no ARG BASE_DIGEST",
    ),
    "bad/undeclared.Dockerfile": ("FROM ${NOPE}\n", "which no ARG declares"),
    "bad/marker-without-reason.Dockerfile": (
        "# assert-images-pinned: built-locally\nFROM ash-e2e:local\n",
        "FROM ash-e2e:local is not pinned",
    ),
    "bad/kind_default.py": (
        'run(["kind", "create", "cluster", "--name", "x"])\n',
        "without a digest-pinned kindest/node",
    ),
    "bad/kind_tag.sh": (
        "kind create cluster --image kindest/node:v1.34.0\n",
        "kindest/node:v1.34.0 is not pinned",
    ),
}


def self_test() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="assert-images-pinned-") as tmp:
        root = Path(tmp)
        for rel, text in SELF_TEST_FILES.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        problems, totals = scan(root, SELF_TEST_FILES)
        if problems:
            print(f"  FAIL: accepted forms were reported: {problems}")
            failures += 1
        else:
            print(f"  ok: accepted forms pass ({totals['references']} references)")
        for rel, (text, needle) in SELF_TEST_BAD.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
            problems, _ = scan(root, [rel])
            if any(
                needle in f"{location}: {message}" for location, message in problems
            ):
                print(f"  ok: {rel} rejected")
            else:
                print(f"  FAIL: {rel} not rejected for '{needle}': {problems}")
                failures += 1
        empty_rc = report(
            [], {"workflows": 0, "dockerfiles": 0, "references": 0, "kind": 0}
        )
        if empty_rc != 1:
            print("  FAIL: an empty census passed")
            failures += 1
        else:
            print("  ok: an empty census fails")
    total = len(SELF_TEST_BAD) + 2
    if failures:
        print(f"self-test FAILED: {failures} of {total} checks")
        return 1
    print(f"self-test passed: {total} checks")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--root", type=Path, default=Path.cwd(), help="repository root (default: cwd)"
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    problems, totals = scan(args.root, tracked_files(args.root))
    return report(problems, totals)


if __name__ == "__main__":
    sys.exit(main())
