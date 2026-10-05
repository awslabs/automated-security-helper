#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fails when anything this repository runs in CI could push a container image.

WHY THIS EXISTS

ASH publishes no container image from this repository, and the e2e container channel
(scripts/e2e/container.sh) builds one from every commit. The repository is public, so
an image pushed from a workflow, from a pull request especially, is an image anyone can
pull, built from code nobody released. The Kubernetes operator already asserts this for
its own files (deploy/kubernetes-operator/tests/test_no_image_publish.py). This is the
same assertion over everything else CI executes.

WHAT IS CHECKED

Every tracked file under the CI roots below, line by line, against the shapes that log in
to a registry or push to one: `docker push`, `docker image push`, `docker login`,
`podman`/`buildah`/`nerdctl`/`finch`/`crane`/`oras` push, `skopeo copy`, `buildx ...
--push`, a registry or `push=true` build output, `push: true`, and the login and
build-and-push actions. Lines that are wholly a `#` or `//` comment are skipped, so
prose can say what is forbidden.

The roots are the CI surface only. deploy/cdk and deploy/terraform push images on
purpose, into the deploying customer's own private registry, from the customer's own
account; that is the product, not this repository's CI.

EXEMPTIONS

A line that matches a shape without publishing anything (a planted fixture inside
another gate's self-test) is listed in EXEMPT with its file, its exact stripped text and
a reason. An exemption that no longer matches a line fails, so one cannot outlive the
line it was written for. This file holds the shapes as data and is excluded by path.

NO VACUOUS PASS

The census must have read at least one file, and must have read the files that build an
image in CI today (REQUIRED). If either is missing the check fails, because a census that
reads nothing reports a clean tree. --self-test plants each shape and requires it
reported, plants the accepted forms and requires silence, and plants a stale exemption
and requires that reported too.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ROOTS: Tuple[str, ...] = (".github/", "scripts/", "packaging/", "tests/e2e/")

# Files that exist to build an image in CI. The census must read each one.
REQUIRED: Tuple[str, ...] = (
    ".github/workflows/ash-e2e.yml",
    ".github/actions/validate-container/action.yml",
    "scripts/e2e/container.sh",
)

SELF: Tuple[str, ...] = (".github/scripts/assert-no-image-publish.py",)

SHAPES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("docker push", re.compile(r"\bdocker\s+(?:image\s+)?push\b")),
    (
        "docker push (argv form)",
        re.compile(r"[\"']docker[\"']\s*,\s*(?:[\"']image[\"']\s*,\s*)?[\"']push[\"']"),
    ),
    ("docker login", re.compile(r"\bdocker\s+login\b")),
    ("docker login (argv form)", re.compile(r"[\"']docker[\"']\s*,\s*[\"']login[\"']")),
    (
        "runtime push",
        re.compile(r"\b(?:podman|buildah|nerdctl|finch|crane|oras)\s+push\b"),
    ),
    ("runtime login", re.compile(r"\b(?:podman|buildah|nerdctl|finch)\s+login\b")),
    ("skopeo copy", re.compile(r"\bskopeo\s+copy\b")),
    ("buildx --push", re.compile(r"\bbuildx\b.*\s--push\b")),
    ("registry output", re.compile(r"\btype=registry\b|\bpush=true\b")),
    ("push: true", re.compile(r"\bpush:\s*[\"']?true\b")),
    (
        "publishing action",
        re.compile(
            r"docker/login-action|docker/build-push-action|aws-actions/amazon-ecr-login"
            r"|redhat-actions/push-to-registry|redhat-actions/podman-login"
        ),
    ),
)

# (file, exact stripped line) -> reason. See EXEMPTIONS above.
EXEMPT: Dict[Tuple[str, str], str] = {
    (
        ".github/scripts/assert-publish-surfaces.py",
        "uses: docker/build-push-action@0000000000000000000000000000000000000000 # v6",
    ): (
        "a planted line inside that gate's own self-test fixture string, written to a "
        "temporary directory and parsed; it is never a workflow step"
    ),
}

Hit = Tuple[str, int, str, str]


def _is_comment(stripped: str) -> bool:
    return stripped.startswith(("#", "//"))


def in_scope(path: str) -> bool:
    return path.startswith(ROOTS) and path not in SELF


def scan(
    root: Path, files: Iterable[str], exempt: Dict[Tuple[str, str], str]
) -> Tuple[List[Hit], List[str], int]:
    """Returns (hits, stale exemptions, files read)."""
    hits: List[Hit] = []
    used = set()
    read = 0
    for rel in files:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        read += 1
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or _is_comment(stripped):
                continue
            for name, pattern in SHAPES:
                if pattern.search(stripped):
                    key = (rel, stripped)
                    if key in exempt:
                        used.add(key)
                    else:
                        hits.append((rel, number, name, stripped))
                    break
    stale = [f"{rel}: {text!r}" for (rel, text) in exempt if (rel, text) not in used]
    return hits, stale, read


def tracked_files(root: Path) -> List[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return sorted(p for p in out.split("\0") if p and in_scope(p))


def check(root: Path, files: List[str], exempt: Dict[Tuple[str, str], str]) -> int:
    hits, stale, read = scan(root, files, exempt)
    problems: List[str] = []
    if read == 0:
        problems.append(
            "the census read no files; the roots or git ls-files are broken"
        )
    for required in REQUIRED:
        if required not in files:
            problems.append(
                f"{required} builds an image in CI but is not in the census; it was "
                "renamed or moved, so this check no longer covers it"
            )
    for rel, number, name, stripped in hits:
        problems.append(f"{rel}:{number}: {name}: {stripped}")
    for entry in stale:
        problems.append(f"exemption matches no line any more, remove it: {entry}")
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        print(f"FAIL: {len(problems)} problem(s); {read} file(s) read")
        return 1
    print(
        f"PASS: {read} file(s) under {', '.join(ROOTS)} read; nothing logs in to a "
        f"registry or pushes an image ({len(exempt)} exemption(s), all in use)"
    )
    return 0


PLANTED_BAD = (
    "run: docker push ghcr.io/example/ash:latest",
    "docker image push example/ash",
    'subprocess.run(["docker", "push", IMAGE])',
    "run(['docker', 'image', 'push', IMAGE])",
    'run(["docker", "login", "ghcr.io"])',
    "echo $TOKEN | docker login ghcr.io -u x --password-stdin",
    "podman push localhost/ash docker://example/ash",
    "sudo nerdctl push example/ash",
    "finch push example/ash",
    "buildah push ash docker://example/ash",
    "crane push ash.tar example/ash",
    "oras push example/ash:1 file",
    "podman login quay.io",
    "skopeo copy oci:ash docker://example/ash",
    "docker buildx build --tag example/ash --push .",
    "docker buildx build --output type=registry,name=example/ash .",
    "--output type=image,name=example/ash,push=true",
    "push: true",
    "  push: 'true'",
    "- uses: docker/login-action@0123456789abcdef0123456789abcdef01234567 # v3",
    "- uses: docker/build-push-action@0123456789abcdef0123456789abcdef01234567 # v6",
    "- uses: aws-actions/amazon-ecr-login@0123456789abcdef0123456789abcdef01234567 # v2",
    "- uses: redhat-actions/push-to-registry@0123456789abcdef0123456789abcdef01234567 # v2",
)

PLANTED_GOOD = (
    "# docker push is forbidden here",
    "// docker push is forbidden here",
    "docker build --tag ash-e2e:local .",
    "docker rmi ash-e2e:local",
    "docker image inspect ash-e2e:local",
    "kind load docker-image ash-e2e:local",
    "docker pull public.ecr.aws/docker/library/python@sha256:" + "0" * 64,
    "git push origin HEAD",
    "push:",
    "  branches: [main]",
    "pushd /tmp",
)


def self_test() -> int:
    failures: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bad_files = []
        for index, line in enumerate(PLANTED_BAD):
            rel = f"bad/{index}.txt"
            (root / "bad").mkdir(exist_ok=True)
            (root / rel).write_text(f"{line}\n", encoding="utf-8")
            bad_files.append(rel)
        hits, _, _ = scan(root, bad_files, {})
        reported = {rel for rel, _, _, _ in hits}
        for rel, line in zip(bad_files, PLANTED_BAD):
            if rel not in reported:
                failures.append(f"planted publish shape not reported: {line!r}")

        (root / "good.txt").write_text("\n".join(PLANTED_GOOD) + "\n", encoding="utf-8")
        hits, _, _ = scan(root, ["good.txt"], {})
        for _, _, name, stripped in hits:
            failures.append(f"accepted form reported as {name}: {stripped!r}")

        (root / "exempt.txt").write_text("push: true\n", encoding="utf-8")
        exempt = {("exempt.txt", "push: true"): "planted"}
        hits, stale, _ = scan(root, ["exempt.txt"], exempt)
        if hits or stale:
            failures.append(f"an exemption in use was not honored: {hits} {stale}")
        stale_exempt = {("exempt.txt", "push: false"): "planted, matches nothing"}
        hits, stale, _ = scan(root, ["exempt.txt"], stale_exempt)
        if not stale:
            failures.append("a stale exemption was not reported")
        if not hits:
            failures.append("a line whose exemption no longer matches was not reported")

        # Its ::error:: lines are the expected outcome here, not this run's verdict.
        with contextlib.redirect_stdout(io.StringIO()):
            empty_rc = check(root, [], {})
        if empty_rc == 0:
            failures.append("an empty census passed")

    for failure in failures:
        print(f"SELF-TEST FAIL: {failure}")
    if failures:
        return 1
    print(
        f"SELF-TEST PASS: {len(PLANTED_BAD)} planted shapes reported, "
        f"{len(PLANTED_GOOD)} accepted forms silent, stale exemption and empty census rejected"
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return check(args.root, tracked_files(args.root), EXEMPT)


if __name__ == "__main__":
    sys.exit(main())
