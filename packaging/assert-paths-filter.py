#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks that ash-native-packages.yml runs when any input to the wheel changes.

Every deb and rpm leg packages a wheel it builds from the checkout, so a change to
any file that wheel is built from changes the packages. The workflow's `paths`
filters decide whether those legs run at all, and a file missing from them is a
change that reaches the packages untested: the filter missed the root Dockerfile
(the hook copies it into the wheel as assets/Dockerfile), README.md (the wheel's
METADATA) and NOTICE (a license file hatchling adds to dist-info), and nothing
said so.

The inputs are measured rather than listed here, because a second hand-written
list is the same defect as the first:

  - the license files are read off the built wheel's dist-info/licenses/, which is
    what hatchling actually included, not what its default globs are believed to be;
  - the readme and the build hook come from pyproject.toml;
  - the files the hook reads from the repository root come from hatch_build.py's
    own `ASH_REPO_ROOT.joinpath("<name>")` calls.

It also requires the push and pull_request lists to be identical, which the
workflow's comment asks for and nothing checked.

Usage: assert-paths-filter.py --wheel <built wheel> [--workflow PATH] [--repo DIR]
       assert-paths-filter.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
import tomllib
import zipfile

DEFAULT_WORKFLOW = ".github/workflows/ash-native-packages.yml"


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """GitHub's paths-filter glob: `**` crosses `/`, `*` and `?` do not."""
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(rf"^{out}$")


def read_paths_filters(workflow_text: str) -> dict[str, list[str]]:
    """Returns {event: [paths]} for the events under `on:` that carry `paths:`.

    Parsed by indentation rather than with a YAML library, so this has no
    dependency beyond the standard library. It reads only the shape the workflow
    uses: `on:` at column 0, events at two spaces, `paths:` at four, and one
    quoted `- "pattern"` per line at six.
    """
    filters: dict[str, list[str]] = {}
    in_on = False
    event = None
    in_paths = False
    for line in workflow_text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_on = line.rstrip() == "on:"
            event = None
            in_paths = False
            continue
        if not in_on:
            continue
        match = re.match(r"^  ([a-z_]+):", line)
        if match:
            event = match.group(1)
            in_paths = False
            continue
        if re.match(r"^    paths:\s*$", line):
            in_paths = True
            filters.setdefault(event or "", [])
            continue
        if re.match(r"^    \S", line):
            in_paths = False
            continue
        if in_paths:
            item = re.match(r"""^      - ["']?([^"']+)["']?\s*$""", line)
            if item is None:
                raise ValueError(f"unreadable paths entry under {event}: {line!r}")
            filters[event or ""].append(item.group(1))
    return filters


def hook_root_files(hook_source: str) -> set[str]:
    """Names the hook reads straight from the repository root."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(hook_source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "joinpath"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "ASH_REPO_ROOT"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.add(node.args[0].value)
    return names


def wheel_inputs(repo: str, wheel: str) -> set[str]:
    """The repository files the wheel is built from that sit outside the package."""
    with open(os.path.join(repo, "pyproject.toml"), "rb") as handle:
        pyproject = tomllib.load(handle)
    inputs = {"pyproject.toml"}
    readme = pyproject["project"].get("readme")
    if isinstance(readme, dict):
        readme = readme.get("file")
    if readme:
        inputs.add(readme)
    hook = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["hooks"]["custom"][
        "path"
    ]
    inputs.add(hook)
    with open(os.path.join(repo, hook), encoding="utf-8") as handle:
        inputs |= hook_root_files(handle.read())

    with zipfile.ZipFile(wheel) as archive:
        licenses = [
            n.split("/licenses/", 1)[1]
            for n in archive.namelist()
            if re.match(r"^[^/]+\.dist-info/licenses/.+", n)
        ]
    if not licenses:
        raise ValueError(
            f"{wheel} has no dist-info/licenses/ member, so the license files cannot "
            "be measured. Refusing to report the filter complete without them."
        )
    inputs |= set(licenses)
    # The package tree itself is an input too, and is listed as a directory glob.
    inputs.add("automated_security_helper/__init__.py")
    return inputs


def check(filters: dict[str, list[str]], inputs: set[str]) -> list[str]:
    problems: list[str] = []
    for event in ("push", "pull_request"):
        if event not in filters:
            problems.append(f"the workflow has no `paths:` filter under {event}")
    push = filters.get("push", [])
    pull = filters.get("pull_request", [])
    if push != pull:
        problems.append(
            "the push and pull_request paths lists differ: only in push "
            f"{sorted(set(push) - set(pull))}, only in pull_request "
            f"{sorted(set(pull) - set(push))}, or the same entries in another order"
        )
    for event in ("push", "pull_request"):
        patterns = [glob_to_regex(p) for p in filters.get(event, [])]
        for name in sorted(inputs):
            if not any(p.match(name) for p in patterns):
                problems.append(
                    f"{name} is an input to the wheel the packages are built from, "
                    f"but no {event} paths entry matches it, so a change to it skips "
                    "every deb and rpm leg"
                )
    return problems


def self_test() -> int:
    good = (
        "on:\n  push:\n    branches: ['**']\n    paths:\n      - \"a/**\"\n"
        '      - "README.md"\n  pull_request:\n    paths:\n      - "a/**"\n'
        '      - "README.md"\n  workflow_dispatch: {}\n'
    )
    cases = [
        ("both lists cover every input", good, {"a/b/c.py", "README.md"}, False),
        ("an input no entry matches", good, {"a/x.py", "Dockerfile"}, True),
        (
            "the two lists differ",
            good.replace('      - "README.md"\n  workflow', "  workflow", 1),
            {"a/x.py"},
            True,
        ),
        (
            "`*` does not cross a directory",
            good.replace("a/**", "a/*"),
            {"a/b/c"},
            True,
        ),
    ]
    failures = 0
    for label, text, inputs, should_fail in cases:
        problems = check(read_paths_filters(text), inputs)
        if bool(problems) != should_fail:
            failures += 1
            print(f"  FAILED {label}: problems={problems}")
        else:
            print(f"  ok {label}{' (rejected)' if should_fail else ''}")
    print("self-test " + ("FAILED" if failures else f"OK ({len(cases)} cases)"))
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--wheel")
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv[1:])
    if args.self_test:
        return self_test()
    if not args.wheel:
        parser.error("--wheel is required")
    with open(os.path.join(args.repo, args.workflow), encoding="utf-8") as handle:
        filters = read_paths_filters(handle.read())
    inputs = wheel_inputs(args.repo, args.wheel)
    problems = check(filters, inputs)
    if problems:
        print(f"paths filter check FAILED for {args.workflow}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"paths filter OK: push and pull_request list the same {len(filters['push'])} "
        f"entries, and they match all {len(inputs)} wheel inputs "
        f"({', '.join(sorted(inputs))})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
