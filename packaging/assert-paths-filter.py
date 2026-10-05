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
  - the readme, the build hook and every source the hatch build config names
    (include, only-include, packages, artifacts, and the source keys of
    force-include, shared-data, shared-scripts and extra-metadata, at the global and
    the wheel-target level) come from pyproject.toml;
  - the paths the hook reaches come from hatch_build.py's own uses of ASH_REPO_ROOT,
    spelled `.joinpath(...)` or `/`, and from relative `Path("...")` and
    `open("...")` literals.

It fails closed rather than skipping what it cannot read: a use of ASH_REPO_ROOT
whose path is not a constant prefix, a second root from __file__, a build option or
build hook it does not know, and a wheel with no dist-info/licenses/ are errors. A
path that is a directory, or ends in a non-constant part, must be matched by an
entry that covers every file below it. GitHub's `!` negations and `paths-ignore`
are refused, because this check models neither.

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
import tempfile
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
    quoted `- "pattern"` per line at six. A `paths-ignore:` list is returned under
    the key `paths-ignore:<event>` so that check() can refuse it.
    """
    filters: dict[str, list[str]] = {}
    in_on = False
    event = None
    key = None
    for line in workflow_text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_on = line.rstrip() == "on:"
            event = None
            key = None
            continue
        if not in_on:
            continue
        match = re.match(r"^  ([a-z_]+):", line)
        if match:
            event = match.group(1)
            key = None
            continue
        match = re.match(r"^    (paths|paths-ignore):(.*)$", line)
        if match:
            key = (
                event or ""
                if match.group(1) == "paths"
                else f"paths-ignore:{event or ''}"
            )
            filters.setdefault(key, [])
            if match.group(2).strip():
                # A flow-style list (`paths: ["a"]`) is a shape this parser does
                # not read; refusing it is safer than reading it as empty.
                raise ValueError(f"unreadable {match.group(1)} under {event}: {line!r}")
            continue
        if re.match(r"^    \S", line):
            key = None
            continue
        if key is not None:
            item = re.match(r"""^      - ["']?([^"']+)["']?\s*$""", line)
            if item is None:
                raise ValueError(f"unreadable paths entry under {event}: {line!r}")
            filters[key].append(item.group(1))
    return filters


# Stands for "any file below this directory". glob_to_regex's `*` and `?` match it,
# so only an entry that covers every file at any depth under the directory (a `**`)
# matches a probe such as `docs/<any>/<any>`.
ANY = "<any>"


class Unresolvable(ValueError):
    """The hook or the build config names a wheel input this script cannot read."""


def _string_parts(nodes: list[ast.expr]) -> tuple[list[str], bool]:
    """Leading constant strings of a joinpath argument list, and whether a
    non-constant argument followed them."""
    parts: list[str] = []
    for node in nodes:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            parts.append(node.value)
        else:
            return parts, True
    return parts, False


def hook_root_files(hook_source: str) -> set[str]:
    """Repository paths the hook reaches through ASH_REPO_ROOT.

    Every occurrence of the name ASH_REPO_ROOT must be one of:
      - its own definition (`ASH_REPO_ROOT = ...`);
      - the start of a chain of `.joinpath(...)` calls and `/` operators. The
        constant leading parts name the path. A chain that ends in a non-constant
        part, or whose result is a directory of the repository, stands for every
        file below it;
      - the `cwd=` of a call, directly or through `.as_posix()`. That names the
        directory a command runs in, not a file the wheel is built from.
    Anything else (an alias such as `ROOT = ASH_REPO_ROOT`, a non-constant first
    part, the name passed to a function) raises Unresolvable rather than being
    skipped, because a skipped use is an input this check does not see. A second
    root spelled `Path(__file__)` is refused the same way.

    Returned paths that stand for a directory end in `/<any>/<any>`; the caller
    turns a resolved path into a directory probe when the repository has a
    directory there (see wheel_inputs).
    """
    tree = ast.parse(hook_source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "__file__":
            if not _defines_repo_root(node, parents):
                raise Unresolvable(
                    f"line {node.lineno}: __file__ is used outside the ASH_REPO_ROOT "
                    "definition, so the hook may reach the repository by a second root"
                )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("Path", "open")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            # A relative literal is read from the build's working directory, which
            # is the repository root.
            names.add(node.args[0].value.strip("/"))
        if not (isinstance(node, ast.Name) and node.id == "ASH_REPO_ROOT"):
            continue
        if isinstance(node.ctx, ast.Store):
            continue
        parts: list[str] = []
        dynamic = False
        current: ast.AST = node
        while not dynamic:
            parent = parents.get(current)
            grand = parents.get(parent) if parent is not None else None
            if (
                isinstance(parent, ast.Attribute)
                and parent.attr == "joinpath"
                and isinstance(grand, ast.Call)
                and grand.func is parent
            ):
                more, dynamic = _string_parts(list(grand.args))
                dynamic = dynamic or bool(grand.keywords)
                parts += more
                current = grand
            elif (
                isinstance(parent, ast.BinOp)
                and isinstance(parent.op, ast.Div)
                and parent.left is current
            ):
                more, dynamic = _string_parts([parent.right])
                parts += more
                current = parent
            else:
                break
        if not parts:
            if not dynamic and _is_cwd(node, parents):
                continue
            raise Unresolvable(
                f"line {node.lineno}: a use of ASH_REPO_ROOT whose path cannot be read "
                f"({ast.unparse(parents.get(node, node))!r}); spell it "
                'ASH_REPO_ROOT.joinpath("<name>") or ASH_REPO_ROOT / "<name>"'
            )
        path = "/".join(parts)
        names.add(f"{path}/{ANY}/{ANY}" if dynamic else path)
    return names


def _defines_repo_root(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Whether node sits in the right-hand side of `ASH_REPO_ROOT = ...`."""
    statement = parents.get(node)
    while statement is not None and not isinstance(statement, ast.stmt):
        statement = parents.get(statement)
    if isinstance(statement, ast.AnnAssign):
        targets = [statement.target]
    elif isinstance(statement, ast.Assign):
        targets = statement.targets
    else:
        return False
    return all(isinstance(t, ast.Name) and t.id == "ASH_REPO_ROOT" for t in targets)


def _is_cwd(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """ASH_REPO_ROOT, or ASH_REPO_ROOT.as_posix(), as the value of `cwd=`."""
    value: ast.AST = node
    parent = parents.get(node)
    if isinstance(parent, ast.Attribute) and parent.attr == "as_posix":
        call = parents.get(parent)
        if isinstance(call, ast.Call) and call.func is parent and not call.args:
            value = call
    keyword = parents.get(value)
    return isinstance(keyword, ast.keyword) and keyword.arg == "cwd"


# The hatch wheel-target options that add files to the wheel, and how each names
# its sources: a list of paths or patterns, or a table whose KEYS are the sources.
INPUT_LISTS = ("include", "only-include", "artifacts", "packages")
INPUT_TABLES = ("force-include", "shared-data", "shared-scripts", "extra-metadata")
# Options that select among, rename or describe files the options above already
# name, so they add no input of their own.
NON_INPUT_OPTIONS = frozenset(
    {
        "exclude",
        "sources",
        "only-packages",
        "skip-excluded-dirs",
        "ignore-vcs",
        "reproducible",
        "directory",
        "dev-mode-dirs",
        "dev-mode-exact",
        "core-metadata-version",
        "strict-naming",
        "macos-max-compat",
        "bypass-selection",
        "require-runtime-dependencies",
        "require-runtime-features",
        "dependencies",
        "versions",
        "hooks",
        "targets",
        "infer-tag",
    }
)


def build_config_inputs(repo: str, build: dict, where: str) -> set[str]:
    """Source paths a hatch build table names, at any of its levels."""
    found: set[str] = set()
    for option, value in build.items():
        if option in NON_INPUT_OPTIONS:
            continue
        if option in INPUT_LISTS:
            if not isinstance(value, list):
                raise Unresolvable(f"{where}.{option} is not a list")
            sources = value
        elif option in INPUT_TABLES:
            if not isinstance(value, dict):
                raise Unresolvable(f"{where}.{option} is not a table")
            sources = list(value)
        else:
            raise Unresolvable(
                f"{where}.{option} is a build option this check does not know, so it "
                "cannot tell whether it adds files to the wheel"
            )
        for source in sources:
            if not isinstance(source, str) or source.startswith("!"):
                raise Unresolvable(f"{where}.{option} entry {source!r} cannot be read")
            path = source.strip("/")
            if os.path.isabs(source) or path.split("/")[0] == "..":
                raise Unresolvable(
                    f"{where}.{option} entry {source!r} is outside the repository"
                )
            found.add(path)
    return found


def as_probe(repo: str, path: str) -> str:
    """A path that names a repository directory stands for every file below it."""
    if not path.endswith(ANY) and os.path.isdir(os.path.join(repo, path)):
        return f"{path}/{ANY}/{ANY}"
    return path


def wheel_inputs(repo: str, wheel: str) -> set[str]:
    """The repository files the wheel is built from."""
    with open(os.path.join(repo, "pyproject.toml"), "rb") as handle:
        pyproject = tomllib.load(handle)
    inputs = {"pyproject.toml"}
    project = pyproject["project"]
    readme = project.get("readme")
    if isinstance(readme, dict):
        readme = readme.get("file")
    if readme:
        inputs.add(readme)
    license_ = project.get("license")
    if isinstance(license_, dict) and license_.get("file"):
        inputs.add(license_["file"])

    build = pyproject.get("tool", {}).get("hatch", {}).get("build", {})
    wheel_target = build.get("targets", {}).get("wheel", {})
    inputs |= build_config_inputs(repo, build, "tool.hatch.build")
    inputs |= build_config_inputs(repo, wheel_target, "tool.hatch.build.targets.wheel")
    hooks = dict(build.get("hooks", {}))
    hooks.update(wheel_target.get("hooks", {}))
    for name in hooks:
        if name != "custom":
            raise Unresolvable(
                f"build hook {name!r} is not the custom hook; this check cannot read "
                "which files it adds to the wheel"
            )
    if hooks:
        hook = hooks["custom"].get("path", "hatch_build.py")
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
        raise Unresolvable(
            f"{wheel} has no dist-info/licenses/ member, so the license files cannot "
            "be measured. Refusing to report the filter complete without them."
        )
    inputs |= set(licenses)
    # The package tree itself is an input too, and is listed as a directory glob.
    inputs.add("automated_security_helper/__init__.py")
    return {as_probe(repo, path) for path in inputs}


def check(filters: dict[str, list[str]], inputs: set[str]) -> list[str]:
    problems: list[str] = []
    for event in ("push", "pull_request"):
        if event not in filters:
            problems.append(f"the workflow has no `paths:` filter under {event}")
    for key, entries in sorted(filters.items()):
        if key.startswith("paths-ignore:"):
            problems.append(
                f"the workflow has a paths-ignore list under {key.split(':', 1)[1]}; "
                "this check reads only `paths`, so an ignored input would go unseen"
            )
            continue
        for entry in entries:
            if entry.startswith("!"):
                problems.append(
                    f"{key} paths entry {entry!r} is a negation, which removes files "
                    "the entries before it matched; this check does not model that"
                )
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


FIXTURE_HOOK = """\
from pathlib import Path
ASH_REPO_ROOT: Path = Path(__file__).parent
ASH_ASSETS_PATH: Path = ASH_REPO_ROOT.joinpath("automated_security_helper", "assets")
def stage(rel, run):
    dockerfile = ASH_REPO_ROOT.joinpath("Dockerfile")
    source = ASH_REPO_ROOT.joinpath("automated_security_helper", *rel.split("/"))
    run(["git", "rev-parse"], cwd=ASH_REPO_ROOT.as_posix())
"""

FIXTURE_PYPROJECT = """\
[project]
name = "automated-security-helper"
readme = "README.md"

[tool.hatch.build.targets.wheel]
include = ["automated_security_helper"]

[tool.hatch.build.targets.wheel.force-include]
"automated_security_helper/assets/Dockerfile" = "automated_security_helper/assets/Dockerfile"

[tool.hatch.build.targets.wheel.hooks.custom]
path = "hatch_build.py"
"""

FIXTURE_FILTER = [
    "automated_security_helper/**",
    "pyproject.toml",
    "hatch_build.py",
    "Dockerfile",
    "README.md",
    "LICENSE",
    "NOTICE",
]


def fixture_workflow(entries: list[str], extra: str = "") -> str:
    listed = "".join(f'      - "{entry}"\n' for entry in entries)
    return (
        f"on:\n  push:\n    branches: ['**']\n    paths:\n{listed}{extra}"
        f"  pull_request:\n    paths:\n{listed}{extra}  workflow_dispatch: {{}}\n"
    )


def run_fixture(
    root: str,
    hook: str = FIXTURE_HOOK,
    pyproject: str = FIXTURE_PYPROJECT,
    workflow: str | None = None,
    licenses: tuple[str, ...] = ("LICENSE", "NOTICE"),
) -> str:
    """Builds a fixture repository and wheel under root; returns "ok", "problems"
    or "error" (Unresolvable)."""
    os.makedirs(os.path.join(root, "automated_security_helper", "assets"))
    files = {"pyproject.toml": pyproject, "hatch_build.py": hook}
    for name, text in files.items():
        with open(os.path.join(root, name), "w", encoding="utf-8") as handle:
            handle.write(text)
    wheel = os.path.join(root, "fixture-1.0-py3-none-any.whl")
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("automated_security_helper/__init__.py", "")
        for name in licenses:
            archive.writestr(f"fixture-1.0.dist-info/licenses/{name}", "text")
    try:
        inputs = wheel_inputs(root, wheel)
    except Unresolvable:
        return "error"
    text = workflow if workflow is not None else fixture_workflow(FIXTURE_FILTER)
    return "problems" if check(read_paths_filters(text), inputs) else "ok"


def without(entry: str) -> list[str]:
    return [e for e in FIXTURE_FILTER if e != entry]


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

    slash_hook = FIXTURE_HOOK.replace(
        'ASH_REPO_ROOT.joinpath("Dockerfile")', 'ASH_REPO_ROOT / "Dockerfile"'
    )
    wheel_cases: list[tuple[str, dict, str]] = [
        ("wheel inputs: the fixture's filter covers them", {}, "ok"),
        (
            "wheel inputs: the hook's Dockerfile is not listed",
            {"workflow": fixture_workflow(without("Dockerfile"))},
            "problems",
        ),
        (
            "wheel inputs: `ASH_REPO_ROOT / name` is read, and is listed",
            {"hook": slash_hook},
            "ok",
        ),
        (
            "wheel inputs: `ASH_REPO_ROOT / name` is read, and is not listed",
            {"hook": slash_hook, "workflow": fixture_workflow(without("Dockerfile"))},
            "problems",
        ),
        (
            "wheel inputs: a root file in wheel force-include",
            {
                "pyproject": FIXTURE_PYPROJECT.replace(
                    "[tool.hatch.build.targets.wheel.hooks",
                    '"CONTRIBUTING.md" = "automated_security_helper/assets/C.md"\n\n'
                    "[tool.hatch.build.targets.wheel.hooks",
                )
            },
            "problems",
        ),
        (
            "wheel inputs: a root directory in wheel shared-data",
            {
                "pyproject": FIXTURE_PYPROJECT
                + '\n[tool.hatch.build.targets.wheel.shared-data]\n"share" = "share"\n'
            },
            "problems",
        ),
        (
            "wheel inputs: a root file in the global only-include",
            {
                "pyproject": FIXTURE_PYPROJECT
                + '\n[tool.hatch.build]\nonly-include = ["automated_security_helper", "SECURITY.md"]\n'
            },
            "problems",
        ),
        (
            "wheel inputs: a root file in wheel artifacts",
            {
                "pyproject": FIXTURE_PYPROJECT.replace(
                    'include = ["automated_security_helper"]',
                    'include = ["automated_security_helper"]\nartifacts = ["VERSION"]',
                )
            },
            "problems",
        ),
        (
            "wheel inputs: a license file in the wheel is not listed",
            {"workflow": fixture_workflow(without("NOTICE"))},
            "problems",
        ),
        (
            "wheel inputs: a wheel with no dist-info/licenses/",
            {"licenses": ()},
            "error",
        ),
        (
            "wheel inputs: a `!` negation entry",
            {"workflow": fixture_workflow([*FIXTURE_FILTER, "!README.md"])},
            "problems",
        ),
        (
            "wheel inputs: a paths-ignore list",
            {
                "workflow": fixture_workflow(
                    FIXTURE_FILTER, '    paths-ignore:\n      - "docs/**"\n'
                )
            },
            "problems",
        ),
        (
            "wheel inputs: a dynamic path under a directory needs `**`",
            {
                "workflow": fixture_workflow(
                    [
                        "automated_security_helper/*",
                        "automated_security_helper/assets/**",
                        *without("automated_security_helper/**"),
                    ]
                )
            },
            "problems",
        ),
        (
            "wheel inputs: a variable joined below a directory needs `**`",
            {
                "hook": FIXTURE_HOOK
                + 'page = ASH_REPO_ROOT.joinpath("templates", name)\n',
                "workflow": fixture_workflow([*FIXTURE_FILTER, "templates"]),
            },
            "problems",
        ),
        (
            "wheel inputs: ASH_REPO_ROOT through an alias",
            {"hook": FIXTURE_HOOK + "ROOT = ASH_REPO_ROOT\n"},
            "error",
        ),
        (
            "wheel inputs: ASH_REPO_ROOT joined with a variable first",
            {"hook": FIXTURE_HOOK + "x = ASH_REPO_ROOT.joinpath(name)\n"},
            "error",
        ),
        (
            "wheel inputs: a second root from __file__",
            {"hook": FIXTURE_HOOK + "OTHER = Path(__file__).parent\n"},
            "error",
        ),
        (
            "wheel inputs: a relative Path literal",
            {
                "hook": FIXTURE_HOOK + 'notes = Path("CHANGELOG.md").read_text()\n',
            },
            "problems",
        ),
        (
            "wheel inputs: a build option this check does not know",
            {
                "pyproject": FIXTURE_PYPROJECT.replace(
                    'include = ["automated_security_helper"]',
                    'include = ["automated_security_helper"]\nnew-option = ["x"]',
                )
            },
            "error",
        ),
        (
            "wheel inputs: a build hook other than the custom one",
            {
                "pyproject": FIXTURE_PYPROJECT
                + "\n[tool.hatch.build.targets.wheel.hooks.vcs]\n"
                + 'version-file = "v.py"\n'
            },
            "error",
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="paths-filter-") as scratch:
        for index, (label, overrides, expected) in enumerate(wheel_cases):
            root = os.path.join(scratch, str(index))
            got = run_fixture(root, **overrides)
            if got != expected:
                failures += 1
                print(f"  FAILED {label}: expected {expected}, got {got}")
            else:
                print(f"  ok {label} ({got})")
    total = len(cases) + len(wheel_cases)
    print("self-test " + ("FAILED" if failures else f"OK ({total} cases)"))
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
    try:
        with open(os.path.join(args.repo, args.workflow), encoding="utf-8") as handle:
            filters = read_paths_filters(handle.read())
        inputs = wheel_inputs(args.repo, args.wheel)
    except ValueError as error:  # Unresolvable is a ValueError
        print(f"paths filter check FAILED for {args.workflow}: {error}")
        return 1
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
