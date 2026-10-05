#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks that ash-native-packages.yml runs when any input to the wheel changes.

Every deb and rpm leg packages a wheel it builds from the checkout, so a change to
any file that wheel is built from changes the packages. The workflow's `paths`
filters decide whether those legs run at all, and a file missing from them is a
change that reaches the packages untested: the filter missed the root Dockerfile
(the hook copies it into the wheel as assets/Dockerfile), README.md (the wheel's
METADATA), NOTICE (a license file hatchling adds to dist-info) and .gitignore
(hatchling leaves out every file it ignores), and nothing said so.

The inputs are measured rather than listed here, because a second hand-written
list is the same defect as the first. There are two layers, and a real run takes
the union of both.

The measured layer builds the wheel in this process with hatchling's own PEP 517
entry point, the one `uv build` calls, under sys.addaudithook. Every file the build
opens for reading inside the repository is an input, however the hook spelled the
path. Every process the build starts must be one this script can attribute (only
the hook's `git rev-parse --abbrev-ref HEAD`, which reads .git and nothing a paths
entry can name); any other subprocess, os.system, exec, spawn or fork is an error,
because what a child process reads cannot be seen from here. The installed build
backend must satisfy pyproject's [build-system] requires, so the build measured is
the build `uv build` runs.

The static layer reads what the measured build cannot show, because the build only
opens the files this one run reaches: a file the hook only tests for (`.exists()`),
or reads on a branch this build did not take. It reads:

  - the license files off the built wheel's dist-info/licenses/;
  - the readme, the build hook, the package's __init__.py, .gitignore, and every
    source the hatch build config names (include, only-include, packages,
    artifacts, and the source keys of force-include, shared-data, shared-scripts
    and extra-metadata, at the global and the wheel-target level) from
    pyproject.toml;
  - the paths the hook reaches through ASH_REPO_ROOT, spelled `.joinpath(...)` or
    `/`, and relative `Path("...")` and `open("...")` literals, from hatch_build.py.

The static layer fails closed rather than skipping what it cannot read: a use of
ASH_REPO_ROOT whose path is not a constant prefix, a second root from __file__, a
`..` in any path, a build option or build hook it does not know (ignore-vcs
included), a .hgignore, and a wheel with no dist-info/licenses/ are errors. A path
that is a directory, or ends in a non-constant part, must be matched by an entry
that covers every file below it. GitHub's `!` negations and `paths-ignore` are
refused, because this check models neither.

It also requires the push and pull_request lists to be identical, which the
workflow's comment asks for and nothing checked.

The self-test runs each layer on its own against fixture repositories it builds
with hatchling, so a deleted measurement in either layer turns it red.

Usage: assert-paths-filter.py [--repo DIR] [--workflow PATH]
       assert-paths-filter.py --self-test
Both need hatchling importable, e.g. `uv run --no-project --with hatchling`.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import importlib.metadata
import os
import re
import sys
import tempfile
import tomllib
import zipfile
from typing import Any

DEFAULT_WORKFLOW = ".github/workflows/ash-native-packages.yml"
PACKAGE_DIR = "automated_security_helper"
LAYERS = ("static", "measured")


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


def repo_relative(path: str, where: str) -> str:
    """A repository-relative path, normalized; refuses absolute paths and `..`.

    A `..` anywhere is refused rather than resolved: `pkg/../CHANGELOG.md` names
    CHANGELOG.md, and reading only the first component missed it.
    """
    if os.path.isabs(path) or "\\" in path:
        raise Unresolvable(f"{where}: {path!r} is not a relative POSIX path")
    if ".." in path.split("/"):
        raise Unresolvable(f"{where}: {path!r} contains `..`")
    normalized = os.path.normpath(path.strip("/")).replace(os.sep, "/")
    return "" if normalized == "." else normalized


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
    root spelled `Path(__file__)` is refused the same way. Spellings this does not
    model at all, such as `Path(self.root)`, are left to the measured layer.

    Returned paths that stand for a directory end in `/<any>/<any>`; the caller
    turns a resolved path into a directory probe when the repository has a
    directory there (see static_inputs).
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
            names.add(
                repo_relative(node.args[0].value, f"hatch_build.py line {node.lineno}")
            )
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
        path = repo_relative("/".join(parts), f"hatch_build.py line {node.lineno}")
        names.add(f"{path}/{ANY}/{ANY}" if dynamic else path)
    return names


def _defines_repo_root(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Whether node sits in the right-hand side of `ASH_REPO_ROOT = ...`."""
    statement = parents.get(node)
    while statement is not None and not isinstance(statement, ast.stmt):
        statement = parents.get(statement)
    targets: list[ast.expr]
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
# name, so they add no input of their own. ignore-vcs is deliberately absent: it
# changes which VCS ignore files are inputs, so it is refused as unknown.
NON_INPUT_OPTIONS = frozenset(
    {
        "exclude",
        "sources",
        "only-packages",
        "skip-excluded-dirs",
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


def build_config_inputs(repo: str, build: dict[str, Any], where: str) -> set[str]:
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
            found.add(repo_relative(source, f"{where}.{option}"))
    return found


def as_probe(repo: str, path: str) -> str:
    """A path that names a repository directory stands for every file below it."""
    if not path.endswith(ANY) and os.path.isdir(os.path.join(repo, path)):
        return f"{path}/{ANY}/{ANY}"
    return path


def read_pyproject(repo: str) -> dict[str, Any]:
    with open(os.path.join(repo, "pyproject.toml"), "rb") as handle:
        return tomllib.load(handle)


def static_config_inputs(repo: str) -> set[str]:
    """The inputs pyproject.toml and the hook's source name. Runs before the build,
    so a config this cannot read is refused without building anything."""
    pyproject = read_pyproject(repo)
    inputs = {"pyproject.toml"}
    project = pyproject["project"]
    readme = project.get("readme")
    if isinstance(readme, dict):
        readme = readme.get("file")
    if readme:
        inputs.add(repo_relative(readme, "project.readme"))
    license_ = project.get("license")
    if isinstance(license_, dict) and license_.get("file"):
        inputs.add(repo_relative(license_["file"], "project.license"))

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
        hook = repo_relative(
            hooks["custom"].get("path", "hatch_build.py"), "hooks.custom.path"
        )
        inputs.add(hook)
        with open(os.path.join(repo, hook), encoding="utf-8") as handle:
            inputs |= hook_root_files(handle.read())

    # hatchling leaves out every file the root .gitignore ignores (with ignore-vcs
    # unset, which build_config_inputs enforces), so one line there can drop source
    # from the wheel. It reads .hgignore the same way; that is not modeled.
    if os.path.exists(os.path.join(repo, ".hgignore")):
        raise Unresolvable(
            ".hgignore exists; hatchling reads it as a second ignore file, and this "
            "check does not model it"
        )
    if os.path.exists(os.path.join(repo, ".gitignore")):
        inputs.add(".gitignore")
    # The package tree itself is an input too, and is listed as a directory glob.
    inputs.add(f"{PACKAGE_DIR}/__init__.py")
    return inputs


def wheel_license_inputs(wheel: str) -> set[str]:
    """The license files hatchling actually put in the wheel's dist-info."""
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
    return set(licenses)


# The audit events that start another process. What a child reads is invisible to
# this process's audit hook, so each one must be attributed or the check fails.
SPAWN_EVENTS = frozenset(
    {
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "os.startfile",
    }
)

# Commands the build may run, keyed by (program name, *arguments). Each must read
# nothing a paths entry could name.
ATTRIBUTED_COMMANDS = {
    ("git", "rev-parse", "--abbrev-ref", "HEAD"): (
        "hatch_build.py records the branch name in ASH_INSTALLED_REVISION; git "
        "reads only .git, which is not a file in the tree"
    ),
}

# Set to a list while a measured build runs; the audit hook appends to it.
_recording: list[tuple[Any, ...]] | None = None
_hook_installed = False


def _audit(event: str, args: tuple[Any, ...]) -> None:
    events = _recording
    if events is None:
        return
    if event == "open":
        # Resolved later: an audit hook should do as little as it can.
        events.append(("open", args[0], args[1], args[2], os.getcwd()))
    elif event in SPAWN_EVENTS:
        events.append((event, args))


def check_build_backend(pyproject: dict[str, Any]) -> None:
    """The backend this process will run must be the one `uv build` would run."""
    build_system = pyproject.get("build-system")
    if not isinstance(build_system, dict):
        raise Unresolvable("pyproject.toml has no [build-system]")
    if build_system.get("build-backend") != "hatchling.build":
        raise Unresolvable(
            f"build-backend is {build_system.get('build-backend')!r}; this check "
            "measures only hatchling.build"
        )
    try:
        from packaging.requirements import Requirement
    except ImportError as error:  # hatchling depends on packaging
        raise Unresolvable(f"cannot read [build-system] requires: {error}") from error
    for spec in build_system.get("requires", []):
        requirement = Requirement(spec)
        try:
            installed = importlib.metadata.version(requirement.name)
        except importlib.metadata.PackageNotFoundError as error:
            raise Unresolvable(
                f"build requirement {spec!r} is not installed, so the build measured "
                "here would not be the build `uv build` runs"
            ) from error
        if not requirement.specifier.contains(installed, prereleases=True):
            raise Unresolvable(
                f"build requirement {spec!r} is not met by the installed "
                f"{requirement.name} {installed}"
            )


def measured_build(repo: str, out_dir: str) -> tuple[str, list[tuple[Any, ...]]]:
    """Builds the wheel in-process under the audit hook; returns its path and the
    open and spawn events recorded while the build ran."""
    global _recording, _hook_installed
    check_build_backend(read_pyproject(repo))
    import hatchling.build

    if not _hook_installed:
        sys.addaudithook(_audit)
        _hook_installed = True
    events: list[tuple[Any, ...]] = []
    cwd = os.getcwd()
    dont_write_bytecode = sys.dont_write_bytecode
    # The frontend runs the backend from the project root, so the hook's relative
    # paths resolve there, as they do under `uv build`.
    os.chdir(repo)
    sys.dont_write_bytecode = True
    try:
        with contextlib.redirect_stdout(sys.stderr):
            _recording = events
            name = hatchling.build.build_wheel(out_dir)
    finally:
        _recording = None
        sys.dont_write_bytecode = dont_write_bytecode
        os.chdir(cwd)
    return os.path.join(out_dir, name), events


def _opened_for_reading(mode: object, flags: object) -> bool:
    if isinstance(flags, int):
        return (flags & os.O_ACCMODE) != os.O_WRONLY
    if isinstance(mode, str):
        return "r" in mode or "+" in mode
    return True


def _environment_roots() -> set[str]:
    return {os.path.realpath(p) for p in (sys.prefix, sys.exec_prefix)}


def _repo_path(repo: str, out_dir: str, raw: object, cwd: str) -> str | None:
    """The repository-relative path an open event names, or None outside it."""
    if raw is None or isinstance(raw, int):
        return None  # a descriptor; the open that produced it was recorded
    path = os.path.realpath(os.path.join(cwd, os.fsdecode(raw)))  # type: ignore[arg-type]
    # The wheel being written, and the interpreter's own environment when it lives
    # in the checkout (a .venv): neither is a file the wheel is built from.
    for skipped in (out_dir, *_environment_roots()):
        if path == skipped or path.startswith(skipped + os.sep):
            return None
    if path != repo and not path.startswith(repo + os.sep):
        return None
    rel = os.path.relpath(path, repo).replace(os.sep, "/")
    parts = rel.split("/")
    if "__pycache__" in parts:
        # A cached module is its source file: `x/__pycache__/m.cpython-313.pyc`.
        at = parts.index("__pycache__")
        rel = "/".join([*parts[:at], parts[-1].split(".", 1)[0] + ".py"])
    return rel


def measured_inputs(repo: str, out_dir: str, events: list[tuple[Any, ...]]) -> set[str]:
    """Files the build read inside the repository; refuses unattributed processes."""
    repo = os.path.realpath(repo)
    out_dir = os.path.realpath(out_dir)
    found: set[str] = set()
    unattributed: list[str] = []
    for event in events:
        if event[0] == "open":
            _, raw, mode, flags, cwd = event
            if not _opened_for_reading(mode, flags):
                continue
            rel = _repo_path(repo, out_dir, raw, cwd)
            if rel is not None:
                found.add(rel)
            continue
        name, args = event
        if name == "subprocess.Popen":
            executable, argv = args[0], args[1]
            if isinstance(argv, (str, bytes, os.PathLike)):
                argv = [argv]
            argv = [os.fsdecode(a) for a in argv]
            program = os.fsdecode(executable) if executable else argv[0]
            key = (os.path.basename(argv[0]), *argv[1:]) if argv else ()
            if key in ATTRIBUTED_COMMANDS and os.path.basename(program) == key[0]:
                continue
            unattributed.append(f"{name} {argv!r}")
        else:
            unattributed.append(f"{name} {args!r}")
    if unattributed:
        raise Unresolvable(
            "the build started a process this check cannot attribute, so what it "
            "read is not measured: " + "; ".join(unattributed)
        )
    return found


def wheel_inputs(repo: str, out_dir: str, layers: tuple[str, ...] = LAYERS) -> set[str]:
    """The repository files the wheel is built from, as the union of the layers."""
    inputs: set[str] = set()
    if "static" in layers:
        inputs |= static_config_inputs(repo)
    wheel, events = measured_build(repo, out_dir)
    if "static" in layers:
        inputs |= wheel_license_inputs(wheel)
    if "measured" in layers:
        inputs |= measured_inputs(repo, out_dir, events)
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


# A real hatchling hook. stage() is never called, so only the static layer sees
# what a case puts there (STATIC_EXTRA); initialize() runs in every build, so the
# measured layer sees what a case puts there (BUILD_EXTRA). The git call in
# initialize() is the one attributed command, so every build exercises that rule.
STATIC_EXTRA = "    # static-extra\n"
BUILD_EXTRA = "        # build-extra\n"
FIXTURE_HOOK = f"""\
import os
import shutil
import subprocess
from pathlib import Path
from hatchling.builders.hooks.plugin.interface import BuildHookInterface
ASH_REPO_ROOT: Path = Path(__file__).parent
ASH_ASSETS_PATH: Path = ASH_REPO_ROOT.joinpath("automated_security_helper", "assets")


def stage(rel, run, name):
    dockerfile = ASH_REPO_ROOT.joinpath("Dockerfile")
    source = ASH_REPO_ROOT.joinpath("automated_security_helper", *rel.split("/"))
    run(["git", "rev-parse"], cwd=ASH_REPO_ROOT.as_posix())
{STATIC_EXTRA}

class FixtureHook(BuildHookInterface):
    def initialize(self, version, build_data):
        try:
            subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=ASH_REPO_ROOT.as_posix(),
                capture_output=True,
                check=False,
            )
        except OSError:
            pass
{BUILD_EXTRA}"""

FIXTURE_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "automated-security-helper"
version = "1.0"
readme = "README.md"

[tool.hatch.build.targets.wheel]
include = ["automated_security_helper"]

[tool.hatch.build.targets.wheel.force-include]
"automated_security_helper/assets/Dockerfile" = "automated_security_helper/assets/Dockerfile"

[tool.hatch.build.targets.wheel.hooks.custom]
path = "hatch_build.py"
"""

# No hook and no include: hatchling finds the package by the project name, and
# nothing in pyproject names the package tree.
FIXTURE_PYPROJECT_BARE = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "automated-security-helper"
version = "1.0"
readme = "README.md"
"""

# Files every fixture repository has. The ones nothing in the default fixture
# names are there so a case can name them without the build failing.
FIXTURE_FILES = {
    "automated_security_helper/__init__.py": "",
    "automated_security_helper/assets/Dockerfile": "FROM scratch\n",
    "Dockerfile": "FROM scratch\n",
    "README.md": "# fixture\n",
    ".gitignore": "*.log\n",
    "CHANGELOG.md": "changes\n",
    "CONTRIBUTING.md": "contributing\n",
    "SECURITY.md": "security\n",
    "VERSION": "1.0\n",
    "share/data.txt": "data\n",
}

FIXTURE_FILTER = [
    "automated_security_helper/**",
    "pyproject.toml",
    "hatch_build.py",
    "Dockerfile",
    "README.md",
    "LICENSE",
    "NOTICE",
    ".gitignore",
]


def fixture_workflow(entries: list[str], extra: str = "") -> str:
    listed = "".join(f'      - "{entry}"\n' for entry in entries)
    return (
        f"on:\n  push:\n    branches: ['**']\n    paths:\n{listed}{extra}"
        f"  pull_request:\n    paths:\n{listed}{extra}  workflow_dispatch: {{}}\n"
    )


def run_fixture(
    root: str,
    layers: tuple[str, ...] = LAYERS,
    hook: str = FIXTURE_HOOK,
    static_extra: str = "",
    build_extra: str = "",
    pyproject: str = FIXTURE_PYPROJECT,
    workflow: str | None = None,
    licenses: tuple[str, ...] = ("LICENSE", "NOTICE"),
    files: dict[str, str] | None = None,
) -> str:
    """Builds a fixture repository under root and a wheel from it with hatchling;
    returns "ok", "problems" or "error: <the Unresolvable message>"."""
    hook = hook.replace(STATIC_EXTRA, f"    {static_extra}\n" if static_extra else "")
    hook = hook.replace(BUILD_EXTRA, f"        {build_extra}\n" if build_extra else "")
    tree = {
        **FIXTURE_FILES,
        "pyproject.toml": pyproject,
        "hatch_build.py": hook,
        **dict.fromkeys(licenses, "license text\n"),
        **(files or {}),
    }
    for name, text in tree.items():
        path = os.path.join(root, *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    out_dir = root + "-dist"
    os.makedirs(out_dir)
    try:
        inputs = wheel_inputs(root, out_dir, layers)
    except Unresolvable as error:
        return f"error: {error}"
    text = workflow if workflow is not None else fixture_workflow(FIXTURE_FILTER)
    return "problems" if check(read_paths_filters(text), inputs) else "ok"


def without(*entries: str) -> list[str]:
    return [e for e in FIXTURE_FILTER if e not in entries]


STATIC = ("static",)
MEASURED = ("measured",)


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
    copy_changelog = 'shutil.copyfile({}, ASH_ASSETS_PATH / "CL.md")'
    wheel_cases: list[tuple[str, dict[str, Any], str]] = [
        # Each layer on its own. A case names the layer whose measurement it needs,
        # so deleting that measurement turns it red even where the other layer
        # would have caught the same file in a real run.
        ("static: the fixture's filter covers the inputs", {"layers": STATIC}, "ok"),
        (
            "static: the hook's Dockerfile is not listed",
            {"layers": STATIC, "workflow": fixture_workflow(without("Dockerfile"))},
            "problems",
        ),
        (
            "static: `ASH_REPO_ROOT / name` is read, and is listed",
            {"layers": STATIC, "hook": slash_hook},
            "ok",
        ),
        (
            "static: `ASH_REPO_ROOT / name` is read, and is not listed",
            {
                "layers": STATIC,
                "hook": slash_hook,
                "workflow": fixture_workflow(without("Dockerfile")),
            },
            "problems",
        ),
        (
            "static: the readme is not listed",
            {"layers": STATIC, "workflow": fixture_workflow(without("README.md"))},
            "problems",
        ),
        (
            "static: the build hook is not listed",
            {"layers": STATIC, "workflow": fixture_workflow(without("hatch_build.py"))},
            "problems",
        ),
        (
            "static: the package tree is not listed, and nothing in pyproject names it",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT_BARE,
                "workflow": fixture_workflow(without("automated_security_helper/**")),
            },
            "problems",
        ),
        (
            "static: .gitignore is not listed",
            {"layers": STATIC, "workflow": fixture_workflow(without(".gitignore"))},
            "problems",
        ),
        (
            "static: a root file in wheel force-include",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    "[tool.hatch.build.targets.wheel.hooks",
                    '"CONTRIBUTING.md" = "automated_security_helper/assets/C.md"\n\n'
                    "[tool.hatch.build.targets.wheel.hooks",
                ),
            },
            "problems",
        ),
        (
            "static: `..` in a force-include source",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    "[tool.hatch.build.targets.wheel.hooks",
                    '"automated_security_helper/../CHANGELOG.md" = '
                    '"automated_security_helper/assets/C.md"\n\n'
                    "[tool.hatch.build.targets.wheel.hooks",
                ),
            },
            "error: contains `..`",
        ),
        (
            "static: a root directory in wheel shared-data",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT
                + '\n[tool.hatch.build.targets.wheel.shared-data]\n"share" = "share"\n',
            },
            "problems",
        ),
        (
            "static: a root file in the global only-include",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT
                + '\n[tool.hatch.build]\nonly-include = ["automated_security_helper", "SECURITY.md"]\n',
            },
            "problems",
        ),
        (
            "static: a root file in wheel artifacts",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    'include = ["automated_security_helper"]',
                    'include = ["automated_security_helper"]\nartifacts = ["VERSION"]',
                ),
            },
            "problems",
        ),
        (
            "static: ignore-vcs, which changes what .gitignore removes",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    'include = ["automated_security_helper"]',
                    'include = ["automated_security_helper"]\nignore-vcs = true',
                ),
            },
            "error: ignore-vcs is a build option",
        ),
        (
            "static: a .hgignore",
            {"layers": STATIC, "files": {".hgignore": "*.log\n"}},
            "error: .hgignore exists",
        ),
        (
            "static: a license file in the wheel is not listed",
            {"layers": STATIC, "workflow": fixture_workflow(without("NOTICE"))},
            "problems",
        ),
        (
            "static: a wheel with no dist-info/licenses/",
            {"layers": STATIC, "licenses": ()},
            "error: no dist-info/licenses/",
        ),
        (
            "static: a dynamic path under a directory needs `**`",
            {
                "layers": STATIC,
                "workflow": fixture_workflow(
                    [
                        "automated_security_helper/*",
                        "automated_security_helper/assets/**",
                        *without("automated_security_helper/**"),
                    ]
                ),
            },
            "problems",
        ),
        (
            "static: a variable joined below a directory needs `**`",
            {
                "layers": STATIC,
                "static_extra": 'page = ASH_REPO_ROOT.joinpath("templates", name)',
                "workflow": fixture_workflow([*FIXTURE_FILTER, "templates"]),
            },
            "problems",
        ),
        (
            "static: `..` in an ASH_REPO_ROOT chain",
            {
                "layers": STATIC,
                "static_extra": 'x = ASH_REPO_ROOT / "automated_security_helper/../CHANGELOG.md"',
            },
            "error: contains `..`",
        ),
        (
            "static: ASH_REPO_ROOT through an alias",
            {"layers": STATIC, "static_extra": "ROOT = ASH_REPO_ROOT"},
            "error: cannot be read",
        ),
        (
            "static: ASH_REPO_ROOT joined with a variable first",
            {"layers": STATIC, "static_extra": "x = ASH_REPO_ROOT.joinpath(name)"},
            "error: cannot be read",
        ),
        (
            "static: a second root from __file__",
            {"layers": STATIC, "static_extra": "OTHER = Path(__file__).parent"},
            "error: second root",
        ),
        (
            "static: a relative Path literal the build never opens",
            {
                "layers": STATIC,
                "static_extra": 'notes = Path("CHANGELOG.md").exists()',
            },
            "problems",
        ),
        (
            "static: a build option this check does not know",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    'include = ["automated_security_helper"]',
                    'include = ["automated_security_helper"]\nnew-option = ["x"]',
                ),
            },
            "error: new-option is a build option",
        ),
        (
            "static: a build hook other than the custom one",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT
                + "\n[tool.hatch.build.targets.wheel.hooks.vcs]\n"
                + 'version-file = "v.py"\n',
            },
            "error: is not the custom hook",
        ),
        (
            "measured: the fixture's filter covers the inputs",
            {"layers": MEASURED},
            "ok",
        ),
        (
            "measured: the readme is not listed",
            {"layers": MEASURED, "workflow": fixture_workflow(without("README.md"))},
            "problems",
        ),
        (
            "measured: the build hook is not listed",
            {
                "layers": MEASURED,
                "workflow": fixture_workflow(without("hatch_build.py")),
            },
            "problems",
        ),
        (
            "measured: .gitignore is not listed",
            {"layers": MEASURED, "workflow": fixture_workflow(without(".gitignore"))},
            "problems",
        ),
        (
            "measured: a license file is not listed",
            {"layers": MEASURED, "workflow": fixture_workflow(without("LICENSE"))},
            "problems",
        ),
        (
            "measured: the package tree is not listed",
            {
                "layers": MEASURED,
                "workflow": fixture_workflow(without("automated_security_helper/**")),
            },
            "problems",
        ),
        (
            "measured: the hook reads a root file through self.root",
            {
                "layers": MEASURED,
                "build_extra": copy_changelog.format(
                    'Path(self.root) / "CHANGELOG.md"'
                ),
            },
            "problems",
        ),
        (
            "measured: the hook copies a root file by a bare string",
            {
                "layers": MEASURED,
                "build_extra": copy_changelog.format('"CHANGELOG.md"'),
            },
            "problems",
        ),
        (
            "measured: the hook reads through ASH_ASSETS_PATH.parent.parent",
            {
                "layers": MEASURED,
                "build_extra": copy_changelog.format(
                    'ASH_ASSETS_PATH.parent.parent / "CHANGELOG.md"'
                ),
            },
            "problems",
        ),
        (
            "measured: `..` in a force-include source",
            {
                "layers": MEASURED,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    "[tool.hatch.build.targets.wheel.hooks",
                    '"automated_security_helper/../CHANGELOG.md" = '
                    '"automated_security_helper/assets/C.md"\n\n'
                    "[tool.hatch.build.targets.wheel.hooks",
                ),
            },
            "problems",
        ),
        (
            "measured: the hook copies a root file with a subprocess",
            {
                "layers": MEASURED,
                "build_extra": 'subprocess.run(["cp", "CHANGELOG.md", "CL.md"], '
                "cwd=ASH_REPO_ROOT, check=True)",
            },
            "error: subprocess.Popen ['cp'",
        ),
        (
            "measured: the hook runs os.system",
            {"layers": MEASURED, "build_extra": 'os.system("true")'},
            "error: os.system",
        ),
        (
            "measured: the hook runs git with other arguments",
            {
                "layers": MEASURED,
                "build_extra": 'subprocess.run(["git", "show", "HEAD:CHANGELOG.md"], '
                "capture_output=True, check=False)",
            },
            "error: subprocess.Popen ['git', 'show'",
        ),
        (
            "measured: an installed hatchling the build-system does not allow",
            {
                "layers": MEASURED,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    'requires = ["hatchling"]', 'requires = ["hatchling>=999"]'
                ),
            },
            "error: is not met",
        ),
        (
            "both: a `!` negation entry",
            {"workflow": fixture_workflow([*FIXTURE_FILTER, "!README.md"])},
            "problems",
        ),
        (
            "both: a paths-ignore list",
            {
                "workflow": fixture_workflow(
                    FIXTURE_FILTER, '    paths-ignore:\n      - "docs/**"\n'
                )
            },
            "problems",
        ),
        ("both: the fixture's filter covers the inputs", {}, "ok"),
    ]
    with tempfile.TemporaryDirectory(prefix="paths-filter-") as scratch:
        for index, (label, overrides, expected) in enumerate(wheel_cases):
            root = os.path.join(scratch, str(index))
            got = run_fixture(root, **overrides)
            # An error case names part of its message, so a case cannot pass on an
            # error some other rule raised.
            if not (
                got == expected
                or (
                    expected.startswith("error: ")
                    and got.startswith("error: ")
                    and expected[7:] in got
                )
            ):
                failures += 1
                print(f"  FAILED {label}: expected {expected}, got {got}")
            else:
                print(f"  ok {label} ({got.split(':', 1)[0]})")
    total = len(cases) + len(wheel_cases)
    print("self-test " + ("FAILED" if failures else f"OK ({total} cases)"))
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv[1:])
    if args.self_test:
        return self_test()
    try:
        with open(os.path.join(args.repo, args.workflow), encoding="utf-8") as handle:
            filters = read_paths_filters(handle.read())
        with tempfile.TemporaryDirectory(prefix="paths-filter-wheel-") as out_dir:
            inputs = wheel_inputs(args.repo, out_dir)
    except ValueError as error:  # Unresolvable is a ValueError
        print(f"paths filter check FAILED for {args.workflow}: {error}")
        return 1
    problems = check(filters, inputs)
    if problems:
        print(f"paths filter check FAILED for {args.workflow}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    outside = sorted(i for i in inputs if not i.startswith(f"{PACKAGE_DIR}/"))
    print(
        f"paths filter OK: push and pull_request list the same {len(filters['push'])} "
        f"entries, and they match all {len(inputs)} wheel inputs; outside "
        f"{PACKAGE_DIR}/ those are {', '.join(outside)}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
