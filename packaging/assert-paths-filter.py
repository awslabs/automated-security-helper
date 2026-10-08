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
entry point, the one `uv build` calls, under sys.addaudithook. Every file the
build opens for reading inside the repository is an input, however the hook
spelled the path. Every process the build starts must be one this script can
attribute (only the hook's `git rev-parse --abbrev-ref HEAD`, run by the git that
`shutil.which("git")` finds outside the repository and given no environment of its
own; it reads .git and nothing a paths entry can name). Any other subprocess,
os.system, exec, spawn or fork is an error, because what a child process reads
cannot be seen from here. Processes are seen through their audit events and
through _posixsubprocess.fork_exec, which this script wraps during the build
because it raises no audit event of its own and multiprocessing's spawn and
forkserver contexts start their processes through it. Any ctypes audit event is an
error too, because a foreign call can read a file or start a process with no event
at all. So is opening a directory, in any mode and anywhere: a descriptor from that
open lets a later open name a file relative to it (`dir_fd=`), and the open event
does not carry the directory. That refusal covers more than reads. shutil.rmtree
and TemporaryDirectory cleanup open each directory they remove, so a build hook
that deletes a tree that way turns this check red; delete files one by one, or
leave the tree for the frontend's temporary directory. The installed build backend
must satisfy pyproject's [build-system] requires, so the build measured is the
build `uv build` runs.

Of the files the build touches, the measured layer sees only the ones it opens. A
file the build only tests for, with `os.path.exists`, `Path.exists()`, `os.stat`
and the like, raises no audit event, so the measured layer cannot see it at all.
Neither layer sees a file read on a branch this build did not take unless the
static layer models its spelling. The static layer is the backstop for both, and
it models only the spellings listed below. It reads:

  - project.license-files from pyproject.toml, which must be set and list files by
    name (unset, hatchling adds every root file matching its default globs, such as
    AUTHORS* or LICENSE*, so a new file there would join the wheel with no paths
    entry naming it), and requires the wheel's dist-info/licenses/ to hold exactly
    those files;
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

An event with no `paths:` filter runs on every change, so it covers every input;
that is the workflow's state today, because its gate is a required check and a
check a filter skipped never reports. Both events must still be triggers: a
workflow that does not trigger on push or pull_request at all covers nothing
there. The lists are compared as they are, so one filtered event and one
unfiltered event is refused as a difference rather than read as coverage.

Opens are resolved when they happen, so a symlink is attributed to the file it
named during the build. A path under /proc or /dev/fd is refused outright: it
names a descriptor or a working directory, and reopening a file the build opened
O_WRONLY through /proc/self/fd/N reads it with no read-mode open of its own. An
O_PATH open counts as a read whatever its access mode.

Threat model: this guards against accidental drift and ordinary edits, such as a
new file the hook copies or a filter entry someone deletes. It does not try to
stop an author who already controls the repository's code from evading it on
purpose (closure tricks, ctypes, editing this script and the like); code
review is the control there.

The self-test runs each layer on its own against fixture repositories it builds
with hatchling, so a deleted measurement in either layer turns it red.

Usage: assert-paths-filter.py [--repo DIR] [--workflow PATH] [--event NAME ...]
       assert-paths-filter.py --self-test
Both need hatchling importable, e.g. `uv run --isolated --no-project --with
hatchling` (`--isolated` so that a hatchling already in a discovered .venv is not
used instead of the newest release).
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import importlib.metadata
import os
import re
import shutil
import sys
import tempfile
import tomllib
import zipfile
from collections.abc import Iterator
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


# The events GitHub applies a `paths` filter to.
FILTERED_EVENTS = ("push", "pull_request", "pull_request_target")


def read_paths_filters(workflow_text: str) -> dict[str, list[str] | None]:
    """Returns {event: [paths]} for the events under `on:`; None for an event
    that carries no `paths:`, which runs on every change.

    Parsed by indentation rather than with a YAML library, so this has no
    dependency beyond the standard library. It reads only the shape the workflow
    uses: `on:` at column 0, events at two spaces, `paths:` at four, and one
    quoted `- "pattern"` per line at six. A `paths-ignore:` list is returned under
    the key `paths-ignore:<event>` so that check() can refuse it.
    """
    filters: dict[str, list[str] | None] = {}
    in_on = False
    event = None
    key = None
    current: list[str] = []
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
            filters.setdefault(event, None)
            continue
        match = re.match(r"^    (paths|paths-ignore):(.*)$", line)
        if match:
            key = (
                event or ""
                if match.group(1) == "paths"
                else f"paths-ignore:{event or ''}"
            )
            current = filters.get(key) or []
            filters[key] = current
            if match.group(2).strip():
                # A flow-style list (`paths: ["a"]`) is a shape this parser does
                # not read; refusing it is safer than reading it as empty.
                raise ValueError(f"unreadable {match.group(1)} under {event}: {line!r}")
            continue
        if event in FILTERED_EVENTS and re.match(
            r"""^\s+["']?(paths|paths-ignore)["']?\s*:""", line
        ):
            # A filter in a shape the match above does not read (another indent, a
            # quoted key) would otherwise read as no filter, which covers everything.
            raise ValueError(f"unreadable paths filter under {event}: {line!r}")
        if re.match(r"^    \S", line):
            key = None
            continue
        if key is not None:
            item = re.match(r"""^      - ["']?([^"']+)["']?\s*$""", line)
            if item is None:
                raise ValueError(f"unreadable paths entry under {event}: {line!r}")
            current.append(item.group(1))
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
    model at all, such as `Path(self.root)`, are seen only if the build opens the
    file; a file reached that way and only tested for (`.exists()`) is seen by
    neither layer.

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


def declared_license_files(pyproject: dict[str, Any]) -> set[str]:
    """project.license-files, which must be set and name each file literally."""
    license_files = pyproject["project"].get("license-files")
    if license_files is None:
        raise Unresolvable(
            "project.license-files is not set, so hatchling adds every root file its "
            "default globs match (LICEN[CS]E*, COPYING*, NOTICE*, AUTHORS*) to the "
            "wheel, and a new one would join it with no paths entry naming it; list "
            "the license files"
        )
    if not isinstance(license_files, list):
        raise Unresolvable("project.license-files is not a list")
    found: set[str] = set()
    for entry in license_files:
        if not isinstance(entry, str) or any(c in entry for c in "*?[]!"):
            raise Unresolvable(
                f"project.license-files entry {entry!r} is a glob or not a string; "
                "this check reads only literal file names"
            )
        found.add(repo_relative(entry, "project.license-files"))
    return found


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
    inputs |= declared_license_files(pyproject)

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


def check_wheel_licenses(wheel: str, declared: set[str]) -> None:
    """The license files hatchling actually put in the wheel's dist-info must be
    exactly the ones project.license-files declares, which static_config_inputs
    already counts as inputs."""
    with zipfile.ZipFile(wheel) as archive:
        licenses = {
            n.split("/licenses/", 1)[1]
            for n in archive.namelist()
            if re.match(r"^[^/]+\.dist-info/licenses/.+", n)
        }
    if not licenses:
        raise Unresolvable(
            f"{wheel} has no dist-info/licenses/ member, so the license files cannot "
            "be measured. Refusing to report the filter complete without them."
        )
    if licenses != declared:
        raise Unresolvable(
            "the wheel's dist-info/licenses/ does not hold exactly the files "
            f"project.license-files declares: only in the wheel {sorted(licenses - declared)}, "
            f"only declared {sorted(declared - licenses)}"
        )


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

# The event this script records for each call to _posixsubprocess.fork_exec, which
# raises no audit event of its own (see measured_build).
FORK_EXEC = "_posixsubprocess.fork_exec"
# The event recorded for an open of a directory, in any mode.
DIRECTORY_OPEN = "open of a directory"
# The event recorded for an open of a path under /proc or /dev/fd, spelled there or
# reached through a symlink. Such a path names a descriptor or a working directory
# rather than a file: /proc/self/fd/N reopens whatever N is, including a file the
# build opened O_WRONLY, and /proc/self/cwd is the build's directory only while the
# build runs. Resolving either after the build gives a different answer, so the
# open is refused rather than resolved.
PROC_OPEN = "open under /proc or /dev/fd"
PROC_ROOTS = ("/proc", "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr")

# Commands the build may run, keyed by (program name, *arguments). Each must read
# nothing a paths entry could name. A command is attributed only when the program
# that runs is the git shutil.which("git") found before the build, that git lies
# outside the repository, and the build did not pass it an environment.
ATTRIBUTED_COMMANDS = {
    ("git", "rev-parse", "--abbrev-ref", "HEAD"): (
        "hatch_build.py records the branch name in ASH_INSTALLED_REVISION; git "
        "reads only .git, which is not a file in the tree"
    ),
}

# Set to a list while a measured build runs; the audit hook appends to it.
_recording: list[tuple[Any, ...]] | None = None
_hook_installed = False

# While a measured build runs: the checkout's real path, and what each file in it
# the build writes, renames or removes held before the build first touched it
# (None for a file that did not exist), plus the directories it created. The
# build hook writes generated files into the checkout (ASH_INSTALLED_REVISION,
# assets/Dockerfile and the staged modules); measuring must leave the checkout as
# it found it, so these are put back afterwards.
_restore_root: str | None = None
_saved: dict[str, tuple[bytes, int] | None] = {}
_created_dirs: list[str] = []
_saving = False

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _opened_for_writing(mode: object, flags: object) -> bool:
    if isinstance(flags, int) and flags & _WRITE_FLAGS:
        return True
    return isinstance(mode, str) and any(c in mode for c in "wax+")


def _in_checkout(raw: object, dir_fd: object = None) -> str | None:
    """The real path of `raw` when it is a path in the checkout being measured."""
    root = _restore_root
    # The os.* audit events report "no dir_fd" as -1.
    if root is None or raw is None or isinstance(raw, int) or dir_fd not in (None, -1):
        return None
    resolved = os.path.realpath(os.path.join(os.getcwd(), os.fsdecode(raw)))
    return resolved if _inside(resolved, root) and resolved != root else None


def _save(path: str | None) -> None:
    """Records what `path` holds now, the first time the build is about to change it."""
    global _saving
    if path is None or path in _saved or os.path.isdir(path):
        return
    _saving = True
    try:
        if os.path.lexists(path):
            with open(path, "rb") as handle:
                _saved[path] = (handle.read(), os.stat(path).st_mode)
        else:
            _saved[path] = None
    finally:
        _saving = False


def _restore_checkout() -> None:
    """Puts back every file _save recorded and removes the directories the build made."""
    global _saving
    _saving = True
    try:
        for path, before in _saved.items():
            if before is None:
                if os.path.lexists(path) and not os.path.isdir(path):
                    os.remove(path)
                continue
            content, mode = before
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(content)
            os.chmod(path, mode & 0o7777)
        for directory in sorted(_created_dirs, key=len, reverse=True):
            if os.path.isdir(directory) and not os.listdir(directory):
                os.rmdir(directory)
    finally:
        _saving = False
        _saved.clear()
        _created_dirs.clear()


def _audit(event: str, args: tuple[Any, ...]) -> None:
    if _saving:
        return
    if event == "open" and _opened_for_writing(args[1], args[2]):
        _save(_in_checkout(args[0]))
    elif event == "os.rename":
        _save(_in_checkout(args[0], args[2]))
        _save(_in_checkout(args[1], args[3]))
    elif event == "os.remove":
        _save(_in_checkout(args[0], args[1]))
    elif event == "os.mkdir":
        made = _in_checkout(args[0], args[2])
        if made is not None and not os.path.exists(made):
            _created_dirs.append(made)
    events = _recording
    if events is None:
        return
    if event == "open":
        # Resolved now, while the build's working directory and descriptors are the
        # ones the path was opened against: a symlink to /proc/self/cwd/X, resolved
        # after the build, names this script's directory instead. Any open of a
        # directory counts, whatever its access mode: on Linux O_PATH ignores the
        # mode, so O_PATH|O_WRONLY still gives a usable dir_fd.
        cwd = os.getcwd()
        raw = args[0]
        if raw is None or isinstance(raw, int):
            events.append(("open", raw, args[1], args[2], cwd))
            return
        path = os.path.join(cwd, os.fsdecode(raw))
        resolved = os.path.realpath(path)
        events.append(("open", resolved, args[1], args[2], cwd))
        if any(
            _inside(p, root)
            for p in (os.path.normpath(path), resolved)
            for root in PROC_ROOTS
        ):
            events.append((PROC_OPEN, path))
        if os.path.isdir(path):
            events.append((DIRECTORY_OPEN, path))
    elif event == "subprocess.Popen":
        executable, argv, _cwd, env = args
        if isinstance(argv, (str, bytes, os.PathLike)):
            argv = [argv]
        argv = [os.fsdecode(a) for a in argv]
        program = os.fsdecode(executable) if executable else (argv[0] if argv else "")
        if program and os.sep not in program:
            # Resolved now, against the PATH the child is started with.
            program = shutil.which(program) or program
        events.append((event, argv, program, env))
    elif event in SPAWN_EVENTS or event.startswith("ctypes."):
        events.append((event, args))


def _first_executable(candidates: object) -> str | None:
    """The program fork_exec runs: the first candidate that is an executable file."""
    for candidate in candidates or ():  # type: ignore[attr-defined]
        path = os.fsdecode(candidate)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


@contextlib.contextmanager
def _recording_fork_exec(events: list[tuple[Any, ...]]) -> Iterator[None]:
    """Records every _posixsubprocess.fork_exec call while the block runs.

    subprocess.Popen raises an audit event before it calls fork_exec, but
    multiprocessing's spawn and forkserver contexts call fork_exec directly, and it
    raises none. Both look the function up on the module at call time, so replacing
    the module attribute is enough.
    """
    import _posixsubprocess

    original = _posixsubprocess.fork_exec

    def fork_exec(*args: Any, **kwargs: Any) -> Any:
        argv = [os.fsdecode(a) for a in args[0]] if args and args[0] else []
        env = args[5] if len(args) > 5 else kwargs.get("env")
        events.append((FORK_EXEC, argv, _first_executable(args[1]), env))
        return original(*args, **kwargs)

    _posixsubprocess.fork_exec = fork_exec
    try:
        yield
    finally:
        _posixsubprocess.fork_exec = original


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


def measured_build(
    repo: str, out_dir: str
) -> tuple[str, list[tuple[Any, ...]], str | None]:
    """Builds the wheel in-process under the audit hook; returns its path, the
    open and spawn events recorded while the build ran, and the real path of the
    git found on PATH before the build, which the build cannot have changed."""
    global _recording, _hook_installed, _restore_root
    check_build_backend(read_pyproject(repo))
    import hatchling.build

    git = shutil.which("git")
    git = os.path.realpath(git) if git else None

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
    _restore_root = os.path.realpath(repo)
    try:
        with contextlib.redirect_stdout(sys.stderr), _recording_fork_exec(events):
            _recording = events
            try:
                name = hatchling.build.build_wheel(out_dir)
            finally:
                _recording = None
    finally:
        _restore_root = None
        _restore_checkout()
        sys.dont_write_bytecode = dont_write_bytecode
        os.chdir(cwd)
    return os.path.join(out_dir, name), events, git


def _opened_for_reading(mode: object, flags: object) -> bool:
    if isinstance(flags, int):
        # O_PATH ignores the access mode: the descriptor names the file whatever
        # O_WRONLY says, so it counts as a read.
        if flags & getattr(os, "O_PATH", 0):
            return True
        return (flags & os.O_ACCMODE) != os.O_WRONLY
    if isinstance(mode, str):
        return "r" in mode or "+" in mode
    return True


def _environment_roots() -> set[str]:
    return {os.path.realpath(p) for p in (sys.prefix, sys.exec_prefix)}


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root + os.sep)


def _attributed(
    argv: list[str], program: str | None, env: object, repo: str, git: str | None
) -> bool:
    """Whether a started process is an ATTRIBUTED_COMMANDS entry run by real git."""
    key = (os.path.basename(argv[0]), *argv[1:]) if argv else ()
    if key not in ATTRIBUTED_COMMANDS or env is not None:
        return False
    if not program or git is None or _inside(git, repo):
        return False
    return os.path.realpath(program) == git


def _repo_path(repo: str, out_dir: str, raw: object, cwd: str) -> str | None:
    """The repository-relative path an open event names, or None outside it."""
    if raw is None or isinstance(raw, int):
        return None  # a descriptor; the open that produced it was recorded
    path = os.path.realpath(os.path.join(cwd, os.fsdecode(raw)))  # type: ignore[arg-type]
    # The wheel being written, and the interpreter's own environment when it lives
    # in the checkout (a .venv): neither is a file the wheel is built from.
    for skipped in (out_dir, *_environment_roots()):
        if _inside(path, skipped):
            return None
    if not _inside(path, repo):
        return None
    rel = os.path.relpath(path, repo).replace(os.sep, "/")
    parts = rel.split("/")
    if "__pycache__" in parts:
        # A cached module is its source file: `x/__pycache__/m.cpython-313.pyc`.
        at = parts.index("__pycache__")
        rel = "/".join([*parts[:at], parts[-1].split(".", 1)[0] + ".py"])
    return rel


def measured_inputs(
    repo: str, out_dir: str, events: list[tuple[Any, ...]], git: str | None
) -> set[str]:
    """Files the build read inside the repository; refuses unattributed processes,
    foreign calls and directory opens."""
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
        name = event[0]
        if name in ("subprocess.Popen", FORK_EXEC):
            _, argv, program, env = event
            if _attributed(argv, program, env, repo, git):
                continue
            unattributed.append(f"{name} {argv!r} running {program!r}")
        elif name == DIRECTORY_OPEN:
            unattributed.append(
                f"{name} {event[1]!r}, whose descriptor can open any file relative to "
                "it unseen"
            )
        elif name == PROC_OPEN:
            unattributed.append(
                f"{name} {event[1]!r}, which names a descriptor or working directory "
                "rather than a file"
            )
        else:
            text = f"{name} {event[1]!r}"
            unattributed.append(text if len(text) <= 200 else text[:200] + "...")
    if unattributed:
        raise Unresolvable(
            "the build started a process this check cannot attribute, called into C, "
            "or opened a directory or a path under /proc, so what it read is not "
            "measured: " + "; ".join(dict.fromkeys(unattributed))
        )
    return found


def wheel_inputs(repo: str, out_dir: str, layers: tuple[str, ...] = LAYERS) -> set[str]:
    """The repository files the wheel is built from, as the union of the layers."""
    inputs: set[str] = set()
    if "static" in layers:
        inputs |= static_config_inputs(repo)
    wheel, events, git = measured_build(repo, out_dir)
    if "static" in layers:
        check_wheel_licenses(wheel, declared_license_files(read_pyproject(repo)))
    if "measured" in layers:
        inputs |= measured_inputs(repo, out_dir, events, git)
    return {as_probe(repo, path) for path in inputs}


EVENTS = ("push", "pull_request")


def check(
    filters: dict[str, list[str] | None],
    inputs: set[str],
    events: tuple[str, ...] = EVENTS,
) -> list[str]:
    """Problems with `filters` as a guard on `inputs`, for the trigger `events`.

    ash-native-packages.yml is checked on push and pull_request. ash-package-formats.yml
    wraps the same wheel and triggers on push only, so it is checked with
    events=("push",)."""
    problems: list[str] = []
    for event in EVENTS:
        if event in filters and event not in events:
            problems.append(
                f"the workflow triggers on {event} but the check leaves {event} out, "
                f"so its {event} filter would go unmeasured"
            )
    for event in events:
        if event not in filters:
            problems.append(
                f"the workflow does not trigger on {event}, so no {event} runs the legs"
            )
    for key, listed in sorted(filters.items()):
        entries = listed or []
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
    push = filters.get("push")
    pull = filters.get("pull_request")
    both = "pull_request" in events
    if both and (push is None) != (pull is None):
        problems.append(
            "one of push and pull_request has a paths filter and the other has none: "
            f"push {'is unfiltered' if push is None else 'is filtered'}, pull_request "
            f"{'is unfiltered' if pull is None else 'is filtered'}"
        )
    elif both and push is not None and pull is not None and push != pull:
        problems.append(
            "the push and pull_request paths lists differ: only in push "
            f"{sorted(set(push) - set(pull))}, only in pull_request "
            f"{sorted(set(pull) - set(push))}, or the same entries in another order"
        )
    for event in events:
        listed = filters.get(event)
        if listed is None:
            # No filter (or no such trigger, reported above): nothing to match.
            continue
        patterns = [glob_to_regex(p) for p in listed]
        for name in sorted(inputs):
            if not any(p.match(name) for p in patterns):
                problems.append(
                    f"{name} is an input to the wheel the packages are built from, "
                    f"but no {event} paths entry matches it, so a change to it skips "
                    "every package leg the workflow runs"
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
license-files = ["LICENSE", "NOTICE"]

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
license-files = ["LICENSE", "NOTICE"]
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
    links: dict[str, str] | None = None,
    path_first: str | None = None,
) -> str:
    """Builds a fixture repository under root and a wheel from it with hatchling;
    returns "ok", "problems" or "error: <the Unresolvable message>".

    path_first names a fixture directory whose files are made executable and which
    is put first on PATH while the check runs, as a checkout's bin/ would be."""
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
    for name, target in (links or {}).items():
        os.symlink(target, os.path.join(root, *name.split("/")))
    out_dir = root + "-dist"
    os.makedirs(out_dir)
    saved_path = os.environ.get("PATH")
    if path_first is not None:
        bin_dir = os.path.join(root, *path_first.split("/"))
        for name in os.listdir(bin_dir):
            # Owner-only: this process is the only one that runs these stand-ins.
            os.chmod(os.path.join(bin_dir, name), 0o700)
        os.environ["PATH"] = bin_dir + os.pathsep + (saved_path or "")
    try:
        inputs = wheel_inputs(root, out_dir, layers)
    except Unresolvable as error:
        return f"error: {error}"
    finally:
        if saved_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved_path
    text = workflow if workflow is not None else fixture_workflow(FIXTURE_FILTER)
    return "problems" if check(read_paths_filters(text), inputs) else "ok"


def outcome_matches(expected: str, got: str) -> bool:
    """An error case names part of its message, so a case cannot pass on an error
    some other rule raised."""
    return got == expected or (
        expected.startswith("error: ")
        and got.startswith("error: ")
        and expected[len("error: ") :] in got
    )


def unit_checks(scratch: str) -> list[tuple[str, bool]]:
    """Checks on single functions that no fixture build can drive; each pair is
    (label, passed)."""
    results = [
        (
            "the case matcher refuses an error some other rule raised",
            not outcome_matches("error: os.system", "error: subprocess.Popen ['x']"),
        ),
        (
            "the case matcher accepts the error the case names",
            outcome_matches("error: os.system", "error: ... os.system ('true',)"),
        ),
    ]
    # The interpreter's own environment is skipped even inside the repository (a
    # .venv in the checkout): with the skip deleted, its files read as inputs.
    prefix = os.path.realpath(sys.prefix)
    results.append(
        (
            "a file in the interpreter's environment inside the repository is skipped",
            _repo_path(
                os.path.dirname(prefix), scratch, os.path.join(prefix, "x.py"), "/"
            )
            is None,
        )
    )
    # A license file hatchling puts in the wheel that license-files does not name.
    wheel = os.path.join(scratch, "x-1.0-py3-none-any.whl")
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in ("LICENSE", "AUTHORS"):
            archive.writestr(f"x-1.0.dist-info/licenses/{name}", "text\n")
    try:
        check_wheel_licenses(wheel, {"LICENSE"})
        refused = False
    except Unresolvable as error:
        refused = "only in the wheel ['AUTHORS']" in str(error)
    results.append(("a wheel license file license-files does not declare", refused))
    return results


# A build hook that writes into the checkout the way hatch_build.py does (a new
# generated file, an overwritten one, new directories) and renames a file.
_CHECKOUT_WRITES = (
    '(ASH_ASSETS_PATH / "ASH_INSTALLED_REVISION").write_text("rev"); '
    'ASH_REPO_ROOT.joinpath("automated_security_helper", "__init__.py")'
    '.write_text("changed"); '
    'os.makedirs(ASH_REPO_ROOT / "made" / "deep"); '
    '(ASH_REPO_ROOT / "made" / "deep" / "f").write_text("x"); '
    'os.replace(ASH_REPO_ROOT / "VERSION", ASH_REPO_ROOT / "VERSION.moved")'
)


def checkout_restored(root: str) -> list[str]:
    """Builds a fixture whose hook writes into the checkout; returns what the
    measured build left changed there (empty when it put everything back)."""
    run_fixture(root, layers=MEASURED, build_extra=_CHECKOUT_WRITES)
    left = []
    for name in (
        "automated_security_helper/assets/ASH_INSTALLED_REVISION",
        "made",
        "VERSION.moved",
    ):
        if os.path.lexists(os.path.join(root, *name.split("/"))):
            left.append(f"{name} is still there")
    for name, text in (
        ("automated_security_helper/__init__.py", ""),
        ("VERSION", "1.0\n"),
    ):
        path = os.path.join(root, *name.split("/"))
        if not os.path.isfile(path):
            left.append(f"{name} is gone")
        elif open(path, encoding="utf-8").read() != text:
            left.append(f"{name} was not restored")
    return left


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
    unfiltered = (
        "on:\n  push:\n    branches: ['**']\n  pull_request:\n    branches: ['**']\n"
        "  workflow_dispatch: {}\n"
    )
    cases = [
        ("both lists cover every input", good, {"a/b/c.py", "README.md"}, False),
        (
            "neither event has a paths filter, so every input is covered",
            unfiltered,
            {"a/x.py", "Dockerfile", "anything/at/all"},
            False,
        ),
        (
            "push is unfiltered and pull_request is filtered",
            unfiltered.replace(
                "  pull_request:\n    branches: ['**']\n",
                '  pull_request:\n    paths:\n      - "a/**"\n',
            ),
            {"a/x.py"},
            True,
        ),
        (
            "the workflow does not trigger on pull_request",
            unfiltered.replace("  pull_request:\n    branches: ['**']\n", ""),
            {"a/x.py"},
            True,
        ),
        (
            "an unfiltered event with a paths-ignore list",
            unfiltered.replace(
                "  pull_request:\n    branches: ['**']\n",
                "  pull_request:\n    branches: ['**']\n"
                '    paths-ignore:\n      - "docs/**"\n',
            ),
            {"a/x.py"},
            True,
        ),
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
    for label, text in (
        (
            "a paths filter at another indent",
            unfiltered.replace(
                "  pull_request:\n", '  pull_request:\n      paths:\n        - "a/**"\n'
            ),
        ),
        (
            "a quoted paths key",
            unfiltered.replace(
                "  pull_request:\n", '  pull_request:\n    "paths":\n      - "a/**"\n'
            ),
        ),
    ):
        try:
            read_paths_filters(text)
            refused = False
        except ValueError:
            refused = True
        if not refused:
            failures += 1
            print(f"  FAILED {label}: read as no filter instead of refused")
        else:
            print(f"  ok {label} (refused)")
    push_only = (
        "on:\n  push:\n    branches: ['**']\n    paths:\n      - \"a/**\"\n"
        '      - "README.md"\n  workflow_dispatch: {}\n'
    )
    for label, text, inputs, events, should_fail in [
        (
            "push only: the push list covers every input",
            push_only,
            {"a/b", "README.md"},
            ("push",),
            False,
        ),
        (
            "push only: an input the push list misses",
            push_only,
            {"a/b", "Dockerfile"},
            ("push",),
            True,
        ),
        (
            "push only: checked on pull_request too, which it lacks",
            push_only,
            {"a/b"},
            EVENTS,
            True,
        ),
        (
            "--event push on a workflow that also triggers on pull_request",
            good,
            {"a/b", "README.md"},
            ("push",),
            True,
        ),
    ]:
        if bool(check(read_paths_filters(text), inputs, events)) != should_fail:
            failures += 1
            print(f"  FAILED {label}")
        else:
            print(f"  ok {label}{' (rejected)' if should_fail else ''}")
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
    spawn_process = (
        'import multiprocessing; p = multiprocessing.get_context("{}")'
        ".Process(target=int); p.start(); p.join()"
    )
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
            {
                "layers": STATIC,
                "licenses": (),
                "pyproject": FIXTURE_PYPROJECT.replace('["LICENSE", "NOTICE"]', "[]"),
            },
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
            "measured: a symlink in the package tree to a root file",
            {
                "layers": MEASURED,
                "links": {"automated_security_helper/link.md": "../CHANGELOG.md"},
            },
            "problems",
        ),
        (
            "measured: the hook starts a process through multiprocessing spawn",
            {"layers": MEASURED, "build_extra": spawn_process.format("spawn")},
            "error: _posixsubprocess.fork_exec",
        ),
        (
            "measured: the hook starts a process through multiprocessing forkserver",
            {"layers": MEASURED, "build_extra": spawn_process.format("forkserver")},
            "error: _posixsubprocess.fork_exec",
        ),
        (
            "measured: the hook calls into C through ctypes",
            {
                "layers": MEASURED,
                "build_extra": "import ctypes; ctypes.CDLL(None).getpid()",
            },
            "error: ctypes.",
        ),
        (
            "measured: the hook runs a `git` from the repository",
            {
                "layers": MEASURED,
                "files": {"automated_security_helper/git": "#!/bin/sh\necho main\n"},
                "build_extra": (
                    'fake = ASH_ASSETS_PATH.parent / "git"; os.chmod(fake, 0o755); '
                    'subprocess.run([str(fake), "rev-parse", "--abbrev-ref", "HEAD"], '
                    "capture_output=True, check=False)"
                ),
            },
            "error: subprocess.Popen ['",
        ),
        (
            "measured: the hook runs git with its own environment",
            {
                "layers": MEASURED,
                "build_extra": (
                    'subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], '
                    "env=dict(os.environ), capture_output=True, check=False)"
                ),
            },
            "error: subprocess.Popen ['git', 'rev-parse'",
        ),
        (
            "measured: the hook runs os.posix_spawn",
            {
                "layers": MEASURED,
                "build_extra": (
                    'os.waitpid(os.posix_spawn("/bin/true", ["true"], dict(os.environ)), 0)'
                ),
            },
            "error: os.posix_spawn",
        ),
        (
            "measured: the hook calls os.execv",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n            os.execv('/nonexistent/x6', ['x6'])\n"
                    "        except OSError:\n            pass"
                ),
            },
            "error: os.exec",
        ),
        (
            "measured: the hook opens a directory and reads relative to it",
            {
                "layers": MEASURED,
                "build_extra": (
                    "dfd = os.open(str(ASH_ASSETS_PATH), os.O_RDONLY); "
                    'os.close(os.open("../../CHANGELOG.md", os.O_RDONLY, dir_fd=dfd)); '
                    "os.close(dfd)"
                ),
            },
            "error: open of a directory",
        ),
        (
            # O_PATH ignores the access mode, so O_WRONLY still gives a descriptor
            # that works as dir_fd. Linux only; elsewhere the open fails, and the
            # attempt is refused all the same.
            "measured: the hook opens a directory O_PATH|O_WRONLY and reads relative to it",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n"
                    "            dfd = os.open(str(ASH_ASSETS_PATH), "
                    'getattr(os, "O_PATH", 0) | os.O_WRONLY)\n'
                    '            os.close(os.open("../../CHANGELOG.md", os.O_RDONLY, dir_fd=dfd))\n'
                    "            os.close(dfd)\n"
                    "        except OSError:\n"
                    "            pass"
                ),
            },
            "error: open of a directory",
        ),
        # A descriptor or a working directory reached through /proc resolves to
        # something else once the build is over: the descriptor is closed, and
        # /proc/self/cwd is this script's directory again. Linux only; elsewhere
        # the opens fail, and the attempt is refused all the same.
        (
            "measured: the hook opens a root file O_WRONLY and reads it through /proc/self/fd",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n"
                    '            fd = os.open("CHANGELOG.md", os.O_WRONLY)\n'
                    '            data = open(f"/proc/self/fd/{fd}", "rb").read()\n'
                    "            os.close(fd)\n"
                    '            Path(ASH_ASSETS_PATH / "CL.md").write_bytes(data)\n'
                    "        except OSError:\n"
                    "            pass"
                ),
            },
            "error: open under /proc or /dev/fd",
        ),
        (
            "measured: the hook opens a root file O_PATH|O_WRONLY and reads it through /proc/self/fd",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n"
                    '            fd = os.open("CHANGELOG.md", getattr(os, "O_PATH", 0) | os.O_WRONLY)\n'
                    '            data = open(f"/proc/self/fd/{fd}", "rb").read()\n'
                    "            os.close(fd)\n"
                    '            Path(ASH_ASSETS_PATH / "CL.md").write_bytes(data)\n'
                    "        except OSError:\n"
                    "            pass"
                ),
            },
            "error: open under /proc or /dev/fd",
        ),
        (
            "measured: the hook reads a root file through /proc/self/cwd",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n"
                    '            data = open("/proc/self/cwd/CHANGELOG.md", "rb").read()\n'
                    '            Path(ASH_ASSETS_PATH / "CL.md").write_bytes(data)\n'
                    "        except OSError:\n"
                    "            pass"
                ),
            },
            "error: open under /proc or /dev/fd",
        ),
        (
            "measured: the hook reads a root file through /proc/<pid>/cwd",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n"
                    '            data = open(f"/proc/{os.getpid()}/cwd/CHANGELOG.md", "rb").read()\n'
                    '            Path(ASH_ASSETS_PATH / "CL.md").write_bytes(data)\n'
                    "        except OSError:\n"
                    "            pass"
                ),
            },
            "error: open under /proc or /dev/fd",
        ),
        (
            "measured: the hook opens a root file O_WRONLY and reads it through /dev/fd",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n"
                    '            fd = os.open("CHANGELOG.md", os.O_WRONLY)\n'
                    '            data = open(f"/dev/fd/{fd}", "rb").read()\n'
                    "            os.close(fd)\n"
                    '            Path(ASH_ASSETS_PATH / "CL.md").write_bytes(data)\n'
                    "        except OSError:\n"
                    "            pass"
                ),
            },
            "error: open under /proc or /dev/fd",
        ),
        (
            # O_PATH ignores the access mode, so the descriptor names the file
            # whatever O_WRONLY says, and counts as a read of it.
            "measured: the hook opens a root file O_PATH|O_WRONLY",
            {
                "layers": MEASURED,
                "build_extra": (
                    "try:\n"
                    '            os.close(os.open("CHANGELOG.md", getattr(os, "O_PATH", 0) | os.O_WRONLY))\n'
                    "        except OSError:\n"
                    "            pass"
                ),
            },
            "problems",
        ),
        (
            # Resolved when the open happens, through /proc while it still names the
            # build's own directory.
            "measured: a symlink in the package tree to a root file through /proc/self/cwd",
            {
                "layers": MEASURED,
                "links": {
                    "automated_security_helper/link.md": "/proc/self/cwd/CHANGELOG.md"
                },
            },
            "problems",
        ),
        (
            "measured: the git first on PATH is inside the repository",
            {
                "layers": MEASURED,
                "files": {"bin/git": "#!/bin/sh\necho main\n"},
                "path_first": "bin",
            },
            "error: subprocess.Popen ['git', 'rev-parse'",
        ),
        (
            "static: license-files is not a list",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    '["LICENSE", "NOTICE"]', '"LICENSE"'
                ),
            },
            "error: project.license-files is not a list",
        ),
        (
            "static: a `?` glob in license-files",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    '["LICENSE", "NOTICE"]', '["LICENS?", "NOTICE"]'
                ),
            },
            "error: is a glob",
        ),
        (
            "static: a `[...]` glob in license-files",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    '["LICENSE", "NOTICE"]', '["LICEN[CS]E", "NOTICE"]'
                ),
            },
            "error: is a glob",
        ),
        (
            "static: a `!` negation in license-files",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    '["LICENSE", "NOTICE"]', '["LICENSE", "NOTICE", "!AUTHORS"]'
                ),
            },
            "error: is a glob",
        ),
        (
            "static: license-files is not set",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    'license-files = ["LICENSE", "NOTICE"]\n', ""
                ),
            },
            "error: license-files is not set",
        ),
        (
            "static: a glob in license-files",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    '["LICENSE", "NOTICE"]', '["LICEN[CS]E*", "NOTICE"]'
                ),
            },
            "error: is a glob",
        ),
        (
            "static: a license file license-files names is not listed",
            {
                "layers": STATIC,
                "pyproject": FIXTURE_PYPROJECT.replace(
                    '["LICENSE", "NOTICE"]', '["LICENSE", "NOTICE", "COPYING"]'
                ),
                "files": {"COPYING": "copying\n"},
            },
            "problems",
        ),
        (
            "both: a root AUTHORS and LICENSE-THIRD-PARTY stay out of the wheel",
            {"files": {"AUTHORS": "authors\n", "LICENSE-THIRD-PARTY": "x\n"}},
            "ok",
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
        (
            "both: a workflow with no paths filter covers every input",
            {
                "workflow": "on:\n  push:\n    branches: ['**']\n  pull_request:\n"
                "  workflow_dispatch: {}\n"
            },
            "ok",
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="paths-filter-") as scratch:
        units = unit_checks(scratch)
        for label, passed in units:
            if not passed:
                failures += 1
                print(f"  FAILED {label}")
            else:
                print(f"  ok {label}")
        for index, (label, overrides, expected) in enumerate(wheel_cases):
            root = os.path.join(scratch, str(index))
            got = run_fixture(root, **overrides)
            if not outcome_matches(expected, got):
                failures += 1
                print(f"  FAILED {label}: expected {expected}, got {got}")
            else:
                print(f"  ok {label} ({got.split(':', 1)[0]})")
        restored = checkout_restored(os.path.join(scratch, "restore"))
        if restored:
            failures += 1
            print(
                f"  FAILED the measured build leaves the checkout as it found it: {restored}"
            )
        else:
            print("  ok the measured build leaves the checkout as it found it")
    total = len(cases) + 2 + 4 + len(units) + len(wheel_cases) + 1
    print("self-test " + ("FAILED" if failures else f"OK ({total} cases)"))
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--event",
        action="append",
        choices=EVENTS,
        help="a trigger to check; repeatable; default push and pull_request",
    )
    args = parser.parse_args(argv[1:])
    events = tuple(args.event) if args.event else EVENTS
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
    problems = check(filters, inputs, events)
    if problems:
        print(f"paths filter check FAILED for {args.workflow}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    outside = sorted(i for i in inputs if not i.startswith(f"{PACKAGE_DIR}/"))
    first = filters[events[0]]
    plural = len(events) > 1
    if first is None:
        listed = f"carr{'y' if plural else 'ies'} no paths filter, so every change runs the legs"
    elif plural:
        listed = f"list the same {len(first)} entries"
    else:
        listed = f"lists {len(first)} entries"
    print(
        f"paths filter OK: {' and '.join(events)} {listed}, and they match all "
        f"{len(inputs)} wheel inputs; outside {PACKAGE_DIR}/ those are "
        f"{', '.join(outside)}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
