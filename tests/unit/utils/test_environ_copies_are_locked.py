"""Every copy of ``os.environ`` in ASH's process is taken under ``ENVIRON_LOCK``.

``utils/process_env.py`` holds ``ENVIRON_LOCK`` while it changes variables, and
``snapshot_environ()`` takes the same lock to copy them. A copy taken any other
way (``dict(os.environ)``, ``os.environ.copy()``, ``{**os.environ}``,
``env=os.environ``, iterating it, or handing the live mapping to a function that
might) reads the key list and then each value with no lock. A change landing in
between gives a copy that is half before and half after it, or a ``KeyError`` for
a variable removed after its key was listed. ``hold_environ`` and
``apply_environ_overrides`` change variables while scans run in other threads, so
this is not hypothetical: a multi-variable override that is half applied reaches
the child the copy was made for.

The static test refuses every use of ``os.environ`` in the package except the
ones that touch a single key: ``os.environ[key]``, ``os.environ.get(...)``,
``key in os.environ`` and the mutating methods, which
``test_environ_mutations_are_locked.py`` keeps inside ``process_env``. Anything
else, an alias included, is a read of the whole mapping. Two files are outside
ASH's process and are not walked; the test checks that they stay outside it.
"""

from __future__ import annotations

import ast
import threading
from pathlib import Path
from typing import Dict, Iterator, List, MutableMapping, Set

import pytest

from tests.unit.utils.test_environ_mutations_are_locked import (
    ALLOWED,
    MUTATING_METHODS,
    PACKAGE_ROOT,
    _is_os_environ,
)

pytestmark = pytest.mark.unit

#: Scripts that run as interpreters of their own and never in ASH's process, so
#: ASH's lock cannot order their reads against anything and has nothing to order:
#: the image build runs install-pinned-tool before ASH is installed, and the
#: sandbox runs landlock_exec as ``python -I landlock_exec.py`` (its forked child
#: could not take a lock another thread held at fork in any case).
#: ``test_separate_interpreters_stay_separate`` keeps this list honest.
SEPARATE_INTERPRETERS = {
    PACKAGE_ROOT / "assets" / "install-pinned-tool.py",
    PACKAGE_ROOT / "utils" / "sandbox" / "landlock_exec.py",
}

SINGLE_KEY_METHODS = {"get"} | MUTATING_METHODS


def _environ_aliases(tree: ast.AST) -> Set[str]:
    return {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "os"
        for alias in node.names
        if alias.name == "environ"
    }


def _single_key_use(node: ast.AST, parent: ast.AST) -> bool:
    """Whether ``parent`` uses ``node`` (the live mapping) for one key only."""
    if isinstance(parent, ast.Subscript) and parent.value is node:
        return True
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return parent.attr in SINGLE_KEY_METHODS
    if isinstance(parent, ast.Compare) and node in parent.comparators:
        index = parent.comparators.index(node)
        return isinstance(parent.ops[index], (ast.In, ast.NotIn))
    return False


def find_unlocked_reads(source: str) -> List[int]:
    """Line numbers in ``source`` that read the whole of ``os.environ``."""
    tree = ast.parse(source)
    aliases = _environ_aliases(tree)
    parents: Dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            # The import itself: a bare ``environ`` hides every later use.
            if any(alias.name == "environ" for alias in node.names):
                lines.append(node.lineno)
            continue
        if not _is_os_environ(node, aliases):
            continue
        parent = parents.get(id(node))
        if isinstance(node, ast.Name) and isinstance(parent, ast.alias):
            continue
        if parent is None or not _single_key_use(node, parent):
            lines.append(node.lineno)
    return sorted(set(lines))


def _package_files() -> Iterator[Path]:
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if path in ALLOWED or path in SEPARATE_INTERPRETERS:
            continue
        yield path


def test_no_unlocked_copy_of_the_environment_in_the_package():
    offenders = [
        f"{path.relative_to(PACKAGE_ROOT.parent)}:{line}"
        for path in _package_files()
        for line in find_unlocked_reads(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], (
        "Copy the environment with automated_security_helper.utils.process_env."
        "snapshot_environ(), which takes ENVIRON_LOCK, not from os.environ "
        "directly: " + ", ".join(offenders)
    )


def test_control_the_walk_reads_the_package():
    """process_env copies os.environ on purpose; the finder has to see that copy."""
    assert find_unlocked_reads(
        (PACKAGE_ROOT / "utils" / "process_env.py").read_text(encoding="utf-8")
    ), "find_unlocked_reads no longer sees snapshot_environ's own copy"
    assert sum(1 for _ in _package_files()) > 100


def test_each_copy_form_is_detected():
    source = """\
import os
from os import environ as env
a = dict(os.environ)
b = os.environ.copy()
c = {**os.environ, "A": "1"}
subprocess.run(cmd, env=os.environ)
d = list(os.environ.items())
e = [k for k in os.environ]
f = os.environ | {"A": "1"}
g = os.environ if x is None else x
h(os.environ, 1)
for key in os.environ: pass
env.get("A")
os.environ.get("A")
os.environ["A"]
"A" in os.environ
"A" not in os.environ
os.environ.pop("A", None)
"""
    assert find_unlocked_reads(source) == [2, *range(3, 13)]


def _imported_modules(path: Path) -> Set[str]:
    """Every module name ``path`` imports, relative imports resolved."""
    package = ".".join(path.relative_to(PACKAGE_ROOT.parent).with_suffix("").parts[:-1])
    names: Set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                stem = parts[: len(parts) - node.level + 1]
                base = ".".join([*stem, base] if base else stem)
            names.add(base)
            names.update(f"{base}.{alias.name}" for alias in node.names)
    return names


def test_separate_interpreters_stay_separate():
    """Each skipped script imports nothing from ASH, and nothing in ASH imports it."""
    for script in SEPARATE_INTERPRETERS:
        assert script.is_file(), script
        own = _imported_modules(script)
        assert not any(name.split(".")[0] == PACKAGE_ROOT.name for name in own), (
            f"{script.name} imports ASH, so it may run in ASH's process"
        )
        module = ".".join(script.relative_to(PACKAGE_ROOT.parent).with_suffix("").parts)
        importers = [
            path.name
            for path in PACKAGE_ROOT.rglob("*.py")
            if path != script and module in _imported_modules(path)
        ]
        assert importers == [], f"{script.name} is imported by {importers}"


class _PausingEnviron(MutableMapping[str, str]):
    """A stand-in for os.environ whose writer stops halfway through an update."""

    def __init__(self, data: Dict[str, str], pause_before: str):
        self._data = dict(data)
        self._pause_before = pause_before
        self.paused = threading.Event()
        self.resume = threading.Event()

    def __getitem__(self, key: str) -> str:
        return self._data[key]

    def __setitem__(self, key: str, value: str) -> None:
        if key == self._pause_before and not self.paused.is_set():
            self.paused.set()
            assert self.resume.wait(10), "the test never resumed the writer"
        self._data[key] = value

    def __delitem__(self, key: str) -> None:
        del self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(list(self._data))

    def __len__(self) -> int:
        return len(self._data)

    def copy(self) -> Dict[str, str]:  # os._Environ.copy
        return dict(self)


KEYS = ("ASH_TEST_JSII_A", "ASH_TEST_JSII_B", "ASH_TEST_JSII_C")


def test_nix_mode_never_starts_its_child_with_a_half_applied_override(
    monkeypatch: pytest.MonkeyPatch,
):
    """The copy for the child is all before or all after a concurrent override.

    A writer applies three variables through apply_environ_overrides (cdk-nag's
    JSII variables are set three at a time like this) and is stopped after the
    first. run_ash_nix then copies the environment for ``nix develop``. Copied
    without the lock it runs straight through and hands the child one new value
    and two old ones; under the lock it waits for the writer and copies all three
    new ones.
    """
    import os
    import subprocess

    from automated_security_helper.interactions import run_ash_nix as nix
    from automated_security_helper.utils.process_env import apply_environ_overrides

    fake = _PausingEnviron(
        {**dict.fromkeys(KEYS, "before"), "PATH": "/usr/bin"}, pause_before=KEYS[1]
    )
    monkeypatch.setattr(os, "environ", fake)
    monkeypatch.setattr(nix, "find_executable", lambda name: "/usr/bin/nix")
    monkeypatch.setattr(nix, "resolve_flake_ref", lambda ref: "path:/flake")
    seen: List[Dict[str, str]] = []

    def fake_enter_shell(cmd, env):
        seen.append(dict(env))
        return subprocess.CompletedProcess(cmd, 0)

    # The call that starts the shell, by the module's own name: run_ash_nix hands
    # the copied environment to _enter_shell and never calls subprocess.run.
    monkeypatch.setattr(nix, "_enter_shell", fake_enter_shell)

    writer = threading.Thread(
        target=apply_environ_overrides, args=(dict.fromkeys(KEYS, "after"),)
    )
    errors: List[BaseException] = []

    def scan() -> None:
        try:
            nix.run_ash_nix(argv=["scan"])
        except BaseException as error:  # reported below
            errors.append(error)

    reader = threading.Thread(target=scan)
    writer.start()
    try:
        assert fake.paused.wait(10), "the writer never reached the second variable"
        reader.start()
        # Long enough for an unlocked copy to finish while the writer is stopped.
        reader.join(0.5)
    finally:
        fake.resume.set()
        writer.join(10)
        if reader.is_alive() or reader.ident is not None:
            reader.join(10)

    assert errors == []
    assert len(seen) == 1
    values = {seen[0][key] for key in KEYS}
    assert values in ({"before"}, {"after"}), (
        f"the child got a half-applied override: {[seen[0][key] for key in KEYS]}"
    )
