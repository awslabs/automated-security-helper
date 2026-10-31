# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each test's private HOME, the run's own home, and the guard on the real ~/.ash.

tests/conftest.py points HOME at a directory of the run's own while pytest loads it, and
at a fresh directory for each test, because tests that install a fixture tool wrote
install receipts into whatever HOME the run inherited -- the operator's real
~/.ash/install-receipts, on every local run. It moves XDG_CONFIG_HOME, XDG_DATA_HOME,
XDG_STATE_HOME and XDG_CACHE_HOME inside that home as well, because a contributor who
sets them would otherwise get tool data and settings written into their own
directories. These tests pin the redirect and prove the guard behind it can fail.

What a module computes from HOME when it is imported points into the run's own home,
which sits in the session temp directory (ASH_TEST_SESSION_TMPDIR). The guard refuses a
write under a watched root with a PermissionError, so the cells here that watch a
stand-in root expect it; test_real_home_guard.py pins the refusals themselves.

No cell depends on where the base temp directory is. A run with --basetemp or TMPDIR
inside the home has every test's home inside it too, and on Windows the temp directory
always is. So the cells ask whether a path is a real home or inside a real ~/.ash, not
whether it is inside a real home.
"""

import ast
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.core import constants
from automated_security_helper.utils.download_utils import receipt_root, write_receipt
from tests.utils import real_home_guard

pytestmark = pytest.mark.unit

#: The shared caches as the run set them, read when pytest imported this module. A unit
#: test has a uv cache of its own inside its home instead (tests/unit/conftest.py), so
#: only the value at import is the run's.
_SHARED_CACHE_VARIABLES = ("UV_CACHE_DIR",)
_SHARED_CACHES_AT_IMPORT = {
    name: os.environ.get(name) for name in _SHARED_CACHE_VARIABLES
}


def _the_tests_home() -> Path:
    """The directory ``_isolated_home`` made for this test, under the base temp."""
    return Path(os.environ["HOME"])


def _same_or_inside(path: Path, directory: Path) -> bool:
    resolved = Path(os.path.realpath(path))
    wanted = Path(os.path.realpath(directory))
    return resolved == wanted or wanted in resolved.parents


def _real_homes(developer_home: Path) -> list:
    """The passwd home and the developer's home, resolved."""
    homes = [real_home_guard.passwd_home(), developer_home]
    return [Path(os.path.realpath(home)) for home in homes if home is not None]


def _in_a_real_ash(path: Path, developer_home: Path) -> bool:
    """Whether ``path`` is ~/.ash of a real home, or inside it."""
    return any(
        _same_or_inside(path, home / ".ash") for home in _real_homes(developer_home)
    )


def _refused_writes(operation) -> set:
    """Run a write the guard must refuse; return the (event, path) records it kept,
    the path spelled as the guard spells it (absolute, as written)."""
    with pytest.raises(PermissionError, match="refused by the test guard"):
        operation()
    return set(real_home_guard.drain())


def _written(path: Path) -> str:
    """``path`` as the guard records a refused write to it."""
    return os.path.abspath(path)


def test_home_is_the_sessions_private_directory(developer_home, tmp_path_factory):
    """HOME and Path.home() are a directory the run made, never the developer's.

    The run puts HOME in its own home while pytest loads the conftest, and
    ``_isolated_home`` gives each test a fresh directory under the base temp
    directory. This is the second: the one the test is in.
    """
    home = _the_tests_home()
    assert Path(os.path.realpath(home)) not in _real_homes(developer_home), home
    assert not _in_a_real_ash(home, developer_home), home
    assert Path.home() == home
    assert home.is_dir()
    assert tmp_path_factory.getbasetemp() in home.parents, home


def test_the_receipt_store_and_default_bin_dir_are_inside_it(developer_home):
    """The two ~/.ash paths ASH writes: one read at call time, one at import time.

    The receipt store follows the test's home. The default bin directory was computed
    when ASH was imported, so it is in the run's own home, inside the session temp
    directory, and not in the developer's.
    """
    assert not _in_a_real_ash(receipt_root(), developer_home), receipt_root()
    assert _the_tests_home() in receipt_root().parents
    if not os.environ.get("ASH_BIN_PATH"):
        assert constants.ASH_BIN_PATH is not None
        assert not _in_a_real_ash(constants.ASH_BIN_PATH, developer_home)
        # The run's own home, not any path under the session directory: ``~/.ash/bin``
        # of a directory the session made directly under its temp directory, named
        # ``home`` (``_enter_session_home``), or ``home-<random>`` for a nested run.
        bin_path = Path(constants.ASH_BIN_PATH)
        assert bin_path.parts[-2:] == (".ash", "bin"), bin_path
        run_home = bin_path.parent.parent
        session_directory = Path(os.environ["ASH_TEST_SESSION_TMPDIR"])
        assert Path(os.path.realpath(run_home.parent)) == Path(
            os.path.realpath(session_directory)
        ), bin_path
        assert run_home.name == "home" or run_home.name.startswith("home-"), bin_path


def test_a_receipt_written_with_no_home_of_its_own_stays_in_it(
    tmp_path, developer_home
):
    """What the leaking tests did: write a receipt and set no HOME."""
    written = write_receipt(tmp_path / "bin", "fixture-tool", {"sha256": "0" * 64})
    assert written is not None
    assert not _in_a_real_ash(written, developer_home), written
    assert _the_tests_home() in written.parents
    assert real_home_guard.drain() == []


@pytest.mark.skipif(os.name == "nt", reason="the guard's roots are POSIX paths here")
def test_the_guard_records_writes_under_a_guarded_root(tmp_path):
    """Control: a guard that never fires would pass every suite.

    Watches a stand-in root and attempts each write that storing a receipt makes
    (mkdir, open for write, chmod, replace). The guard refuses every one, so nothing
    lands, and records the event with the path it refused; a read of a file that is
    already there is neither. Each record is compared as the (event, path) pair, so a
    guard that refused the right operation on another path would not pass, and a
    rename is recorded at both of its ends. Each record is drained as it is checked,
    so the teardown check does not fail this test for them.
    """
    root = tmp_path / "fake-real-home" / ".ash"
    store = root / "install-receipts"
    store.mkdir(parents=True)
    existing = store / "x.json"
    existing.write_text("{}", encoding="utf-8")
    new_dir = store / "new"
    new_file = store / "new.json"
    renamed = store / "y.json"
    with real_home_guard.watching(root):
        assert _refused_writes(lambda: new_dir.mkdir()) == {
            ("os.mkdir", _written(new_dir))
        }
        assert _refused_writes(lambda: new_file.write_text("{}", encoding="utf-8")) == {
            ("open", _written(new_file))
        }
        assert _refused_writes(lambda: os.chmod(existing, 0o600)) == {
            ("os.chmod", _written(existing))
        }
        assert _refused_writes(lambda: os.replace(existing, renamed)) == {
            ("os.rename", _written(existing)),
            ("os.rename", _written(renamed)),
        }
        # A read is not a write.
        assert existing.read_text(encoding="utf-8") == "{}"
        assert real_home_guard.drain() == []
    assert sorted(path.name for path in store.iterdir()) == ["x.json"]


#: The XDG directories the run moves, and their default places under a home.
_MOVED_XDG = {
    "XDG_CACHE_HOME": (".cache",),
    "XDG_CONFIG_HOME": (".config",),
    "XDG_DATA_HOME": (".local", "share"),
    "XDG_STATE_HOME": (".local", "state"),
}
#: The ones the guard's roots are built from.
_GUARDED_XDG = ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")


@pytest.mark.parametrize("variable", sorted(_MOVED_XDG))
def test_each_moved_xdg_directory_is_inside_it(
    variable, developer_home, developer_environment
):
    """Where a tool keeps its config, data, state or cache, whether or not the caller
    set it."""
    home = _the_tests_home()
    default = Path.home().joinpath(*_MOVED_XDG[variable])
    effective = Path(os.environ.get(variable) or default)
    assert home in effective.parents, (variable, effective)
    # Set, not only defaulted: a child that falls back some other way still gets it.
    assert os.environ.get(variable) == str(home.joinpath(*_MOVED_XDG[variable]))
    # And not the developer's own directory, set by them or defaulted under their home.
    # A boolean, so a failure does not print the environment.
    developers = developer_environment.get(variable) or developer_home.joinpath(
        *_MOVED_XDG[variable]
    )
    is_the_developers = os.path.realpath(effective) == os.path.realpath(developers)
    assert not is_the_developers, variable


@pytest.mark.parametrize("variable", _SHARED_CACHE_VARIABLES)
def test_the_shared_caches_are_left_where_the_caller_put_them(
    variable, developer_environment
):
    """Caches stay shared, so a run does not download every tool again.

    XDG_CACHE_HOME is not one of them: it moves into the home with the other XDG
    directories. uv's cache is the developer's, where they set it or where uv would
    have put it, so it is outside the run's own directories.
    """
    value = _SHARED_CACHES_AT_IMPORT[variable]
    if not value:
        # The run pins the variable to the developer's cache unless uv keeps the cache
        # somewhere moving HOME does not move (tests/conftest.py, _developer_uv_cache),
        # which is Windows alone; anywhere else an unset value is the run not pinning
        # it, and the test has to fail rather than pass with nothing checked.
        assert os.name == "nt", f"the run did not pin {variable}"
        pytest.skip(
            f"{variable} is unset: uv's cache is under LOCALAPPDATA there, which the "
            "run does not move"
        )
    session_directory = Path(os.environ["ASH_TEST_SESSION_TMPDIR"])
    assert not _same_or_inside(Path(value), session_directory), variable
    if variable in developer_environment:
        # A boolean, so a failure does not print the environment.
        is_the_developers = value == developer_environment[variable]
        assert is_the_developers, variable


def test_the_guard_watches_each_moved_xdg_directory(tmp_path):
    """The caller's own value of each variable, or its default under their HOME."""
    from tests.conftest import _real_home_guard_roots

    # The guard spells its roots through os.path.normcase, which changes the case of a
    # path on Windows, so the paths compared with them are spelled the same way.
    normcase = os.path.normcase
    home = tmp_path / "home"
    named = {variable: tmp_path / variable.lower() for variable in _GUARDED_XDG}
    roots = _real_home_guard_roots(
        {"HOME": str(home), **{v: str(p) for v, p in named.items()}}
    )
    assert normcase(os.path.abspath(home / ".ash")) in roots
    for variable, path in named.items():
        assert normcase(os.path.abspath(path)) in roots, variable
    defaults = _real_home_guard_roots({"HOME": str(home)})
    for variable in _GUARDED_XDG:
        default = home.joinpath(*_MOVED_XDG[variable])
        assert normcase(os.path.abspath(default)) in defaults, variable


def test_the_interpreter_installation_is_not_guarded():
    """uv installs Python under XDG_DATA_HOME, and an import can write bytecode there."""
    from tests.conftest import _real_home_guard_exclusions

    excluded = _real_home_guard_exclusions(Path.cwd())
    assert os.path.normcase(os.path.realpath(sys.base_prefix)) in excluded
    assert os.path.normcase(os.path.realpath(sys.prefix)) in excluded


@pytest.mark.skipif(os.name == "nt", reason="the guard's roots are POSIX paths here")
def test_the_guard_ignores_writes_under_an_excluded_path(tmp_path):
    """Control for the exclusions: only the write outside them is refused and recorded."""
    root = tmp_path / "fake-xdg-data"
    interpreter = root / "uv" / "python"
    interpreter.mkdir(parents=True)
    with real_home_guard.watching(root, exclude=[interpreter]):
        (interpreter / "module.pyc").write_bytes(b"")
        with pytest.raises(PermissionError, match="refused by the test guard"):
            (root / "uv" / "tools").mkdir()
        recorded = real_home_guard.drain()
    assert recorded == [("os.mkdir", os.path.abspath(root / "uv" / "tools"))]
    assert not (root / "uv" / "tools").exists()


#: The compound statements whose arms bind names at the level they stand at. A def or
#: a class binds its own name at that level and is a scope of its own inside.
_COMPOUND = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.Match,
)
if hasattr(ast, "TryStar"):  # Python 3.11+
    _COMPOUND = (*_COMPOUND, ast.TryStar)


def _exclusive_arms(node) -> list:
    """The arms of a compound statement of which at most one runs, each the statements
    that run together when it does.

    An ``if`` runs its body or its else. A ``try`` runs its body, then its else when
    the body raised nothing, then its finally in any case: those three are ONE arm,
    run in sequence, and each handler (whose own run is followed by the finally too)
    is another. A loop's body and its else run in sequence as well. A ``match`` runs
    one case. A ``with`` has one arm.
    """
    if isinstance(node, ast.If):
        return [node.body, node.orelse]
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        return [node.body + node.orelse]
    if isinstance(node, ast.Match):
        return [case.body for case in node.cases]
    if hasattr(node, "handlers"):  # Try, TryStar
        return [node.body + node.orelse + node.finalbody] + [
            handler.body + node.finalbody for handler in node.handlers
        ]
    return [node.body]


def _module_level_bindings(statements) -> list:
    """Each ``(name, line)`` a block of statements binds at the module level.

    A def, a class, an assignment and an annotated assignment with a value bind at the
    line they stand on. A compound statement (if, try, with, for, while, match) binds
    what its arms bind, at the lines inside it: the arms are read with this same walk,
    and a name bound in several MUTUALLY EXCLUSIVE arms of one statement
    (:func:`_exclusive_arms`) is counted from the arm that binds it most often, since
    an ``if``/``else`` or a ``try``/``except`` that each bind a name once bind it once
    at run time, while an arm that binds it twice is two bindings. Blocks that run in
    sequence (a try body and its finally, a loop body and its else) are one arm, so a
    name bound in both is two bindings.
    """
    found = []
    for node in statements:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.append((node.name, node.lineno))
        elif isinstance(node, ast.Assign):
            found.extend(
                (target.id, node.lineno)
                for target in node.targets
                if isinstance(target, ast.Name)
            )
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                found.append((node.target.id, node.lineno))
        elif isinstance(node, _COMPOUND):
            arms = [arm for arm in _exclusive_arms(node) if arm]
            most: dict = {}
            for arm in arms:
                lines_by_name: dict = {}
                for name, line in _module_level_bindings(arm):
                    lines_by_name.setdefault(name, []).append(line)
                for name, lines in lines_by_name.items():
                    if len(lines) > len(most.get(name, [])):
                        most[name] = lines
            for name, lines in most.items():
                found.extend((name, line) for line in lines)
    return found


def _bound_more_than_once(source: str) -> dict:
    """``{name: [lines]}`` for each module-level name ``source`` binds twice or more."""
    lines_by_name: dict = {}
    for name, line in _module_level_bindings(ast.parse(source).body):
        lines_by_name.setdefault(name, []).append(line)
    return {name: lines for name, lines in lines_by_name.items() if len(lines) > 1}


def test_the_root_conftest_binds_each_top_level_name_once():
    """A second ``def`` or assignment of a name silently replaces the first.

    The later one is what every caller gets, so the earlier is code that reads as live
    and is not. This module once tested a session-home setup that the conftest's own
    second definitions of the same functions had already replaced. The walk looks into
    a top-level if, try, with or loop too: a def inside one replaces a top-level def
    of the same name just as a second top-level def does.
    """
    source = (Path(__file__).resolve().parents[1] / "conftest.py").read_text(
        encoding="utf-8"
    )
    twice = _bound_more_than_once(source)
    assert not twice, twice


_PLANTED_SECOND_BINDINGS = """\
import os


def helper():
    return 1


if os.name == "nt":

    def helper():
        return 2


try:
    FALLBACK = read_it()
except OSError:
    FALLBACK = None

if os.name == "nt":
    ONCE = 1
else:
    ONCE = 2

with open("settings") as handle:
    SETTING = handle.read()
SETTING = "again"
"""


def test_the_binding_walk_sees_into_a_top_level_compound_statement():
    """Control: a def inside a top-level ``if`` that replaces a top-level def, and an
    assignment inside a ``with`` repeated at the top level, are each two bindings;
    a ``try``/``except`` whose body and handler each assign one name, and an
    ``if``/``else`` that assign one name once each, bind it once at run time
    whichever arm runs, and are one. (An ``import`` is not a binding the walk
    counts, so the arms are assignments here, which it does.)"""
    twice = _bound_more_than_once(_PLANTED_SECOND_BINDINGS)

    assert set(twice) == {"helper", "SETTING"}, twice
    assert twice["helper"] == [4, 10]
    assert twice["SETTING"] == [25, 26]
    assert "FALLBACK" not in twice
    assert "ONCE" not in twice


def test_the_binding_walk_counts_an_arm_that_binds_twice_as_twice():
    """Control: two bindings of one name inside one arm are a replacement even
    though the other arm binds it once."""
    source = "if x:\n    A = 1\n    A = 2\nelse:\n    A = 3\n"

    assert _bound_more_than_once(source) == {"A": [2, 3]}


_PLANTED_SEQUENTIAL_ARMS = """\
try:
    A = open_it()
finally:
    A = None

for item in items:
    B = item
else:
    B = None

try:
    C = read()
except OSError:
    C = None
else:
    E = C.strip()

match flavor:
    case "one":
        D = 1
    case _:
        D = 2
"""


def test_the_binding_walk_sums_the_arms_that_run_in_sequence():
    """Control: a try body and its finally run one after the other, as a loop body
    and its else do, so a name each binds once is bound twice at run time; the
    walk once took the most-binding arm across them and read each as one. A name
    bound in a try body and in its handler is bound once on either path (the
    handler replaces a body that raised), the else after the body is a binding of
    its own, and a match with one binding per case binds once."""
    twice = _bound_more_than_once(_PLANTED_SEQUENTIAL_ARMS)

    assert twice == {"A": [2, 4], "B": [7, 9]}, twice


@pytest.mark.skipif(os.name == "nt", reason="the guard's roots are POSIX paths here")
def test_allowing_lets_through_only_the_named_paths_and_only_inside_the_block(
    tmp_path,
):
    """Control for ``allowing``: named files pass, a neighbor is recorded, and the
    exemption ends with the block."""
    root = tmp_path / "fake-xdg-data"
    root.mkdir()
    planted = root / "planted.txt"
    neighbor = root / "neighbor.txt"
    with real_home_guard.watching(root):
        with real_home_guard.allowing([planted]):
            planted.write_text("x", encoding="utf-8")
            planted.unlink()
            with pytest.raises(PermissionError, match="refused by the test guard"):
                neighbor.write_text("x", encoding="utf-8")
        inside = real_home_guard.drain()
        with pytest.raises(PermissionError, match="refused by the test guard"):
            planted.write_text("x", encoding="utf-8")
        after = real_home_guard.drain()
    assert inside == [("open", os.path.abspath(neighbor))]
    assert after == [("open", os.path.abspath(planted))]
