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


def _refused_events(operation) -> set:
    """Run a write the guard must refuse; return the events it recorded for it."""
    with pytest.raises(PermissionError, match="refused by the test guard"):
        operation()
    return {event for event, _ in real_home_guard.drain()}


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
        session_directory = Path(os.environ["ASH_TEST_SESSION_TMPDIR"])
        assert not _in_a_real_ash(constants.ASH_BIN_PATH, developer_home)
        assert _same_or_inside(constants.ASH_BIN_PATH, session_directory)


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
    lands, and records the event; a read of a file that is already there is neither.
    Each record is drained as it is checked, so the teardown check does not fail this
    test for them.
    """
    root = tmp_path / "fake-real-home" / ".ash"
    store = root / "install-receipts"
    store.mkdir(parents=True)
    existing = store / "x.json"
    existing.write_text("{}", encoding="utf-8")
    with real_home_guard.watching(root):
        assert _refused_events(lambda: (store / "new").mkdir()) == {"os.mkdir"}
        assert _refused_events(
            lambda: (store / "new.json").write_text("{}", encoding="utf-8")
        ) == {"open"}
        assert _refused_events(lambda: os.chmod(existing, 0o600)) == {"os.chmod"}
        assert _refused_events(lambda: os.replace(existing, store / "y.json")) == {
            "os.rename"
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
    if value:
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


def test_the_root_conftest_binds_each_top_level_name_once():
    """A second ``def`` or assignment of a name silently replaces the first.

    The later one is what every caller gets, so the earlier is code that reads as live
    and is not. This module once tested a session-home setup that the conftest's own
    second definitions of the same functions had already replaced.
    """
    source = (Path(__file__).resolve().parents[1] / "conftest.py").read_text(
        encoding="utf-8"
    )
    lines_by_name: dict = {}
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            names = [node.target.id] if isinstance(node.target, ast.Name) else []
        else:
            continue
        for name in names:
            lines_by_name.setdefault(name, []).append(node.lineno)
    twice = {name: lines for name, lines in lines_by_name.items() if len(lines) > 1}
    assert not twice, twice


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
